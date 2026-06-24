//! ce-auth — the operator's reusable auth/SSO app for CE.
//!
//! ce-auth owns the operator's device registry and answers one question for every other app:
//! "is this device the operator?". It is the central home for the device-auth that previously lived
//! inside individual apps (e.g. ce-watch). A light axum service that lives beside the relay; it holds
//! NO libp2p / wasmtime / heavy deps.
//!
//! Two surfaces:
//!
//!   1. The **relying-party API** every app uses:
//!      - `GET /challenge?aud=<appId>` -> `{ aud, nonce, ts }`. The nonce is the stateless
//!        `HMAC-SHA256(server_secret, aud + "|" + ts)`; nothing is stored; 300s TTL.
//!      - `POST /verify { aud, deviceId, sig, nonce, ts }` -> `{ ok, role, deviceId }`. ce-auth
//!        re-derives + TTL-checks the nonce (bound to `aud`), looks up `deviceId` in its registry, and
//!        verifies `sig` against the device's ENROLLED ecdsa pub. `ok = (sig valid AND role==admin)`.
//!        A device enrolled here == the operator == trusted by every app.
//!
//!   2. The operator's own **device-management console** (`/me`, `/claim`, `/request`, `/devices`,
//!      `/devices/approve`, `/devices/revoke`), gated by ce-auth's OWN device-auth with `aud=ce-auth`.
//!      Enrollment is self-service: TOFU `claim` for the first device, then request / approve / revoke.

mod auth;
mod secrets;
mod store;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use tower_http::cors::CorsLayer;

use secrets::SecretStore;
use store::{DeviceStore, RevokeOutcome};

const CONSOLE_HTML: &str = include_str!("console.html");

#[derive(Clone)]
struct AppState {
    /// The operator's self-managed device registry (deviceId -> { pub, role, label, added_ts }),
    /// persisted to `devices.json`. The source of truth for who the operator is after boot.
    devices: Arc<DeviceStore>,
    /// Stateless-nonce HMAC key. Persisted across a process restart only if `CE_AUTH_SERVER_SECRET`
    /// is set; otherwise a fresh random secret is minted per boot (in-flight challenges from before a
    /// restart simply expire). For multi-instance / restart-stable verification, set the env.
    server_secret: Arc<Vec<u8>>,
    /// The operator's immutable, boot-loaded named-secret map (from `CE_AUTH_SECRETS`). Served by
    /// `GET /secret/:name` to an enrolled admin device. Values are never logged.
    secret_store: Arc<SecretStore>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ce_auth=info,tower_http=warn".into()),
        )
        .init();

    let data_dir = store::default_data_dir();

    // The env is a BOOTSTRAP seed, not the source of truth: it is written into the persisted device
    // store at startup for any device not already present, after which devices are managed
    // self-service (claim / request / approve / revoke) without ever touching the env or redeploying.
    let seed = auth::parse_seed(&std::env::var("CE_AUTH_ADMIN_DEVICES").unwrap_or_default());
    let devices = Arc::new(DeviceStore::open(&data_dir, &seed)?);
    let server_secret = server_secret_from_env();

    // Named secrets are loaded ONCE at boot from CE_AUTH_SECRETS and are immutable thereafter. Only
    // the count of names is logged here — values are never logged anywhere.
    let secret_store = SecretStore::from_env(&std::env::var("CE_AUTH_SECRETS").unwrap_or_default());
    tracing::info!(count = secret_store.len(), "named secrets loaded for SECRET-DELIVERY");

    if std::env::var("CE_AUTH_SERVER_SECRET").map(|s| s.is_empty()).unwrap_or(true) {
        tracing::warn!(
            "CE_AUTH_SERVER_SECRET is unset — using a per-boot ephemeral nonce key. Challenges do \
             not survive a restart; set CE_AUTH_SERVER_SECRET for stable verification."
        );
    }
    if !devices.has_admins() {
        tracing::warn!(
            "no operator device yet — open the console and click \"claim this console\" to become \
             the first admin (TOFU). Or seed one via CE_AUTH_ADMIN_DEVICES (deviceId:ecdsaPubB64url)."
        );
    } else {
        tracing::info!(count = devices.admin_count(), "operator device(s) present");
    }

    let state = AppState {
        devices,
        server_secret: Arc::new(server_secret),
        secret_store: Arc::new(secret_store),
    };

    let app = router(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8972);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!(%addr, data_dir = %data_dir.display(), "ce-auth listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(serve_console))
        .route("/health", get(|| async { "ok" }))
        // Relying-party API (used by every app).
        .route("/challenge", get(challenge))
        .route("/verify", post(verify))
        // Operator's own device-management console surfaces (gated by aud=ce-auth device-auth).
        .route("/me", get(me))
        .route("/claim", post(claim))
        .route("/request", post(request))
        .route("/devices", get(devices_list))
        .route("/devices/approve", post(devices_approve))
        .route("/devices/revoke", post(devices_revoke))
        // SECRET-DELIVERY: hand a named secret to an enrolled admin device (admin device-auth).
        .route("/secret/:name", get(secret))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// Resolve the stateless-nonce HMAC key: from `CE_AUTH_SERVER_SECRET` if set (so challenges survive a
/// restart and verification is stable), otherwise a fresh 32-byte random-ish secret minted per boot.
fn server_secret_from_env() -> Vec<u8> {
    if let Ok(s) = std::env::var("CE_AUTH_SERVER_SECRET") {
        if !s.is_empty() {
            return s.into_bytes();
        }
    }
    // Cheap, dependency-free entropy: mix time + pid + an addr. The nonce is only a replay guard
    // within a 300s window, not a long-term key, so a per-boot ephemeral secret is sufficient.
    let mut seed = Vec::with_capacity(32);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    seed.extend_from_slice(&nanos.to_le_bytes());
    seed.extend_from_slice(&std::process::id().to_le_bytes());
    let h = &seed as *const _ as usize;
    seed.extend_from_slice(&h.to_le_bytes());
    while seed.len() < 32 {
        seed.push(seed[seed.len() % seed.len().max(1)].wrapping_add(0x9e));
    }
    seed.truncate(32);
    seed
}

// ---- relying-party API ------------------------------------------------------

#[derive(Deserialize)]
struct ChallengeQuery {
    aud: Option<String>,
}

/// `GET /challenge?aud=<appId>` — mint a fresh `{ aud, nonce, ts }` for a device to sign. Public: the
/// nonce is single-use within 300s and only the holder of an enrolled device key can produce a
/// signature that subsequently verifies, so handing out challenges is harmless. `aud` defaults to the
/// console audience (`ce-auth`) when omitted, so the console can hit the same endpoint.
async fn challenge(
    State(st): State<AppState>,
    Query(q): Query<ChallengeQuery>,
) -> impl IntoResponse {
    let aud = q
        .aud
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(auth::CONSOLE_AUD);
    let ch = auth::make_challenge(&st.server_secret, aud);
    (
        StatusCode::OK,
        Json(json!({ "aud": ch.aud, "nonce": ch.nonce, "ts": ch.ts })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct VerifyBody {
    aud: String,
    #[serde(rename = "deviceId")]
    device_id: String,
    sig: String,
    nonce: String,
    ts: String,
}

/// `POST /verify { aud, deviceId, sig, nonce, ts }` -> `{ ok, role, deviceId }`. The single call every
/// app makes. We re-derive + TTL-check the nonce (bound to `aud`), look up `deviceId` in the registry,
/// and verify `sig` against the device's ENROLLED ecdsa pub. `ok = (signature valid AND role==admin)`.
///
/// A device unknown to the registry, or one whose signature is invalid / tampered / expired / for a
/// different `aud`, yields `ok=false`. We always return 200 with the structured verdict; the verdict,
/// not the HTTP status, is the answer.
async fn verify(State(st): State<AppState>, Json(body): Json<VerifyBody>) -> impl IntoResponse {
    let role = st.devices.role_of(&body.device_id);

    // Resolve the ENROLLED pub for this device. An unknown device has no enrolled pub, so there is
    // nothing to verify against -> ok=false, role=none. We never verify against a caller-supplied pub
    // here: enrollment is the whole point.
    let ok = match st.devices.pub_of(&body.device_id) {
        Some(pub_b64) => {
            let sig_valid = auth::verify_signature(
                &st.server_secret,
                &body.aud,
                &body.device_id,
                &body.nonce,
                &body.ts,
                &body.sig,
                &pub_b64,
            )
            .is_ok();
            if !sig_valid {
                tracing::debug!(device_id = %body.device_id, aud = %body.aud, "verify: signature/nonce check failed");
            }
            // The operator == an enrolled admin. A pending device (key-valid but not yet approved) is
            // NOT the operator, so ok stays false even with a perfect signature.
            sig_valid && role == store::ROLE_ADMIN
        }
        None => false,
    };

    (
        StatusCode::OK,
        Json(json!({ "ok": ok, "role": role, "deviceId": body.device_id })),
    )
        .into_response()
}

// ---- console auth helpers ---------------------------------------------------

/// The 401 returned whenever console device-auth fails, for any reason. We deliberately do not leak
/// which check failed.
fn unauthorized() -> axum::response::Response {
    (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"}))).into_response()
}

/// Prove the request controls the device key for the claimed `deviceId` over a fresh `aud=ce-auth`
/// challenge ("key-valid"). The verifying key is resolved from the persisted store if the device is
/// known; otherwise (a first-time device) the caller must supply it via `body_pub` (TOFU for
/// claim/request). The stored pub always wins when present, so a known device can never be
/// authenticated against an attacker-chosen body pub. Returns the authenticated device id, or a 401.
fn require_key_valid(
    st: &AppState,
    headers: &HeaderMap,
    body_pub: Option<&str>,
) -> Result<String, axum::response::Response> {
    let device_id = match auth::header_device_id(headers) {
        Some(id) => id,
        None => return Err(unauthorized()),
    };
    let pub_b64 = match st.devices.pub_of(device_id).or_else(|| body_pub.map(|s| s.to_string())) {
        Some(p) => p,
        None => return Err(unauthorized()),
    };
    match auth::authenticate_console(headers, &pub_b64, &st.server_secret) {
        Ok(id) => Ok(id.to_string()),
        Err(e) => {
            tracing::debug!(reason = ?e, "console key-valid auth rejected");
            Err(unauthorized())
        }
    }
}

/// Require the request be both key-valid AND carry `role=admin` (the operator). Used by the
/// device-management endpoints. Returns the authenticated admin device id.
fn require_admin(st: &AppState, headers: &HeaderMap) -> Result<String, axum::response::Response> {
    let device_id = require_key_valid(st, headers, None)?;
    if st.devices.is_admin(&device_id) {
        Ok(device_id)
    } else {
        tracing::debug!(device_id = %device_id, "key-valid but not admin");
        Err(unauthorized())
    }
}

// ---- console endpoints ------------------------------------------------------

/// `GET /me` — key-valid required. Reports this device's role from the store and whether any admin
/// exists yet, so the console can pick the right screen (console / claim / request).
async fn me(State(st): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let device_id = match require_key_valid(&st, &headers, None) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let role = st.devices.role_of(&device_id);
    (
        StatusCode::OK,
        Json(json!({
            "deviceId": device_id,
            "role": role,
            "hasAdmins": st.devices.has_admins(),
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct ClaimBody {
    #[serde(default, rename = "pub")]
    pub_b64: String,
}

/// `POST /claim` — TOFU first-claim. If the store has ZERO admins, the (key-valid) requesting device
/// becomes `role=admin`. If any admin already exists -> 409. The body carries the device's compact
/// pub so we can both key-verify and persist it.
async fn claim(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ClaimBody>,
) -> impl IntoResponse {
    if body.pub_b64.is_empty() || auth::validate_compact_pub(&body.pub_b64).is_err() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad pub"}))).into_response();
    }
    let device_id = match require_key_valid(&st, &headers, Some(&body.pub_b64)) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    match st.devices.claim(&device_id, &body.pub_b64) {
        Ok(true) => (
            StatusCode::OK,
            Json(json!({"ok": true, "deviceId": device_id, "role": "admin"})),
        )
            .into_response(),
        Ok(false) => (
            StatusCode::CONFLICT,
            Json(json!({"error": "admins already exist; ask one to approve your request"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "claim persist failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "store"}))).into_response()
        }
    }
}

#[derive(Deserialize)]
struct RequestBody {
    #[serde(default)]
    label: String,
    #[serde(default, rename = "pub")]
    pub_b64: String,
}

/// `POST /request` — key-valid required. Records the device as `role=pending` with its compact pub
/// (so an admin can later approve+verify it) and an optional label. Idempotent.
async fn request(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RequestBody>,
) -> impl IntoResponse {
    if body.pub_b64.is_empty() || auth::validate_compact_pub(&body.pub_b64).is_err() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad pub"}))).into_response();
    }
    let device_id = match require_key_valid(&st, &headers, Some(&body.pub_b64)) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    match st.devices.request(&device_id, &body.pub_b64, body.label.trim()) {
        Ok(role) => (
            StatusCode::OK,
            Json(json!({"ok": true, "deviceId": device_id, "role": role})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "request persist failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "store"}))).into_response()
        }
    }
}

/// `GET /devices` — ADMIN ONLY. Lists admins and pending devices.
async fn devices_list(State(st): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(resp) = require_admin(&st, &headers) {
        return resp;
    }
    let mut admins = Vec::new();
    let mut pending = Vec::new();
    for (id, dev) in st.devices.list() {
        let row = json!({ "deviceId": id, "label": dev.label, "added_ts": dev.added_ts });
        if dev.role == store::ROLE_ADMIN {
            admins.push(row);
        } else {
            pending.push(row);
        }
    }
    (StatusCode::OK, Json(json!({ "admins": admins, "pending": pending }))).into_response()
}

#[derive(Deserialize)]
struct DeviceIdBody {
    #[serde(rename = "deviceId")]
    device_id: String,
}

/// `POST /devices/approve` — ADMIN ONLY. Promote a pending device to admin.
async fn devices_approve(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DeviceIdBody>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&st, &headers) {
        return resp;
    }
    match st.devices.approve(&body.device_id) {
        Ok(true) => (StatusCode::OK, Json(json!({"ok": true, "role": "admin"}))).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "no pending device with that id"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "approve persist failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "store"}))).into_response()
        }
    }
}

/// `POST /devices/revoke` — ADMIN ONLY. Remove a device. Cannot remove the last admin.
async fn devices_revoke(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DeviceIdBody>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&st, &headers) {
        return resp;
    }
    match st.devices.revoke(&body.device_id) {
        Ok(RevokeOutcome::Removed) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Ok(RevokeOutcome::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "no device with that id"})),
        )
            .into_response(),
        Ok(RevokeOutcome::LastAdmin) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "cannot revoke the last admin"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "revoke persist failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "store"}))).into_response()
        }
    }
}

// ---- SECRET-DELIVERY --------------------------------------------------------

/// `GET /secret/:name` — ADMIN ONLY (same device-auth as `/me` / `/devices`: prove possession of an
/// ENROLLED admin device key over a fresh `aud=ce-auth` challenge). On success returns
/// `200 { "name": <name>, "value": <secret> }`. Bad/missing/expired signature or a non-admin device
/// -> 401; a name not in the boot-loaded secret map -> 404. The secret VALUE is never logged.
async fn secret(
    State(st): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Authorize FIRST so an unauthorized caller cannot probe which names exist (no 404/200 oracle).
    if let Err(resp) = require_admin(&st, &headers) {
        return resp;
    }
    match st.secret_store.get(&name) {
        Some(value) => (
            StatusCode::OK,
            Json(json!({ "name": name, "value": value })),
        )
            .into_response(),
        None => {
            // Name is not a secret — safe to log (it is not a secret value).
            tracing::debug!(%name, "secret request for unknown name");
            (StatusCode::NOT_FOUND, Json(json!({"error": "unknown secret"}))).into_response()
        }
    }
}

async fn serve_console() -> impl IntoResponse {
    // The HTML itself is public; every data call behind it is gated by ce-secrets device-auth. The
    // page holds a device key in localStorage, fetches /challenge, signs it, and sends the
    // x-ce-device-id / x-ce-auth / x-ce-aud / x-ce-nonce / x-ce-ts headers.
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::HeaderName::from_static("x-robots-tag"), "noindex"),
        ],
        Html(CONSOLE_HTML),
    )
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // oneshot

    use ce_secrets_rs::{sign_challenge, DeviceKey};

    const SERVER_SECRET: &[u8] = b"test-server-secret";
    /// Named secrets the test state is booted with (mirrors `CE_AUTH_SECRETS`).
    const TEST_SECRETS: &str = "api-key=s3cr3t-value;db-url=postgres://x";

    fn temp_dir() -> std::path::PathBuf {
        let mut d = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        d.push(format!("ce-auth-test-{}-{}", std::process::id(), nanos));
        d
    }

    /// The operator's device key, enrolled into the test state. Real P-256 ECDH+ECDSA pair.
    fn test_device() -> DeviceKey {
        let dk_json = r#"{
          "ecdhPriv":{"key_ops":["deriveBits"],"ext":true,"kty":"EC","x":"M3CtY4emfBsOGSCycOGY_wRD2ufV_Glmwt95AQRJRKo","y":"Q2p7o-FMQ-wRaiTOXzMd6Dyj3aFQQsi4v71k1sNnArs","crv":"P-256","d":"sR3IYJSDqB8x4l3J3p6w8t3y2QZ1m0c9V7n4kL2bA8E"},
          "ecdhPub":{"key_ops":[],"ext":true,"kty":"EC","x":"M3CtY4emfBsOGSCycOGY_wRD2ufV_Glmwt95AQRJRKo","y":"Q2p7o-FMQ-wRaiTOXzMd6Dyj3aFQQsi4v71k1sNnArs","crv":"P-256"},
          "ecdsaPriv":{"key_ops":["sign"],"ext":true,"kty":"EC","x":"ReIzIU_aBWgw2kRAa42L_AZiQmiYYb4RsvdGTwdR-jk","y":"oPRQppQEcMfMJknsjaQNU2uZc4Hz7GZ9T_Bf0J2L4KM","crv":"P-256","d":"pQ7w2zX9c4V6n8m1L3k5J7h9G2f4D6s8A0b2C4e6F8I"},
          "ecdsaPub":{"key_ops":["verify"],"ext":true,"kty":"EC","x":"ReIzIU_aBWgw2kRAa42L_AZiQmiYYb4RsvdGTwdR-jk","y":"oPRQppQEcMfMJknsjaQNU2uZc4Hz7GZ9T_Bf0J2L4KM","crv":"P-256"},
          "id":"0e30d71a203f8933"
        }"#;
        DeviceKey::from_json(dk_json).unwrap()
    }

    /// A SECOND, distinct real P-256 device key used to exercise request/approve/revoke + the
    /// unenrolled/pending verify paths.
    fn second_device() -> DeviceKey {
        let dk_json = r#"{
          "ecdhPriv":{"key_ops":["deriveBits"],"ext":true,"kty":"EC","x":"Xmkz8xdxZN39CEu4t437RTP9zqSpeN_HEPWFl-Wcvic","y":"WHvWLOzDWyZmUhG8nnISc8dN5Gol-Cyfm1YaJpIvUWU","crv":"P-256","d":"ok8M6GVgJIfF71fjBubSB3L_0HvfvcQeunr9N-5IFnA"},
          "ecdhPub":{"key_ops":[],"ext":true,"kty":"EC","x":"Xmkz8xdxZN39CEu4t437RTP9zqSpeN_HEPWFl-Wcvic","y":"WHvWLOzDWyZmUhG8nnISc8dN5Gol-Cyfm1YaJpIvUWU","crv":"P-256"},
          "ecdsaPriv":{"key_ops":["sign"],"ext":true,"kty":"EC","x":"Xmkz8xdxZN39CEu4t437RTP9zqSpeN_HEPWFl-Wcvic","y":"WHvWLOzDWyZmUhG8nnISc8dN5Gol-Cyfm1YaJpIvUWU","crv":"P-256","d":"ok8M6GVgJIfF71fjBubSB3L_0HvfvcQeunr9N-5IFnA"},
          "ecdsaPub":{"key_ops":["verify"],"ext":true,"kty":"EC","x":"Xmkz8xdxZN39CEu4t437RTP9zqSpeN_HEPWFl-Wcvic","y":"WHvWLOzDWyZmUhG8nnISc8dN5Gol-Cyfm1YaJpIvUWU","crv":"P-256"},
          "id":"f00dcafe12345678"
        }"#;
        DeviceKey::from_json(dk_json).unwrap()
    }

    fn compact_pub(dk: &DeviceKey) -> String {
        ce_secrets_rs::encoding::b64url_encode(&dk.ecdsa_pub.raw_public_bytes().unwrap())
    }

    /// State with the test device SEEDED as an admin (mirrors `CE_AUTH_ADMIN_DEVICES`) and a fixed
    /// server secret (so challenges are reproducible across handler calls within a test).
    fn state_with(dir: std::path::PathBuf) -> AppState {
        let dk = test_device();
        let seed = vec![(dk.id.clone(), compact_pub(&dk))];
        AppState {
            devices: Arc::new(DeviceStore::open(&dir, &seed).expect("open device store")),
            server_secret: Arc::new(SERVER_SECRET.to_vec()),
            secret_store: Arc::new(SecretStore::from_env(TEST_SECRETS)),
        }
    }

    /// State with NO admins seeded — empty store.
    fn state_empty(dir: std::path::PathBuf) -> AppState {
        AppState {
            devices: Arc::new(DeviceStore::open(&dir, &[]).expect("open device store")),
            server_secret: Arc::new(SERVER_SECRET.to_vec()),
            secret_store: Arc::new(SecretStore::from_env(TEST_SECRETS)),
        }
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Fetch a live challenge for `aud` from the router and return `(aud, nonce, ts)`.
    async fn get_challenge(app: &Router, aud: &str) -> (String, String, String) {
        let req = Request::builder()
            .uri(format!("/challenge?aud={aud}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        assert_eq!(j["aud"], aud);
        (
            j["aud"].as_str().unwrap().to_string(),
            j["nonce"].as_str().unwrap().to_string(),
            j["ts"].as_str().unwrap().to_string(),
        )
    }

    /// The console headers a real device request would carry, for a fresh `aud=ce-auth` challenge.
    async fn signed_console_headers(app: &Router, dk: &DeviceKey) -> Vec<(String, String)> {
        let (aud, nonce, ts) = get_challenge(app, auth::CONSOLE_AUD).await;
        let sig = sign_challenge(dk, &aud, &nonce, &ts).unwrap();
        vec![
            ("x-ce-device-id".into(), dk.id.clone()),
            ("x-ce-auth".into(), sig),
            ("x-ce-aud".into(), aud),
            ("x-ce-nonce".into(), nonce),
            ("x-ce-ts".into(), ts),
        ]
    }

    fn with_headers(
        mut b: axum::http::request::Builder,
        headers: &[(String, String)],
    ) -> axum::http::request::Builder {
        for (k, v) in headers {
            b = b.header(k.as_str(), v.as_str());
        }
        b
    }

    async fn post_verify(app: &Router, body: serde_json::Value) -> serde_json::Value {
        let req = Request::builder()
            .method("POST")
            .uri("/verify")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        body_json(resp).await
    }

    // ---- relying-party /challenge + /verify ----

    #[tokio::test]
    async fn challenge_returns_aud_bound_nonce() {
        let dir = temp_dir();
        let app = router(state_with(dir.clone()));
        let (aud, nonce, ts) = get_challenge(&app, "some-app").await;
        assert_eq!(aud, "some-app");
        assert!(!nonce.is_empty());
        // The nonce is exactly HMAC(K_aud, ts) over the audience-scoped key — re-derive and confirm.
        let expected = ce_secrets_rs::make_nonce(&auth::aud_secret(SERVER_SECRET, &aud), &ts);
        assert_eq!(nonce, expected);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn verify_ok_admin_for_enrolled_admin() {
        let dir = temp_dir();
        let app = router(state_with(dir.clone()));
        let dk = test_device();
        let aud = "demo-app";
        let (aud, nonce, ts) = get_challenge(&app, aud).await;
        let sig = sign_challenge(&dk, &aud, &nonce, &ts).unwrap();
        let j = post_verify(
            &app,
            json!({ "aud": aud, "deviceId": dk.id, "sig": sig, "nonce": nonce, "ts": ts }),
        )
        .await;
        assert_eq!(j["ok"], true);
        assert_eq!(j["role"], "admin");
        assert_eq!(j["deviceId"], dk.id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn verify_false_for_unenrolled_device() {
        // A perfectly valid signature from a device that is NOT in the registry -> ok=false, none.
        let dir = temp_dir();
        let app = router(state_with(dir.clone()));
        let stranger = second_device();
        let (aud, nonce, ts) = get_challenge(&app, "demo-app").await;
        let sig = sign_challenge(&stranger, &aud, &nonce, &ts).unwrap();
        let j = post_verify(
            &app,
            json!({ "aud": aud, "deviceId": stranger.id, "sig": sig, "nonce": nonce, "ts": ts }),
        )
        .await;
        assert_eq!(j["ok"], false);
        assert_eq!(j["role"], "none");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn verify_false_for_pending_device() {
        // A device enrolled as pending (key-valid, real enrolled pub) but not approved is NOT the
        // operator: ok=false even with a valid signature, role reported as pending.
        let dir = temp_dir();
        let st = state_with(dir.clone());
        let pending = second_device();
        st.devices.request(&pending.id, &compact_pub(&pending), "phone").unwrap();
        let app = router(st);
        let (aud, nonce, ts) = get_challenge(&app, "demo-app").await;
        let sig = sign_challenge(&pending, &aud, &nonce, &ts).unwrap();
        let j = post_verify(
            &app,
            json!({ "aud": aud, "deviceId": pending.id, "sig": sig, "nonce": nonce, "ts": ts }),
        )
        .await;
        assert_eq!(j["ok"], false);
        assert_eq!(j["role"], "pending");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn verify_false_for_tampered_signature() {
        let dir = temp_dir();
        let app = router(state_with(dir.clone()));
        let dk = test_device();
        let (aud, nonce, ts) = get_challenge(&app, "demo-app").await;
        let mut sig = sign_challenge(&dk, &aud, &nonce, &ts).unwrap();
        let last = sig.pop().unwrap();
        sig.push(if last == 'A' { 'B' } else { 'A' });
        let j = post_verify(
            &app,
            json!({ "aud": aud, "deviceId": dk.id, "sig": sig, "nonce": nonce, "ts": ts }),
        )
        .await;
        assert_eq!(j["ok"], false);
        // Tampered signature, but the device IS an enrolled admin, so role still reports admin.
        assert_eq!(j["role"], "admin");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn verify_false_for_expired_challenge() {
        let dir = temp_dir();
        let app = router(state_with(dir.clone()));
        let dk = test_device();
        let aud = "demo-app";
        // Build a ts 10 minutes in the past with a correctly-derived (aud-bound) nonce + valid sig.
        let old_ms = ce_secrets_rs::now_unix_ms() - 600_000;
        let old_secs = old_ms / 1000;
        let days = old_secs.div_euclid(86_400) + 719_468;
        let tod = old_secs.rem_euclid(86_400);
        // Reuse the SDK round-trip to make the ts; simplest is via a tiny civil-from-days here.
        let (y, mo, d) = {
            let z = days;
            let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
            let doe = z - era * 146_097;
            let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
            let y = yoe + era * 400;
            let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
            let mp = (5 * doy + 2) / 153;
            let dd = doy - (153 * mp + 2) / 5 + 1;
            let m = if mp < 10 { mp + 3 } else { mp - 9 };
            (if m <= 2 { y + 1 } else { y }, m, dd)
        };
        let old_ts = format!(
            "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
            tod / 3600,
            (tod % 3600) / 60,
            tod % 60
        );
        let nonce = ce_secrets_rs::make_nonce(&auth::aud_secret(SERVER_SECRET, aud), &old_ts);
        let sig = sign_challenge(&dk, aud, &nonce, &old_ts).unwrap();
        let j = post_verify(
            &app,
            json!({ "aud": aud, "deviceId": dk.id, "sig": sig, "nonce": nonce, "ts": old_ts }),
        )
        .await;
        assert_eq!(j["ok"], false);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn verify_binds_aud_cross_aud_fails() {
        // A signature obtained for aud=X must NOT verify when posted as aud=Y. The nonce was minted
        // for X (HMAC(secret, X|ts)); re-deriving under Y will not match -> ok=false.
        let dir = temp_dir();
        let app = router(state_with(dir.clone()));
        let dk = test_device();
        let (aud_x, nonce, ts) = get_challenge(&app, "aud-x").await;
        let sig = sign_challenge(&dk, &aud_x, &nonce, &ts).unwrap();
        // Post the SAME nonce/ts/sig but claim aud=aud-y.
        let j = post_verify(
            &app,
            json!({ "aud": "aud-y", "deviceId": dk.id, "sig": sig, "nonce": nonce, "ts": ts }),
        )
        .await;
        assert_eq!(j["ok"], false, "a sig for aud-x must fail verify for aud-y");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- console: claim / request / approve / revoke / persistence ----

    #[tokio::test]
    async fn first_claim_works_second_conflicts() {
        let dir = temp_dir();
        let st = state_empty(dir.clone());
        let app = router(st.clone());
        let dk = test_device();
        let pub_b64 = compact_pub(&dk);

        let headers = signed_console_headers(&app, &dk).await;
        let body = json!({ "pub": pub_b64 }).to_string();
        let req = with_headers(
            Request::builder().method("POST").uri("/claim").header("content-type", "application/json"),
            &headers,
        )
        .body(Body::from(body.clone()))
        .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(st.devices.is_admin(&dk.id));

        let headers = signed_console_headers(&app, &dk).await;
        let req = with_headers(
            Request::builder().method("POST").uri("/claim").header("content-type", "application/json"),
            &headers,
        )
        .body(Body::from(body))
        .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn request_approve_then_verify_ok_then_revoke() {
        let dir = temp_dir();
        let st = state_with(dir.clone());
        let app = router(st.clone());
        let admin = test_device();
        let requester = second_device();
        let req_pub = compact_pub(&requester);

        // Before approval, verify for an app reports ok=false (pending != operator) — first record it.
        let headers = signed_console_headers(&app, &requester).await;
        let body = json!({ "label": "leif-phone", "pub": req_pub }).to_string();
        let req = with_headers(
            Request::builder().method("POST").uri("/request").header("content-type", "application/json"),
            &headers,
        )
        .body(Body::from(body))
        .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(st.devices.role_of(&requester.id), "pending");

        // Admin lists devices and sees the pending requester.
        let headers = signed_console_headers(&app, &admin).await;
        let req = with_headers(Request::builder().uri("/devices"), &headers)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        assert_eq!(j["pending"].as_array().unwrap().len(), 1);

        // Admin approves.
        let headers = signed_console_headers(&app, &admin).await;
        let req = with_headers(
            Request::builder().method("POST").uri("/devices/approve").header("content-type", "application/json"),
            &headers,
        )
        .body(Body::from(json!({ "deviceId": requester.id }).to_string()))
        .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(st.devices.is_admin(&requester.id));

        // Now /verify reports ok=true for the requester (it is the operator).
        let (aud, nonce, ts) = get_challenge(&app, "demo-app").await;
        let sig = sign_challenge(&requester, &aud, &nonce, &ts).unwrap();
        let v = post_verify(
            &app,
            json!({ "aud": aud, "deviceId": requester.id, "sig": sig, "nonce": nonce, "ts": ts }),
        )
        .await;
        assert_eq!(v["ok"], true);
        assert_eq!(v["role"], "admin");

        // Admin revokes.
        let headers = signed_console_headers(&app, &admin).await;
        let req = with_headers(
            Request::builder().method("POST").uri("/devices/revoke").header("content-type", "application/json"),
            &headers,
        )
        .body(Body::from(json!({ "deviceId": requester.id }).to_string()))
        .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(st.devices.role_of(&requester.id), "none");

        // After revoke, /verify is ok=false again.
        let (aud, nonce, ts) = get_challenge(&app, "demo-app").await;
        let sig = sign_challenge(&requester, &aud, &nonce, &ts).unwrap();
        let v = post_verify(
            &app,
            json!({ "aud": aud, "deviceId": requester.id, "sig": sig, "nonce": nonce, "ts": ts }),
        )
        .await;
        assert_eq!(v["ok"], false);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn cannot_revoke_last_admin() {
        let dir = temp_dir();
        let st = state_with(dir.clone());
        let app = router(st.clone());
        let admin = test_device();
        let headers = signed_console_headers(&app, &admin).await;
        let req = with_headers(
            Request::builder().method("POST").uri("/devices/revoke").header("content-type", "application/json"),
            &headers,
        )
        .body(Body::from(json!({ "deviceId": admin.id }).to_string()))
        .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(st.devices.is_admin(&admin.id));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn devices_endpoints_require_admin() {
        let dir = temp_dir();
        let app = router(state_empty(dir.clone()));
        // No headers -> 401.
        let req = Request::builder().uri("/devices").body(Body::empty()).unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn me_reports_role() {
        let dir = temp_dir();
        let st = state_with(dir.clone());
        let app = router(st);
        let dk = test_device();
        let headers = signed_console_headers(&app, &dk).await;
        let req = with_headers(Request::builder().uri("/me"), &headers)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        assert_eq!(j["role"], "admin");
        assert_eq!(j["hasAdmins"], true);
        assert_eq!(j["deviceId"], dk.id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn registry_persists_across_reload_and_verify_still_ok() {
        // Enroll a second admin, drop the state (simulate restart), reopen with no seed, and confirm
        // /verify still says ok=true for the persisted device.
        let dir = temp_dir();
        let requester = second_device();
        {
            let st = state_with(dir.clone());
            st.devices.request(&requester.id, &compact_pub(&requester), "x").unwrap();
            st.devices.approve(&requester.id).unwrap();
            assert!(st.devices.is_admin(&requester.id));
        }
        // Reopen with NO seed: the persisted file is the source of truth. Same server secret so a
        // fresh challenge verifies.
        let st2 = AppState {
            devices: Arc::new(DeviceStore::open(&dir, &[]).unwrap()),
            server_secret: Arc::new(SERVER_SECRET.to_vec()),
            secret_store: Arc::new(SecretStore::from_env(TEST_SECRETS)),
        };
        assert!(st2.devices.is_admin(&requester.id));
        assert!(st2.devices.is_admin(&test_device().id));
        assert_eq!(st2.devices.admin_count(), 2);

        let app = router(st2);
        let (aud, nonce, ts) = get_challenge(&app, "demo-app").await;
        let sig = sign_challenge(&requester, &aud, &nonce, &ts).unwrap();
        let v = post_verify(
            &app,
            json!({ "aud": aud, "deviceId": requester.id, "sig": sig, "nonce": nonce, "ts": ts }),
        )
        .await;
        assert_eq!(v["ok"], true);
        assert_eq!(v["role"], "admin");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- SECRET-DELIVERY: GET /secret/:name ----

    /// Issue a `GET /secret/<name>` with the given (already-signed console) headers.
    async fn get_secret(
        app: &Router,
        name: &str,
        headers: &[(String, String)],
    ) -> axum::response::Response {
        let req = with_headers(Request::builder().uri(format!("/secret/{name}")), headers)
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(req).await.unwrap()
    }

    #[tokio::test]
    async fn admin_gets_secret_value() {
        let dir = temp_dir();
        let app = router(state_with(dir.clone()));
        let admin = test_device();
        let headers = signed_console_headers(&app, &admin).await;
        let resp = get_secret(&app, "api-key", &headers).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        assert_eq!(j["name"], "api-key");
        assert_eq!(j["value"], "s3cr3t-value");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn admin_unknown_name_404() {
        let dir = temp_dir();
        let app = router(state_with(dir.clone()));
        let admin = test_device();
        let headers = signed_console_headers(&app, &admin).await;
        let resp = get_secret(&app, "does-not-exist", &headers).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unenrolled_device_401() {
        // A real, valid signature from a device that is NOT in the registry -> 401 (not admin).
        let dir = temp_dir();
        let app = router(state_with(dir.clone()));
        let stranger = second_device();
        let headers = signed_console_headers(&app, &stranger).await;
        let resp = get_secret(&app, "api-key", &headers).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn pending_device_401() {
        // A device enrolled as pending (key-valid, real enrolled pub) but not approved -> 401.
        let dir = temp_dir();
        let st = state_with(dir.clone());
        let pending = second_device();
        st.devices.request(&pending.id, &compact_pub(&pending), "phone").unwrap();
        let app = router(st);
        let headers = signed_console_headers(&app, &pending).await;
        let resp = get_secret(&app, "api-key", &headers).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn no_headers_401() {
        let dir = temp_dir();
        let app = router(state_with(dir.clone()));
        let req = Request::builder().uri("/secret/api-key").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn bad_signature_401() {
        let dir = temp_dir();
        let app = router(state_with(dir.clone()));
        let admin = test_device();
        let mut headers = signed_console_headers(&app, &admin).await;
        // Tamper the signature header (x-ce-auth is index 1).
        let sig = &mut headers[1].1;
        let last = sig.pop().unwrap();
        sig.push(if last == 'A' { 'B' } else { 'A' });
        let resp = get_secret(&app, "api-key", &headers).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn expired_challenge_401() {
        // A correctly-derived (aud-bound) nonce + valid sig for a ts 10 minutes in the past -> 401.
        let dir = temp_dir();
        let app = router(state_with(dir.clone()));
        let admin = test_device();
        let aud = auth::CONSOLE_AUD;

        let old_ms = ce_secrets_rs::now_unix_ms() - 600_000;
        let old_secs = old_ms / 1000;
        let days = old_secs.div_euclid(86_400) + 719_468;
        let tod = old_secs.rem_euclid(86_400);
        let (y, mo, d) = {
            let z = days;
            let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
            let doe = z - era * 146_097;
            let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
            let y = yoe + era * 400;
            let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
            let mp = (5 * doy + 2) / 153;
            let dd = doy - (153 * mp + 2) / 5 + 1;
            let m = if mp < 10 { mp + 3 } else { mp - 9 };
            (if m <= 2 { y + 1 } else { y }, m, dd)
        };
        let old_ts = format!(
            "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
            tod / 3600,
            (tod % 3600) / 60,
            tod % 60
        );
        let nonce = ce_secrets_rs::make_nonce(&auth::aud_secret(SERVER_SECRET, aud), &old_ts);
        let sig = sign_challenge(&admin, aud, &nonce, &old_ts).unwrap();
        let headers = vec![
            ("x-ce-device-id".to_string(), admin.id.clone()),
            ("x-ce-auth".to_string(), sig),
            ("x-ce-aud".to_string(), aud.to_string()),
            ("x-ce-nonce".to_string(), nonce),
            ("x-ce-ts".to_string(), old_ts),
        ];
        let resp = get_secret(&app, "api-key", &headers).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
