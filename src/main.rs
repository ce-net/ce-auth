//! ce-auth — the operator's mesh-native, capability-minting auth/SSO service for CE.
//!
//! See `lib.rs` for the architecture. This binary wires two surfaces over one shared [`MeshState`]:
//!
//!   1. **Mesh service** (the real service-to-service surface): advertise the pinned name `ce-auth`
//!      and answer verbs over libp2p via `ce_rs::serve`. The defining verb `verify` MINTS an
//!      attenuating ce-cap grant (the bridge) a relying party verifies OFFLINE. Attached to a local CE
//!      node (`CE_NODE_URL`, default `http://127.0.0.1:8844`; `CE_API_TOKEN` auto-discovered by ce-rs).
//!
//!   2. **Thin console HTTP** (operator frontend ONLY): a small axum server serving the
//!      device-management console and its console-class verbs, gated by the same ce-secrets device
//!      auth (header-delivered). Service-to-service never uses this; it exists only for the browser.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use tower_http::cors::CorsLayer;

use ce_auth::auth;
use ce_iam::bridge::CapBridge;
use ce_auth::secrets::SecretStore;
use ce_auth::service::{self, MeshState};
use ce_iam::device::{self as store, DeviceStore};

const CONSOLE_HTML: &str = include_str!("console.html");

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ce_auth=info,tower_http=warn".into()),
        )
        .init();

    let data_dir = store::default_data_dir();

    let seed = auth::parse_seed(&std::env::var("CE_AUTH_ADMIN_DEVICES").unwrap_or_default());
    let devices = Arc::new(DeviceStore::open(&data_dir, &seed)?);
    let server_secret = server_secret_from_env();
    let secret_store = SecretStore::from_env(&std::env::var("CE_AUTH_SECRETS").unwrap_or_default());
    tracing::info!(count = secret_store.len(), "named secrets loaded for SECRET-DELIVERY");

    // The cap bridge: ce-auth's org-root identity + grant scope/TTL. This is the issuer of every
    // minted operator grant; apps configure its NodeId as an accepted root.
    let bridge = Arc::new(CapBridge::from_env(&data_dir)?);
    tracing::info!(cap_root = %bridge.root_node_id_hex(), "cap bridge ready — relying-party apps must trust this root NodeId");

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

    let state = Arc::new(MeshState {
        devices,
        server_secret: Arc::new(server_secret),
        secret_store: Arc::new(secret_store),
        bridge,
    });

    // ---- Mesh service: advertise "ce-auth" and serve verbs over libp2p. ----
    let node_url = std::env::var("CE_NODE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:8844".to_string());
    let ce = ce_rs::CeClient::new(node_url.clone());
    let mesh_state = state.clone();
    let mesh = tokio::spawn(async move {
        match ce.status().await {
            Ok(s) => tracing::info!(node = %s.node_id, %node_url, service = service::SERVICE_NAME, "attached to CE node; serving ce-auth over the mesh"),
            Err(e) => tracing::warn!(error = %e, %node_url, "CE node not reachable yet; the mesh serve loop will retry. (Start a local node or set CE_NODE_URL.)"),
        }
        if let Err(e) = service::serve_mesh(ce, mesh_state, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        {
            tracing::error!(error = %e, "mesh serve loop exited");
        }
    });

    // ---- Thin console HTTP: operator frontend only. ----
    let app = console_router(state);
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8972);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!(%addr, data_dir = %data_dir.display(), "ce-auth console (thin HTTP) listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await?;
    mesh.abort();
    Ok(())
}

/// Resolve the stateless-nonce HMAC key from `CE_AUTH_SERVER_SECRET`, else a per-boot ephemeral one.
fn server_secret_from_env() -> Vec<u8> {
    if let Ok(s) = std::env::var("CE_AUTH_SERVER_SECRET") {
        if !s.is_empty() {
            return s.into_bytes();
        }
    }
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

// ---- thin console HTTP -------------------------------------------------------
//
// The console is the operator's browser frontend. Every data call behind it carries a ce-secrets
// device proof in the `x-ce-*` headers. These handlers translate the headers into the same JSON
// envelope the mesh verbs use and run them through `MeshState::dispatch`, so the console and the mesh
// service share ONE implementation and one auth path. The relying-party `/challenge` + `/verify` are
// also exposed here for browser apps that prefer HTTP over the mesh; they mint the same bridged cap.

fn console_router(state: Arc<MeshState>) -> Router {
    Router::new()
        .route("/", get(serve_console))
        .route("/health", get(|| async { "ok" }))
        // Relying-party API over HTTP (browser apps). Service-to-service uses the mesh instead.
        .route("/challenge", get(http_challenge))
        .route("/verify", post(http_verify))
        // Console-class verbs (device-auth via x-ce-* headers).
        .route("/me", get(http_me))
        .route("/claim", post(http_claim))
        .route("/request", post(http_request))
        .route("/devices", get(http_devices))
        .route("/devices/approve", post(http_approve))
        .route("/devices/revoke", post(http_revoke))
        .route("/secret/:name", get(http_secret))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// Merge the five `x-ce-*` device-auth headers into a verb body so console HTTP and mesh share the
/// dispatch path. Missing headers simply produce absent fields (dispatch then returns unauthorized).
fn auth_fields_from_headers(headers: &HeaderMap) -> Value {
    let get = |k: &str| headers.get(k).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    json!({
        "deviceId": get("x-ce-device-id"),
        "sig": get("x-ce-auth"),
        "aud": get("x-ce-aud"),
        "nonce": get("x-ce-nonce"),
        "ts": get("x-ce-ts"),
    })
}

/// Merge `extra` object fields onto `base`.
fn merge(mut base: Value, extra: Value) -> Value {
    if let (Value::Object(b), Value::Object(e)) = (&mut base, extra) {
        for (k, v) in e {
            b.insert(k, v);
        }
    }
    base
}

/// Map a dispatch reply to an HTTP response: `{ error: "unauthorized" }` -> 401, other `{ error }`
/// -> 400/404/409 by message, otherwise 200.
fn reply_to_http(reply: Value) -> axum::response::Response {
    if let Some(err) = reply.get("error").and_then(Value::as_str) {
        let code = match err {
            "unauthorized" => StatusCode::UNAUTHORIZED,
            "unknown secret" => StatusCode::NOT_FOUND,
            "no pending device with that id" | "no device with that id" => StatusCode::NOT_FOUND,
            e if e.contains("already exist") => StatusCode::CONFLICT,
            e if e.contains("cannot revoke") || e.starts_with("bad ") || e.contains("nodeId") => {
                StatusCode::BAD_REQUEST
            }
            _ => StatusCode::BAD_REQUEST,
        };
        return (code, Json(reply)).into_response();
    }
    (StatusCode::OK, Json(reply)).into_response()
}

#[derive(Deserialize)]
struct ChallengeQuery {
    aud: Option<String>,
}

async fn http_challenge(State(st): State<Arc<MeshState>>, Query(q): Query<ChallengeQuery>) -> impl IntoResponse {
    let body = json!({ "verb": "challenge", "aud": q.aud.unwrap_or_default() });
    (StatusCode::OK, Json(st.dispatch(&body))).into_response()
}

async fn http_verify(State(st): State<Arc<MeshState>>, Json(body): Json<Value>) -> impl IntoResponse {
    // `/verify` always returns 200; the verdict (and any minted cap) is in the body.
    let body = merge(body, json!({ "verb": "verify" }));
    (StatusCode::OK, Json(st.dispatch(&body))).into_response()
}

async fn http_me(State(st): State<Arc<MeshState>>, headers: HeaderMap) -> impl IntoResponse {
    let body = merge(auth_fields_from_headers(&headers), json!({ "verb": "me" }));
    reply_to_http(st.dispatch(&body))
}

async fn http_claim(State(st): State<Arc<MeshState>>, headers: HeaderMap, Json(b): Json<Value>) -> impl IntoResponse {
    let body = merge(auth_fields_from_headers(&headers), merge(b, json!({ "verb": "claim" })));
    reply_to_http(st.dispatch(&body))
}

async fn http_request(State(st): State<Arc<MeshState>>, headers: HeaderMap, Json(b): Json<Value>) -> impl IntoResponse {
    let body = merge(auth_fields_from_headers(&headers), merge(b, json!({ "verb": "request" })));
    reply_to_http(st.dispatch(&body))
}

async fn http_devices(State(st): State<Arc<MeshState>>, headers: HeaderMap) -> impl IntoResponse {
    let body = merge(auth_fields_from_headers(&headers), json!({ "verb": "devices" }));
    reply_to_http(st.dispatch(&body))
}

async fn http_approve(State(st): State<Arc<MeshState>>, headers: HeaderMap, Json(b): Json<Value>) -> impl IntoResponse {
    // Over HTTP, auth is in headers, so the body `deviceId` is the TARGET; map it to `targetDeviceId`
    // (the field the verb reads) so it never collides with the header-derived caller `deviceId`.
    let body = merge(auth_fields_from_headers(&headers), merge(target_from_device_id(b), json!({ "verb": "approve" })));
    reply_to_http(st.dispatch(&body))
}

async fn http_revoke(State(st): State<Arc<MeshState>>, headers: HeaderMap, Json(b): Json<Value>) -> impl IntoResponse {
    let body = merge(auth_fields_from_headers(&headers), merge(target_from_device_id(b), json!({ "verb": "revoke" })));
    reply_to_http(st.dispatch(&body))
}

/// Rename an HTTP console body's `deviceId` (the operation target) to `targetDeviceId`, the field the
/// verbs read. (Over HTTP the caller's auth is in headers, so the body `deviceId` is unambiguously the
/// target.)
fn target_from_device_id(mut b: Value) -> Value {
    if let Value::Object(m) = &mut b {
        if let Some(v) = m.remove("deviceId") {
            m.insert("targetDeviceId".to_string(), v);
        }
    }
    b
}

async fn http_secret(State(st): State<Arc<MeshState>>, Path(name): Path<String>, headers: HeaderMap) -> impl IntoResponse {
    let body = merge(auth_fields_from_headers(&headers), json!({ "verb": "secret", "name": name }));
    reply_to_http(st.dispatch(&body))
}

async fn serve_console() -> impl IntoResponse {
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
    use ce_identity::Identity;
    use ce_secrets_rs::{DeviceKey, sign_challenge};
    use tower::ServiceExt;

    const SERVER_SECRET: &[u8] = b"http-test-server-secret";

    fn temp_dir() -> std::path::PathBuf {
        let mut d = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        d.push(format!("ce-auth-http-test-{}-{}", std::process::id(), nanos));
        d
    }

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

    fn compact_pub(dk: &DeviceKey) -> String {
        ce_secrets_rs::encoding::b64url_encode(&dk.ecdsa_pub.raw_public_bytes().unwrap())
    }

    fn state_with(dir: std::path::PathBuf, dk: &DeviceKey, node: &Identity) -> Arc<MeshState> {
        let seed = vec![(dk.id.clone(), compact_pub(dk))];
        let devices = Arc::new(DeviceStore::open(&dir, &seed).unwrap());
        devices.request(&dk.id, &compact_pub(dk), &node.node_id_hex(), "test").unwrap();
        Arc::new(MeshState {
            devices,
            server_secret: Arc::new(SERVER_SECRET.to_vec()),
            secret_store: Arc::new(SecretStore::from_env("api-key=s3cr3t")),
            bridge: Arc::new(CapBridge::new(Identity::from_secret_bytes(&[7u8; 32]), ce_iam::ResourceMatch::Any, 600)),
        })
    }

    async fn body_json(resp: axum::response::Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn get_challenge(app: &Router, aud: &str) -> (String, String, String) {
        let req = Request::builder().uri(format!("/challenge?aud={aud}")).body(Body::empty()).unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let j = body_json(resp).await;
        (j["aud"].as_str().unwrap().into(), j["nonce"].as_str().unwrap().into(), j["ts"].as_str().unwrap().into())
    }

    #[tokio::test]
    async fn http_verify_mints_cap() {
        let dir = temp_dir();
        let dk = test_device();
        let node = Identity::from_secret_bytes(&[21u8; 32]);
        let app = console_router(state_with(dir.clone(), &dk, &node));

        let (aud, nonce, ts) = get_challenge(&app, "demo-app").await;
        let sig = sign_challenge(&dk, &aud, &nonce, &ts).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/verify")
            .header("content-type", "application/json")
            .body(Body::from(json!({ "aud": aud, "deviceId": dk.id, "sig": sig, "nonce": nonce, "ts": ts }).to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        assert_eq!(j["ok"], true);
        assert_eq!(j["nodeId"], node.node_id_hex());
        assert!(j["cap"].is_string(), "HTTP /verify must mint a cap token too");
        // capRoot is ce-auth's cap-root NodeId (seed [7u8;32] in this test state).
        assert_eq!(j["capRoot"], Identity::from_secret_bytes(&[7u8; 32]).node_id_hex());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn http_devices_requires_admin() {
        let dir = temp_dir();
        let dk = test_device();
        let node = Identity::from_secret_bytes(&[21u8; 32]);
        let app = console_router(state_with(dir.clone(), &dk, &node));
        let req = Request::builder().uri("/devices").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
