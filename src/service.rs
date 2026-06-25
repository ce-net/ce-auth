//! The mesh-native ce-auth service: serve verbs over libp2p via [`ce_rs::serve`].
//!
//! Service-to-service auth in CE rides the mesh, not HTTP. ce-auth advertises the pinned service name
//! [`SERVICE_NAME`] (`ce-auth`) so any relying party can `ce_rs::locate("ce-auth")` and send it a
//! request over `/ce/rpc/1`. Each request is a JSON envelope tagged with a `verb`; the handler
//! dispatches, runs the same ce-secrets device-auth as the console, and replies with JSON.
//!
//! The defining verb is **`verify`**: on a valid enrolled-admin device proof it MINTS an attenuating
//! ce-cap grant (the bridge, see [`crate::bridge`]) and returns the token. A relying party then
//! verifies that token OFFLINE with ce-cap — it never calls `verify` again per request.
//!
//! ## Verbs
//!
//! | verb      | payload                                   | reply                                      |
//! |-----------|-------------------------------------------|--------------------------------------------|
//! | challenge | `{ aud }`                                 | `{ aud, nonce, ts }`                        |
//! | verify    | `{ aud, deviceId, sig, nonce, ts }`       | `{ ok, role, deviceId, nodeId?, cap?, capRoot? }` |
//! | me        | `{ ...console auth... }`                   | `{ deviceId, role, hasAdmins, nodeId? }`   |
//! | claim     | `{ pub, nodeId?, ...console auth... }`     | `{ ok, deviceId, role }`                    |
//! | request   | `{ pub, nodeId?, label?, ...auth... }`     | `{ ok, deviceId, role }`                    |
//! | devices   | `{ ...admin auth... }`                     | `{ admins, pending }`                       |
//! | approve   | `{ targetDeviceId, ...admin auth... }`     | `{ ok, role }`                              |
//! | revoke    | `{ targetDeviceId, ...admin auth... }`     | `{ ok }`                                    |
//! | secret    | `{ name, ...admin auth... }`               | `{ name, value }`                           |
//!
//! Note: `deviceId` always names the **caller's** device (its auth proof); a verb that acts on
//! another device names it with `targetDeviceId`, so the two never collide over the mesh.
//!
//! "console auth" / "admin auth" fields are `{ deviceId, sig, aud, nonce, ts }` carrying a
//! `aud=ce-auth` device proof (the same five-field challenge the console signs), but delivered in the
//! mesh request body rather than HTTP headers.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::auth::{self, AuthError};
use ce_iam::bridge::CapBridge;
use crate::secrets::SecretStore;
use ce_iam::device::{self as store, DeviceStore, RevokeOutcome};

/// The pinned mesh service name ce-auth advertises and relying parties `locate`.
pub const SERVICE_NAME: &str = "ce-auth";

/// The mesh request/reply topic for ce-auth verbs.
pub const TOPIC: &str = "ce-auth/rpc";

/// Shared state behind both the mesh service and the thin console HTTP server.
pub struct MeshState {
    pub devices: Arc<DeviceStore>,
    pub server_secret: Arc<Vec<u8>>,
    pub secret_store: Arc<SecretStore>,
    pub bridge: Arc<CapBridge>,
}

impl MeshState {
    /// Dispatch one decoded mesh request `{ verb, .. }` to its handler, returning the JSON reply
    /// value. Unknown verbs and malformed bodies return a structured `{ error }` (never a panic), so
    /// the requester's [`ce_rs::CeClient::request`] always gets an answer.
    pub fn dispatch(&self, body: &Value) -> Value {
        let verb = body.get("verb").and_then(Value::as_str).unwrap_or("");
        match verb {
            "challenge" => self.challenge(body),
            "verify" => self.verify(body),
            "me" => self.me(body),
            "claim" => self.claim(body),
            "request" => self.request(body),
            "devices" => self.devices(body),
            "approve" => self.approve(body),
            "revoke" => self.revoke(body),
            "secret" => self.secret(body),
            "" => json!({ "error": "missing verb" }),
            other => json!({ "error": format!("unknown verb '{other}'") }),
        }
    }

    // ---- relying-party verbs ----

    fn challenge(&self, body: &Value) -> Value {
        let aud = body
            .get("aud")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(auth::CONSOLE_AUD);
        let ch = auth::make_challenge(&self.server_secret, aud);
        json!({ "aud": ch.aud, "nonce": ch.nonce, "ts": ch.ts })
    }

    /// `verify` — THE bridge verb. Validate the P-256 device proof for `aud`, confirm the device is an
    /// enrolled admin (the operator), and on success MINT an attenuating ce-cap grant bound to the
    /// device's registered CE NodeId + this `aud`, returned as `cap` (with `capRoot` = the root NodeId
    /// the app must trust). `ok = (signature valid AND role==admin)`.
    fn verify(&self, body: &Value) -> Value {
        let aud = str_field(body, "aud");
        let device_id = str_field(body, "deviceId");
        let sig = str_field(body, "sig");
        let nonce = str_field(body, "nonce");
        let ts = str_field(body, "ts");

        let role = self.devices.role_of(&device_id);
        let sig_valid = match self.devices.pub_of(&device_id) {
            Some(pub_b64) => auth::verify_signature(
                &self.server_secret,
                &aud,
                &device_id,
                &nonce,
                &ts,
                &sig,
                &pub_b64,
            )
            .is_ok(),
            None => false,
        };
        let ok = sig_valid && role == store::ROLE_ADMIN;

        let mut reply = json!({ "ok": ok, "role": role, "deviceId": device_id });
        if ok {
            // Mint the bridged cap. The device must have a registered CE NodeId (the ce-cap principal);
            // without one we authenticate but cannot mint — report that precisely so the operator
            // re-enrolls with a NodeId rather than silently getting no cap.
            match self.devices.node_id_of(&device_id) {
                Some(node_id) => {
                    let now = now_unix_secs();
                    match self.bridge.mint_operator_grant(&node_id, &aud, now) {
                        Ok(token) => {
                            reply["nodeId"] = json!(node_id);
                            reply["cap"] = json!(token);
                            reply["capRoot"] = json!(self.bridge.root_node_id_hex());
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, device_id = %device_id, "verify: cap mint failed");
                            reply["capError"] = json!("mint failed");
                        }
                    }
                }
                None => {
                    reply["capError"] = json!("device has no registered CE NodeId; re-enroll with nodeId");
                }
            }
        }
        reply
    }

    // ---- console verbs (device-auth in the body, aud=ce-auth) ----

    fn me(&self, body: &Value) -> Value {
        let device_id = match self.console_device(body) {
            Ok(id) => id,
            Err(_) => return unauthorized(),
        };
        let role = self.devices.role_of(&device_id);
        let mut v = json!({
            "deviceId": device_id,
            "role": role,
            "hasAdmins": self.devices.has_admins(),
        });
        if let Some(n) = self.devices.node_id_of(&device_id) {
            v["nodeId"] = json!(n);
        }
        v
    }

    fn claim(&self, body: &Value) -> Value {
        let pub_b64 = str_field(body, "pub");
        let node_id = str_field(body, "nodeId");
        if pub_b64.is_empty() || auth::validate_compact_pub(&pub_b64).is_err() {
            return json!({ "error": "bad pub" });
        }
        if let Err(e) = validate_optional_node_id(&node_id) {
            return json!({ "error": e });
        }
        let device_id = match self.console_device_with_pub(body, Some(&pub_b64)) {
            Ok(id) => id,
            Err(_) => return unauthorized(),
        };
        match self.devices.claim(&device_id, &pub_b64, &node_id) {
            Ok(true) => json!({ "ok": true, "deviceId": device_id, "role": "admin" }),
            Ok(false) => json!({ "error": "admins already exist; ask one to approve your request" }),
            Err(e) => {
                tracing::error!(error = %e, "claim persist failed");
                json!({ "error": "store" })
            }
        }
    }

    fn request(&self, body: &Value) -> Value {
        let pub_b64 = str_field(body, "pub");
        let node_id = str_field(body, "nodeId");
        let label = str_field(body, "label");
        if pub_b64.is_empty() || auth::validate_compact_pub(&pub_b64).is_err() {
            return json!({ "error": "bad pub" });
        }
        if let Err(e) = validate_optional_node_id(&node_id) {
            return json!({ "error": e });
        }
        let device_id = match self.console_device_with_pub(body, Some(&pub_b64)) {
            Ok(id) => id,
            Err(_) => return unauthorized(),
        };
        match self.devices.request(&device_id, &pub_b64, &node_id, label.trim()) {
            Ok(role) => json!({ "ok": true, "deviceId": device_id, "role": role }),
            Err(e) => {
                tracing::error!(error = %e, "request persist failed");
                json!({ "error": "store" })
            }
        }
    }

    fn devices(&self, body: &Value) -> Value {
        if self.require_admin(body).is_err() {
            return unauthorized();
        }
        let mut admins = Vec::new();
        let mut pending = Vec::new();
        for (id, dev) in self.devices.list() {
            let row = json!({
                "deviceId": id,
                "label": dev.label,
                "added_ts": dev.added_ts,
                "nodeId": dev.node_id,
            });
            if dev.role == store::ROLE_ADMIN {
                admins.push(row);
            } else {
                pending.push(row);
            }
        }
        json!({ "admins": admins, "pending": pending })
    }

    fn approve(&self, body: &Value) -> Value {
        if self.require_admin(body).is_err() {
            return unauthorized();
        }
        // The operation TARGET is `targetDeviceId` (distinct from the admin's own `deviceId`, which
        // carries the auth proof). Fall back to `deviceId` only when no target is given.
        let target = target_device_id(body);
        match self.devices.approve(&target) {
            Ok(true) => json!({ "ok": true, "role": "admin" }),
            Ok(false) => json!({ "error": "no pending device with that id" }),
            Err(e) => {
                tracing::error!(error = %e, "approve persist failed");
                json!({ "error": "store" })
            }
        }
    }

    fn revoke(&self, body: &Value) -> Value {
        if self.require_admin(body).is_err() {
            return unauthorized();
        }
        let target = target_device_id(body);
        match self.devices.revoke(&target) {
            Ok(RevokeOutcome::Removed) => json!({ "ok": true }),
            Ok(RevokeOutcome::NotFound) => json!({ "error": "no device with that id" }),
            Ok(RevokeOutcome::LastAdmin) => json!({ "error": "cannot revoke the last admin" }),
            Err(e) => {
                tracing::error!(error = %e, "revoke persist failed");
                json!({ "error": "store" })
            }
        }
    }

    fn secret(&self, body: &Value) -> Value {
        // Authorize FIRST so an unauthorized caller cannot probe which names exist.
        if self.require_admin(body).is_err() {
            return unauthorized();
        }
        let name = str_field(body, "name");
        match self.secret_store.get(&name) {
            Some(value) => json!({ "name": name, "value": value }),
            None => json!({ "error": "unknown secret" }),
        }
    }

    // ---- shared console auth (device proof carried in the request body) ----

    /// Authenticate a console-class request: prove possession of the device key for the body's
    /// `deviceId` over a fresh `aud=ce-auth` challenge, resolving the verifying pub from the store.
    fn console_device(&self, body: &Value) -> Result<String, AuthError> {
        self.console_device_with_pub(body, None)
    }

    /// Like [`console_device`](Self::console_device) but allows a TOFU body-supplied pub for a
    /// first-time device (claim/request). The stored pub always wins when present.
    fn console_device_with_pub(&self, body: &Value, body_pub: Option<&str>) -> Result<String, AuthError> {
        let device_id = nonempty(body, "deviceId").ok_or(AuthError::MissingHeaders)?;
        let sig = nonempty(body, "sig").ok_or(AuthError::MissingHeaders)?;
        let aud = nonempty(body, "aud").ok_or(AuthError::MissingHeaders)?;
        let nonce = nonempty(body, "nonce").ok_or(AuthError::MissingHeaders)?;
        let ts = nonempty(body, "ts").ok_or(AuthError::MissingHeaders)?;
        if aud != auth::CONSOLE_AUD {
            return Err(AuthError::AudMismatch);
        }
        let pub_b64 = self
            .devices
            .pub_of(&device_id)
            .or_else(|| body_pub.map(|s| s.to_string()))
            .ok_or(AuthError::MissingHeaders)?;
        auth::verify_signature(&self.server_secret, &aud, &device_id, &nonce, &ts, &sig, &pub_b64)?;
        Ok(device_id)
    }

    /// Require a console-authenticated request that is ALSO an enrolled admin.
    fn require_admin(&self, body: &Value) -> Result<String, AuthError> {
        let device_id = self.console_device(body)?;
        if self.devices.is_admin(&device_id) {
            Ok(device_id)
        } else {
            Err(AuthError::BadSignature)
        }
    }
}

/// Serve ce-auth over the mesh until `shutdown` resolves, and keep it discoverable via `locate`.
/// Spawns the periodic DHT re-advertisement and runs the [`ce_rs::serve`] loop dispatching [`TOPIC`]
/// requests through [`MeshState::dispatch`].
pub async fn serve_mesh(
    ce: ce_rs::CeClient,
    state: Arc<MeshState>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    // A shared trigger so both the register loop and the serve loop stop together.
    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown.await;
        let _ = tx.send(true);
    });

    // Keep this node discoverable as an instance of "ce-auth" (DHT provider records expire).
    let reg_ce = ce.clone();
    let mut reg_rx = rx.clone();
    let register = tokio::spawn(async move {
        let _ = ce_rs::locate::register(
            &reg_ce,
            SERVICE_NAME,
            std::time::Duration::from_secs(60),
            async move {
                let _ = reg_rx.changed().await;
            },
        )
        .await;
    });

    let handler = MeshHandler { state };
    let mut serve_rx = rx.clone();
    let res = ce_rs::serve::serve(&ce, &[TOPIC], &handler, async move {
        let _ = serve_rx.changed().await;
    })
    .await;

    register.abort();
    res
}

/// The [`ce_rs::serve::Handler`] adapter: decode the JSON envelope, dispatch, encode the JSON reply.
struct MeshHandler {
    state: Arc<MeshState>,
}

impl ce_rs::serve::Handler for MeshHandler {
    async fn handle(&self, req: ce_rs::serve::Request) -> Vec<u8> {
        // `req.from` is the authenticated sender NodeId (verified by the local node). Device-level
        // authorization is the P-256 proof inside the body; the mesh sender is logged for audit.
        let body: Value = match serde_json::from_slice(&req.payload) {
            Ok(v) => v,
            Err(e) => {
                let r = json!({ "error": format!("bad request json: {e}") });
                return serde_json::to_vec(&r).unwrap_or_default();
            }
        };
        let verb = body.get("verb").and_then(Value::as_str).unwrap_or("?").to_string();
        let reply = self.state.dispatch(&body);
        tracing::debug!(from = %req.from, %verb, "ce-auth mesh verb served");
        serde_json::to_vec(&reply).unwrap_or_default()
    }
}

// ---- helpers ----

fn str_field(body: &Value, key: &str) -> String {
    body.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

/// The device a console operation targets. It is `targetDeviceId` — kept distinct from `deviceId`,
/// which carries the operator's own auth proof (over the mesh the two devices differ; conflating them
/// would let an admin's auth id silently become the operation target). The HTTP console maps its body
/// `deviceId` into `targetDeviceId` before dispatch (HTTP carries auth in headers, not the body).
fn target_device_id(body: &Value) -> String {
    str_field(body, "targetDeviceId")
}

fn nonempty(body: &Value, key: &str) -> Option<String> {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

fn unauthorized() -> Value {
    json!({ "error": "unauthorized" })
}

/// A registered CE NodeId, when present, must be a 64-hex 32-byte Ed25519 id. Empty is allowed (the
/// device may register it later), but a malformed one is rejected so a bad principal never enrolls.
fn validate_optional_node_id(node_id: &str) -> Result<(), String> {
    if node_id.is_empty() {
        return Ok(());
    }
    match hex::decode(node_id) {
        Ok(b) if b.len() == 32 => Ok(()),
        _ => Err("nodeId must be a 64-hex (32-byte) CE NodeId".to_string()),
    }
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ce_iam::bridge::{ABILITY_OPERATOR, ability_for_aud};
    use ce_iam::{Iam, Principal};
    use ce_identity::Identity;
    use ce_secrets_rs::{DeviceKey, sign_challenge};

    const SERVER_SECRET: &[u8] = b"mesh-test-server-secret";

    fn temp_dir() -> std::path::PathBuf {
        let mut d = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        d.push(format!("ce-auth-mesh-test-{}-{}", std::process::id(), nanos));
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

    /// ce-auth's cap root (fixed seed so tests can build the relying-party verifier for it).
    fn cap_root() -> Identity {
        Identity::from_secret_bytes(&[7u8; 32])
    }

    /// State with `dk` seeded as admin and bound to CE NodeId `node` (the bridged principal).
    fn state_with(dir: std::path::PathBuf, dk: &DeviceKey, node: &Identity) -> Arc<MeshState> {
        let seed = vec![(dk.id.clone(), compact_pub(dk))];
        let devices = Arc::new(DeviceStore::open(&dir, &seed).unwrap());
        // Bind the device to its CE NodeId via a request refresh (admin record keeps role=admin).
        devices.request(&dk.id, &compact_pub(dk), &node.node_id_hex(), "test").unwrap();
        Arc::new(MeshState {
            devices,
            server_secret: Arc::new(SERVER_SECRET.to_vec()),
            secret_store: Arc::new(SecretStore::from_env("api-key=s3cr3t")),
            bridge: Arc::new(CapBridge::new(cap_root(), ResourceMatch::Any, 600)),
        })
    }

    /// Drive challenge->sign->verb through dispatch, returning the reply.
    fn signed_body(st: &MeshState, dk: &DeviceKey, aud: &str, extra: Value) -> Value {
        let ch = st.dispatch(&json!({ "verb": "challenge", "aud": aud }));
        let nonce = ch["nonce"].as_str().unwrap();
        let ts = ch["ts"].as_str().unwrap();
        let sig = sign_challenge(dk, aud, nonce, ts).unwrap();
        let mut body = json!({
            "deviceId": dk.id, "sig": sig, "aud": aud, "nonce": nonce, "ts": ts,
        });
        if let Value::Object(m) = extra {
            for (k, v) in m {
                body[k] = v;
            }
        }
        body
    }

    use ce_iam::ResourceMatch;

    #[test]
    fn verify_mints_cap_that_verifies_offline() {
        let dir = temp_dir();
        let dk = test_device();
        let node = Identity::from_secret_bytes(&[21u8; 32]);
        let st = state_with(dir.clone(), &dk, &node);

        let aud = "ce-cast";
        let mut body = signed_body(&st, &dk, aud, json!({}));
        body["verb"] = json!("verify");
        let reply = st.dispatch(&body);

        assert_eq!(reply["ok"], true);
        assert_eq!(reply["role"], "admin");
        assert_eq!(reply["nodeId"], node.node_id_hex());
        let token = reply["cap"].as_str().expect("a cap token must be minted");
        let cap_root_reply = reply["capRoot"].as_str().unwrap();
        assert_eq!(cap_root_reply, cap_root_hex());

        // A relying-party app verifies the cap OFFLINE — no callback to ce-auth.
        let app = Iam::new()
            .with_action_universe([ABILITY_OPERATOR.to_string()])
            .with_accepted_roots([cap_root().node_id()]);
        let now = now_unix_secs();
        let principal = Principal(node.node_id());
        assert!(
            app.verify(&[1u8; 32], &[], now, &principal, ABILITY_OPERATOR, token, &|_, _| false)
                .is_ok()
        );
        assert!(
            app.verify(&[1u8; 32], &[], now, &principal, &ability_for_aud(aud), token, &|_, _| false)
                .is_ok()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn cap_root_hex() -> String {
        cap_root().node_id_hex()
    }

    #[test]
    fn unenrolled_device_gets_no_cap() {
        let dir = temp_dir();
        let admin = test_device();
        let node = Identity::from_secret_bytes(&[21u8; 32]);
        let st = state_with(dir.clone(), &admin, &node);

        // A real, valid signature from a device NOT in the registry -> ok=false, no cap.
        let stranger = second_device();
        let mut body = signed_body(&st, &stranger, "ce-cast", json!({}));
        body["verb"] = json!("verify");
        let reply = st.dispatch(&body);
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["role"], "none");
        assert!(reply.get("cap").is_none(), "an unenrolled device must get NO cap");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pending_device_gets_no_cap() {
        let dir = temp_dir();
        let admin = test_device();
        let node = Identity::from_secret_bytes(&[21u8; 32]);
        let st = state_with(dir.clone(), &admin, &node);

        let pending = second_device();
        let pnode = Identity::from_secret_bytes(&[31u8; 32]);
        st.devices
            .request(&pending.id, &compact_pub(&pending), &pnode.node_id_hex(), "phone")
            .unwrap();

        let mut body = signed_body(&st, &pending, "ce-cast", json!({}));
        body["verb"] = json!("verify");
        let reply = st.dispatch(&body);
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["role"], "pending");
        assert!(reply.get("cap").is_none(), "a pending device must get NO cap");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_aud_signature_gets_no_cap() {
        // A signature obtained for aud=X posted as aud=Y must fail verify (nonce is aud-bound).
        let dir = temp_dir();
        let dk = test_device();
        let node = Identity::from_secret_bytes(&[21u8; 32]);
        let st = state_with(dir.clone(), &dk, &node);

        // Sign for aud-x but claim aud-y in the verify body.
        let body_x = signed_body(&st, &dk, "aud-x", json!({}));
        let mut body = body_x.clone();
        body["verb"] = json!("verify");
        body["aud"] = json!("aud-y");
        let reply = st.dispatch(&body);
        assert_eq!(reply["ok"], false, "cross-aud signature must not verify");
        assert!(reply.get("cap").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admin_without_node_id_authenticates_but_gets_no_cap() {
        // An admin device with NO registered CE NodeId can authenticate (ok=true) but cannot be
        // minted a cap — there is no ce-cap principal to bind. Reported precisely.
        let dir = temp_dir();
        let dk = test_device();
        let seed = vec![(dk.id.clone(), compact_pub(&dk))];
        let devices = Arc::new(DeviceStore::open(&dir, &seed).unwrap());
        // NOTE: no node_id bound.
        let st = Arc::new(MeshState {
            devices,
            server_secret: Arc::new(SERVER_SECRET.to_vec()),
            secret_store: Arc::new(SecretStore::from_env("")),
            bridge: Arc::new(CapBridge::new(cap_root(), ResourceMatch::Any, 600)),
        });
        let mut body = signed_body(&st, &dk, "ce-cast", json!({}));
        body["verb"] = json!("verify");
        let reply = st.dispatch(&body);
        assert_eq!(reply["ok"], true);
        assert!(reply.get("cap").is_none());
        assert!(reply["capError"].as_str().unwrap().contains("NodeId"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_request_approve_revoke_over_mesh() {
        let dir = temp_dir();
        let admin = test_device();
        let anode = Identity::from_secret_bytes(&[21u8; 32]);
        let st = state_with(dir.clone(), &admin, &anode);

        // A second device requests access (carrying its CE NodeId), over the mesh verbs.
        let req_dev = second_device();
        let rnode = Identity::from_secret_bytes(&[33u8; 32]);
        let mut body = signed_body(&st, &req_dev, auth::CONSOLE_AUD, json!({
            "pub": compact_pub(&req_dev), "nodeId": rnode.node_id_hex(), "label": "phone"
        }));
        body["verb"] = json!("request");
        let reply = st.dispatch(&body);
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["role"], "pending");
        assert_eq!(st.devices.node_id_of(&req_dev.id), Some(rnode.node_id_hex()));

        // Admin approves over the mesh. `deviceId` carries the admin's auth; the TARGET is
        // `targetDeviceId` (the requester) so the two device ids never collide.
        let mut body = signed_body(&st, &admin, auth::CONSOLE_AUD, json!({ "targetDeviceId": req_dev.id }));
        body["verb"] = json!("approve");
        let reply = st.dispatch(&body);
        assert_eq!(reply["ok"], true);
        assert!(st.devices.is_admin(&req_dev.id));

        // Now the requester can verify+get a cap.
        let mut body = signed_body(&st, &req_dev, "ce-cast", json!({}));
        body["verb"] = json!("verify");
        let reply = st.dispatch(&body);
        assert_eq!(reply["ok"], true);
        assert!(reply.get("cap").is_some());

        // Admin revokes.
        let mut body = signed_body(&st, &admin, auth::CONSOLE_AUD, json!({ "targetDeviceId": req_dev.id }));
        body["verb"] = json!("revoke");
        let reply = st.dispatch(&body);
        assert_eq!(reply["ok"], true);
        assert_eq!(st.devices.role_of(&req_dev.id), "none");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn devices_verb_requires_admin() {
        let dir = temp_dir();
        let dk = test_device();
        let node = Identity::from_secret_bytes(&[21u8; 32]);
        let st = state_with(dir.clone(), &dk, &node);
        // No auth fields -> unauthorized.
        let reply = st.dispatch(&json!({ "verb": "devices" }));
        assert_eq!(reply["error"], "unauthorized");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn secret_verb_admin_only() {
        let dir = temp_dir();
        let dk = test_device();
        let node = Identity::from_secret_bytes(&[21u8; 32]);
        let st = state_with(dir.clone(), &dk, &node);
        let mut body = signed_body(&st, &dk, auth::CONSOLE_AUD, json!({ "name": "api-key" }));
        body["verb"] = json!("secret");
        let reply = st.dispatch(&body);
        assert_eq!(reply["value"], "s3cr3t");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_verb_is_structured_error() {
        let dir = temp_dir();
        let dk = test_device();
        let node = Identity::from_secret_bytes(&[21u8; 32]);
        let st = state_with(dir.clone(), &dk, &node);
        let reply = st.dispatch(&json!({ "verb": "frobnicate" }));
        assert!(reply["error"].as_str().unwrap().contains("unknown verb"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
