//! THE CAP BRIDGE — the core of mesh-native ce-auth.
//!
//! ce-auth straddles two identity worlds and joins them here:
//!
//!   * **ce-secrets device world** — a device is a P-256 ECDSA key with a short `deviceId`. "Enrolled
//!     as admin" == "is the operator". `verify` proves *possession* of that P-256 key over a fresh,
//!     audience-bound challenge (see `auth.rs`).
//!   * **ce-cap capability world** — authority is a signed, attenuating capability chain whose
//!     principals are **Ed25519 CE NodeIds** (`ce_cap::Capability::{issuer,audience}`). Apps verify a
//!     chain OFFLINE with `ce_cap::authorize` / `ce_iam::Iam::verify` — no callback to ce-auth.
//!
//! These do not share a key type, so we bridge them explicitly:
//!
//!   1. **Enroll-time binding.** Each enrolled device registers its CE NodeId (Ed25519, 64-hex) at
//!      claim/request time (`store::Device::node_id`). That NodeId is the ce-cap *principal* for the
//!      device. The P-256 key stays the authenticator; the Ed25519 NodeId becomes the cap subject.
//!   2. **Verify-time mint.** On a successful `verify` (P-256 signature valid AND the device is an
//!      enrolled admin AND it has a registered NodeId), ce-auth MINTS a fresh attenuating ce-cap grant
//!      via `ce_iam::Iam::mint`:
//!        - **issuer**  = ce-auth's own CE identity (the org root) — so any app that trusts this root
//!          accepts the grant. (Configure a different org root with `CE_AUTH_CAP_ROOT_SEED`.)
//!        - **audience** = the device's registered NodeId (the bridged principal).
//!        - **abilities** = `["auth:operator", "aud:<app>"]` — a stable "this principal is the
//!          operator" claim, plus an app-scoped ability so the grant is bound to the requesting app's
//!          audience and an app can require exactly its own audience offline.
//!        - **resource** = `*` by default (the operator is the operator everywhere); narrowable per
//!          deploy with `CE_AUTH_CAP_RESOURCE`.
//!        - **caveats**  = a short TTL (`CE_AUTH_CAP_TTL_SECS`, default 600s) — the grant is
//!          short-lived; the device re-verifies to refresh it.
//!      The device carries the returned token. Relying-party apps verify it OFFLINE with ce-cap; they
//!      never call back to ce-auth per request.
//!
//! Because the grant is a real ce-cap chain, it is **attenuating by construction**: the holder
//! (device NodeId) can sub-delegate a *subset* to another NodeId via `ce_iam::Iam::attenuate`, but
//! `ce_cap`'s verifier rejects any attempt to broaden abilities, resource, or caveats. The mint here
//! is the chain root; everything downstream can only narrow.

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use ce_iam::{Conditions, Iam, Principal, ResourceMatch, simple_policy};
use ce_identity::Identity;

/// The stable ability asserting "this principal is the enrolled operator". Apps that only care that
/// the caller is the operator (not which app audience) require this.
pub const ABILITY_OPERATOR: &str = "auth:operator";

/// Build the app-scoped ability for an audience: `aud:<app>`. An app requires *exactly* its own
/// `aud:<app>` ability when verifying offline, so a grant minted for `aud=X` does not satisfy an app
/// expecting `aud=Y` — the audience binding survives all the way into the offline cap check.
pub fn ability_for_aud(aud: &str) -> String {
    format!("aud:{aud}")
}

/// The cap-minting bridge. Holds ce-auth's root CE identity (the issuer/org-root every relying app
/// trusts), an `Iam` handle for minting/verifying, the default resource scope, and the grant TTL.
pub struct CapBridge {
    /// ce-auth's own CE identity — the root that signs (issues) every minted grant.
    root: Identity,
    /// IAM handle. Its action universe contains the operator ability so `*` could expand; literal
    /// `aud:<app>` abilities are always allowed (literal grants bypass the universe).
    iam: Iam,
    /// Default resource the grant applies to (`*` unless `CE_AUTH_CAP_RESOURCE` narrows it).
    resource: ResourceMatch,
    /// Grant lifetime in seconds (short — the device re-verifies to refresh).
    ttl_secs: u64,
    /// Monotonic nonce source so each minted grant is independently revocable.
    nonce: AtomicU64,
}

impl CapBridge {
    /// Construct the bridge from a root [`Identity`], resource scope, and TTL. The IAM action
    /// universe is seeded with [`ABILITY_OPERATOR`] (literal `aud:*` abilities need no universe).
    pub fn new(root: Identity, resource: ResourceMatch, ttl_secs: u64) -> Self {
        let iam = Iam::new().with_action_universe([ABILITY_OPERATOR.to_string()]);
        // Seed the nonce from the wall clock so nonces do not collide across process restarts (each
        // mint must be independently revocable by (issuer, nonce); a fresh boot must not reuse them).
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);
        Self {
            root,
            iam,
            resource,
            ttl_secs,
            nonce: AtomicU64::new(seed),
        }
    }

    /// Load the bridge from the environment / data dir:
    ///   * `CE_AUTH_CAP_ROOT_SEED` — 64-hex 32-byte secret for the org root key (deterministic across
    ///     restarts/instances; share it across replicas so they all mint under the same root). If
    ///     unset, the root identity is loaded/generated under `<data_dir>/identity` (per-instance).
    ///   * `CE_AUTH_CAP_RESOURCE` — resource spelling (`*`, `tag:<t>`, `all-of:a,b`, or a node id);
    ///     default `*`.
    ///   * `CE_AUTH_CAP_TTL_SECS` — grant TTL seconds; default 600.
    pub fn from_env(data_dir: &std::path::Path) -> Result<Self> {
        let root = match std::env::var("CE_AUTH_CAP_ROOT_SEED").ok().filter(|s| !s.trim().is_empty()) {
            Some(hex_seed) => {
                let bytes = hex::decode(hex_seed.trim())
                    .context("CE_AUTH_CAP_ROOT_SEED is not valid hex")?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("CE_AUTH_CAP_ROOT_SEED must be 32 bytes (64 hex)"))?;
                Identity::from_secret_bytes(&arr)
            }
            None => {
                let id_dir = data_dir.join("identity");
                Identity::load_or_generate(&id_dir)
                    .with_context(|| format!("load/generate cap-root identity in {}", id_dir.display()))?
            }
        };
        let resource = match std::env::var("CE_AUTH_CAP_RESOURCE").ok().filter(|s| !s.trim().is_empty()) {
            Some(s) => ResourceMatch::parse(s.trim())
                .map_err(|e| anyhow::anyhow!("CE_AUTH_CAP_RESOURCE invalid: {e}"))?,
            None => ResourceMatch::Any,
        };
        let ttl_secs = std::env::var("CE_AUTH_CAP_TTL_SECS")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .filter(|n| *n > 0)
            .unwrap_or(600);
        Ok(Self::new(root, resource, ttl_secs))
    }

    /// The 64-hex CE NodeId of the root that signs every minted grant. Relying-party apps configure
    /// THIS as an accepted root (`Iam::with_accepted_roots`) so they honor ce-auth-minted grants.
    pub fn root_node_id_hex(&self) -> String {
        self.root.node_id_hex()
    }

    /// The IAM handle (its accepted-roots/universe), exposed for the service to verify chains.
    pub fn iam(&self) -> &Iam {
        &self.iam
    }

    /// MINT the operator grant for a verified device. Bridges the verified P-256 device (already
    /// proven by the caller) to its registered CE NodeId `audience_node_id_hex` and the requesting app
    /// `aud`. Returns the portable hex cap token the device carries.
    ///
    /// The minted leaf grants `[auth:operator, aud:<app>]` on the configured resource, expiring in
    /// `ttl_secs`. It is a root grant signed by ce-auth's identity; apps that accept this root verify
    /// it offline. Errors only if the NodeId is malformed or the policy fails to compile.
    pub fn mint_operator_grant(&self, audience_node_id_hex: &str, aud: &str, now: u64) -> Result<String> {
        let audience = Principal::parse(audience_node_id_hex)
            .with_context(|| format!("device CE NodeId '{audience_node_id_hex}' is not a valid principal"))?;
        let policy = simple_policy(
            vec![ABILITY_OPERATOR.to_string(), ability_for_aud(aud)],
            self.resource.clone(),
            Conditions { not_after: Some(now + self.ttl_secs), ..Default::default() },
        );
        let nonce = self.nonce.fetch_add(1, Ordering::Relaxed);
        let grant = self
            .iam
            .mint(&self.root, audience, &policy, nonce)
            .map_err(|e| anyhow::anyhow!("mint operator grant: {e}"))?;
        Ok(grant.token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ce_iam::Iam;

    fn root() -> Identity {
        Identity::from_secret_bytes(&[7u8; 32])
    }

    fn device_node() -> Identity {
        Identity::from_secret_bytes(&[9u8; 32])
    }

    fn bridge() -> CapBridge {
        CapBridge::new(root(), ResourceMatch::Any, 600)
    }

    fn never_revoked() -> impl Fn(&ce_identity::NodeId, u64) -> bool {
        |_: &ce_identity::NodeId, _: u64| false
    }

    /// A relying-party app's verifier: trusts ce-auth's root and the operator action universe.
    fn app_iam(root_node_id: ce_identity::NodeId) -> Iam {
        Iam::new()
            .with_action_universe([ABILITY_OPERATOR.to_string()])
            .with_accepted_roots([root_node_id])
    }

    #[test]
    fn minted_grant_verifies_offline_for_aud_and_operator() {
        let b = bridge();
        let dev = device_node();
        let now = 1000u64;
        let token = b.mint_operator_grant(&dev.node_id_hex(), "ce-cast", now).unwrap();

        let app = app_iam(b.root.node_id());
        let principal = Principal(dev.node_id());
        // The operator ability verifies for the bridged NodeId.
        assert!(
            app.verify(&[1u8; 32], &[], now, &principal, ABILITY_OPERATOR, &token, &never_revoked())
                .is_ok(),
            "operator ability must verify offline against ce-auth's root"
        );
        // The app-scoped audience ability verifies.
        assert!(
            app.verify(&[1u8; 32], &[], now, &principal, &ability_for_aud("ce-cast"), &token, &never_revoked())
                .is_ok(),
            "aud:<app> ability must verify offline"
        );
    }

    #[test]
    fn grant_is_bound_to_the_subject_nodeid() {
        // A grant minted for device A's NodeId must NOT verify for a different principal B.
        let b = bridge();
        let dev_a = device_node();
        let dev_b = Identity::from_secret_bytes(&[11u8; 32]);
        let now = 1000u64;
        let token = b.mint_operator_grant(&dev_a.node_id_hex(), "ce-cast", now).unwrap();

        let app = app_iam(b.root.node_id());
        assert!(
            app.verify(&[1u8; 32], &[], now, &Principal(dev_b.node_id()), ABILITY_OPERATOR, &token, &never_revoked())
                .is_err(),
            "a grant for A must not authorize principal B"
        );
    }

    #[test]
    fn wrong_aud_does_not_verify() {
        // A grant minted for aud=X carries aud:X, not aud:Y; an app requiring aud:Y is denied.
        let b = bridge();
        let dev = device_node();
        let now = 1000u64;
        let token = b.mint_operator_grant(&dev.node_id_hex(), "aud-x", now).unwrap();

        let app = app_iam(b.root.node_id());
        let principal = Principal(dev.node_id());
        assert!(
            app.verify(&[1u8; 32], &[], now, &principal, &ability_for_aud("aud-y"), &token, &never_revoked())
                .is_err(),
            "a grant for aud-x must not satisfy aud-y"
        );
    }

    #[test]
    fn expired_grant_does_not_verify() {
        let b = CapBridge::new(root(), ResourceMatch::Any, 600);
        let dev = device_node();
        let now = 1000u64;
        let token = b.mint_operator_grant(&dev.node_id_hex(), "ce-cast", now).unwrap();
        let app = app_iam(b.root.node_id());
        let principal = Principal(dev.node_id());
        // 1000 + 600 = 1600 is the expiry; at 2000 the grant is dead.
        assert!(
            app.verify(&[1u8; 32], &[], 2000, &principal, ABILITY_OPERATOR, &token, &never_revoked())
                .is_err(),
            "an expired grant must be rejected offline"
        );
    }

    #[test]
    fn untrusted_root_is_rejected() {
        // An app that does NOT trust ce-auth's root must reject the grant (it roots at a stranger).
        let b = bridge();
        let dev = device_node();
        let now = 1000u64;
        let token = b.mint_operator_grant(&dev.node_id_hex(), "ce-cast", now).unwrap();
        // App trusts a DIFFERENT root, and the verifying node is itself a third party.
        let other_root = Identity::from_secret_bytes(&[42u8; 32]).node_id();
        let app = app_iam(other_root);
        let principal = Principal(dev.node_id());
        assert!(
            app.verify(&[1u8; 32], &[], now, &principal, ABILITY_OPERATOR, &token, &never_revoked())
                .is_err(),
            "a grant rooted at ce-auth must not verify under an app trusting a different root"
        );
    }

    #[test]
    fn grant_is_attenuating_holder_cannot_broaden() {
        // The bridged device sub-delegates to a third NodeId. It can NARROW (drop aud:<app>, keep
        // operator) but the verifier rejects any attempt to BROADEN beyond what it holds.
        let b = bridge();
        let dev = device_node();
        let now = 1000u64;
        let token = b.mint_operator_grant(&dev.node_id_hex(), "ce-cast", now).unwrap();

        let app = app_iam(b.root.node_id());
        let parent = app.decode(&token).unwrap();

        // (a) A valid narrowing: delegate ONLY auth:operator to a delegate NodeId.
        let delegate = Identity::from_secret_bytes(&[13u8; 32]);
        let narrower = simple_policy(
            vec![ABILITY_OPERATOR.to_string()],
            ResourceMatch::Any,
            Conditions { not_after: Some(now + 100), ..Default::default() }, // tighter expiry
        );
        let child = app.attenuate(&dev, &parent, Principal(delegate.node_id()), &narrower, 99).unwrap();
        assert!(
            app.verify_chain(&[1u8; 32], &[], now, &Principal(delegate.node_id()), ABILITY_OPERATOR, &child.chain, &never_revoked())
                .is_ok(),
            "a narrowed sub-delegation must verify for the delegate"
        );

        // (b) Attempting to BROADEN (add an ability the parent never had) is refused at attenuate time
        // — the cap math guarantees a delegation can never amplify authority.
        let broaden = simple_policy(
            vec![ABILITY_OPERATOR.to_string(), "auth:superuser".to_string()],
            ResourceMatch::Any,
            Conditions::default(),
        );
        assert!(
            app.attenuate(&dev, &parent, Principal(delegate.node_id()), &broaden, 100).is_err(),
            "broadening abilities beyond the parent must be rejected"
        );
    }

    #[test]
    fn unparseable_node_id_errors_not_panics() {
        let b = bridge();
        assert!(b.mint_operator_grant("not-a-node-id", "ce-cast", 1000).is_err());
    }
}
