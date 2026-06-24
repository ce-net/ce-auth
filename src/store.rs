//! The operator's persisted, self-managed device registry (`devices.json` in the data dir).
//!
//! This is ce-auth's source of truth for "who is the operator" after boot. A device enrolled here
//! with `role=admin` is the operator: every app that delegates auth to ce-auth trusts it. Enrollment
//! is self-service — TOFU `claim` for the first device, then `request` / `approve` / `revoke`.
//! Env-seeded devices (`CE_AUTH_ADMIN_DEVICES`) are written in as `role=admin` at startup (a
//! bootstrap) but never override a device already present in the file.
//!
//! The map (`deviceId -> Device`) is held under a mutex and mirrored to disk atomically (write to a
//! temp file, fsync, rename) with mode 0600 on unix, so a crash mid-write cannot corrupt it.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// The role a device holds in the registry. `Admin` is the operator (trusted by every app and able
/// to manage other devices); `Pending` is a device that has requested access but is not yet approved.
pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_PENDING: &str = "pending";

/// A persisted admin/pending device record. `pub` is the compact ECDSA SEC1 form
/// (`base64url(04||x||y)`) the console derives from its WebCrypto key — the exact string accepted by
/// `auth::ecdsa_pub_from_compact`, so we can reconstruct the verifying key to authenticate the device
/// on every request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Device {
    /// Compact ECDSA SEC1 public point, base64url(no-pad) of `04 || x(32) || y(32)`.
    #[serde(rename = "pub")]
    pub pub_b64: String,
    /// `"admin"` or `"pending"`.
    pub role: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub added_ts: u64,
}

/// The persisted, self-managed device store (`devices.json` in the data dir).
pub struct DeviceStore {
    path: PathBuf,
    inner: Mutex<BTreeMap<String, Device>>,
}

impl DeviceStore {
    /// Open (creating if needed) the store at `data_dir/devices.json`, replaying any existing file,
    /// then seeding any `seed` entries (deviceId -> compact-pub) as `role=admin` for devices not
    /// already present. A change from seeding is persisted immediately.
    pub fn open(data_dir: &Path, seed: &[(String, String)]) -> Result<Self> {
        std::fs::create_dir_all(data_dir)
            .with_context(|| format!("create data dir {}", data_dir.display()))?;
        let path = data_dir.join("devices.json");

        let mut map: BTreeMap<String, Device> = BTreeMap::new();
        if path.exists() {
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            if !raw.trim().is_empty() {
                map = serde_json::from_str(&raw)
                    .with_context(|| format!("parse {}", path.display()))?;
            }
        }

        let store = Self { path, inner: Mutex::new(map) };

        // Seed env-provided devices as admins (bootstrap). The persisted file wins for any device
        // already present, so re-deploying with the same env never demotes/overwrites live state.
        let mut changed = false;
        {
            let mut g = store
                .inner
                .lock()
                .map_err(|_| anyhow::anyhow!("device store poisoned"))?;
            for (id, pub_b64) in seed {
                if !g.contains_key(id) {
                    g.insert(
                        id.clone(),
                        Device {
                            pub_b64: pub_b64.clone(),
                            role: ROLE_ADMIN.to_string(),
                            label: "env-seed".to_string(),
                            added_ts: now_unix_secs(),
                        },
                    );
                    changed = true;
                }
            }
        }
        if changed {
            store.persist()?;
        }
        Ok(store)
    }

    /// Atomically write the current map to disk (temp file + fsync + rename), mode 0600 on unix.
    fn persist(&self) -> Result<()> {
        let g = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("device store poisoned"))?;
        let json = serde_json::to_string_pretty(&*g).context("serialize devices")?;
        drop(g);

        let tmp = self.path.with_extension("json.tmp");
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)
                .with_context(|| format!("open temp {}", tmp.display()))?;
            f.write_all(json.as_bytes()).context("write devices temp")?;
            f.flush().ok();
            let _ = f.sync_all();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &self.path).context("rename devices into place")?;
        Ok(())
    }

    /// Number of devices with `role=admin`.
    pub fn admin_count(&self) -> usize {
        match self.inner.lock() {
            Ok(g) => g.values().filter(|d| d.role == ROLE_ADMIN).count(),
            Err(_) => 0,
        }
    }

    /// True when at least one admin exists.
    pub fn has_admins(&self) -> bool {
        self.admin_count() > 0
    }

    /// The role of a device id: `"admin"`, `"pending"`, or `"none"` (unknown).
    pub fn role_of(&self, device_id: &str) -> &'static str {
        match self.inner.lock() {
            Ok(g) => match g.get(device_id).map(|d| d.role.as_str()) {
                Some(ROLE_ADMIN) => ROLE_ADMIN,
                Some(ROLE_PENDING) => ROLE_PENDING,
                _ => "none",
            },
            Err(_) => "none",
        }
    }

    pub fn is_admin(&self, device_id: &str) -> bool {
        self.role_of(device_id) == ROLE_ADMIN
    }

    /// Snapshot the device map (id -> record) for listing.
    pub fn list(&self) -> Vec<(String, Device)> {
        match self.inner.lock() {
            Ok(g) => g.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// TOFU first claim: if there are ZERO admins, make `device_id` an admin (recording its `pub`).
    /// Returns `Ok(true)` on success, `Ok(false)` if an admin already exists (caller -> 409).
    pub fn claim(&self, device_id: &str, pub_b64: &str) -> Result<bool> {
        {
            let mut g = self
                .inner
                .lock()
                .map_err(|_| anyhow::anyhow!("device store poisoned"))?;
            if g.values().any(|d| d.role == ROLE_ADMIN) {
                return Ok(false);
            }
            g.insert(
                device_id.to_string(),
                Device {
                    pub_b64: pub_b64.to_string(),
                    role: ROLE_ADMIN.to_string(),
                    label: "claimed".to_string(),
                    added_ts: now_unix_secs(),
                },
            );
        }
        self.persist()?;
        Ok(true)
    }

    /// Record a device as `role=pending` with its compact pub and optional label. Idempotent: a
    /// device already present (admin or pending) is left as-is except a pending device may refresh
    /// its label/pub. Returns the resulting role.
    pub fn request(&self, device_id: &str, pub_b64: &str, label: &str) -> Result<&'static str> {
        let role;
        {
            let mut g = self
                .inner
                .lock()
                .map_err(|_| anyhow::anyhow!("device store poisoned"))?;
            match g.get_mut(device_id) {
                Some(d) if d.role == ROLE_ADMIN => {
                    role = ROLE_ADMIN;
                }
                Some(d) => {
                    // already pending — refresh its advertised pub/label
                    d.pub_b64 = pub_b64.to_string();
                    if !label.is_empty() {
                        d.label = label.to_string();
                    }
                    role = ROLE_PENDING;
                }
                None => {
                    g.insert(
                        device_id.to_string(),
                        Device {
                            pub_b64: pub_b64.to_string(),
                            role: ROLE_PENDING.to_string(),
                            label: label.to_string(),
                            added_ts: now_unix_secs(),
                        },
                    );
                    role = ROLE_PENDING;
                }
            }
        }
        self.persist()?;
        Ok(role)
    }

    /// Promote a pending device to admin. Returns `Ok(true)` if a pending device was promoted,
    /// `Ok(false)` if the device is unknown or already an admin.
    pub fn approve(&self, device_id: &str) -> Result<bool> {
        let mut promoted = false;
        {
            let mut g = self
                .inner
                .lock()
                .map_err(|_| anyhow::anyhow!("device store poisoned"))?;
            if let Some(d) = g.get_mut(device_id) {
                if d.role == ROLE_PENDING {
                    d.role = ROLE_ADMIN.to_string();
                    promoted = true;
                }
            }
        }
        if promoted {
            self.persist()?;
        }
        Ok(promoted)
    }

    /// Remove a device entirely. The guard is on the GLOBAL admin count, so the last admin cannot be
    /// removed by anyone (that would lock the operator out of every app).
    pub fn revoke(&self, device_id: &str) -> Result<RevokeOutcome> {
        let outcome;
        {
            let mut g = self
                .inner
                .lock()
                .map_err(|_| anyhow::anyhow!("device store poisoned"))?;
            match g.get(device_id) {
                None => return Ok(RevokeOutcome::NotFound),
                Some(d) => {
                    let is_admin = d.role == ROLE_ADMIN;
                    let admin_count = g.values().filter(|x| x.role == ROLE_ADMIN).count();
                    if is_admin && admin_count <= 1 {
                        return Ok(RevokeOutcome::LastAdmin);
                    }
                }
            }
            g.remove(device_id);
            outcome = RevokeOutcome::Removed;
        }
        self.persist()?;
        Ok(outcome)
    }

    /// Look up a device's compact pub (for reconstructing its verifying key during auth).
    pub fn pub_of(&self, device_id: &str) -> Option<String> {
        match self.inner.lock() {
            Ok(g) => g.get(device_id).map(|d| d.pub_b64.clone()),
            Err(_) => None,
        }
    }
}

/// Outcome of a revoke attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum RevokeOutcome {
    Removed,
    NotFound,
    LastAdmin,
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resolve the data dir from env (`CE_AUTH_DATA_DIR`) or default to `./ce-auth-data`.
pub fn default_data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("CE_AUTH_DATA_DIR") {
        if !d.is_empty() {
            return PathBuf::from(d);
        }
    }
    Path::new("ce-auth-data").to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let mut d = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        d.push(format!("ce-auth-store-test-{}-{}", std::process::id(), nanos));
        d
    }

    const PUB_A: &str = "BEXiMyFP2gVoMNpEQGuNi_wGYkJomGG-EbL3Rk8HUfo5oPRQppQEcMfMJknsjaQNU2uZc4Hz7GZ9T_Bf0J2L4KM";
    const PUB_B: &str = "BF5pM_MXcWTd_QhLuLeN-0Uz_c6kqXjfxxD1hZflnL4nWHvWLOzDWyZmUhG8nnISc8dN5Gol-Cyfm1YaJpIvUWU";

    #[test]
    fn claim_then_second_claim_blocked() {
        let dir = temp_dir();
        let store = DeviceStore::open(&dir, &[]).unwrap();
        assert!(!store.has_admins());
        assert!(store.claim("dev-a", PUB_A).unwrap());
        assert!(store.is_admin("dev-a"));
        // A second claim is blocked once an admin exists.
        assert!(!store.claim("dev-b", PUB_B).unwrap());
        assert_eq!(store.role_of("dev-b"), "none");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn request_approve_revoke_cycle() {
        let dir = temp_dir();
        let store = DeviceStore::open(&dir, &[("dev-a".into(), PUB_A.into())]).unwrap();
        assert_eq!(store.request("dev-b", PUB_B, "phone").unwrap(), ROLE_PENDING);
        assert_eq!(store.role_of("dev-b"), "pending");
        assert!(store.approve("dev-b").unwrap());
        assert!(store.is_admin("dev-b"));
        assert_eq!(store.revoke("dev-b").unwrap(), RevokeOutcome::Removed);
        assert_eq!(store.role_of("dev-b"), "none");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cannot_revoke_last_admin() {
        let dir = temp_dir();
        let store = DeviceStore::open(&dir, &[("dev-a".into(), PUB_A.into())]).unwrap();
        assert_eq!(store.revoke("dev-a").unwrap(), RevokeOutcome::LastAdmin);
        assert!(store.is_admin("dev-a"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persists_across_reload() {
        let dir = temp_dir();
        {
            let store = DeviceStore::open(&dir, &[("dev-a".into(), PUB_A.into())]).unwrap();
            store.request("dev-b", PUB_B, "x").unwrap();
            store.approve("dev-b").unwrap();
        }
        let store = DeviceStore::open(&dir, &[]).unwrap();
        assert!(store.is_admin("dev-a"));
        assert!(store.is_admin("dev-b"));
        assert_eq!(store.admin_count(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
