//! The operator's boot-loaded secret map for SECRET-DELIVERY.
//!
//! ce-auth can hand a named secret to an enrolled ADMIN device that proves possession of its device
//! key over a fresh challenge (the same device-auth that gates `/me` and `/devices`). The secrets are
//! configured ONCE at boot from the env `CE_AUTH_SECRETS` in the format `name1=value1;name2=value2`
//! (semicolon-separated `name=value` pairs). Values are never logged — only names ever appear in
//! diagnostics — and the map is immutable after boot.
//!
//! Parsing rules (lenient, never fail boot):
//!   - Split on `;`. Empty segments (e.g. a trailing `;`) are skipped.
//!   - Each segment splits on the FIRST `=`: everything left is the name (trimmed), everything right
//!     is the value (NOT trimmed — a secret may legitimately contain leading/trailing spaces, though
//!     per the contract values are `=`-free tokens; we keep any `=` that follow the first one too,
//!     which `split_once` preserves).
//!   - A segment with no `=`, or an empty name, is skipped with a warning that NEVER prints the value.

use std::collections::BTreeMap;

/// The operator's immutable, boot-loaded secret map (`name -> value`). Lookups are exact-match.
#[derive(Clone, Default)]
pub struct SecretStore {
    inner: BTreeMap<String, String>,
}

impl SecretStore {
    /// Parse `CE_AUTH_SECRETS` (`name1=value1;name2=value2`) into the store. Lenient: malformed
    /// segments are skipped (with a value-free warning) rather than failing boot. An empty env yields
    /// an empty store. A later duplicate name overrides an earlier one.
    pub fn from_env(env: &str) -> Self {
        let mut inner = BTreeMap::new();
        for seg in env.split(';') {
            if seg.trim().is_empty() {
                continue;
            }
            let Some((name, value)) = seg.split_once('=') else {
                tracing::warn!("CE_AUTH_SECRETS segment missing '=' — skipped (value not logged)");
                continue;
            };
            let name = name.trim().to_string();
            if name.is_empty() {
                tracing::warn!("CE_AUTH_SECRETS segment has empty name — skipped (value not logged)");
                continue;
            }
            inner.insert(name, value.to_string());
        }
        Self { inner }
    }

    /// Look up a secret by exact name. Returns the value, or `None` if the name is unknown.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.inner.get(name).map(|s| s.as_str())
    }

    /// Number of configured secrets (names only — never exposes values).
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multiple_pairs() {
        let s = SecretStore::from_env("api=abc123;db=postgres-url;token=xyz");
        assert_eq!(s.len(), 3);
        assert_eq!(s.get("api"), Some("abc123"));
        assert_eq!(s.get("db"), Some("postgres-url"));
        assert_eq!(s.get("token"), Some("xyz"));
    }

    #[test]
    fn unknown_name_is_none() {
        let s = SecretStore::from_env("api=abc123");
        assert_eq!(s.get("missing"), None);
    }

    #[test]
    fn empty_env_yields_empty_store() {
        let s = SecretStore::from_env("");
        assert!(s.is_empty());
        assert_eq!(s.get("anything"), None);
    }

    #[test]
    fn trailing_and_empty_segments_skipped() {
        // Trailing `;`, a doubled `;;`, and whitespace-only segments are all skipped.
        let s = SecretStore::from_env("a=1;;b=2; ;");
        assert_eq!(s.len(), 2);
        assert_eq!(s.get("a"), Some("1"));
        assert_eq!(s.get("b"), Some("2"));
    }

    #[test]
    fn name_is_trimmed() {
        let s = SecretStore::from_env("  spaced  =value");
        assert_eq!(s.get("spaced"), Some("value"));
    }

    #[test]
    fn segment_without_equals_skipped() {
        let s = SecretStore::from_env("noequals;ok=yes");
        assert_eq!(s.len(), 1);
        assert_eq!(s.get("ok"), Some("yes"));
        assert_eq!(s.get("noequals"), None);
    }

    #[test]
    fn empty_name_skipped() {
        let s = SecretStore::from_env("=orphan;real=here");
        assert_eq!(s.len(), 1);
        assert_eq!(s.get("real"), Some("here"));
    }

    #[test]
    fn duplicate_name_last_wins() {
        let s = SecretStore::from_env("k=first;k=second");
        assert_eq!(s.get("k"), Some("second"));
    }
}
