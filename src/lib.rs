//! # ce-auth — mesh-native, capability-minting auth/SSO for CE
//!
//! ce-auth owns the operator's device registry and answers, for every other app, "is this device the
//! operator?" — but it does so over the **mesh** and, crucially, by **minting an attenuating ce-cap
//! grant** the relying party verifies OFFLINE. There is no per-request callback to ce-auth.
//!
//! ## Two surfaces
//!
//! 1. **Mesh service** ([`service`]) — ce-auth advertises the pinned service name
//!    [`service::SERVICE_NAME`] (`ce-auth`). Any relying party `ce_rs::locate("ce-auth")`s a live
//!    instance and sends it a verb request over libp2p (`ce_rs::serve` on topic
//!    [`service::TOPIC`]). The defining verb is `verify`: on a valid enrolled-admin device proof it
//!    returns a minted ce-cap token. All service-to-service traffic is mesh, never HTTP.
//!
//! 2. **Thin console HTTP** — a small local axum server (operator-only) that serves the
//!    device-management console (the human frontend). It carries the *same* verbs as the mesh
//!    service, but only for the browser operator UI; service-to-service never uses it.
//!
//! ## The cap bridge ([`bridge`])
//!
//! ce-auth bridges two identity worlds: an enrolled device is a **P-256 ce-secrets** key (the
//! authenticator), while ce-cap principals are **Ed25519 CE NodeIds**. Each enrolled device registers
//! its CE NodeId at enroll time; on a valid P-256 proof ce-auth mints a cap FOR that NodeId, rooted at
//! ce-auth's own CE identity (the org root apps trust). See [`bridge`] for the precise design.

pub mod auth;
pub mod bridge;
pub mod secrets;
pub mod service;
pub mod store;
