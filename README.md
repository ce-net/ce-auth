# ce-auth

The operator's **mesh-native, capability-minting** auth/SSO service for CE. ce-auth owns the
operator's **device registry** and answers one question for every other app — **"is this device the
operator?"** — but it does so over the **CE mesh**, and on a valid answer it **mints an attenuating
`ce-cap` grant** the relying party verifies **OFFLINE**. There is no per-request callback to ce-auth.

Device auth is the ce-secrets challenge-response primitive (via `ce-secrets-rs`): a device proves
possession of its ECDSA P-256 private key over a fresh, audience-bound challenge. No pasted bearer
tokens.

## Two surfaces

### 1. Mesh service (every app uses this) — `ce_rs::serve` / `ce_rs::locate`

ce-auth advertises the pinned service name **`ce-auth`** on the DHT. A relying party finds a live
instance with `ce_rs::locate("ce-auth")` and sends it a verb request over libp2p (`/ce/rpc/1`,
topic `ce-auth/rpc`). Each request is a JSON envelope `{ "verb": ..., ... }`. **No HTTP** for
service-to-service.

| verb | payload | reply |
|---|---|---|
| `challenge` | `{ aud }` | `{ aud, nonce, ts }` |
| `verify` | `{ aud, deviceId, sig, nonce, ts }` | `{ ok, role, deviceId, nodeId?, cap?, capRoot? }` |
| `me` | `{ ...console auth... }` | `{ deviceId, role, hasAdmins, nodeId? }` |
| `claim` | `{ pub, nodeId?, ...console auth... }` | `{ ok, deviceId, role }` |
| `request` | `{ pub, nodeId?, label?, ...console auth... }` | `{ ok, deviceId, role }` |
| `devices` | `{ ...admin auth... }` | `{ admins, pending }` |
| `approve` | `{ targetDeviceId, ...admin auth... }` | `{ ok, role }` |
| `revoke` | `{ targetDeviceId, ...admin auth... }` | `{ ok }` |
| `secret` | `{ name, ...admin auth... }` | `{ name, value }` |

The nonce is stateless: `nonce = HMAC-SHA256(K_aud, ts)` where `K_aud` mixes the audience into the
HMAC key, so a challenge minted for `aud=X` cannot be replayed against `aud=Y`. TTL is 300s.

`deviceId` always names the **caller's** device (its auth proof); a verb that acts on another device
names it with `targetDeviceId`, so the two never collide over the mesh.

### The cap bridge (the core deliverable)

On a successful `verify` — the P-256 device signature is valid **and** the device is enrolled as an
**admin** (the operator) **and** it has a registered **CE NodeId** — ce-auth MINTS an attenuating
`ce-cap` grant via `ce-iam` and returns it in `cap`:

- **issuer** = ce-auth's own CE identity (the org root). Any app that trusts this root accepts the
  grant. The root NodeId is reported as `capRoot`; configure a shared org root with
  `CE_AUTH_CAP_ROOT_SEED`.
- **audience** = the device's registered **CE NodeId** (the bridged principal).
- **abilities** = `["auth:operator", "aud:<app>"]` — a stable "this principal is the operator" claim
  plus an app-scoped ability, so a grant minted for `aud=X` does not satisfy an app requiring
  `aud=Y`. The audience binding survives all the way into the offline cap check.
- **resource** = `*` by default (`CE_AUTH_CAP_RESOURCE` narrows it).
- **caveats** = a short TTL (`CE_AUTH_CAP_TTL_SECS`, default 600s). The device re-verifies to refresh.

The device carries `cap`. Relying-party apps verify it **offline** with `ce-cap` /
`ce_iam::Iam::verify` (configure ce-auth's `capRoot` as an accepted root) — they never call `verify`
again per request. Because the grant is a real `ce-cap` chain it is **attenuating by construction**:
the holder can sub-delegate a *subset* to another NodeId, but the verifier rejects any attempt to
broaden abilities, resource, or caveats.

#### Why the bridge exists (two identity worlds)

ce-auth straddles two key systems and joins them explicitly:

- **ce-secrets device world** — a device is a **P-256 ECDSA** key with a short `deviceId`. `verify`
  proves *possession* of that key. "Enrolled admin" == "is the operator".
- **ce-cap world** — authority is a signed, attenuating chain whose principals are **Ed25519 CE
  NodeIds**.

These do not share a key type. We bridge them by requiring each enrolled device to **register its CE
NodeId** at claim/enroll time (`store::Device.node_id`). The P-256 key stays the authenticator; the
registered Ed25519 NodeId becomes the cap subject. On a valid P-256 proof ce-auth mints the cap FOR
that NodeId. A device with no registered NodeId can authenticate (`ok=true`) but gets **no cap**
(`capError` says so) — there is no principal to bind.

### 2. Thin operator console (browser frontend only)

A small local axum server (`PORT`, default `8972`) serves the single-page device-management console
and the same verbs over HTTP for the browser. Auth is delivered in `x-ce-*` headers; the handlers map
each call into the same verb dispatch the mesh uses, so there is one implementation and one auth path.
Service-to-service never uses this surface. The relying-party `/challenge` + `/verify` are also
exposed here for browser apps that prefer HTTP — they mint the **same** bridged cap.

| Method | Path | Description |
|---|---|---|
| GET | `/challenge?aud=<appId>` | `{ aud, nonce, ts }` |
| POST | `/verify` | `{ ok, role, deviceId, nodeId?, cap?, capRoot? }` |
| GET | `/me` | `{ deviceId, role, hasAdmins, nodeId? }` |
| POST | `/claim` | TOFU first device becomes admin; 409 once an admin exists |
| POST | `/request` | `{ pub, nodeId?, label? }` — record this device as `pending` |
| GET | `/devices` | admin only — `{ admins, pending }` |
| POST | `/devices/approve` | admin only — `{ deviceId }` (the target) — promote a pending device |
| POST | `/devices/revoke` | admin only — `{ deviceId }` (the target) — remove a device (not the last admin) |
| GET | `/` | the single-page console (embedded via `include_str!`) |
| GET | `/health` | liveness |

Enrollment is self-service: the first browser to open `/` claims ce-auth (TOFU); any later device
requests access and an existing admin approves it in-console. No env editing, no redeploy.

## Configuration

| Env | Default | Meaning |
|---|---|---|
| `PORT` | `8972` | console HTTP listen port |
| `CE_NODE_URL` | `http://127.0.0.1:8844` | the local CE node this service attaches to for the mesh |
| `CE_API_TOKEN` | auto-discovered | node API token (ce-rs reads `$CE_API_TOKEN` else the data-dir `api.token`) |
| `CE_AUTH_DATA_DIR` | `./ce-auth-data` | data dir; `devices.json` + the cap-root `identity/` |
| `CE_AUTH_SERVER_SECRET` | per-boot random | stateless-nonce HMAC key. Set it for stable verification across restarts. |
| `CE_AUTH_ADMIN_DEVICES` | — | one-time bootstrap seed: `deviceId:ecdsaPubB64url,...` (pub = base64url(no-pad) of the 65-byte SEC1 point `04‖x‖y`) |
| `CE_AUTH_SECRETS` | — | optional seed for the `secret` verb's `SecretStore`: `name=value,...` operator secrets served to authorized devices |
| `CE_AUTH_CAP_ROOT_SEED` | per-instance key | 64-hex 32-byte secret for the cap org-root. Share across replicas to mint under one root; else a per-instance identity in `<data_dir>/identity`. |
| `CE_AUTH_CAP_RESOURCE` | `*` | resource scope of minted grants (`*`, `tag:<t>`, `all-of:a,b`, or a node id) |
| `CE_AUTH_CAP_TTL_SECS` | `600` | minted-grant lifetime in seconds |

The device-seed env is a **bootstrap only**: it is written into `devices.json` for any device not
already present, after which the persisted file is the source of truth.

## Run / test

```bash
cargo build
cargo test                 # 30 lib + 2 bin unit tests, all offline
cargo run                  # serves the mesh service + console on :8972
```

## Crates used (the exact APIs)

- **`ce-rs`** (`serve`, `locate` features): `ce_rs::serve::serve` + `Handler`/`Request`,
  `ce_rs::locate::register`, `CeClient::{new, status, request, reply, advertise_service,
  find_service}`.
- **`ce-iam`**: `Iam::{new, with_action_universe, with_accepted_roots, mint, attenuate, verify,
  verify_chain, decode}`, `Principal::parse`, `simple_policy`, `Conditions`, `ResourceMatch`.
- **`ce-cap`** (via ce-iam): the attenuating chain primitive (`SignedCapability`, `authorize`).
- **`ce-identity`**: `Identity::{from_secret_bytes, load_or_generate, node_id, node_id_hex}`.
- **`ce-secrets-rs`**: `sign_challenge`, `verify_auth`, `make_nonce`, `check_nonce` (the P-256 device
  proof).

## License

AGPL-3.0-only. A commercial license is also available — see [`LICENSING.md`](./LICENSING.md)
and [`COMMERCIAL-LICENSE.md`](./COMMERCIAL-LICENSE.md).
