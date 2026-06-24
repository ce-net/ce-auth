# ce-auth

The operator's reusable auth/SSO app for CE. ce-auth owns the operator's **device registry** and
answers one question for every other app: **"is this device the operator?"**

It is the central home for the device-auth that previously lived inside individual apps (e.g.
ce-watch). A light axum service that lives beside the relay — no libp2p, no wasmtime, no heavy deps.
Auth is the ce-secrets challenge-response primitive (via `ce-secrets-rs`): a device proves possession
of its ECDSA P-256 private key over a fresh, audience-bound challenge. No pasted bearer tokens.

## Two surfaces

### 1. Relying-party API (every app uses this)

An app delegates auth to ce-auth in two steps:

```
GET  /challenge?aud=<appId>
  -> { "aud": "<appId>", "nonce": "<hex>", "ts": "<ISO-8601 ms>" }
```

The nonce is stateless: `nonce = HMAC-SHA256(server_secret, aud + "|" + ts)`, hex. Nothing is stored.
TTL is 300s. Because the audience is mixed into the nonce, a challenge minted for `aud=X` cannot be
replayed against `aud=Y`.

```
POST /verify { "aud", "deviceId", "sig", "nonce", "ts" }
  -> { "ok": bool, "role": "admin"|"pending"|"none", "deviceId": "..." }
```

ce-auth re-derives + TTL-checks the nonce (bound to `aud`), looks up `deviceId` in its registry, and
verifies `sig` against the device's **enrolled** ECDSA pub. `ok = (signature valid AND role==admin)`.
A device enrolled here with `role=admin` **is the operator** — and is therefore trusted by every app.
`/verify` always returns HTTP 200; the verdict is in the body.

### 2. Operator device-management console

The operator's own surfaces, gated by ce-auth's OWN device-auth with `aud="ce-auth"`:

| Method | Path | Description |
|---|---|---|
| GET | `/me` | `{ deviceId, role, hasAdmins }` — pick the right screen |
| POST | `/claim` | TOFU: the first device becomes admin; 409 once an admin exists |
| POST | `/request` | `{ pub, label? }` — record this device as `pending` |
| GET | `/devices` | admin only — `{ admins, pending }` |
| POST | `/devices/approve` | admin only — `{ deviceId }` — promote a pending device |
| POST | `/devices/revoke` | admin only — `{ deviceId }` — remove a device (not the last admin) |
| GET | `/` | the single-page console (embedded via `include_str!`) |
| GET | `/health` | liveness |

Enrollment is self-service: the first browser to open `/` claims ce-auth (TOFU); any later device
requests access and an existing admin approves it in-console. No env editing, no redeploy.

## Configuration

| Env | Default | Meaning |
|---|---|---|
| `PORT` | `8972` | listen port |
| `CE_AUTH_DATA_DIR` | `./ce-auth-data` | data dir; holds `devices.json` (atomic, chmod 600 on unix) |
| `CE_AUTH_SERVER_SECRET` | per-boot random | stateless-nonce HMAC key. Set it for stable verification across restarts. |
| `CE_AUTH_ADMIN_DEVICES` | — | one-time bootstrap seed: `deviceId:ecdsaPubB64url,...` (pub = base64url(no-pad) of the 65-byte SEC1 point `04‖x‖y`) |

The env seed is a **bootstrap only**: it is written into `devices.json` for any device not already
present, after which the persisted file is the source of truth.

## Run / test

```bash
cargo build
cargo test
cargo run    # serves on :8972
```
