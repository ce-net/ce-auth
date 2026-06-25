# Deploying ce-auth on the relay

ce-auth is a mesh app: it attaches to the co-located CE node, advertises the **`ce-auth`** service on
the DHT, and answers `challenge`/`verify` (and console) verbs over libp2p (`/ce/rpc/1`, topic
`ce-auth/rpc`). The production browser at `https://ce-net.com` reaches it **only over the mesh**,
through ce-serve's `/mesh-bridge` — never by calling ce-auth's HTTP port. The thin HTTP console
(`:8972`) exists only for the operator device-management UI.

## What gets deployed

| Path on relay | What |
|---|---|
| `/opt/ce-auth/ce-auth` | the binary (built natively on the relay) |
| `/opt/ce-auth/data/` | `devices.json` (operator device registry) + `identity/` (cap-root key if no seed) |
| `/etc/systemd/system/ce-auth.service` | the unit (from `deploy/ce-auth.service`) |
| `/etc/ce-auth/ce-auth.env` | secrets / stable identity — **you create this**, root-only (chmod 600) |

## Build + deploy (one command, from the laptop)

```bash
cd ~/ce-net/ce-auth
ssh-add ~/.ssh/id_ed25519          # the relay key must be in your agent
bash deploy/build-on-relay.sh      # sync sources -> native build on relay -> install + restart
# or just compile-check on the relay without installing:
bash deploy/build-on-relay.sh check
```

The script stages ce-auth and its path deps (`ce-rs`, `ce-secrets-rs`, `ce-iam`,
`ce/crates/{ce-cap,ce-identity}`) into `/opt/ce-build/` in the `~/ce-net` layout so the relative
`path = "../..."` deps resolve, builds `--release`, installs the binary, syncs the unit, and restarts.
This mirrors `web/deploy/ce-build.sh`.

## Required: `/etc/ce-auth/ce-auth.env` (secrets — never commit, never invent)

The unit reads this root-only file. **Do not hard-code secrets in the unit or this repo.** Create it
on the relay once:

```ini
# Stateless-nonce HMAC key. MUST be stable across restarts (else in-flight challenges break on
# restart). Generate ONCE and keep it: `openssl rand -hex 32`.
CE_AUTH_SERVER_SECRET=<64-hex you generated and saved>

# Pins ce-auth's capRoot NodeId across restarts/replicas. Generate ONCE: `openssl rand -hex 32`.
# Relying-party apps trust the NodeId DERIVED from this seed (see "capRoot" below). If you omit it, a
# per-instance key is generated under /opt/ce-auth/data/identity and the capRoot changes if that dir
# is wiped — acceptable for a single stable relay, but pin it for reproducibility / replicas.
CE_AUTH_CAP_ROOT_SEED=<64-hex you generated and saved>

# Optional tuning:
# CE_AUTH_CAP_TTL_SECS=600
# CE_AUTH_CAP_RESOURCE=*
# CE_AUTH_ADMIN_DEVICES=<deviceId>:<ecdsaPubB64url>   # bootstrap the first operator without TOFU
```

```bash
install -d -m700 /etc/ce-auth
$EDITOR /etc/ce-auth/ce-auth.env && chmod 600 /etc/ce-auth/ce-auth.env
systemctl restart ce-auth
```

`CE_AUTH_SERVER_SECRET` and `CE_AUTH_CAP_ROOT_SEED` are operator secrets you generate with
`openssl rand -hex 32`. They are not sourced from anywhere else; save them in your password manager /
the ce-secrets vault. Losing `CE_AUTH_CAP_ROOT_SEED` (and the data-dir key) changes the capRoot, which
invalidates the trust every relying-party app was configured with.

## How a relying-party app (and the website) learns ce-auth's `capRoot`

`capRoot` is the **NodeId apps must trust** — the Ed25519 CE NodeId of the key that signs every minted
grant. It is:

- printed at startup: `journalctl -u ce-auth | grep "cap bridge ready"` →
  `cap_root=<64-hex NodeId> ...`, and
- returned in every `verify` reply as `capRoot`, alongside the minted `cap`.

A relying-party app configures that NodeId as an accepted root
(`ce_iam::Iam::with_accepted_roots([...])`) and then verifies minted `cap` tokens **offline** — it
never calls ce-auth per request. Because `capRoot` is deterministic from `CE_AUTH_CAP_ROOT_SEED`, you
can compute it ahead of deploy and bake it into apps; otherwise read it from the journal after the
first start.

## The browser-facing call (via ce-serve `/mesh-bridge` / `window.__ceNode`)

The website never touches ce-auth's HTTP port. It speaks the mesh-bridge contract:

1. **Find a live ce-auth instance** (its NodeId is the mesh `to`):

   `GET /discovery/find/ce-auth` → `{ "providers": ["<nodeIdHex>", ...] }`  (pick one)

2. **challenge** — one mesh request:

   `POST /mesh/request` with body
   `{ "to": "<nodeIdHex>", "topic": "ce-auth/rpc", "payload_hex": hex(utf8(JSON {"verb":"challenge","aud":"<appId>"})), "timeout_ms": 10000 }`
   → reply `{ "payload_hex": hex(utf8(JSON {"aud","nonce","ts"})) }`

3. The browser signs the P-256 challenge (ce-secrets `sign_challenge` over `aud, nonce, ts`).

4. **verify** — one mesh request to the same `to`/`topic`:

   `payload_hex = hex(utf8(JSON {"verb":"verify","aud","deviceId","sig","nonce","ts"}))`
   → reply payload JSON `{ "ok", "role", "deviceId", "nodeId?", "cap?", "capRoot?" }`.

On `ok:true` the browser holds `cap` (the operator grant) and `capRoot`. See the repo `README.md` and
`src/service.rs` for the full verb table (claim/request/approve/revoke/me/secret, console-class).

## Public exposure

Service-to-service and the browser both reach ce-auth over the mesh, so **no public port is required**
for the auth flow. If you want the operator console reachable as a page, proxy `:8972` behind
Cloudflare/nginx like the other relay services — but the `challenge`/`verify` capability flow does not
need it.
