#!/usr/bin/env bash
# build-on-relay — build ce-auth ON the relay (Hetzner, x86_64 Linux), install it, and (re)start the
# service. Mirrors web/deploy/ce-build.sh: a native build on the relay IS the deploy artifact (same
# target we run on, no cross-compile), keeps heavy Rust build trees off the laptop, and dogfoods the
# mesh host. Needs the relay key in your ssh-agent (ssh-add ~/.ssh/id_ed25519).
#
#   bash deploy/build-on-relay.sh            # sync sources, build natively, install + restart ce-auth
#   bash deploy/build-on-relay.sh check      # sync + `cargo check` only (no install)
#
# This does NOT create /etc/ce-auth/ce-auth.env for you — the unit reads secrets from there. See
# deploy/README.md for the env vars (CE_AUTH_SERVER_SECRET, CE_AUTH_CAP_ROOT_SEED, ...).
set -euo pipefail

RELAY="root@178.105.145.170"
KEY="$HOME/.ssh/id_ed25519"
# One persistent multiplexed SSH connection for the whole multi-step build.
RSH="ssh -o BatchMode=yes -o ServerAliveInterval=15 -o ControlMaster=auto -o ControlPath=/tmp/ce-auth-ssh-%C -o ControlPersist=180 -i $KEY"
SSH=($RSH)
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # ce-auth/
WS="$(cd "$HERE/.." && pwd)"                              # ~/ce-net (workspace root)
REMOTE=/opt/ce-build                                      # same staging root ce-build.sh uses
# Never ship build trees or the laptop-absolute .cargo/config (would break cargo on the relay).
EXC=(--exclude 'target' --exclude 'target-*' --exclude 'node_modules' --exclude 'dist' --exclude 'pkg' --exclude '.git' --exclude '.cargo')

sync() { # <localdir> <remote-rel-path>
  "${SSH[@]}" "$RELAY" "mkdir -p $REMOTE/$(dirname "$2")"
  rsync -az --delete "${EXC[@]}" -e "$RSH" "$1/" "$RELAY:$REMOTE/$2/"
}

echo "==> stage ce-auth + its path deps onto the relay in the ~/ce-net layout (so ../ resolves)"
# ce-auth's path deps (and ce-iam's, transitively) all resolve relative to this layout:
#   ce-auth -> ../ce-rs, ../ce-secrets-rs, ../ce-iam/crates/ce-iam, ../ce/crates/{ce-cap,ce-identity}
# ce-cap/ce-identity are standalone packages (no workspace inheritance) so staging just ce/crates/* —
# WITHOUT ce/Cargo.toml — keeps the heavy node workspace off the build host.
sync "$WS/ce-auth"                 ce-auth
sync "$WS/ce-rs"                   ce-rs
sync "$WS/ce-secrets-rs"           ce-secrets-rs
sync "$WS/ce-iam"                  ce-iam
sync "$WS/ce/crates/ce-cap"        ce/crates/ce-cap
sync "$WS/ce/crates/ce-identity"   ce/crates/ce-identity

if [ "${1:-}" = "check" ]; then
  echo "==> cargo check ce-auth on the relay"
  "${SSH[@]}" "$RELAY" 'source $HOME/.cargo/env; cd '"$REMOTE"'/ce-auth && cargo check 2>&1 | tail -40'
  exit 0
fi

echo "==> build ce-auth --release natively on the relay"
"${SSH[@]}" "$RELAY" 'source $HOME/.cargo/env; cd '"$REMOTE"'/ce-auth && (cargo build --release > /tmp/ce-auth-build.log 2>&1; rc=$?; tail -25 /tmp/ce-auth-build.log; exit $rc)'

echo "==> install binary + keep the systemd unit in sync + restart"
rsync -az -e "$RSH" "$HERE"/deploy/ce-auth.service "$RELAY:/etc/systemd/system/ce-auth.service"
"${SSH[@]}" "$RELAY" '
  mkdir -p /opt/ce-auth/data /etc/ce-auth &&
  install -m755 '"$REMOTE"'/ce-auth/target/release/ce-auth /opt/ce-auth/ce-auth.new &&
  mv -f /opt/ce-auth/ce-auth.new /opt/ce-auth/ce-auth &&
  ([ -f /etc/ce-auth/ce-auth.env ] || echo "WARN: /etc/ce-auth/ce-auth.env missing — running with a per-boot nonce key and a per-instance capRoot. See deploy/README.md.") &&
  systemctl daemon-reload && systemctl enable ce-auth >/dev/null 2>&1 &&
  systemctl restart ce-auth && sleep 1 &&
  printf "service: " && systemctl is-active ce-auth &&
  printf "console: " && curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8972/health'
echo "==> ce-auth built on the relay and live: mesh service \"ce-auth\" + console on :8972"
echo "    read its capRoot from the journal: journalctl -u ce-auth | grep \"cap bridge ready\""
