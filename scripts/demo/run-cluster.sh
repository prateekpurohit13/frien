#!/usr/bin/env bash
# run-cluster.sh — bring up a local 3-node frien demo mesh.
#
# It generates a demo PKI (CA + per-node leaf certs whose OU carries the trust
# tier + an operator keypair), writes a config per node, signs the demo policy
# offline with the operator key, builds the binaries, and starts three friend
# daemons that gossip over local QUIC. Then run ./attack.sh to feed it a threat
# and `frienctl dashboard` to watch quorum → observe → enforce.
#
# Linux/macOS. Enforcement stays in OBSERVE by default (safe); promote with
# `frienctl mode set` once you've watched the decisions in the dashboard.
set -euo pipefail
cd "$(dirname "$0")/../.."           # repo root
RUN=demo/run
CERTS=demo/certs
NODES=("core-1:trusted:core" "edge-2:standard:edge" "edge-3:standard:edge")
BASE_PORT=7443
BASE_HEALTH=9110
BASE_METRICS=9109

echo "==> building binaries"
go build -o "$RUN/bin/friend" ./cmd/friend
go build -o "$RUN/bin/frienctl" ./cmd/frienctl
FRIENCTL="$RUN/bin/frienctl"

echo "==> generating demo PKI"
node_spec=$(IFS=,; printf '%s' "${NODES[*]/%/}" | sed -E 's/:[a-z]+,/,/g; s/:[a-z]+$//')
# node_spec becomes e.g. "core-1:trusted,edge-2:standard,edge-3:standard"
node_spec=$(printf '%s\n' "${NODES[@]}" | awk -F: '{printf (NR>1?",":"")$1":"$2}')
go run scripts/gen-certs.go -out "$CERTS" -nodes "$node_spec"

echo "==> signing demo policy with the operator key (offline)"
mkdir -p "$RUN"
"$FRIENCTL" policy sign --file scripts/demo/policy.yaml \
  --key "$CERTS/operator.key" --key-id demo-operator --out "$RUN/policy.signed.yaml"

# Build a seed list of every node's peer address so the mesh forms a full graph.
seeds=""
for i in "${!NODES[@]}"; do
  seeds+="  - address: 127.0.0.1:$((BASE_PORT+i))\n"
done

echo "==> writing per-node configs + starting daemons"
pids=()
mkdir -p "$RUN/logs"
for i in "${!NODES[@]}"; do
  IFS=: read -r id tier role <<<"${NODES[$i]}"
  d="$RUN/$id"; mkdir -p "$d/wal" "$d/snap" "$d/authlog"
  touch "$d/authlog/auth.log"
  cat > "$d/config.yaml" <<YAML
node: { id: $id, zone: zone-a, role: $role, trust_tier: $tier }
identity:
  cert_path: $CERTS/$id/node.crt
  key_path: $CERTS/$id/node.key
  ca_cert_path: $CERTS/ca.crt
  operator_root_cert: $CERTS/operator.crt
transport:
  peer_port: $((BASE_PORT+i))
  peer_bind: 127.0.0.1
  max_message_bytes: 1048576
  clock_skew_window: 2s
seeds:
$(printf "$seeds")
admin_api: { socket: $d/admin.sock }
storage: { wal_dir: $d/wal, db_path: $d/frien.db, snapshot_dir: $d/snap }
policy: { policy_file: $RUN/policy.signed.yaml, enforce_mode: observe }
enforcement:
  nftables: { enabled: false }   # observe/dry-run backend for the demo; set true on a real Linux host w/ CAP_NET_ADMIN
detectors:
  ssh_bruteforce: { enabled: true, auth_log: $d/authlog/auth.log, threshold: 5, window: 60s, confidence: 0.95 }
observability: { health_bind: 127.0.0.1:$((BASE_HEALTH+i)), metrics_bind: 127.0.0.1:$((BASE_METRICS+i)) }
YAML
  "$RUN/bin/friend" --config "$d/config.yaml" >"$RUN/logs/$id.log" 2>&1 &
  pids+=($!)
  echo "    started $id (tier=$tier) pid=${pids[$i]}  admin=$d/admin.sock"
done

echo "$RUN" > "$RUN/.rundir"
printf '%s\n' "${pids[@]}" > "$RUN/.pids"
cat <<EOF

==> cluster up. next:
  watch it:   $FRIENCTL dashboard --socket $RUN/core-1/admin.sock
  attack it:  scripts/demo/attack.sh
  promote:    $FRIENCTL mode set --adapter nftables --mode enforce --reason demo \\
                --socket $RUN/core-1/admin.sock
  tear down:  scripts/demo/stop-cluster.sh
EOF
