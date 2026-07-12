#!/usr/bin/env bash
# attack.sh — simulate an SSH brute-force against the demo cluster.
#
# It appends failed-auth lines to every node's watched auth log, so each node's
# ssh_bruteforce detector independently observes the same attacker and reports a
# threat. Three distinct signed identities reporting the same indicator is what
# forms a partition-safe, distinct-identity quorum — watch it converge and cross
# the enforcement threshold in `frienctl dashboard`.
#
# Usage: scripts/demo/attack.sh [ATTACKER_IP] [COUNT]
set -euo pipefail
cd "$(dirname "$0")/../.."
RUN=demo/run
IP="${1:-203.0.113.66}"
COUNT="${2:-8}"

if [[ ! -d "$RUN" ]]; then echo "cluster not running — start it with run-cluster.sh"; exit 1; fi

echo "==> simulating $COUNT failed SSH logins from $IP against every node"
for d in "$RUN"/core-1 "$RUN"/edge-2 "$RUN"/edge-3; do
  log="$d/authlog/auth.log"
  [[ -e "$log" ]] || continue
  for n in $(seq 1 "$COUNT"); do
    printf '%s host sshd[%d]: Failed password for invalid user root from %s port %d ssh2\n' \
      "$(date '+%b %d %H:%M:%S')" "$RANDOM" "$IP" "$((40000+n))" >> "$log"
  done
  echo "    fed $COUNT lines to $(basename "$d")"
done

cat <<EOF

==> done. within a few seconds each detector should report $IP.
    inspect the decision on any node:
      $RUN/bin/frienctl explain --indicator $IP --socket $RUN/core-1/admin.sock
    while in observe mode it shows 'observe_only' with the matched quorum weight;
    after 'frienctl mode set ... --mode enforce' the same indicator becomes 'enforced'
    with a self-expiring rule (kernel timeout).
EOF
