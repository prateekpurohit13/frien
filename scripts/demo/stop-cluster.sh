#!/usr/bin/env bash
# stop-cluster.sh — stop the demo cluster started by run-cluster.sh.
set -euo pipefail
cd "$(dirname "$0")/../.."
RUN=demo/run
if [[ -f "$RUN/.pids" ]]; then
  while read -r pid; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null && echo "stopped pid $pid" || true
  done < "$RUN/.pids"
  rm -f "$RUN/.pids"
else
  echo "no recorded pids; try: pkill -f '$RUN/bin/friend'"
fi
echo "run state left under $RUN (delete it to reset)"
