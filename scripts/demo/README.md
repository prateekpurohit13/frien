# frien local demo cluster

A self-contained 3-node mesh you can run on one Linux/macOS host to watch the
whole pipeline: **detect → admit → gossip → converge → quorum → observe → enforce**,
live in the terminal dashboard.

## Nodes

| node   | tier      | quorum weight |
|--------|-----------|---------------|
| core-1 | trusted   | 3.0           |
| edge-2 | standard  | 1.0           |
| edge-3 | standard  | 1.0           |

The demo policy requires weight **3.0**, so either the one `trusted` node alone
or the two edges plus core together can cross the enforcement threshold — a
compact illustration of distinct-identity, trust-tier-weighted quorum. Trust
tiers are bound to each node's **certificate** (the OU field), not self-declared,
so a node cannot inflate its own weight.

## Run it

```bash
scripts/demo/run-cluster.sh                    # gen PKI, write configs, start 3 daemons
scripts/demo/attack.sh 203.0.113.66 8          # simulate an SSH brute-force from an IP
frienctl dashboard --socket demo/run/core-1/admin.sock   # watch it (in a 2nd terminal)
```

While in **observe** mode (the safe default), the dashboard shows the threat
converging and the decision as `observe_only` with the matched quorum weight — no
rule is applied. Promote a node to **enforce** and watch the same indicator flip
to `enforced` with a self-expiring rule:

```bash
frienctl mode set --adapter nftables --mode enforce --reason demo \
  --socket demo/run/core-1/admin.sock
frienctl explain --indicator 203.0.113.66 --socket demo/run/core-1/admin.sock
```

Tear down with `scripts/demo/stop-cluster.sh`.

## The dashboard

`frienctl dashboard` (alias `tui`) is a read-only terminal UI over the local
admin socket — the same trust boundary as every other `frienctl` command, no new
network surface. Tabs (keys `1`–`4`): **Overview** (KPI tiles, bar charts,
sparklines, quorum gauges), **Threats**, **Enforcement**, **Audit**.

## Notes

- **Enforcement backend:** the demo runs the in-memory (observe/dry-run) enforcer
  so it works anywhere. On a real Linux host with `CAP_NET_ADMIN`, set
  `enforcement.nftables.enabled: true` in the generated configs to install real,
  self-expiring nftables rules.
- **Manual threats:** `frienctl report --indicator <ip> --severity high` injects a
  threat directly (bypassing the log detectors) — handy for driving the dashboard.
- These orchestration scripts are validated by inspection (they wire together
  components that are themselves unit/integration-tested); the PKI generator
  (`scripts/gen-certs.go`) is verified to produce certs the identity layer loads.
