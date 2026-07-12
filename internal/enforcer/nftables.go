//go:build linux

package enforcer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// NFTablesAdapter enforces via nftables, using kernel-native per-element
// timeouts so a rule self-removes even if every frien process dies. It keeps
// all state in ONE table (default "frien") isolated from the host baseline:
// two named sets (IPv4/IPv6) with `flags interval, timeout` hold the blocked
// targets, and a single input chain drops traffic whose source is in either
// set. Flushing frien's chains/sets therefore never touches host firewall
// rules — the core promise of docs/ENFORCEMENT_SAFETY.md §2.
//
// The rollback token is stored as each element's nft comment, so List/Remove
// and cross-restart reconciliation can recover the token↔target mapping from
// the kernel itself rather than depending on frien's own store surviving.
//
// This file only builds on linux and is exercised by Linux integration tests
// (a real `nft` binary + CAP_NET_ADMIN); the platform-independent enforcement
// logic is unit-tested against MemAdapter.
type NFTablesAdapter struct {
	table string
	set4  string
	set6  string
	chain string
	log   zerolog.Logger

	runMu sync.Mutex // serialize nft invocations (nft is not concurrency-safe per table)
}

// NFTablesOptions configures the adapter. Zero values fall back to safe defaults.
type NFTablesOptions struct {
	Table      string // default "frien"
	ChainInput string // default "input"
}

// NewNFTablesAdapter constructs the adapter and ensures frien's table, sets, and
// drop chain exist. Chain rules are (re)written idempotently on every start;
// existing set elements — and thus their live kernel timeouts — are preserved
// across a restart so reconciliation can adopt them.
func NewNFTablesAdapter(opts NFTablesOptions, log zerolog.Logger) (*NFTablesAdapter, error) {
	if _, err := exec.LookPath("nft"); err != nil {
		return nil, fmt.Errorf("enforcer: nft binary not found: %w", err)
	}
	a := &NFTablesAdapter{
		table: orDefault(opts.Table, "frien"),
		set4:  "frien_block4",
		set6:  "frien_block6",
		chain: orDefault(opts.ChainInput, "input"),
		log:   log,
	}
	if err := a.ensure(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *NFTablesAdapter) Name() string { return "nftables" }

// ensure creates the table/sets/chain and rewrites the two match rules. Sets are
// created with `add` (idempotent) so their elements survive; the chain is
// flushed and its two rules re-added so exactly one drop rule per family exists.
func (a *NFTablesAdapter) ensure() error {
	batch := strings.Join([]string{
		fmt.Sprintf("add table inet %s", a.table),
		fmt.Sprintf("add set inet %s %s { type ipv4_addr; flags interval, timeout; }", a.table, a.set4),
		fmt.Sprintf("add set inet %s %s { type ipv6_addr; flags interval, timeout; }", a.table, a.set6),
		fmt.Sprintf("add chain inet %s %s { type filter hook input priority -10; policy accept; }", a.table, a.chain),
		fmt.Sprintf("flush chain inet %s %s", a.table, a.chain),
		fmt.Sprintf("add rule inet %s %s ip saddr @%s drop", a.table, a.chain, a.set4),
		fmt.Sprintf("add rule inet %s %s ip6 saddr @%s drop", a.table, a.chain, a.set6),
	}, "\n")
	if err := a.runStdin(batch); err != nil {
		return fmt.Errorf("enforcer: initializing nftables: %w", err)
	}
	return nil
}

func (a *NFTablesAdapter) Apply(r Rule) error {
	set, family, err := a.setFor(r.Target)
	if err != nil {
		return err
	}
	if r.Timeout <= 0 {
		return fmt.Errorf("enforcer: nftables refuses a rule with no timeout for %s", r.Target)
	}
	// Delete any existing element for this target first so re-applying refreshes
	// the timeout instead of erroring on a duplicate.
	_ = a.run("delete", "element", "inet", a.table, set, "{", r.Target, "}")
	elem := fmt.Sprintf("{ %s timeout %s comment \"%s\" }", r.Target, nftDuration(r.Timeout), r.Token)
	if err := a.run("add", "element", "inet", a.table, set, elem); err != nil {
		return fmt.Errorf("enforcer: adding %s element for %s: %w", family, r.Target, err)
	}
	return nil
}

func (a *NFTablesAdapter) Remove(token string) error {
	// Find the element carrying this token comment, in either set.
	active, err := a.List()
	if err != nil {
		return err
	}
	for _, r := range active {
		if r.Token != token {
			continue
		}
		set, _, err := a.setFor(r.Target)
		if err != nil {
			return err
		}
		_ = a.run("delete", "element", "inet", a.table, set, "{", r.Target, "}")
		return nil
	}
	return nil // absent is success (fail-open)
}

func (a *NFTablesAdapter) List() ([]ActiveRule, error) {
	var out []ActiveRule
	for _, set := range []string{a.set4, a.set6} {
		rules, err := a.listSet(set)
		if err != nil {
			return nil, err
		}
		out = append(out, rules...)
	}
	return out, nil
}

func (a *NFTablesAdapter) FlushAll() (int, error) {
	active, _ := a.List()
	n := len(active)
	// Flushing the sets drops every frien-managed element at once and touches
	// nothing outside frien's own table.
	_ = a.run("flush", "set", "inet", a.table, a.set4)
	_ = a.run("flush", "set", "inet", a.table, a.set6)
	return n, nil
}

// ── nft plumbing ────────────────────────────────────────────────────────────

// nftSetList models the subset of `nft -j list set` output we read.
type nftSetList struct {
	Nftables []struct {
		Set *struct {
			Elem []json.RawMessage `json:"elem"`
		} `json:"set"`
	} `json:"nftables"`
}

type nftElem struct {
	Elem struct {
		Val     interface{} `json:"val"`
		Expires int64       `json:"expires"`
		Comment string      `json:"comment"`
	} `json:"elem"`
}

func (a *NFTablesAdapter) listSet(set string) ([]ActiveRule, error) {
	out, err := a.output("-j", "list", "set", "inet", a.table, set)
	if err != nil {
		// A missing set (e.g. before first apply) is not an error for listing.
		if strings.Contains(err.Error(), "No such file or directory") {
			return nil, nil
		}
		return nil, err
	}
	var parsed nftSetList
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, fmt.Errorf("enforcer: parsing nft json: %w", err)
	}
	var rules []ActiveRule
	now := time.Now()
	for _, item := range parsed.Nftables {
		if item.Set == nil {
			continue
		}
		for _, raw := range item.Set.Elem {
			var e nftElem
			if err := json.Unmarshal(raw, &e); err != nil {
				continue // plain-string element without timeout/comment: skip
			}
			target := nftVal(e.Elem.Val)
			if target == "" {
				continue
			}
			ar := ActiveRule{Token: e.Elem.Comment, Target: target, Action: "block"}
			if e.Elem.Expires > 0 {
				ar.ExpiresAt = now.Add(time.Duration(e.Elem.Expires) * time.Second)
			}
			if ar.Token == "" {
				ar.Token = target // fall back so an un-commented element is still addressable
			}
			rules = append(rules, ar)
		}
	}
	return rules, nil
}

// nftVal renders a set element value, which nft emits either as a bare string
// ("1.2.3.4") or as a prefix object ({"prefix":{"addr":"10.0.0.0","len":8}}).
func nftVal(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]interface{}:
		if p, ok := t["prefix"].(map[string]interface{}); ok {
			addr, _ := p["addr"].(string)
			if l, ok := p["len"].(float64); ok && addr != "" {
				return fmt.Sprintf("%s/%d", addr, int(l))
			}
		}
	}
	return ""
}

func (a *NFTablesAdapter) setFor(target string) (set, family string, err error) {
	ip := net.ParseIP(strings.SplitN(target, "/", 2)[0])
	if ip == nil {
		return "", "", fmt.Errorf("enforcer: target %q is not an IP/CIDR", target)
	}
	if ip.To4() != nil {
		return a.set4, "ipv4", nil
	}
	return a.set6, "ipv6", nil
}

func (a *NFTablesAdapter) run(args ...string) error {
	a.runMu.Lock()
	defer a.runMu.Unlock()
	cmd := exec.Command("nft", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (a *NFTablesAdapter) output(args ...string) ([]byte, error) {
	a.runMu.Lock()
	defer a.runMu.Unlock()
	cmd := exec.Command("nft", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (a *NFTablesAdapter) runStdin(batch string) error {
	a.runMu.Lock()
	defer a.runMu.Unlock()
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(batch)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft -f -: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// nftDuration renders a Go duration as nft's timeout syntax (e.g. "1h30m",
// "45s"). nft accepts the same unit letters Go uses for these ranges.
func nftDuration(d time.Duration) string {
	if d < time.Second {
		d = time.Second
	}
	return d.Truncate(time.Second).String()
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
