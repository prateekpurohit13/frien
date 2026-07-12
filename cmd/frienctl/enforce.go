package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"

	"github.com/prateekpurohit13/frien/internal/identity"
	"github.com/prateekpurohit13/frien/internal/policy"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// dialAdmin resolves the admin socket and returns a connected AdminService
// client plus a cleanup func. It centralizes the boilerplate the Phase 5
// commands share.
func dialAdmin(socket, cfgPath string) (frienv1.AdminServiceClient, func(), error) {
	socketPath, err := resolveSocket(socket, cfgPath)
	if err != nil {
		return nil, nil, err
	}
	conn, err := grpc.NewClient("unix:"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to admin socket %s: %w", socketPath, err)
	}
	return frienv1.NewAdminServiceClient(conn), func() { _ = conn.Close() }, nil
}

// cmdExplain prints the full decision trail for an indicator.
func cmdExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	indicator := fs.String("indicator", "", "indicator to explain (required)")
	socket := fs.String("socket", "", "admin API Unix socket")
	cfgPath := fs.String("config", "", "daemon config file to read the socket path from")
	timeout := fs.Duration("timeout", 5*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *indicator == "" {
		return fmt.Errorf("--indicator is required")
	}
	client, done, err := dialAdmin(*socket, *cfgPath)
	if err != nil {
		return err
	}
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	resp, err := client.ExplainDecision(ctx, &frienv1.ExplainDecisionRequest{Indicator: *indicator})
	if err != nil {
		return fmt.Errorf("ExplainDecision: %w", err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(w, "indicator\t%s\n", resp.GetIndicator())
	fmt.Fprintf(w, "decision\t%s\n", resp.GetDecision())
	fmt.Fprintf(w, "reason\t%s\n", resp.GetReason())
	fmt.Fprintf(w, "matched_weight\t%.2f\n", resp.GetMatchedWeight())
	fmt.Fprintf(w, "required_weight\t%.2f\n", resp.GetRequiredWeight())
	fmt.Fprintf(w, "policy\t%s v%d\n", resp.GetPolicyId(), resp.GetPolicyVersion())
	fmt.Fprintf(w, "adapter\t%s\n", resp.GetAdapter())
	fmt.Fprintf(w, "expires_at\t%s\n", resp.GetExpiresAt())
	fmt.Fprintf(w, "rollback_token\t%s\n", resp.GetRollbackToken())
	fmt.Fprintf(w, "audit_entry\t%s\n", resp.GetAuditEntryId())
	fmt.Fprintf(w, "contributing_identities\t%v\n", resp.GetContributingIdentities())
	return w.Flush()
}

// cmdMode handles `mode set`.
func cmdMode(args []string) error {
	if len(args) == 0 || args[0] != "set" {
		return fmt.Errorf("usage: frienctl mode set --adapter A --mode observe|enforce --reason R")
	}
	fs := flag.NewFlagSet("mode set", flag.ContinueOnError)
	adapter := fs.String("adapter", "nftables", "enforcement adapter")
	mode := fs.String("mode", "", "observe|enforce (required)")
	reason := fs.String("reason", "", "audit reason (required)")
	socket := fs.String("socket", "", "admin API Unix socket")
	cfgPath := fs.String("config", "", "daemon config file to read the socket path from")
	timeout := fs.Duration("timeout", 5*time.Second, "request timeout")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *mode == "" || *reason == "" {
		return fmt.Errorf("--mode and --reason are required")
	}
	client, done, err := dialAdmin(*socket, *cfgPath)
	if err != nil {
		return err
	}
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	resp, err := client.SetEnforceMode(ctx, &frienv1.SetEnforceModeRequest{Mode: *mode, Adapter: *adapter, Reason: *reason})
	if err != nil {
		return fmt.Errorf("SetEnforceMode: %w", err)
	}
	fmt.Printf("adapter %s: %s -> %s (audit %s)\n", *adapter, resp.GetPreviousMode(), resp.GetCurrentMode(), resp.GetAuditId())
	return nil
}

// cmdRollback removes an applied rule by rollback token.
func cmdRollback(args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	token := fs.String("token", "", "rollback token (required)")
	reason := fs.String("reason", "", "audit reason (required)")
	socket := fs.String("socket", "", "admin API Unix socket")
	cfgPath := fs.String("config", "", "daemon config file to read the socket path from")
	timeout := fs.Duration("timeout", 5*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" || *reason == "" {
		return fmt.Errorf("--token and --reason are required")
	}
	client, done, err := dialAdmin(*socket, *cfgPath)
	if err != nil {
		return err
	}
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	resp, err := client.RollbackEnforcement(ctx, &frienv1.RollbackEnforcementRequest{RollbackToken: *token, Reason: *reason})
	if err != nil {
		return fmt.Errorf("RollbackEnforcement: %w", err)
	}
	fmt.Printf("rollback %s: %s (audit %s)\n", *token, resp.GetStatus(), resp.GetAuditId())
	return nil
}

// cmdEnforcements handles `enforcements list`.
func cmdEnforcements(args []string) error {
	if len(args) == 0 || args[0] != "list" {
		return fmt.Errorf("usage: frienctl enforcements list [--adapter A] [--include-expired]")
	}
	fs := flag.NewFlagSet("enforcements list", flag.ContinueOnError)
	adapter := fs.String("adapter", "", "filter by adapter")
	includeExpired := fs.Bool("include-expired", false, "include expired rules")
	socket := fs.String("socket", "", "admin API Unix socket")
	cfgPath := fs.String("config", "", "daemon config file to read the socket path from")
	timeout := fs.Duration("timeout", 5*time.Second, "request timeout")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	client, done, err := dialAdmin(*socket, *cfgPath)
	if err != nil {
		return err
	}
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	resp, err := client.ListEnforcements(ctx, &frienv1.ListEnforcementsRequest{AdapterFilter: *adapter, IncludeExpired: *includeExpired})
	if err != nil {
		return fmt.Errorf("ListEnforcements: %w", err)
	}
	if len(resp.GetEnforcements()) == 0 {
		fmt.Println("no active enforcements")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "TARGET\tACTION\tADAPTER\tEXPIRES\tTOKEN")
	for _, e := range resp.GetEnforcements() {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", e.GetTarget(), e.GetAction(), e.GetAdapter(), e.GetExpiresAt(), e.GetRollbackToken())
	}
	return w.Flush()
}

// cmdBreakglass flushes all enforcement and forces observe mode.
func cmdBreakglass(args []string) error {
	fs := flag.NewFlagSet("breakglass", flag.ContinueOnError)
	flush := fs.Bool("flush-enforcement", false, "required: remove all frien-managed rules")
	forceObserve := fs.Bool("force-observe", false, "required: set all adapters to observe")
	reason := fs.String("reason", "", "audit reason (required)")
	confirm := fs.String("confirm", "", "confirmation code (required; prevents accidental invocation)")
	socket := fs.String("socket", "", "admin API Unix socket")
	cfgPath := fs.String("config", "", "daemon config file to read the socket path from")
	timeout := fs.Duration("timeout", 5*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*flush || !*forceObserve {
		return fmt.Errorf("both --flush-enforcement and --force-observe are required")
	}
	if *reason == "" || *confirm == "" {
		return fmt.Errorf("--reason and --confirm are required")
	}
	client, done, err := dialAdmin(*socket, *cfgPath)
	if err != nil {
		return err
	}
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	resp, err := client.Breakglass(ctx, &frienv1.BreakglassRequest{
		FlushEnforcement: *flush, ForceObserve: *forceObserve, Reason: *reason, ConfirmationCode: *confirm,
	})
	if err != nil {
		return fmt.Errorf("Breakglass: %w", err)
	}
	fmt.Printf("breakglass: removed %d rules, mode now %s (audit %s)\n", resp.GetRulesRemoved(), resp.GetNewMode(), resp.GetAuditId())
	return nil
}

// cmdPolicy dispatches `policy sign` (offline) and `policy test` (dry-run).
func cmdPolicy(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: frienctl policy sign|test ...")
	}
	switch args[0] {
	case "sign":
		return cmdPolicySign(args[1:])
	case "test":
		return cmdPolicyTest(args[1:])
	default:
		return fmt.Errorf("unknown policy subcommand %q (want sign or test)", args[0])
	}
}

// cmdPolicySign signs a policy YAML offline with the operator key. Like `revoke
// sign`, it never touches a socket and the private key never reaches a node.
func cmdPolicySign(args []string) error {
	fs := flag.NewFlagSet("policy sign", flag.ContinueOnError)
	file := fs.String("file", "", "policy YAML to sign (required)")
	keyPath := fs.String("key", "", "operator ed25519 private key PEM (required)")
	keyID := fs.String("key-id", "operator", "operator key id recorded in the policy")
	out := fs.String("out", "", "output file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" || *keyPath == "" {
		return fmt.Errorf("--file and --key are required")
	}
	p, err := policy.Load(*file)
	if err != nil {
		return err
	}
	signer, err := identity.NewEd25519SignerFromFile(*keyPath)
	if err != nil {
		return fmt.Errorf("loading operator key: %w", err)
	}
	if err := p.SignDetached(signer.Sign, *keyID); err != nil {
		return fmt.Errorf("signing policy: %w", err)
	}
	doc, err := yaml.Marshal(map[string]*policy.Policy{"policy": p})
	if err != nil {
		return err
	}
	if *out == "" {
		fmt.Print(string(doc))
		return nil
	}
	if err := os.WriteFile(*out, doc, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", *out, err)
	}
	fmt.Printf("wrote signed policy %s v%d to %s\n", p.ID, p.Version, *out)
	return nil
}

// cmdPolicyTest dry-runs a sample threat record against the node's active policy.
func cmdPolicyTest(args []string) error {
	fs := flag.NewFlagSet("policy test", flag.ContinueOnError)
	record := fs.String("record", "", "JSON ThreatRecord file to test (required)")
	policyID := fs.String("policy-id", "", "policy id (default: active policy)")
	socket := fs.String("socket", "", "admin API Unix socket")
	cfgPath := fs.String("config", "", "daemon config file to read the socket path from")
	timeout := fs.Duration("timeout", 5*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *record == "" {
		return fmt.Errorf("--record is required")
	}
	data, err := os.ReadFile(*record)
	if err != nil {
		return fmt.Errorf("reading %s: %w", *record, err)
	}
	client, done, err := dialAdmin(*socket, *cfgPath)
	if err != nil {
		return err
	}
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	resp, err := client.TestPolicy(ctx, &frienv1.TestPolicyRequest{PolicyId: *policyID, ThreatJson: string(data)})
	if err != nil {
		return fmt.Errorf("TestPolicy: %w", err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(w, "decision\t%s\n", resp.GetDecision())
	fmt.Fprintf(w, "reason\t%s\n", resp.GetReason())
	fmt.Fprintf(w, "matched_policy\t%s\n", resp.GetMatchedPolicy())
	fmt.Fprintf(w, "required_weight\t%.2f\n", resp.GetRequiredWeight())
	if len(resp.GetProtectedReasons()) > 0 {
		fmt.Fprintf(w, "protected\t%v\n", resp.GetProtectedReasons())
	}
	return w.Flush()
}
