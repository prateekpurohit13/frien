package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// cmdReport injects a threat observation through the daemon's admission +
// publish path. It is the manual counterpart to the automated detectors —
// useful for driving the demo, the dashboard, and the quorum/enforce pipeline
// without a real log source.
func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	indicator := fs.String("indicator", "", "indicator value, e.g. an IP (required)")
	indType := fs.String("type", "ip", "indicator type: ip|cidr|hostname|user|hash")
	reason := fs.String("reason", "manual operator report", "human-readable reason")
	severity := fs.String("severity", "high", "low|medium|high|critical")
	confidence := fs.Float64("confidence", 0.9, "0.0-1.0")
	ttl := fs.String("ttl", "1h", "record TTL, e.g. 1h")
	scopeFlag := fs.String("scope", "fleet", "local|zone:<name>|fleet")
	evidence := fs.String("evidence", "", "optional JSON evidence blob")
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

	resp, err := client.ReportThreat(ctx, &frienv1.ReportThreatRequest{
		Indicator:     *indicator,
		IndicatorType: *indType,
		Reason:        *reason,
		Severity:      *severity,
		Confidence:    *confidence,
		Ttl:           *ttl,
		Scope:         *scopeFlag,
		EvidenceJson:  *evidence,
	})
	if err != nil {
		return fmt.Errorf("ReportThreat: %w", err)
	}
	fmt.Printf("%s: op=%s threat=%s\n", resp.GetStatus(), resp.GetOpId(), resp.GetThreatId())
	return nil
}
