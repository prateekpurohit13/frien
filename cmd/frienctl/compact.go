package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// cmdCompact triggers a compaction pass on demand instead of waiting for the
// configured interval -- useful before a maintenance window, or to inspect
// the checkpoint a cut produces right away.
func cmdCompact(args []string) error {
	fs := flag.NewFlagSet("compact", flag.ContinueOnError)
	scope := fs.String("scope", "", `scope to compact ("fleet" | "zone:<name>"); empty = every subscribed scope`)
	socket := fs.String("socket", "", "admin API Unix socket")
	cfgPath := fs.String("config", "", "daemon config file to read the socket path from")
	timeout := fs.Duration("timeout", 30*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	socketPath, err := resolveSocket(*socket, *cfgPath)
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient("unix:"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("connecting to admin socket %s: %w", socketPath, err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	resp, err := frienv1.NewAdminServiceClient(conn).TriggerCompaction(ctx, &frienv1.TriggerCompactionRequest{Scope: *scope})
	if err != nil {
		return fmt.Errorf("TriggerCompaction: %w", err)
	}
	if len(resp.GetCompactedScopes()) == 0 {
		fmt.Println("nothing compacted (no safe floor yet, or nothing to compact)")
		return nil
	}
	fmt.Println("compacted:")
	for _, sc := range resp.GetCompactedScopes() {
		fmt.Printf("  %s\n", sc)
	}
	return nil
}
