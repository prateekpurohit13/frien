package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// cmdRotateCA stages a new CA bundle on a running node for the overlap
// window (see internal/identity.TrustBundle) rather than an atomic cutover.
// Run this on every node before rolling out any new-CA-issued leaf
// certificate; the old CA stays trusted until the configured
// identity.ca_overlap_window elapses.
func cmdRotateCA(args []string) error {
	fs := flag.NewFlagSet("rotate-ca", flag.ContinueOnError)
	caFile := fs.String("ca-file", "", "PEM-encoded new CA bundle to stage (required)")
	socket := fs.String("socket", "", "admin API Unix socket")
	cfgPath := fs.String("config", "", "daemon config file to read the socket path from")
	timeout := fs.Duration("timeout", 5*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caFile == "" {
		return fmt.Errorf("--ca-file is required")
	}
	pemBytes, err := os.ReadFile(*caFile)
	if err != nil {
		return fmt.Errorf("reading %s: %w", *caFile, err)
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

	resp, err := frienv1.NewAdminServiceClient(conn).RotateCA(ctx, &frienv1.RotateCARequest{NextCaPem: pemBytes})
	if err != nil {
		return fmt.Errorf("RotateCA: %w", err)
	}
	if resp.GetInOverlap() {
		fmt.Println("staged: new CA now trusted alongside the current one for the configured overlap window")
	}
	return nil
}
