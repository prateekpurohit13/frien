// Command frienctl is the operator CLI. It talks to a local friend daemon over the
// admin gRPC Unix socket. In Phase 1 it implements `version` and `status`; the
// remaining operator commands (peers, report, explain, mode, rollback, breakglass,
// harden, policy) are added as their server-side RPCs land.
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

	"github.com/prateekpurohit13/frien/internal/config"
	"github.com/prateekpurohit13/frien/internal/version"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

const defaultSocket = "/run/frien/admin.sock"

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "frienctl: %v\n", err)
		os.Exit(1)
	}
}

func dispatch(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("no command given")
	}
	switch args[0] {
	case "version":
		fmt.Printf("frienctl %s (proto v%d)\n", version.SoftwareVersion, version.ProtoVersion)
		return nil
	case "status":
		return cmdStatus(args[1:])
	case "revoke":
		return cmdRevoke(args[1:])
	case "compact":
		return cmdCompact(args[1:])
	case "rotate-ca":
		return cmdRotateCA(args[1:])
	case "dashboard", "tui":
		return cmdDashboard(args[1:])
	case "report":
		return cmdReport(args[1:])
	case "explain":
		return cmdExplain(args[1:])
	case "mode":
		return cmdMode(args[1:])
	case "rollback":
		return cmdRollback(args[1:])
	case "enforcements":
		return cmdEnforcements(args[1:])
	case "breakglass":
		return cmdBreakglass(args[1:])
	case "policy":
		return cmdPolicy(args[1:])
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `frienctl — frien operator CLI

Usage:
  frienctl status [--socket PATH | --config PATH]
  frienctl revoke sign --node-id ID --fingerprint FP --key PATH [--reason TEXT] [--status tainted|revoked] [--out FILE]
  frienctl revoke submit [--file FILE] [--socket PATH | --config PATH]
  frienctl compact [--scope SCOPE] [--socket PATH | --config PATH]
  frienctl rotate-ca --ca-file BUNDLE.pem [--socket PATH | --config PATH]
  frienctl dashboard [--demo] [--interval 1s] [--socket PATH | --config PATH]
  frienctl report --indicator IP [--type ip] [--severity high] [--confidence 0.9] [--ttl 1h] [--scope fleet]
  frienctl explain --indicator VALUE [--socket PATH | --config PATH]
  frienctl mode set --adapter A --mode observe|enforce --reason TEXT [--socket PATH | --config PATH]
  frienctl rollback --token TOKEN --reason TEXT [--socket PATH | --config PATH]
  frienctl enforcements list [--adapter A] [--include-expired] [--socket PATH | --config PATH]
  frienctl breakglass --flush-enforcement --force-observe --reason TEXT --confirm CODE [--socket PATH | --config PATH]
  frienctl policy sign --file policy.yaml --key operator.pem [--key-id ID] [--out FILE]
  frienctl policy test --record threat.json [--policy-id ID] [--socket PATH | --config PATH]
  frienctl version

"revoke sign" runs entirely offline against the operator's own private key
(never send that key to a node); it writes a base64-encoded signed envelope.
"revoke submit" reads that envelope and forwards it to a running node, which
only ever verifies it against the pinned operator public key.

Flags:
  --socket PATH   admin API Unix socket (default `+defaultSocket+`)
  --config PATH   read the socket path from a daemon config file
`)
}

// cmdStatus dials the admin socket and prints the node's status.
func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	socket := fs.String("socket", "", "admin API Unix socket path")
	cfgPath := fs.String("config", "", "daemon config file to read the socket path from")
	timeout := fs.Duration("timeout", 5*time.Second, "request timeout")
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

	resp, err := frienv1.NewAdminServiceClient(conn).GetStatus(ctx, &frienv1.GetStatusRequest{})
	if err != nil {
		return fmt.Errorf("GetStatus: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(w, "node_id\t%s\n", resp.NodeId)
	fmt.Fprintf(w, "status\t%s\n", resp.Status)
	fmt.Fprintf(w, "enforce_mode\t%s\n", resp.EnforceMode)
	fmt.Fprintf(w, "peers\t%d\n", resp.PeerCount)
	fmt.Fprintf(w, "proto_version\t%s\n", resp.ProtoVersion)
	fmt.Fprintf(w, "cert_expires\t%s\n", resp.CertExpires)
	fmt.Fprintf(w, "wal_size_bytes\t%d\n", resp.WalSizeBytes)
	fmt.Fprintf(w, "uptime\t%s\n", resp.Uptime)
	return w.Flush()
}

// resolveSocket determines which admin socket to dial, in precedence order:
// explicit --socket, then the socket path from --config, then the default.
func resolveSocket(socket, cfgPath string) (string, error) {
	if socket != "" {
		return socket, nil
	}
	if cfgPath != "" {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return "", fmt.Errorf("loading config %s: %w", cfgPath, err)
		}
		return cfg.AdminAPI.Socket, nil
	}
	return defaultSocket, nil
}
