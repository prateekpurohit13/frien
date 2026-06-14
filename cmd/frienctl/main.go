package main

import (
	"fmt"
	"os"

	"github.com/prateekpurohit13/frien/internal/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("frienctl %s (proto v%d)\n", version.SoftwareVersion, version.ProtoVersion)
		os.Exit(0)
	}
	// TODO(phase1): implement frienctl subcommands (status, peers, report, explain, mode, rollback, breakglass, harden, policy)
	fmt.Fprintln(os.Stderr, "frienctl: not yet implemented — coming in Phase 1")
	os.Exit(1)
}
