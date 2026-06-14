package main

import (
	"fmt"
	"os"

	"github.com/prateekpurohit13/frien/internal/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("frien-enforcer %s (proto v%d)\n", version.SoftwareVersion, version.ProtoVersion)
		os.Exit(0)
	}
	// implement enforcer process with:
	// - nftables adapter with kernel-native timeout
	// - dead-man's switch (heartbeat monitor)
	// - durable rollback token reconciliation
	// - breakglass flush
	fmt.Fprintln(os.Stderr, "frien-enforcer: not yet implemented — coming in Phase 5")
	os.Exit(1)
}
