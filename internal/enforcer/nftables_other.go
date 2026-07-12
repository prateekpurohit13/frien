//go:build !linux

package enforcer

import (
	"fmt"

	"github.com/rs/zerolog"
)

// NFTablesOptions is defined on all platforms so daemon wiring compiles
// everywhere; only the linux build provides a working adapter.
type NFTablesOptions struct {
	Table      string
	ChainInput string
}

// NewNFTablesAdapter is unavailable off Linux. The daemon falls back to a
// MemAdapter (observe/dry-run) on other platforms; a real nftables backend
// requires a Linux host with the nft binary and CAP_NET_ADMIN.
func NewNFTablesAdapter(_ NFTablesOptions, _ zerolog.Logger) (Adapter, error) {
	return nil, fmt.Errorf("enforcer: nftables adapter requires Linux")
}
