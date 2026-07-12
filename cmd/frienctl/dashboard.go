package main

import (
	"flag"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/prateekpurohit13/frien/internal/tui"
)

// cmdDashboard launches the live operator TUI over the local admin socket. It is
// read-only and talks only to the local Unix socket — the same trust boundary as
// every other frienctl command, with no new network surface.
func cmdDashboard(args []string) error {
	fs := flag.NewFlagSet("dashboard", flag.ContinueOnError)
	socket := fs.String("socket", "", "admin API Unix socket")
	cfgPath := fs.String("config", "", "daemon config file to read the socket path from")
	interval := fs.Duration("interval", time.Second, "refresh interval")
	demo := fs.Bool("demo", false, "run against a synthetic evolving cluster (no daemon/certs needed)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var src tui.Source
	if *demo {
		src = tui.NewDemoSource()
	} else {
		socketPath, err := resolveSocket(*socket, *cfgPath)
		if err != nil {
			return err
		}
		client, err := tui.Dial(socketPath)
		if err != nil {
			return fmt.Errorf("connecting to admin socket %s: %w", socketPath, err)
		}
		defer client.Close()
		src = client
	}

	p := tea.NewProgram(tui.New(src, *interval), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
