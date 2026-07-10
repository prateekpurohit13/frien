package gossip

import (
	"context"
	"runtime/debug"
	"time"

	"github.com/rs/zerolog"
)

const loopRestartBackoff = time.Second

// supervise runs fn and restarts it after a panic so a bug on the probe or
// anti-entropy path cannot silently freeze a node's failure detection. It
// returns when the context is cancelled or fn returns without panicking.
func supervise(ctx context.Context, log zerolog.Logger, name string, backoff time.Duration, fn func(context.Context)) {
	for ctx.Err() == nil {
		if !runGuarded(ctx, log, name, fn) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

// runGuarded runs fn once and reports whether it panicked.
func runGuarded(ctx context.Context, log zerolog.Logger, name string, fn func(context.Context)) (panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			log.Error().
				Str("loop", name).
				Interface("panic", r).
				Bytes("stack", debug.Stack()).
				Msg("gossip loop panicked; restarting")
		}
	}()
	fn(ctx)
	return false
}
