package gossip

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestSuperviseRestartsAfterPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls int32
	ready := make(chan struct{})
	fn := func(ctx context.Context) {
		if atomic.AddInt32(&calls, 1) == 1 {
			panic("boom")
		}
		close(ready)
		<-ctx.Done()
	}

	go supervise(ctx, zerolog.Nop(), "test", time.Millisecond, fn)

	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("supervised loop did not restart after a panic")
	}
	if got := atomic.LoadInt32(&calls); got < 2 {
		t.Fatalf("expected the loop to restart, calls=%d", got)
	}
}

func TestSuperviseStopsOnCleanReturn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls int32
	done := make(chan struct{})
	go func() {
		supervise(ctx, zerolog.Nop(), "test", time.Millisecond, func(context.Context) {
			atomic.AddInt32(&calls, 1)
		})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("supervise should return once fn returns without panicking")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("a clean return must not restart, calls=%d", got)
	}
}
