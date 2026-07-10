package gossip

import (
	"context"
	"testing"
	"time"
)

func TestJitterStaysWithinBound(t *testing.T) {
	const d = 100 * time.Millisecond
	for i := 0; i < 1000; i++ {
		j := jitter(d)
		if j < 0 || j >= d {
			t.Fatalf("jitter %v out of [0, %v)", j, d)
		}
	}
	if jitter(0) != 0 || jitter(-time.Second) != 0 {
		t.Fatal("non-positive input should yield zero jitter")
	}
}

func TestSleepCtxCompletes(t *testing.T) {
	start := time.Now()
	if !sleepCtx(context.Background(), 20*time.Millisecond) {
		t.Fatal("sleepCtx should report completion when not cancelled")
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Fatalf("sleepCtx returned early after %v", elapsed)
	}
}

func TestSleepCtxCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sleepCtx(ctx, time.Hour) {
		t.Fatal("sleepCtx should report cancellation, not completion")
	}
}
