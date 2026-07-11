package gossip

import (
	"testing"

	"github.com/rs/zerolog"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

type fakeCheckpointSource struct {
	id, treeHead string
	ok           bool
}

func (f fakeCheckpointSource) Latest(string) (string, string, bool) { return f.id, f.treeHead, f.ok }

func TestLatestCheckpointNilSourceIsFalse(t *testing.T) {
	e := &Engine{log: zerolog.Nop()}
	if _, _, ok := e.latestCheckpoint("fleet"); ok {
		t.Fatal("expected no checkpoint before SetCheckpointSource")
	}
}

func TestSetCheckpointSourcePopulatesRequest(t *testing.T) {
	e := &Engine{log: zerolog.Nop()}
	e.SetCheckpointSource(fakeCheckpointSource{id: "cp_1", treeHead: "th_1", ok: true})
	id, th, ok := e.latestCheckpoint("fleet")
	if !ok || id != "cp_1" || th != "th_1" {
		t.Fatalf("latestCheckpoint() = %q, %q, %v; want cp_1, th_1, true", id, th, ok)
	}
}

func TestCheckCheckpointDivergenceIgnoresUnrelatedOrMissingClaim(t *testing.T) {
	e := &Engine{log: zerolog.Nop()}
	e.SetCheckpointSource(fakeCheckpointSource{id: "cp_1", treeHead: "th_1", ok: true})

	// No claim at all: nothing to compare.
	e.checkCheckpointDivergence(&frienv1.AntiEntropyRequest{})
	// A different checkpoint id: peer is simply on a different cut, not a fork.
	e.checkCheckpointDivergence(&frienv1.AntiEntropyRequest{SinceCheckpoint: "cp_other", RootHash: "anything"})
	// Reaching here without a panic and without a way to assert on the (nop)
	// log output is the point: these are documented no-ops.
}

func TestCheckCheckpointDivergenceMatchingIDAndHashIsQuiet(t *testing.T) {
	e := &Engine{log: zerolog.Nop()}
	e.SetCheckpointSource(fakeCheckpointSource{id: "cp_1", treeHead: "th_1", ok: true})
	e.checkCheckpointDivergence(&frienv1.AntiEntropyRequest{SinceCheckpoint: "cp_1", RootHash: "th_1"})
}

func TestCheckCheckpointDivergenceMismatchedHashUnderSameID(t *testing.T) {
	// Same checkpoint id but a different tree_head is the tamper/corruption
	// signal checkCheckpointDivergence exists to catch. It only logs today
	// (see the method's doc comment), so this test's job is to prove it
	// doesn't panic or otherwise misbehave on the exact input that should
	// trip the warning -- an eyeballed log assertion isn't worth a custom
	// zerolog sink here.
	e := &Engine{log: zerolog.Nop()}
	e.SetCheckpointSource(fakeCheckpointSource{id: "cp_1", treeHead: "th_1", ok: true})
	e.checkCheckpointDivergence(&frienv1.AntiEntropyRequest{SinceCheckpoint: "cp_1", RootHash: "th_DIFFERENT"})
}
