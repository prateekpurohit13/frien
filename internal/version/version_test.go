package version_test

import (
	"testing"

	"github.com/prateekpurohit13/frien/internal/version"
)

func TestNegotiate(t *testing.T) {
	tests := []struct {
		name   string
		remote []uint32
		want   uint32
	}{
		{"common version", []uint32{1}, 1},
		{"multiple remote with common", []uint32{2, 1}, 1},
		{"no common version", []uint32{99, 100}, 0},
		{"empty remote", []uint32{}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := version.Negotiate(tc.remote); got != tc.want {
				t.Errorf("Negotiate(%v) = %d, want %d", tc.remote, got, tc.want)
			}
		})
	}
}

func TestIsSupported(t *testing.T) {
	if !version.IsSupported(1) {
		t.Error("version 1 should be supported")
	}
	if version.IsSupported(0) {
		t.Error("version 0 should not be supported")
	}
	if version.IsSupported(999) {
		t.Error("version 999 should not be supported")
	}
}
