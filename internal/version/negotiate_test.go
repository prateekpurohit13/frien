package version_test

import (
	"errors"
	"testing"

	"github.com/prateekpurohit13/frien/internal/version"
)

func TestHighestCommon(t *testing.T) {
	tests := []struct {
		name   string
		remote []uint32
		want   uint32
	}{
		{"single common", []uint32{1}, 1},
		{"order-independent", []uint32{2, 1}, 1},
		{"picks highest, not first", []uint32{1, 99, 1}, 1},
		{"no overlap", []uint32{99, 100}, 0},
		{"empty", nil, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := version.HighestCommon(tc.remote); got != tc.want {
				t.Errorf("HighestCommon(%v) = %d, want %d", tc.remote, got, tc.want)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	v, err := version.Resolve([]uint32{2, 1})
	if err != nil || v != 1 {
		t.Fatalf("Resolve = (%d, %v), want (1, nil)", v, err)
	}

	if _, err := version.Resolve([]uint32{99}); !errors.Is(err, version.ErrNoCommonVersion) {
		t.Fatalf("Resolve(no overlap) err = %v, want ErrNoCommonVersion", err)
	}
}

func TestAccept(t *testing.T) {
	v, err := version.Accept(1)
	if err != nil || v != 1 {
		t.Fatalf("Accept(1) = (%d, %v), want (1, nil)", v, err)
	}

	for _, bad := range []uint32{0, 99} {
		if _, err := version.Accept(bad); !errors.Is(err, version.ErrNoCommonVersion) {
			t.Errorf("Accept(%d) err = %v, want ErrNoCommonVersion", bad, err)
		}
	}
}
