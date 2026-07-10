package version_test

import (
	"testing"

	"github.com/prateekpurohit13/frien/internal/version"
)

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
