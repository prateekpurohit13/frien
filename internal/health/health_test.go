package health

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
)

func TestProbes_ReadinessGating(t *testing.T) {
	c := New()
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()

	// Liveness is always OK while the server answers.
	if code := get(t, srv.URL+"/healthz"); code != http.StatusOK {
		t.Errorf("liveness before ready: got %d, want 200", code)
	}

	// Readiness is 503 until SetReady(true).
	if code := get(t, srv.URL+"/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("readiness before ready: got %d, want 503", code)
	}

	c.SetReady(true)
	if code := get(t, srv.URL+"/readyz"); code != http.StatusOK {
		t.Errorf("readiness after ready: got %d, want 200", code)
	}

	// Draining: readiness flips back to 503 while liveness stays OK.
	c.SetReady(false)
	if code := get(t, srv.URL+"/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("readiness after drain: got %d, want 503", code)
	}
	if code := get(t, srv.URL+"/healthz"); code != http.StatusOK {
		t.Errorf("liveness during drain: got %d, want 200", code)
	}
}

func TestNewServer_BadAddress(t *testing.T) {
	if _, _, err := NewServer("256.256.256.256:99999", New(), zerolog.Nop()); err == nil {
		t.Fatal("binding an invalid address should fail fast")
	}
}

func get(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}
