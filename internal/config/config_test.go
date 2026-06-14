package config_test

import (
	"os"
	"strings"
	"testing"

	"github.com/prateekpurohit13/frien/internal/config"
)

// toForwardSlash converts Windows backslashes to forward slashes for YAML embedding.
func toForwardSlash(s string) string {
	return strings.ReplaceAll(s, `\`, `/`)
}

// minimalValidYAML returns the minimum required fields for a valid config.
// cert and ca paths point to real files created by the test.
func minimalValidYAML(t *testing.T) (string, func()) {
	t.Helper()

	// Create temp cert and CA files (content irrelevant for loader; validator checks existence)
	certFile, err := os.CreateTemp("", "frien-test-cert-*.crt")
	if err != nil {
		t.Fatal(err)
	}
	caFile, err := os.CreateTemp("", "frien-test-ca-*.crt")
	if err != nil {
		t.Fatal(err)
	}
	walDir, err := os.MkdirTemp("", "frien-test-wal-*")
	if err != nil {
		t.Fatal(err)
	}
	certFile.Close()
	caFile.Close()

	yaml := `
node:
  id: "node.test.01"
  zone: "test-zone"
  role: "edge"
identity:
  cert_path: "` + toForwardSlash(certFile.Name()) + `"
  key_path: "/tmp/test.key"
  ca_cert_path: "` + toForwardSlash(caFile.Name()) + `"
transport:
  peer_port: 7443
  max_message_bytes: 1048576
  clock_skew_window: "10s"
storage:
  wal_dir: "` + toForwardSlash(walDir) + `"
  db_path: "/tmp/test.db"
`
	cleanup := func() {
		os.Remove(certFile.Name())
		os.Remove(caFile.Name())
		os.RemoveAll(walDir)
	}
	return yaml, cleanup
}

func TestLoadFromBytes_Valid(t *testing.T) {
	yaml, cleanup := minimalValidYAML(t)
	defer cleanup()

	cfg, err := config.LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if cfg.Node.ID != "node.test.01" {
		t.Errorf("unexpected node.id: %q", cfg.Node.ID)
	}
	// enforce_mode must default to observe
	if cfg.Policy.EnforceMode != "observe" {
		t.Errorf("enforce_mode should default to observe, got %q", cfg.Policy.EnforceMode)
	}
}

func TestLoadFromBytes_MissingNodeID(t *testing.T) {
	yaml := `
node:
  zone: "test-zone"
  role: "edge"
identity:
  cert_path: "/tmp/nonexistent.crt"
  key_path: "/tmp/test.key"
  ca_cert_path: "/tmp/nonexistent.ca.crt"
transport:
  peer_port: 7443
  max_message_bytes: 1048576
  clock_skew_window: "10s"
storage:
  wal_dir: "/tmp"
  db_path: "/tmp/test.db"
`
	_, err := config.LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing node.id")
	}
	if !strings.Contains(err.Error(), "node.id") {
		t.Errorf("error should mention node.id, got: %v", err)
	}
}

func TestLoadFromBytes_InvalidRole(t *testing.T) {
	_, cleanup := minimalValidYAML(t)
	defer cleanup()

	yaml := `
node:
  id: "node.test.01"
  zone: "test-zone"
  role: "superadmin"
identity:
  cert_path: "/tmp/x.crt"
  key_path: "/tmp/x.key"
  ca_cert_path: "/tmp/x.ca.crt"
transport:
  peer_port: 7443
  max_message_bytes: 1048576
  clock_skew_window: "10s"
storage:
  wal_dir: "/tmp"
  db_path: "/tmp/test.db"
`
	_, err := config.LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid role")
	}
	if !strings.Contains(err.Error(), "node.role") {
		t.Errorf("error should mention node.role, got: %v", err)
	}
}

func TestLoadFromBytes_InvalidPort(t *testing.T) {
	_, cleanup := minimalValidYAML(t)
	defer cleanup()

	yaml := `
node:
  id: "node.test.01"
  zone: "test-zone"
  role: "edge"
identity:
  cert_path: "/tmp/x.crt"
  key_path: "/tmp/x.key"
  ca_cert_path: "/tmp/x.ca.crt"
transport:
  peer_port: 99999
  max_message_bytes: 1048576
  clock_skew_window: "10s"
storage:
  wal_dir: "/tmp"
  db_path: "/tmp/test.db"
`
	_, err := config.LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
	if !strings.Contains(err.Error(), "transport.peer_port") {
		t.Errorf("error should mention transport.peer_port, got: %v", err)
	}
}

func TestLoadFromBytes_MultipleErrors(t *testing.T) {
	yaml := `
node:
  zone: "test-zone"
storage:
  db_path: "/tmp/test.db"
`
	_, err := config.LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected multiple errors")
	}
	ve, ok := err.(*config.ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if len(ve.Fields) < 2 {
		t.Errorf("expected multiple validation errors, got %d: %v", len(ve.Fields), ve.Fields)
	}
}

func TestEnvOverride_NodeID(t *testing.T) {
	t.Setenv("FRIEN_NODE_ID", "node.env.overridden")

	yaml, cleanup := minimalValidYAML(t)
	defer cleanup()

	cfg, err := config.LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Node.ID != "node.env.overridden" {
		t.Errorf("env override failed: expected node.env.overridden, got %q", cfg.Node.ID)
	}
}

func TestEnvOverride_EnforceModeEnforceBlocked(t *testing.T) {
	// env var cannot set enforce_mode to "enforce" — must be explicit in config file
	t.Setenv("FRIEN_POLICY_ENFORCE_MODE", "enforce")

	yaml, cleanup := minimalValidYAML(t)
	defer cleanup()

	cfg, err := config.LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Policy.EnforceMode == "enforce" {
		t.Error("env var should not be able to set enforce_mode to enforce")
	}
}

func TestDefaultProtectedCIDRs(t *testing.T) {
	yaml, cleanup := minimalValidYAML(t)
	defer cleanup()

	cfg, err := config.LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	required := []string{"127.0.0.0/8", "10.0.0.0/8", "::1/128", "fe80::/10"}
	cidrs := make(map[string]bool)
	for _, c := range cfg.Policy.ProtectedCIDRs {
		cidrs[c] = true
	}
	for _, r := range required {
		if !cidrs[r] {
			t.Errorf("protected_cidrs missing required entry: %s", r)
		}
	}
}
