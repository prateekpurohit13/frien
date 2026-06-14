package config

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Config is the validated runtime configuration for the frien daemon.
// All fields are populated after Load() returns without error.
type Config struct {
	Node        NodeConfig        `yaml:"node"`
	Identity    IdentityConfig    `yaml:"identity"`
	Transport   TransportConfig   `yaml:"transport"`
	Seeds       []SeedConfig      `yaml:"seeds"`
	MDNSEnabled bool              `yaml:"mdns_discovery"`
	Membership  MembershipConfig  `yaml:"membership"`
	AdminAPI    AdminAPIConfig    `yaml:"admin_api"`
	Storage     StorageConfig     `yaml:"storage"`
	Admission   AdmissionConfig   `yaml:"admission"`
	Policy      PolicyConfig      `yaml:"policy"`
	Enforcement EnforcementConfig `yaml:"enforcement"`
	Detectors   DetectorConfig    `yaml:"detectors"`
	Observability ObsConfig       `yaml:"observability"`
	Harden      HardenConfig      `yaml:"harden"`
}

type NodeConfig struct {
	ID        string `yaml:"id"`
	Zone      string `yaml:"zone"`
	Role      string `yaml:"role"`
	TrustTier string `yaml:"trust_tier"`
}

type IdentityConfig struct {
	// Classical TLS identity (mTLS + ed25519 envelope signing)
	CertPath         string `yaml:"cert_path"`
	KeyPath          string `yaml:"key_path"`
	CACertPath       string `yaml:"ca_cert_path"`
	RenewalThreshold string `yaml:"renewal_threshold"`
	RenewalEndpoint  string `yaml:"renewal_endpoint"`
	OperatorRootCert string `yaml:"operator_root_cert"`

	// CA integration mode: "file" (default) | "bundle_url" | "spiffe"
	CAMode      string `yaml:"ca_mode"`
	CABundleURL string `yaml:"ca_bundle_url"`    // used when ca_mode=bundle_url
	CABundleRefresh string `yaml:"ca_bundle_refresh"` // e.g. "1h"; used when ca_mode=bundle_url
	SPIFFESocket string `yaml:"spiffe_socket"`    // used when ca_mode=spiffe

	// PQC signing (ML-DSA-65, FIPS 204)
	// signing_algorithm controls what is sent. Verification always accepts
	// whichever algorithm the peer presents, in order of preference (PQC > classical).
	//   "ed25519"                  — classical only (default; safe baseline)
	//   "hybrid-ed25519-ml-dsa-65" — send both; receivers accept either
	//   "ml-dsa-65"                — PQC only (not recommended until ecosystem matures)
	SigningAlgorithm string `yaml:"signing_algorithm"`
	PQCKeyPath       string `yaml:"pqc_key_path"` // ML-DSA-65 private key PEM path

	PQCKem string `yaml:"pqc_kem"`
}

type TransportConfig struct {
	PeerPort          int    `yaml:"peer_port"`
	PeerBind          string `yaml:"peer_bind"`
	MaxMessageBytes   int    `yaml:"max_message_bytes"`
	HandshakeRateLimit int   `yaml:"handshake_rate_limit"`
	StreamRateLimit   int    `yaml:"stream_rate_limit"`
	DialTimeout       string `yaml:"dial_timeout"`
	SessionIdleTimeout string `yaml:"session_idle_timeout"`
	ClockSkewWindow   string `yaml:"clock_skew_window"`
}

type SeedConfig struct {
	Address string `yaml:"address"`
}

type MembershipConfig struct {
	ProbeInterval     string `yaml:"probe_interval"`
	ProbeTimeout      string `yaml:"probe_timeout"`
	SuspectMultiplier int    `yaml:"suspect_multiplier"`
	MaxGossipNodes    int    `yaml:"max_gossip_nodes"`
}

type AdminAPIConfig struct {
	Socket              string `yaml:"socket"`
	TCPListen           string `yaml:"tcp_listen"`
	TLSCert             string `yaml:"tls_cert"`
	TLSKey              string `yaml:"tls_key"`
	MaxRecvMessageBytes int    `yaml:"max_recv_message_bytes"`
	RequestTimeout      string `yaml:"request_timeout"`
	ReadOnly            bool   `yaml:"read_only"`
}

type StorageConfig struct {
	WALDir                    string  `yaml:"wal_dir"`
	DBPath                    string  `yaml:"db_path"`
	SnapshotDir               string  `yaml:"snapshot_dir"`
	WALSync                   bool    `yaml:"wal_sync"`
	CompactionInterval        string  `yaml:"compaction_interval"`
	CompactionMinAge          string  `yaml:"compaction_min_age"`
	CompactionPeerAckFraction float64 `yaml:"compaction_peer_ack_fraction"`
}

type AdmissionConfig struct {
	PerDetectorBurst  int     `yaml:"per_detector_burst"`
	PerDetectorRate   float64 `yaml:"per_detector_rate"`
	PerNodeBurst      int     `yaml:"per_node_burst"`
	PerNodeRate       float64 `yaml:"per_node_rate"`
	CoalesceWindow    string  `yaml:"coalesce_window"`
	ShedMinConfidence float64 `yaml:"shed_min_confidence"`
}

type PolicyConfig struct {
	PolicyFile              string   `yaml:"policy_file"`
	EnforceMode             string   `yaml:"enforce_mode"`
	DryRun                  bool     `yaml:"dry_run"`
	MaxNewRulesPerMinute    int      `yaml:"max_new_rules_per_minute"`
	ProtectedCIDRs          []string `yaml:"protected_cidrs"`
	ProtectSelfPlanes       bool     `yaml:"protect_self_planes"`
	DenyTargetingAdminEndpoint bool  `yaml:"deny_targeting_admin_endpoint"`
}

type EnforcementConfig struct {
	NFTables     NFTablesConfig     `yaml:"nftables"`
	Kubernetes   KubernetesConfig   `yaml:"kubernetes"`
	Cilium       CiliumConfig       `yaml:"cilium"`
	SIEMWebhook  SIEMWebhookConfig  `yaml:"siem_webhook"`
}

type NFTablesConfig struct {
	Enabled               bool   `yaml:"enabled"`
	Table                 string `yaml:"table"`
	ChainInput            string `yaml:"chain_input"`
	ChainForward          string `yaml:"chain_forward"`
	MaxRuleTTL            string `yaml:"max_rule_ttl"`
	KernelTimeoutRequired bool   `yaml:"kernel_timeout_required"`
	DeadmanSwitchTimeout  string `yaml:"deadman_switch_timeout"`
}

type KubernetesConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Kubeconfig string `yaml:"kubeconfig"`
}

type CiliumConfig struct {
	Enabled bool `yaml:"enabled"`
}

type SIEMWebhookConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Endpoint   string `yaml:"endpoint"`
	AuthHeader string `yaml:"auth_header"`
}

type DetectorConfig struct {
	SSHBruteForce   SSHBruteForceDetector   `yaml:"ssh_bruteforce"`
	HTTPRateAnomaly HTTPRateAnomalyDetector `yaml:"http_rate_anomaly"`
}

type SSHBruteForceDetector struct {
	Enabled    bool    `yaml:"enabled"`
	AuthLog    string  `yaml:"auth_log"`
	Threshold  int     `yaml:"threshold"`
	Window     string  `yaml:"window"`
	Confidence float64 `yaml:"confidence"`
}

type HTTPRateAnomalyDetector struct {
	Enabled    bool    `yaml:"enabled"`
	AccessLog  string  `yaml:"access_log"`
	Threshold  int     `yaml:"threshold"`
	Window     string  `yaml:"window"`
	Confidence float64 `yaml:"confidence"`
}

type ObsConfig struct {
	LogLevel    string `yaml:"log_level"`
	LogFormat   string `yaml:"log_format"`
	MetricsBind string `yaml:"metrics_bind"`
	OTELEndpoint string `yaml:"otel_endpoint"`
	TraceSampleRate float64 `yaml:"trace_sample_rate"`
	HealthBind  string `yaml:"health_bind"`
}

type HardenConfig struct {
	Profile   string `yaml:"profile"`
	AutoApply bool   `yaml:"auto_apply"`
}

// ValidationError accumulates all config validation failures for a single fail-fast report.
type ValidationError struct {
	Fields []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("config validation failed\n  %s", strings.Join(e.Fields, "\n  "))
}

func (e *ValidationError) add(msg string) {
	e.Fields = append(e.Fields, msg)
}

func (e *ValidationError) hasErrors() bool {
	return len(e.Fields) > 0
}

// Validate checks all required fields and invariants.
func (c *Config) Validate() error {
	ve := &ValidationError{}

	// Required node fields
	if c.Node.ID == "" {
		ve.add("node.id: required, got empty string")
	}
	if c.Node.Zone == "" {
		ve.add("node.zone: required, got empty string")
	}
	validRoles := map[string]bool{"edge": true, "core": true, "gateway": true}
	if c.Node.Role == "" {
		ve.add("node.role: required, got empty string")
	} else if !validRoles[c.Node.Role] {
		ve.add(fmt.Sprintf("node.role: must be edge|core|gateway, got %q", c.Node.Role))
	}

	// Required identity fields
	if c.Identity.CertPath == "" {
		ve.add("identity.cert_path: required, got empty string")
	} else if _, err := os.Stat(c.Identity.CertPath); err != nil {
		ve.add(fmt.Sprintf("identity.cert_path: file not found: %s", c.Identity.CertPath))
	}
	if c.Identity.KeyPath == "" {
		ve.add("identity.key_path: required, got empty string")
	}
	if c.Identity.CACertPath == "" {
		ve.add("identity.ca_cert_path: required, got empty string")
	} else if _, err := os.Stat(c.Identity.CACertPath); err != nil {
		ve.add(fmt.Sprintf("identity.ca_cert_path: file not found: %s", c.Identity.CACertPath))
	}

	// CA integration mode
	validCAModes := map[string]bool{"": true, "file": true, "bundle_url": true, "spiffe": true}
	if !validCAModes[c.Identity.CAMode] {
		ve.add(fmt.Sprintf("identity.ca_mode: must be file|bundle_url|spiffe, got %q", c.Identity.CAMode))
	}
	if c.Identity.CAMode == "bundle_url" && c.Identity.CABundleURL == "" {
		ve.add("identity.ca_bundle_url: required when ca_mode=bundle_url")
	}
	if c.Identity.CAMode == "spiffe" && c.Identity.SPIFFESocket == "" {
		ve.add("identity.spiffe_socket: required when ca_mode=spiffe")
	}

	// PQC signing algorithm
	validSigningAlgos := map[string]bool{
		"":                          true,
		"ed25519":                   true,
		"hybrid-ed25519-ml-dsa-65": true,
		"ml-dsa-65":                 true,
	}
	if !validSigningAlgos[c.Identity.SigningAlgorithm] {
		ve.add(fmt.Sprintf("identity.signing_algorithm: must be ed25519|hybrid-ed25519-ml-dsa-65|ml-dsa-65, got %q",
			c.Identity.SigningAlgorithm))
	}
	// pqc_key_path is required only for "ml-dsa-65" (PQC-only mode).
	// For "hybrid-ed25519-ml-dsa-65", a key is auto-generated at startup if not provided.
	if c.Identity.SigningAlgorithm == "ml-dsa-65" && c.Identity.PQCKeyPath == "" {
		ve.add("identity.pqc_key_path: required when signing_algorithm=ml-dsa-65 (PQC-only mode)")
	}

	// PQC KEM for TLS
	validKEMs := map[string]bool{"": true, "classical": true, "x25519mlkem768": true}
	if !validKEMs[c.Identity.PQCKem] {
		ve.add(fmt.Sprintf("identity.pqc_kem: must be classical|x25519mlkem768, got %q", c.Identity.PQCKem))
	}

	// Transport
	if c.Transport.PeerPort <= 0 || c.Transport.PeerPort > 65535 {
		ve.add(fmt.Sprintf("transport.peer_port: must be 1–65535, got %d", c.Transport.PeerPort))
	}
	if c.Transport.MaxMessageBytes < 65536 || c.Transport.MaxMessageBytes > 16*1024*1024 {
		ve.add(fmt.Sprintf("transport.max_message_bytes: must be 64KB–16MB, got %d", c.Transport.MaxMessageBytes))
	}
	if _, err := time.ParseDuration(c.Transport.ClockSkewWindow); err != nil {
		ve.add(fmt.Sprintf("transport.clock_skew_window: invalid duration %q: %v", c.Transport.ClockSkewWindow, err))
	}

	// Storage
	if c.Storage.WALDir == "" {
		ve.add("storage.wal_dir: required, got empty string")
	} else {
		if info, err := os.Stat(c.Storage.WALDir); err != nil {
			ve.add(fmt.Sprintf("storage.wal_dir: not accessible: %s (%v)", c.Storage.WALDir, err))
		} else if !info.IsDir() {
			ve.add(fmt.Sprintf("storage.wal_dir: not a directory: %s", c.Storage.WALDir))
		}
	}
	if c.Storage.DBPath == "" {
		ve.add("storage.db_path: required, got empty string")
	}

	// Policy
	validModes := map[string]bool{"observe": true, "enforce": true}
	if c.Policy.EnforceMode == "" {
		c.Policy.EnforceMode = "observe" // default
	} else if !validModes[c.Policy.EnforceMode] {
		ve.add(fmt.Sprintf("policy.enforce_mode: must be observe|enforce, got %q", c.Policy.EnforceMode))
	}

	// Protected CIDRs
	for _, cidr := range c.Policy.ProtectedCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			ve.add(fmt.Sprintf("policy.protected_cidrs: invalid CIDR %q: %v", cidr, err))
		}
	}

	// Admin API: if TCP is enabled, TLS certs are required
	if c.AdminAPI.TCPListen != "" {
		if c.AdminAPI.TLSCert == "" {
			ve.add("admin_api.tls_cert: required when tcp_listen is set")
		}
		if c.AdminAPI.TLSKey == "" {
			ve.add("admin_api.tls_key: required when tcp_listen is set")
		}
	}

	// Observability log level
	validLogLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if c.Observability.LogLevel != "" && !validLogLevels[c.Observability.LogLevel] {
		ve.add(fmt.Sprintf("observability.log_level: must be debug|info|warn|error, got %q", c.Observability.LogLevel))
	}

	if ve.hasErrors() {
		return ve
	}
	return nil
}
