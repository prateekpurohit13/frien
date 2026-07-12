package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// defaultSearchPaths are tried in order when no --config flag is provided.
var defaultSearchPaths = []string{
	"/etc/frien/config.yaml",
	"./frien.yaml",
}

// Load reads configuration from file (or the first found default path),
// applies environment variable overrides, and validates the result.
// It returns the validated Config or a descriptive error.
func Load(path string) (*Config, error) {
	if path == "" {
		path = findDefaultConfig()
	}
	if path == "" {
		return nil, fmt.Errorf("no config file found; tried %v", defaultSearchPaths)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	cfg := defaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	applyEnvOverrides(cfg)

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadFromBytes parses configuration from a raw YAML byte slice (for testing).
func LoadFromBytes(data []byte) (*Config, error) {
	cfg := defaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	applyEnvOverrides(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func findDefaultConfig() string {
	for _, p := range defaultSearchPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// defaultConfig provides safe defaults for optional fields.
func defaultConfig() *Config {
	return &Config{
		Node: NodeConfig{
			TrustTier: "standard",
		},
		Identity: IdentityConfig{
			CAMode:           "file",                     // default: file-based CA cert
			SigningAlgorithm: "hybrid-ed25519-ml-dsa-65", // send both; receiver picks
			PQCKem:           "x25519mlkem768",           // hybrid PQC+classical TLS key exchange
			CABundleRefresh:  "1h",
		},
		Transport: TransportConfig{
			PeerPort:           7443,
			PeerBind:           "0.0.0.0",
			MaxMessageBytes:    1 * 1024 * 1024,
			HandshakeRateLimit: 10,
			StreamRateLimit:    100,
			DialTimeout:        "5s",
			SessionIdleTimeout: "30s",
			ClockSkewWindow:    "10s",
		},
		Membership: MembershipConfig{
			ProbeInterval:     "1s",
			ProbeTimeout:      "500ms",
			SuspectMultiplier: 4,
			MaxGossipNodes:    3,
		},
		AdminAPI: AdminAPIConfig{
			Socket:              "/run/frien/admin.sock",
			MaxRecvMessageBytes: 512 * 1024,
			RequestTimeout:      "10s",
		},
		Storage: StorageConfig{
			WALSync:                   true,
			CompactionInterval:        "1h",
			CompactionMinAge:          "2h",
			CompactionPeerAckFraction: 0.6,
		},
		Admission: AdmissionConfig{
			PerDetectorBurst:  100,
			PerDetectorRate:   10,
			PerNodeBurst:      500,
			PerNodeRate:       50,
			CoalesceWindow:    "5s",
			ShedMinConfidence: 0.5,
		},
		Policy: PolicyConfig{
			EnforceMode:          "observe",
			MaxNewRulesPerMinute: 20,
			ProtectedCIDRs: []string{
				"127.0.0.0/8",
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
				"169.254.0.0/16",
				"::1/128",
				"fc00::/7",
				"fe80::/10",
			},
			ProtectSelfPlanes:          true,
			DenyTargetingAdminEndpoint: true,
		},
		Enforcement: EnforcementConfig{
			HeartbeatInterval: "10s",
			SweepInterval:     "15s",
			NFTables: NFTablesConfig{
				Enabled:               false,
				Table:                 "frien",
				ChainInput:            "frien-input",
				ChainForward:          "frien-forward",
				MaxRuleTTL:            "24h",
				KernelTimeoutRequired: true,
				DeadmanSwitchTimeout:  "30s",
			},
		},
		Detectors: DetectorConfig{
			SSHBruteForce: SSHBruteForceDetector{
				Enabled:    true,
				AuthLog:    "/var/log/auth.log",
				Threshold:  10,
				Window:     "60s",
				Confidence: 0.9,
			},
		},
		Observability: ObsConfig{
			LogLevel:        "info",
			LogFormat:       "json",
			MetricsBind:     "127.0.0.1:9109",
			TraceSampleRate: 0.1,
			HealthBind:      "127.0.0.1:9110",
		},
		Harden: HardenConfig{
			Profile:   "server",
			AutoApply: false,
		},
	}
}

// applyEnvOverrides reads environment variables with the FRIEN_ prefix
// and overrides the corresponding config fields.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("FRIEN_NODE_ID"); v != "" {
		cfg.Node.ID = v
	}
	if v := os.Getenv("FRIEN_NODE_ZONE"); v != "" {
		cfg.Node.Zone = v
	}
	if v := os.Getenv("FRIEN_NODE_ROLE"); v != "" {
		cfg.Node.Role = v
	}
	if v := os.Getenv("FRIEN_IDENTITY_CERT_PATH"); v != "" {
		cfg.Identity.CertPath = v
	}
	if v := os.Getenv("FRIEN_IDENTITY_KEY_PATH"); v != "" {
		cfg.Identity.KeyPath = v
	}
	if v := os.Getenv("FRIEN_IDENTITY_CA_CERT_PATH"); v != "" {
		cfg.Identity.CACertPath = v
	}
	if v := os.Getenv("FRIEN_TRANSPORT_PEER_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Transport.PeerPort = port
		}
	}
	if v := os.Getenv("FRIEN_ADMIN_API_SOCKET"); v != "" {
		cfg.AdminAPI.Socket = v
	}
	if v := os.Getenv("FRIEN_STORAGE_WAL_DIR"); v != "" {
		cfg.Storage.WALDir = v
	}
	if v := os.Getenv("FRIEN_STORAGE_DB_PATH"); v != "" {
		cfg.Storage.DBPath = v
	}
	// enforce_mode cannot be set to "enforce" via environment variable;
	// it must be set explicitly in the config file to prevent accidental activation.
	if v := os.Getenv("FRIEN_POLICY_ENFORCE_MODE"); v != "" && v == "observe" {
		cfg.Policy.EnforceMode = v
	}
	if v := os.Getenv("FRIEN_OBSERVABILITY_LOG_LEVEL"); v != "" {
		cfg.Observability.LogLevel = v
	}
	// Secrets: only via env, never config file
	if v := os.Getenv("FRIEN_ENFORCEMENT_SIEM_AUTH_HEADER"); v != "" {
		cfg.Enforcement.SIEMWebhook.AuthHeader = v
	}
	// Seeds can be overridden via comma-separated env
	if v := os.Getenv("FRIEN_SEEDS"); v != "" {
		cfg.Seeds = nil
		for _, addr := range strings.Split(v, ",") {
			addr = strings.TrimSpace(addr)
			if addr != "" {
				cfg.Seeds = append(cfg.Seeds, SeedConfig{Address: addr})
			}
		}
	}
}
