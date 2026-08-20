package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the full server configuration.
type Config struct {
	Version         int                `yaml:"version"`
	Server          ServerConfig       `yaml:"server"`
	Runtime         RuntimeConfig      `yaml:"runtime"`
	Security        SecurityConfig     `yaml:"security"`
	Jobs            JobsConfig         `yaml:"jobs"`
	TargetsFile     string             `yaml:"targets_file,omitempty"`
	CredentialsFile string             `yaml:"credentials_file,omitempty"`
	Targets         []TargetConfig     `yaml:"targets,omitempty"`
	Credentials     []CredentialConfig `yaml:"-"`
	SourcePath      string             `yaml:"-"`
}

// ServerConfig holds HTTP/MCP server configuration.
type ServerConfig struct {
	Listen       string           `yaml:"listen"`
	PublicBaseURL  string           `yaml:"public_base_url,omitempty"`
	MCPPath      string           `yaml:"mcp_path"`
	DataDir      string           `yaml:"data_dir"`
	LogLevel     string           `yaml:"log_level"`
	ReadTimeout  Duration         `yaml:"read_timeout"`
	WriteTimeout Duration         `yaml:"write_timeout"`
	IdleTimeout  Duration         `yaml:"idle_timeout"`
	Auth         ServerAuthConfig `yaml:"auth"`
}

// ServerAuthConfig defines authentication requirement for MCP clients.
type ServerAuthConfig struct {
	Type                   string   `yaml:"type"` // "none", "bearer", "api_key"
	BearerToken            string   `yaml:"bearer_token,omitempty"`
	TokenFile              string   `yaml:"token_file,omitempty"`
	PublicBaseURL          string   `yaml:"public_base_url,omitempty"`
	CapabilityEnabled      bool     `yaml:"capability_enabled"`
	CapabilityRegistryFile string   `yaml:"capability_registry_file,omitempty"`
	BearerRegistryFile     string   `yaml:"bearer_registry_file,omitempty"`
	AllowedOrigins         []string `yaml:"allowed_origins,omitempty"`
}

// RuntimeConfig defines execution limits and buffer sizes.
type RuntimeConfig struct {
	MaxConcurrentRequests  int      `yaml:"max_concurrent_requests"`
	MaxConcurrentSSH       int      `yaml:"max_concurrent_ssh"`
	MaxConcurrentTransfers int      `yaml:"max_concurrent_transfers"`
	MaxRequestsPerMinute   int      `yaml:"max_requests_per_minute"`
	RequestBurst           int      `yaml:"request_burst"`
	SyncExecTimeout        Duration `yaml:"sync_exec_timeout"`
	MaxStdoutBytes         int64    `yaml:"max_stdout_bytes"`
	MaxStderrBytes         int64    `yaml:"max_stderr_bytes"`
	MaxJobOutputReadBytes  int64    `yaml:"max_job_output_read_bytes"`
	MaxUploadBytes         int64    `yaml:"max_upload_bytes"`
	TransferBufferBytes    int      `yaml:"transfer_buffer_bytes"`
	DefaultDownloadTicketTTL int    `yaml:"default_download_ticket_ttl,omitempty"`
	MaxDownloadTicketTTL     int    `yaml:"max_download_ticket_ttl,omitempty"`
	MaxActiveDownloadTickets int    `yaml:"max_active_download_tickets,omitempty"`
}

// SecurityConfig holds global security rules.
type SecurityConfig struct {
	AllowInlineSecrets            bool     `yaml:"allow_inline_secrets"`
	RequireKnownHosts             bool     `yaml:"require_known_hosts"`
	AllowedFileDownloadSchemes    []string `yaml:"allowed_file_download_schemes"`
	BlockPrivateDownloadAddresses bool     `yaml:"block_private_download_addresses"`
	MaxDownloadRedirects          int      `yaml:"max_download_redirects"`
	AuditLogPath                  string   `yaml:"audit_log_path"`
	MaskSensitiveCommands         bool     `yaml:"mask_sensitive_commands"`
	KnownHostsFile                string   `yaml:"known_hosts_file,omitempty"`
}

// JobsConfig defines job storage and retention.
type JobsConfig struct {
	RemoteBaseDir string   `yaml:"remote_base_dir"`
	Retention     Duration `yaml:"retention"`
}

// TargetConfig defines an individual target server.
type TargetConfig struct {
	ID           string             `yaml:"id"`
	Name         string             `yaml:"name"`
	Host         string             `yaml:"host"`
	Port         int                `yaml:"port"`
	User         string             `yaml:"user"`
	Auth         TargetAuthConfig   `yaml:"auth"`
	HostKey      HostKeyConfig      `yaml:"host_key"`
	DefaultCwd   string             `yaml:"default_cwd"`
	Shell        string             `yaml:"shell"`
	Tags         []string           `yaml:"tags"`
	Limits       TargetLimitsConfig `yaml:"limits"`
	Capabilities TargetCapabilities `yaml:"capabilities"`
	AllowedPaths []string           `yaml:"allowed_paths"`
	Env          map[string]string  `yaml:"env"`
	AuthRef      string             `yaml:"auth_ref,omitempty"`
	KnownHostRef string             `yaml:"known_host_ref,omitempty"`
	Enabled      *bool              `yaml:"enabled,omitempty"`
}

// IsEnabled reports whether the target is active. Missing YAML field defaults to true.
func (t TargetConfig) IsEnabled() bool {
	return t.Enabled == nil || *t.Enabled
}

// CredentialConfig is a named SSH credential reference. Secret paths never leave the server.
type CredentialConfig struct {
	ID                       string `yaml:"id"`
	Type                     string `yaml:"type"`
	PrivateKeyFile           string `yaml:"private_key_file,omitempty"`
	PrivateKeyPassphraseFile string `yaml:"private_key_passphrase_file,omitempty"`
	PasswordFile             string `yaml:"password_file,omitempty"`
}

type credentialsFile struct {
	Version     int                `yaml:"version"`
	Credentials []CredentialConfig `yaml:"credentials"`
}

type targetsFile struct {
	Version int            `yaml:"version"`
	Targets []TargetConfig `yaml:"targets"`
}

// TargetAuthConfig defines SSH credentials.
type TargetAuthConfig struct {
	Type                     string `yaml:"type"` // "private_key" or "password"
	PrivateKeyFile           string `yaml:"private_key_file"`
	PrivateKeyPassphraseFile string `yaml:"private_key_passphrase_file"`
	PasswordFile             string `yaml:"password_file"`
}

// HostKeyConfig defines host key verification rules.
type HostKeyConfig struct {
	KnownHostsFile string `yaml:"known_hosts_file"`
	Strict         bool   `yaml:"strict"`
}

// TargetLimitsConfig defines per-target limits.
type TargetLimitsConfig struct {
	MaxExecSeconds int   `yaml:"max_exec_seconds"`
	MaxUploadBytes int64 `yaml:"max_upload_bytes"`
}

// TargetCapabilities defines what actions are allowed on this target.
type TargetCapabilities struct {
	Exec   bool `yaml:"exec"`
	Upload bool `yaml:"upload"`
	Jobs   bool `yaml:"jobs"`
}

// Duration is a wrapper around time.Duration to support YAML unmarshaling.
type Duration time.Duration

func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration format %q: %w", s, err)
	}
	*d = Duration(dur)
	return nil
}

func (d Duration) MarshalYAML() (interface{}, error) {
	return time.Duration(d).String(), nil
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Version: 1,
		Server: ServerConfig{
			Listen:       "127.0.0.1:8080",
			MCPPath:      "/mcp",
			DataDir:      "/var/lib/remote-mcp",
			LogLevel:     "info",
			ReadTimeout:  Duration(30 * time.Second),
			WriteTimeout: Duration(30 * time.Second),
			IdleTimeout:  Duration(120 * time.Second),
			Auth: ServerAuthConfig{
				Type: "none",
			},
		},
		Runtime: RuntimeConfig{
			MaxConcurrentRequests:  8,
			MaxConcurrentSSH:       4,
			MaxConcurrentTransfers: 1,
			MaxRequestsPerMinute:   120,
			RequestBurst:           30,
			SyncExecTimeout:        Duration(30 * time.Second),
			MaxStdoutBytes:         65536,      // 64 KiB
			MaxStderrBytes:         65536,      // 64 KiB
			MaxJobOutputReadBytes:  131072,     // 128 KiB
			MaxUploadBytes:           5368709120, // 5 GB
			TransferBufferBytes:      65536,      // 64 KiB
			DefaultDownloadTicketTTL: 900,
			MaxDownloadTicketTTL:     3600,
			MaxActiveDownloadTickets: 100,
		},
		Security: SecurityConfig{
			AllowInlineSecrets:            false,
			RequireKnownHosts:             true,
			AllowedFileDownloadSchemes:    []string{"https"},
			BlockPrivateDownloadAddresses: true,
			MaxDownloadRedirects:          3,
			MaskSensitiveCommands:         false,
		},
		Jobs: JobsConfig{
			RemoteBaseDir: ".remote-mcp/jobs",
			Retention:     Duration(72 * time.Hour),
		},
		Targets: make([]TargetConfig, 0),
	}
}

// LoadConfig reads and parses a YAML configuration file.
func LoadConfig(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", filePath, err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config YAML: %w", err)
	}
	cfg.SourcePath = filePath
	if err := loadSidecars(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
