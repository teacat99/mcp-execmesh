package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, 1, cfg.Version)
	assert.Equal(t, "127.0.0.1:8080", cfg.Server.Listen)
	assert.Equal(t, "/mcp", cfg.Server.MCPPath)
	assert.Equal(t, int64(65536), cfg.Runtime.MaxStdoutBytes)
	assert.Equal(t, int64(65536), cfg.Runtime.MaxStderrBytes)
	assert.Equal(t, 8, cfg.Runtime.MaxConcurrentRequests)
	assert.Equal(t, 4, cfg.Runtime.MaxConcurrentSSH)
	assert.True(t, cfg.Security.RequireKnownHosts)
}

func TestLoadConfigAndValidate(t *testing.T) {
	tempDir := t.TempDir()

	keyFile := filepath.Join(tempDir, "id_ed25519")
	require.NoError(t, os.WriteFile(keyFile, []byte("fake-key-data"), 0600))

	knownHostsFile := filepath.Join(tempDir, "known_hosts")
	require.NoError(t, os.WriteFile(knownHostsFile, []byte("fake-known-hosts"), 0600))

	configYAML := `
version: 1
server:
  listen: "0.0.0.0:9090"
  mcp_path: "/mcp"
  log_level: "debug"
  read_timeout: "15s"
runtime:
  max_concurrent_requests: 10
  max_concurrent_ssh: 5
  max_stdout_bytes: 32768
targets:
  - id: "test-01"
    name: "Test Node 01"
    host: "10.0.0.1"
    port: 2222
    user: "root"
    auth:
      type: "private_key"
      private_key_file: "` + keyFile + `"
    host_key:
      known_hosts_file: "` + knownHostsFile + `"
      strict: true
    default_cwd: "/root/work"
    tags: ["test", "linux"]
`

	cfgFile := filepath.Join(tempDir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte(configYAML), 0644))

	cfg, err := LoadConfig(cfgFile)
	require.NoError(t, err)
	assert.Equal(t, "0.0.0.0:9090", cfg.Server.Listen)
	assert.Equal(t, 15*time.Second, cfg.Server.ReadTimeout.Duration())
	assert.Equal(t, int64(32768), cfg.Runtime.MaxStdoutBytes)
	assert.Len(t, cfg.Targets, 1)
	assert.Equal(t, "test-01", cfg.Targets[0].ID)
	assert.Equal(t, 2222, cfg.Targets[0].Port)
	assert.True(t, cfg.Targets[0].Capabilities.Exec)

	err = Validate(cfg, ValidationOptions{CheckFilesExist: true})
	assert.NoError(t, err)
}

func TestValidateErrors(t *testing.T) {
	tests := []struct {
		name        string
		modify      func(cfg *Config)
		errContains string
	}{
		{
			name: "invalid version",
			modify: func(cfg *Config) {
				cfg.Version = 2
			},
			errContains: "unsupported config version: 2",
		},
		{
			name: "empty listen address",
			modify: func(cfg *Config) {
				cfg.Server.Listen = ""
			},
			errContains: "server.listen cannot be empty",
		},
		{
			name: "invalid target ID",
			modify: func(cfg *Config) {
				cfg.Targets = []TargetConfig{
					{
						ID:   "invalid target!",
						Host: "1.1.1.1",
						Port: 22,
						User: "test",
						Auth: TargetAuthConfig{Type: "password", PasswordFile: "/tmp/pw"},
					},
				}
			},
			errContains: "contains invalid characters",
		},
		{
			name: "duplicate target ID",
			modify: func(cfg *Config) {
				cfg.Targets = []TargetConfig{
					{
						ID:   "node-1",
						Host: "1.1.1.1",
						Port: 22,
						User: "test",
						Auth: TargetAuthConfig{Type: "password", PasswordFile: "/tmp/pw"},
					},
					{
						ID:   "node-1",
						Host: "1.1.1.2",
						Port: 22,
						User: "test",
						Auth: TargetAuthConfig{Type: "password", PasswordFile: "/tmp/pw"},
					},
				}
			},
			errContains: "duplicate target ID",
		},
		{
			name: "invalid port",
			modify: func(cfg *Config) {
				cfg.Targets = []TargetConfig{
					{
						ID:   "node-1",
						Host: "1.1.1.1",
						Port: 70000,
						User: "test",
						Auth: TargetAuthConfig{Type: "password", PasswordFile: "/tmp/pw"},
					},
				}
			},
			errContains: "port 70000 out of valid range",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := Validate(cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestSecretRedaction(t *testing.T) {
	secretBytes := SecretBytes("my-super-secret-key")
	assert.Equal(t, "[REDACTED_SECRET]", secretBytes.String())
	assert.Equal(t, "[REDACTED_SECRET]", secretBytes.GoString())

	secretStr := SecretString("my-super-secret-pw")
	assert.Equal(t, "[REDACTED_SECRET]", secretStr.String())
	assert.Equal(t, "[REDACTED_SECRET]", secretStr.GoString())
}

func TestLoadPasswordAndKey(t *testing.T) {
	tempDir := t.TempDir()

	pwFile := filepath.Join(tempDir, "pw.txt")
	require.NoError(t, os.WriteFile(pwFile, []byte("secret_password\r\n"), 0600))

	pw, err := LoadPassword(pwFile)
	require.NoError(t, err)
	assert.Equal(t, "secret_password", pw)

	keyFile := filepath.Join(tempDir, "key.pem")
	passFile := filepath.Join(tempDir, "pass.txt")
	require.NoError(t, os.WriteFile(keyFile, []byte("key_content"), 0600))
	require.NoError(t, os.WriteFile(passFile, []byte("pass_content\n"), 0600))

	k, p, err := LoadPrivateKeyData(keyFile, passFile)
	require.NoError(t, err)
	assert.Equal(t, []byte("key_content"), k)
	assert.Equal(t, []byte("pass_content"), p)
}

func TestDurationMarshalYAML(t *testing.T) {
	d := Duration(10 * time.Second)
	node, err := d.MarshalYAML()
	require.NoError(t, err)
	assert.Equal(t, "10s", node)
}
