package authcli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/teacat99/mcp-execmesh/internal/security"
)

func TestCapabilityCLICreateListRevokeRotate(t *testing.T) {
	dir := t.TempDir()
	capPath := filepath.Join(dir, "capabilities.yaml")
	cfgPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
version: 1
server:
  listen: "127.0.0.1:8080"
  mcp_path: "/mcp"
  auth:
    type: none
    capability_enabled: true
    capability_registry_file: "`+capPath+`"
    public_base_url: "https://mcp-execmesh.example.com"
runtime:
  max_concurrent_requests: 1
  max_concurrent_ssh: 1
  max_concurrent_transfers: 1
  max_stdout_bytes: 1024
  max_stderr_bytes: 1024
  transfer_buffer_bytes: 1024
security:
  require_known_hosts: false
`), 0600))

	require.NoError(t, Run([]string{
		"capability", "create",
		"--config", cfgPath,
		"--id", "chatgpt-main",
		"--scope", "targets:read",
		"--scope", "exec:run",
		"--target", "*",
	}))
	require.NoError(t, Run([]string{"capability", "list", "--config", cfgPath}))
	require.NoError(t, Run([]string{"capability", "rotate", "--config", cfgPath, "--id", "chatgpt-main"}))
	cf, err := security.LoadCapabilityFile(capPath)
	require.NoError(t, err)
	require.Len(t, cf.Capabilities, 1)
	require.Len(t, cf.Capabilities[0].ActiveTokens, 2)
	require.NoError(t, Run([]string{"capability", "revoke", "--config", cfgPath, "--id", "chatgpt-main"}))
	cf, err = security.LoadCapabilityFile(capPath)
	require.NoError(t, err)
	require.False(t, cf.Capabilities[0].Enabled)
}
