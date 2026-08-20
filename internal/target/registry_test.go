package target

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/teacat/mcp-execmesh/internal/config"
)

func TestTargetRegistry(t *testing.T) {
	tempDir := t.TempDir()
	pwFile := filepath.Join(tempDir, "pw.txt")
	require.NoError(t, os.WriteFile(pwFile, []byte("password123"), 0600))

	cfg := &config.Config{
		Version: 1,
		Targets: []config.TargetConfig{
			{
				ID:   "web-01",
				Name: "Web Server 01",
				Host: "192.168.1.10",
				Port: 22,
				User: "admin",
				Auth: config.TargetAuthConfig{
					Type:         "password",
					PasswordFile: pwFile,
				},
				HostKey: config.HostKeyConfig{
					Strict: false,
				},
				DefaultCwd: "/var/www",
				Tags:       []string{"web", "prod"},
				Capabilities: config.TargetCapabilities{
					Exec:   true,
					Upload: false,
					Jobs:   true,
				},
			},
		},
	}

	reg, err := NewRegistry(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	list := reg.List(ctx)
	assert.Len(t, list, 1)
	assert.Equal(t, "web-01", list[0].ID)
	assert.Equal(t, "Web Server 01", list[0].Name)
	assert.Equal(t, "/var/www", list[0].DefaultCwd)
	assert.True(t, list[0].Capabilities.Exec)
	assert.False(t, list[0].Capabilities.Upload)

	tgt, err := reg.Get(ctx, "web-01")
	require.NoError(t, err)
	assert.Equal(t, "web-01", tgt.ID)
	assert.Equal(t, "192.168.1.10:22", tgt.Address())

	_, err = reg.Get(ctx, "non-existent")
	assert.Error(t, err)
}
