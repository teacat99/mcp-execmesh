package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidatePublicBaseURL(t *testing.T) {
	t.Run("https ok", func(t *testing.T) {
		u, err := ValidatePublicBaseURL("https://mcp.example.com", false)
		require.NoError(t, err)
		assert.Equal(t, "https", u.Scheme)
	})

	t.Run("path prefix", func(t *testing.T) {
		joined, err := JoinPublicURL("https://example.com/execmesh", "files", "abc")
		require.NoError(t, err)
		assert.Equal(t, "https://example.com/execmesh/files/abc", joined)
	})

	t.Run("reject http non-localhost", func(t *testing.T) {
		_, err := ValidatePublicBaseURL("http://mcp.example.com", false)
		assert.Error(t, err)
	})

	t.Run("allow localhost http in dev", func(t *testing.T) {
		_, err := ValidatePublicBaseURL("http://127.0.0.1:8080", true)
		assert.NoError(t, err)
	})
}

func TestConfigPublicBaseURLFallback(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			PublicBaseURL: "https://a.example.com",
			Auth:          ServerAuthConfig{PublicBaseURL: "https://b.example.com"},
		},
	}
	assert.Equal(t, "https://a.example.com", cfg.PublicBaseURL())

	cfg.Server.PublicBaseURL = ""
	assert.Equal(t, "https://b.example.com", cfg.PublicBaseURL())
}
