package tests

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/teacat99/mcp-execmesh/internal/audit"
	"github.com/teacat99/mcp-execmesh/internal/config"
	servermcp "github.com/teacat99/mcp-execmesh/internal/mcp"
	"github.com/teacat99/mcp-execmesh/internal/security"
	"github.com/teacat99/mcp-execmesh/internal/target"
)

func TestCapabilityAndBearerDualAuth(t *testing.T) {
	dir := t.TempDir()
	tok, err := security.GenerateCapability()
	require.NoError(t, err)
	capPath := filepath.Join(dir, "capabilities.yaml")
	require.NoError(t, security.SaveCapabilityFile(capPath, &security.CapabilityFile{
		Version: 1,
		Capabilities: []security.CapabilityFileEntry{{
			ID:          "chatgpt-main",
			TokenSHA256: security.HashTokenHex(tok),
			Enabled:     true,
			Subject:     "chatgpt-main",
			Scopes:      security.AllScopes,
			Targets:     []string{"*"},
		}},
	}))

	cfg := config.DefaultConfig()
	cfg.Server.Auth.Type = "bearer"
	cfg.Server.Auth.BearerToken = "legacy-bearer"
	cfg.Server.Auth.CapabilityEnabled = true
	cfg.Server.Auth.CapabilityRegistryFile = capPath
	cfg.Server.Auth.AllowedOrigins = []string{"https://chatgpt.com"}

	reg, err := target.NewRegistry(cfg)
	require.NoError(t, err)
	auditLog := filepath.Join(dir, "audit.log")
	auditLogger, err := audit.NewLogger(auditLog, true)
	require.NoError(t, err)
	defer auditLogger.Close()

	auth, err := security.NewAuthenticator(cfg.Server.Auth)
	require.NoError(t, err)
	mgr, err := security.NewManager(security.ManagerOptions{
		CapabilityFile: capPath,
		LegacyType:     "bearer",
		LegacyBearer:   "legacy-bearer",
	})
	require.NoError(t, err)

	srv, err := servermcp.NewServer(cfg, reg, nil, nil, nil, auth, auditLogger)
	require.NoError(t, err)
	srv.UseAuthManager(mgr)
	handler := srv.Handler()

	// health unauthenticated
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	assert.Equal(t, http.StatusOK, rec.Code)

	// /mcp without bearer -> 401
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Empty(t, rec.Header().Get("WWW-Authenticate"))

	// /mcp with bearer -> not 401
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer legacy-bearer")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.NotEqual(t, http.StatusUnauthorized, rec.Code)
	assert.NotEqual(t, http.StatusNotFound, rec.Code)

	// valid capability GET/POST/DELETE
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
		req := httptest.NewRequest(method, "/mcp/"+tok, nil)
		req.Header.Set("Origin", "https://chatgpt.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.NotEqual(t, http.StatusNotFound, rec.Code, method)
		assert.NotEqual(t, http.StatusUnauthorized, rec.Code, method)
	}

	// invalid capability -> 404, no leak
	req = httptest.NewRequest(http.MethodPost, "/mcp/cap_v1_"+strings.Repeat("C", 43), nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.NotContains(t, rec.Body.String(), tok)
	assert.NotContains(t, rec.Body.String(), "revoked")

	// query credential rejected
	req = httptest.NewRequest(http.MethodPost, "/mcp/"+tok+"?token=abc", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)

	// origin denied
	req = httptest.NewRequest(http.MethodPost, "/mcp/"+tok, nil)
	req.Header.Set("Origin", "https://evil.example")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	auditLogger.Close()
	data, err := os.ReadFile(auditLog)
	require.NoError(t, err)
	assert.NotContains(t, string(data), tok)
	assert.NotContains(t, string(data), "cap_v1_")
}
