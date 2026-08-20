package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/teacat/mcp-execmesh/internal/config"
	"github.com/teacat/mcp-execmesh/internal/executor"
	"github.com/teacat/mcp-execmesh/internal/security"
	"github.com/teacat/mcp-execmesh/internal/ssh"
	"github.com/teacat/mcp-execmesh/internal/target"
)

type mockRegistry struct {
	targets map[string]*target.Target
}

func (m *mockRegistry) List(ctx context.Context) []target.TargetSummary {
	var res []target.TargetSummary
	for _, t := range m.targets {
		res = append(res, t.Summary())
	}
	return res
}

func (m *mockRegistry) Get(ctx context.Context, id string) (*target.Target, error) {
	t, ok := m.targets[id]
	if !ok {
		return nil, assert.AnError
	}
	return t, nil
}

func (m *mockRegistry) Reload(cfg *config.Config) error {
	return nil
}

type mockExecutor struct{}

func (m *mockExecutor) Exec(ctx context.Context, p *security.Principal, t *target.Target, req executor.ExecRequest) (*ssh.ExecResult, error) {
	return &ssh.ExecResult{
		ExitCode:   0,
		Stdout:     "mocked uname output",
		DurationMS: 10,
	}, nil
}

func TestHealthEndpoints(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := &mockRegistry{
		targets: map[string]*target.Target{
			"test-01": {
				ID:   "test-01",
				Name: "Test Node 01",
			},
		},
	}
	exec := &mockExecutor{}
	auth := &security.NoneAuthenticator{}

	srv, err := NewServer(cfg, reg, exec, nil, nil, auth, nil)
	require.NoError(t, err)

	handler := srv.Handler()

	// 1. /healthz
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var healthBody map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &healthBody)
	require.NoError(t, err)
	assert.Equal(t, "ok", healthBody["status"])

	// 2. /readyz
	req = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var readyBody map[string]any
	err = json.Unmarshal(rec.Body.Bytes(), &readyBody)
	require.NoError(t, err)
	assert.Equal(t, "ok", readyBody["status"])
	assert.Equal(t, float64(1), readyBody["targets_count"])
}

func TestAuthProtection(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := &mockRegistry{targets: make(map[string]*target.Target)}
	exec := &mockExecutor{}
	auth, err := security.NewAuthenticator(config.ServerAuthConfig{
		Type:        "bearer",
		BearerToken: "valid-secret-token",
	})
	require.NoError(t, err)

	srv, err := NewServer(cfg, reg, exec, nil, nil, auth, nil)
	require.NoError(t, err)

	handler := srv.Handler()

	// Unauthenticated request to /mcp
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// Authenticated request to /mcp
	req = httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer valid-secret-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	// Even if body is invalid JSON-RPC, status should not be 401 Unauthorized
	assert.NotEqual(t, http.StatusUnauthorized, rec.Code)
}
