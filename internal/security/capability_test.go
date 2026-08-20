package security

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCapability(t *testing.T) {
	a, err := GenerateCapability()
	require.NoError(t, err)
	b, err := GenerateCapability()
	require.NoError(t, err)
	assert.NotEqual(t, a, b)
	assert.True(t, IsCapabilityToken(a))
	assert.False(t, strings.Contains(a, "/"))
	assert.False(t, strings.Contains(a, "="))
	assert.Equal(t, 50, len(a))
}

func TestParseCapabilityPath(t *testing.T) {
	tok, err := GenerateCapability()
	require.NoError(t, err)

	got, err := ParseCapabilityPath("/mcp/" + tok)
	require.NoError(t, err)
	assert.Equal(t, tok, got)

	invalid := []string{
		"/mcp/",
		"/mcp/foo",
		"/mcp/cap/extra",
		"/mcp/%2Fxxxx",
		"/mcp/../secret",
		"/mcp//" + tok,
		"/mcp/" + tok + "/extra",
	}
	for _, p := range invalid {
		_, err := ParseCapabilityPath(p)
		assert.Error(t, err, p)
	}
}

func TestRedactPath(t *testing.T) {
	tok, err := GenerateCapability()
	require.NoError(t, err)
	raw := "/mcp/" + tok
	assert.Equal(t, "/mcp/[CAPABILITY]", RedactPath(raw))
	assert.NotContains(t, RedactPath("POST "+raw), tok)
}

func TestCapabilityRegistryVerify(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capabilities.yaml")
	tok, err := GenerateCapability()
	require.NoError(t, err)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	expiredTok, err := GenerateCapability()
	require.NoError(t, err)
	disabledTok, err := GenerateCapability()
	require.NoError(t, err)

	cf := &CapabilityFile{
		Version: 1,
		Capabilities: []CapabilityFileEntry{
			{
				ID:          "ok",
				TokenSHA256: HashTokenHex(tok),
				Enabled:     true,
				Subject:     "chatgpt-main",
				Scopes:      []string{ScopeTargetsRead, ScopeExecRun},
				Targets:     []string{"test-01"},
			},
			{
				ID:          "expired",
				TokenSHA256: HashTokenHex(expiredTok),
				Enabled:     true,
				Subject:     "expired",
				ExpiresAt:   &past,
				Scopes:      AllScopes,
				Targets:     []string{"*"},
			},
			{
				ID:          "disabled",
				TokenSHA256: HashTokenHex(disabledTok),
				Enabled:     false,
				Subject:     "disabled",
				Scopes:      AllScopes,
				Targets:     []string{"*"},
			},
		},
	}
	require.NoError(t, SaveCapabilityFile(path, cf))

	mgr, err := NewManager(ManagerOptions{CapabilityFile: path})
	require.NoError(t, err)

	p, err := mgr.VerifyCapability(tok, "127.0.0.1:1")
	require.NoError(t, err)
	assert.Equal(t, "chatgpt-main", p.Subject)
	assert.Equal(t, "capability", p.AuthType)
	assert.True(t, p.HasScope(ScopeExecRun))
	assert.True(t, p.AllowsTarget("test-01"))
	assert.False(t, p.AllowsTarget("other"))

	_, err = mgr.VerifyCapability(expiredTok, "")
	assert.Error(t, err)
	_, err = mgr.VerifyCapability(disabledTok, "")
	assert.Error(t, err)
	_, err = mgr.VerifyCapability("cap_v1_"+strings.Repeat("A", 43), "")
	assert.Error(t, err)
}

func TestCapabilityHTTPMiddleware(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capabilities.yaml")
	tok, err := GenerateCapability()
	require.NoError(t, err)
	cf := &CapabilityFile{Version: 1, Capabilities: []CapabilityFileEntry{{
		ID: "chatgpt-main", TokenSHA256: HashTokenHex(tok), Enabled: true,
		Subject: "chatgpt-main", Scopes: AllScopes, Targets: []string{"*"},
	}}}
	require.NoError(t, SaveCapabilityFile(path, cf))
	mgr, err := NewManager(ManagerOptions{CapabilityFile: path})
	require.NoError(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/mcp", r.URL.Path)
		p := PrincipalFromContext(r.Context())
		require.NotNil(t, p)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	h := CapabilityAuth(mgr, nil, NewRateLimiter(0, 0), next)

	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
		req := httptest.NewRequest(method, "/mcp/"+tok, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, method)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp/cap_v1_"+strings.Repeat("B", 43), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.NotContains(t, rec.Body.String(), "expired")
	assert.NotContains(t, rec.Body.String(), "invalid capability")
}

func TestOriginAndAuthorize(t *testing.T) {
	assert.True(t, OriginAllowed([]string{"https://chatgpt.com"}, ""))
	assert.True(t, OriginAllowed([]string{"https://chatgpt.com"}, "https://chatgpt.com"))
	assert.False(t, OriginAllowed([]string{"https://chatgpt.com"}, "https://evil.example"))

	p := &Principal{
		AuthType: "capability",
		Scopes:   ScopeSet([]string{ScopeTargetsRead}),
		Targets:  TargetSet([]string{"test-01"}),
	}
	assert.NoError(t, Authorize(p, ScopeTargetsRead, "test-01"))
	assert.Error(t, Authorize(p, ScopeExecRun, "test-01"))
	assert.Error(t, Authorize(p, ScopeTargetsRead, "other"))
}

func TestCORSPreflight(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := CORSAndOrigin([]string{"https://chatgpt.com", "https://platform.openai.com"}, next)

	req := httptest.NewRequest(http.MethodOptions, "/mcp/cap_v1_x", nil)
	req.Header.Set("Origin", "https://chatgpt.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "https://chatgpt.com", rec.Header().Get("Access-Control-Allow-Origin"))

	req = httptest.NewRequest(http.MethodOptions, "/mcp", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestSaveCapabilityFileMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capabilities.yaml")
	require.NoError(t, SaveCapabilityFile(path, &CapabilityFile{Version: 1}))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}
