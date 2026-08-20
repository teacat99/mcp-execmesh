package security

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/teacat99/mcp-execmesh/internal/config"
)

func TestIsPathAllowed(t *testing.T) {
	allowedRoots := []string{"/srv/app", "/var/log"}

	assert.True(t, IsPathAllowed("/srv/app", allowedRoots))
	assert.True(t, IsPathAllowed("/srv/app/bin/app", allowedRoots))
	assert.True(t, IsPathAllowed("/var/log/syslog", allowedRoots))

	assert.False(t, IsPathAllowed("/srv/app-other", allowedRoots))
	assert.False(t, IsPathAllowed("/etc/passwd", allowedRoots))
	assert.False(t, IsPathAllowed("/srv/app/../etc/passwd", allowedRoots))
	assert.False(t, IsPathAllowed("", allowedRoots))
}

func TestAuthenticator(t *testing.T) {
	// 1. None auth
	noneAuth, err := NewAuthenticator(config.ServerAuthConfig{Type: "none"})
	require.NoError(t, err)
	req := httptest.NewRequest("GET", "/mcp", nil)
	principal, err := noneAuth.Authenticate(req)
	require.NoError(t, err)
	assert.Equal(t, "anonymous", principal.Subject)

	// 2. Bearer auth
	bearerAuth, err := NewAuthenticator(config.ServerAuthConfig{Type: "bearer", BearerToken: "my-secret-token"})
	require.NoError(t, err)

	// Unauthorized
	_, err = bearerAuth.Authenticate(req)
	assert.Error(t, err)

	// Authorized
	reqWithBearer := httptest.NewRequest("GET", "/mcp", nil)
	reqWithBearer.Header.Set("Authorization", "Bearer my-secret-token")
	principal, err = bearerAuth.Authenticate(reqWithBearer)
	require.NoError(t, err)
	assert.Equal(t, "bearer-user", principal.Subject)

	// 3. API Key auth
	apiKeyAuth, err := NewAuthenticator(config.ServerAuthConfig{Type: "api_key", BearerToken: "my-api-key"})
	require.NoError(t, err)

	// Via X-API-Key
	reqWithAPIKey := httptest.NewRequest("GET", "/mcp", nil)
	reqWithAPIKey.Header.Set("X-API-Key", "my-api-key")
	principal, err = apiKeyAuth.Authenticate(reqWithAPIKey)
	require.NoError(t, err)
	assert.Equal(t, "api-key-user", principal.Subject)

	// Via Bearer fallback
	reqWithAPIKeyBearer := httptest.NewRequest("GET", "/mcp", nil)
	reqWithAPIKeyBearer.Header.Set("Authorization", "Bearer my-api-key")
	principal, err = apiKeyAuth.Authenticate(reqWithAPIKeyBearer)
	require.NoError(t, err)
	assert.Equal(t, "api-key-user", principal.Subject)
}

func TestCommandPolicy(t *testing.T) {
	p := &CommandPolicy{
		MaxCommandLength: 20,
		Blacklist:        []string{"rm -rf /"},
	}

	assert.NoError(t, p.ValidateCommand("ls -la"))
	assert.Error(t, p.ValidateCommand(""))
	assert.Error(t, p.ValidateCommand("a very long command that exceeds 20 characters"))
	assert.Error(t, p.ValidateCommand("rm -rf /"))
}

func TestSSRFValidation(t *testing.T) {
	opts := DefaultSafeHTTPClientOptions()

	// 1. Valid HTTPS URL
	u, err := ValidateURL("https://example.com/file.tar.gz", opts)
	require.NoError(t, err)
	assert.Equal(t, "example.com", u.Hostname())

	// 2. Disallowed scheme (HTTP by default)
	_, err = ValidateURL("http://example.com/file.tar.gz", opts)
	require.ErrorIs(t, err, ErrSchemeNotAllowed)

	// 3. File scheme
	_, err = ValidateURL("file:///etc/passwd", opts)
	require.ErrorIs(t, err, ErrSchemeNotAllowed)

	// 4. Private / Loopback IPs directly in URL
	_, err = ValidateURL("https://127.0.0.1/file.tar.gz", opts)
	require.ErrorIs(t, err, ErrPrivateIPBlocked)

	_, err = ValidateURL("https://10.0.1.5/file.tar.gz", opts)
	require.ErrorIs(t, err, ErrPrivateIPBlocked)

	_, err = ValidateURL("https://192.168.1.1/file.tar.gz", opts)
	require.ErrorIs(t, err, ErrPrivateIPBlocked)

	_, err = ValidateURL("https://169.254.169.254/latest/meta-data", opts)
	require.ErrorIs(t, err, ErrPrivateIPBlocked)

	// 5. Test IsPrivateIP helper
	assert.True(t, IsPrivateIP(nil))
	assert.True(t, IsPrivateIP([]byte{127, 0, 0, 1}))
	assert.True(t, IsPrivateIP([]byte{10, 0, 0, 1}))
	assert.True(t, IsPrivateIP([]byte{172, 16, 0, 1}))
	assert.True(t, IsPrivateIP([]byte{192, 168, 1, 1}))
	assert.True(t, IsPrivateIP([]byte{169, 254, 1, 1}))
	assert.False(t, IsPrivateIP([]byte{8, 8, 8, 8}))
	assert.False(t, IsPrivateIP([]byte{1, 1, 1, 1}))
}

func TestNormalizeAccept(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		origAccept string
		wantAccept string
	}{
		{
			name:       "empty accept in POST",
			method:     "POST",
			origAccept: "",
			wantAccept: "application/json, text/event-stream",
		},
		{
			name:       "json only in POST",
			method:     "POST",
			origAccept: "application/json",
			wantAccept: "application/json, text/event-stream",
		},
		{
			name:       "sse only in POST",
			method:     "POST",
			origAccept: "text/event-stream",
			wantAccept: "application/json, text/event-stream",
		},
		{
			name:       "wildcard in POST",
			method:     "POST",
			origAccept: "*/*",
			wantAccept: "*/*",
		},
		{
			name:       "both present in POST",
			method:     "POST",
			origAccept: "application/json, text/event-stream",
			wantAccept: "application/json, text/event-stream",
		},
		{
			name:       "GET request untouched",
			method:     "GET",
			origAccept: "text/html",
			wantAccept: "text/html",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var recordedAccept string
			handler := NormalizeAccept(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				recordedAccept = r.Header.Get("Accept")
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(tc.method, "/mcp", nil)
			if tc.origAccept != "" {
				req.Header.Set("Accept", tc.origAccept)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equal(t, tc.wantAccept, recordedAccept)
		})
	}
}

func TestRequestLogger(t *testing.T) {
	var handled bool
	handler := RequestLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))

	req := httptest.NewRequest("POST", "/mcp/cap_v1_testsecret1234567890abcdef1234567890", strings.NewReader(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"targets_list"}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.True(t, handled)
	assert.Equal(t, http.StatusOK, rec.Code)
}


