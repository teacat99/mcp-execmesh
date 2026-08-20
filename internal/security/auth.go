package security

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/teacat99/mcp-execmesh/internal/config"
)

// Principal represents the authenticated client identity after any auth method.
// MCP tools must authorize against Principal only, never Capability vs Bearer.
type Principal struct {
	ID       string              `json:"id,omitempty"`
	Subject  string              `json:"subject"`
	AuthType string              `json:"auth_type"`
	RemoteIP string              `json:"remote_ip"`
	Scopes   map[string]struct{} `json:"-"`
	Targets  map[string]struct{} `json:"-"`
}

func (p *Principal) HasScope(scope string) bool {
	if p == nil || isUnrestricted(p) {
		return true
	}
	_, ok := p.Scopes[scope]
	return ok
}

func (p *Principal) AllowsTarget(targetID string) bool {
	if p == nil || isUnrestricted(p) {
		return true
	}
	if _, ok := p.Targets["*"]; ok {
		return true
	}
	_, ok := p.Targets[targetID]
	return ok
}

func isUnrestricted(p *Principal) bool {
	if p.AuthType == "none" {
		return true
	}
	return len(p.Scopes) == 0 && len(p.Targets) == 0
}

// Authenticator provides client authentication for incoming HTTP/MCP requests.
type Authenticator interface {
	Authenticate(r *http.Request) (*Principal, error)
}

// NewAuthenticator creates an Authenticator matching server configuration.
func NewAuthenticator(cfg config.ServerAuthConfig) (Authenticator, error) {
	switch strings.ToLower(cfg.Type) {
	case "", "none":
		return &NoneAuthenticator{}, nil
	case "bearer":
		token := cfg.BearerToken
		if token == "" && cfg.TokenFile != "" {
			t, err := config.LoadPassword(cfg.TokenFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load auth token file: %w", err)
			}
			token = t
		}
		if token == "" {
			return nil, errors.New("bearer auth is configured but token is empty")
		}
		return &BearerAuthenticator{expectedToken: token}, nil
	case "api_key":
		token := cfg.BearerToken
		if token == "" && cfg.TokenFile != "" {
			t, err := config.LoadPassword(cfg.TokenFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load API key file: %w", err)
			}
			token = t
		}
		if token == "" {
			return nil, errors.New("api_key auth is configured but token is empty")
		}
		return &APIKeyAuthenticator{expectedKey: token}, nil
	default:
		return nil, fmt.Errorf("unsupported server auth type %q", cfg.Type)
	}
}

// NoneAuthenticator permits any request (for trusted local networks).
type NoneAuthenticator struct{}

func (a *NoneAuthenticator) Authenticate(r *http.Request) (*Principal, error) {
	return &Principal{
		Subject:  "anonymous",
		AuthType: "none",
		RemoteIP: r.RemoteAddr,
	}, nil
}

// BearerAuthenticator validates Authorization: Bearer <token>.
type BearerAuthenticator struct {
	expectedToken string
}

func (a *BearerAuthenticator) Authenticate(r *http.Request) (*Principal, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, errors.New("missing Authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, errors.New("invalid Authorization format, expected 'Bearer <token>'")
	}

	token := strings.TrimSpace(parts[1])
	if subtle.ConstantTimeCompare([]byte(token), []byte(a.expectedToken)) != 1 {
		return nil, errors.New("invalid bearer token")
	}

	return &Principal{
		Subject:  "bearer-user",
		AuthType: "bearer",
		RemoteIP: r.RemoteAddr,
	}, nil
}

// APIKeyAuthenticator checks X-API-Key or Bearer token.
type APIKeyAuthenticator struct {
	expectedKey string
}

func (a *APIKeyAuthenticator) Authenticate(r *http.Request) (*Principal, error) {
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		// Fallback to Bearer
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			apiKey = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		}
	}

	if apiKey == "" {
		return nil, errors.New("missing API key in X-API-Key or Authorization header")
	}

	if subtle.ConstantTimeCompare([]byte(apiKey), []byte(a.expectedKey)) != 1 {
		return nil, errors.New("invalid API key")
	}

	return &Principal{
		Subject:  "api-key-user",
		AuthType: "api_key",
		RemoteIP: r.RemoteAddr,
	}, nil
}
