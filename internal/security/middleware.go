package security

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/teacat/mcp-execmesh/internal/audit"
)

type ctxKey string

const PrincipalContextKey ctxKey = "mcp_principal"

func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	ctx = context.WithValue(ctx, PrincipalContextKey, p)
	ctx = context.WithValue(ctx, "mcp_principal", p) // compatibility with existing tools
	return ctx
}

func PrincipalFromContext(ctx context.Context) *Principal {
	if ctx == nil {
		return nil
	}
	if p, ok := ctx.Value(PrincipalContextKey).(*Principal); ok {
		return p
	}
	if p, ok := ctx.Value("mcp_principal").(*Principal); ok {
		return p
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeNotFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]any{
		"error": map[string]any{
			"code":    "NOT_FOUND",
			"message": "not found",
		},
	})
}

func writeUnauthorized(w http.ResponseWriter) {
	writeJSON(w, http.StatusUnauthorized, map[string]any{
		"error": map[string]any{
			"code":    "UNAUTHORIZED",
			"message": "authentication required",
		},
	})
}

func auditAuthFailure(auditLogger *audit.Logger, reason, remoteIP, authType string) {
	if auditLogger == nil {
		return
	}
	auditLogger.Log(audit.Record{
		Tool:         "auth",
		Result:       "denied",
		ErrorMessage: reason,
		Subject:      authType,
	})
	_ = remoteIP
}

// CapabilityAuth verifies /mcp/{capability} on every GET/POST/DELETE, then rewrites path to /mcp.
func CapabilityAuth(mgr *Manager, auditLogger *audit.Logger, limiter *RateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow(RateLimitKey(nil, r)) {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error": map[string]any{"code": "TOO_MANY_REQUESTS", "message": "rate limit exceeded"},
			})
			return
		}
		if strings.Contains(r.URL.RawQuery, "token=") || strings.Contains(r.URL.RawQuery, "capability=") {
			writeNotFound(w)
			return
		}
		token, err := ParseCapabilityPath(r.URL.Path)
		if err != nil {
			auditAuthFailure(auditLogger, "invalid_capability_path", r.RemoteAddr, "capability")
			writeNotFound(w)
			return
		}
		principal, err := mgr.VerifyCapability(token, r.RemoteAddr)
		if err != nil {
			auditAuthFailure(auditLogger, "invalid_or_revoked_capability", r.RemoteAddr, "capability")
			writeNotFound(w)
			return
		}
		clone := r.Clone(WithPrincipal(r.Context(), principal))
		clone.URL.Path = "/mcp"
		clone.URL.RawPath = ""
		next.ServeHTTP(w, clone)
	})
}

// BearerAuth authenticates /mcp using Authorization or X-API-Key against the registry / legacy fallback.
func BearerAuth(mgr *Manager, fallback Authenticator, auditLogger *audit.Logger, limiter *RateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attach := func(p *Principal) {
			ctx := WithPrincipal(r.Context(), p)
			if !limiter.Allow(RateLimitKey(p, r)) {
				writeJSON(w, http.StatusTooManyRequests, map[string]any{
					"error": map[string]any{"code": "TOO_MANY_REQUESTS", "message": "rate limit exceeded"},
				})
				return
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		if mgr != nil {
			token := extractBearerOrAPIKey(r)
			if token != "" {
				principal, err := mgr.VerifyBearer(token, r.RemoteAddr)
				if err == nil {
					attach(principal)
					return
				}
			}
		}
		if fallback != nil {
			provided := extractBearerOrAPIKey(r)
			if mgr != nil && provided != "" {
				if _, isNone := fallback.(*NoneAuthenticator); !isNone {
					if !limiter.Allow(RateLimitKey(nil, r)) {
						writeJSON(w, http.StatusTooManyRequests, map[string]any{
							"error": map[string]any{"code": "TOO_MANY_REQUESTS", "message": "rate limit exceeded"},
						})
						return
					}
					auditAuthFailure(auditLogger, "bearer_failed", r.RemoteAddr, "bearer")
					writeUnauthorized(w)
					return
				}
			}
			principal, err := fallback.Authenticate(r)
			if err != nil {
				if !limiter.Allow(RateLimitKey(nil, r)) {
					writeJSON(w, http.StatusTooManyRequests, map[string]any{
						"error": map[string]any{"code": "TOO_MANY_REQUESTS", "message": "rate limit exceeded"},
					})
					return
				}
				auditAuthFailure(auditLogger, "bearer_failed", r.RemoteAddr, "bearer")
				writeUnauthorized(w)
				return
			}
			attach(principal)
			return
		}
		auditAuthFailure(auditLogger, "bearer_missing", r.RemoteAddr, "bearer")
		writeUnauthorized(w)
	})
}

func extractBearerOrAPIKey(r *http.Request) string {
	if k := strings.TrimSpace(r.Header.Get("X-API-Key")); k != "" {
		return k
	}
	authHeader := r.Header.Get("Authorization")
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return strings.TrimSpace(parts[1])
	}
	return ""
}
