package security

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/teacat99/mcp-execmesh/internal/audit"
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

// NormalizeAccept ensures MCP POST requests satisfy the Go MCP SDK's streamableAccepts requirement
// (must contain both 'application/json' and 'text/event-stream' or '*/*') without causing 400 Bad Request
// for standard clients, ChatGPT actions, or curl that only send 'Accept: application/json' or omit Accept.
func NormalizeAccept(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			accept := r.Header.Get("Accept")
			if accept == "" || (!strings.Contains(accept, "application/json") && !strings.Contains(accept, "*/*")) ||
				(!strings.Contains(accept, "text/event-stream") && !strings.Contains(accept, "*/*")) {
				r.Header.Set("Accept", "application/json, text/event-stream")
			}
		}
		next.ServeHTTP(w, r)
	})
}

type statusResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (w *statusResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusResponseWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytesWritten += int64(n)
	return n, err
}

func (w *statusResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

type mcpRequestSnippet struct {
	Method string `json:"method"`
	Params struct {
		Name string `json:"name"`
	} `json:"params"`
}

func sniffMCPMethod(r *http.Request) (mcpMethod string, toolName string) {
	if r.Method != http.MethodPost || r.Body == nil {
		return "", ""
	}
	var peekBuf [2048]byte
	n, err := io.ReadFull(r.Body, peekBuf[:])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "", ""
	}
	r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(peekBuf[:n]), r.Body))

	var snippet mcpRequestSnippet
	if err := json.Unmarshal(peekBuf[:n], &snippet); err == nil {
		return snippet.Method, snippet.Params.Name
	}
	return "", ""
}

// RequestLogger logs high-level structured diagnostics for MCP HTTP requests with path redaction.
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		mcpMethod, toolName := sniffMCPMethod(r)

		sw := &statusResponseWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)

		duration := time.Since(start)
		status := sw.statusCode
		if status == 0 {
			status = http.StatusOK
		}

		redactedPath := RedactPath(r.URL.Path)
		attrs := []any{
			"method", r.Method,
			"path", redactedPath,
			"status", status,
			"duration_ms", duration.Milliseconds(),
			"remote_ip", r.RemoteAddr,
		}
		if mcpMethod != "" {
			attrs = append(attrs, "mcp_method", mcpMethod)
		}
		if toolName != "" {
			attrs = append(attrs, "tool", toolName)
		}

		if status >= 500 {
			slog.Error("mcp request", attrs...)
		} else if status >= 400 {
			slog.Warn("mcp request", attrs...)
		} else {
			slog.Info("mcp request", attrs...)
		}
	})
}

