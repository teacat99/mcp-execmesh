package security

import (
	"net/http"
	"strings"
)

const corsAllowHeaders = "Accept, Content-Type, Authorization, X-API-Key, MCP-Protocol-Version, Mcp-Session-Id, MCP-Session-Id, Last-Event-ID"

func writeCORSHeaders(w http.ResponseWriter, origin string) {
	if origin == "" {
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Vary", "Origin")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", corsAllowHeaders)
	w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id, MCP-Session-Id, MCP-Protocol-Version")
	w.Header().Set("Access-Control-Max-Age", "600")
}

// CORSAndOrigin handles browser preflight before authentication.
// OPTIONS never requires Capability/Bearer. Disallowed Origin is 403.
func CORSAndOrigin(allowed []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" && !OriginAllowed(allowed, origin) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		writeCORSHeaders(w, origin)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
