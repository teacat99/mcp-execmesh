package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/teacat99/mcp-execmesh/internal/audit"
	"github.com/teacat99/mcp-execmesh/internal/config"
	"github.com/teacat99/mcp-execmesh/internal/executor"
	"github.com/teacat99/mcp-execmesh/internal/jobs"
	"github.com/teacat99/mcp-execmesh/internal/management"
	"github.com/teacat99/mcp-execmesh/internal/mcp/tools"
	"github.com/teacat99/mcp-execmesh/internal/security"
	"github.com/teacat99/mcp-execmesh/internal/target"
	"github.com/teacat99/mcp-execmesh/internal/transfer"
)

const ServerInstructions = `This MCP manages configured remote hosts.

Use targets_list when the intended target is unknown.
Use target_info to inspect capabilities and limits of a specific target.
Admin principals may use target_add/update/enable/disable/remove, target_test, credentials_list, known_host_info/add/remove, and config_reload.
Use exec for short commands (e.g. status checks, git, short inspection).
Use exec_start for long-running builds, tests, or deployments.
Use job_status and job_output to monitor asynchronous jobs.
Use job_cancel to terminate running jobs.
Use file_push to transfer files from ChatGPT/URLs to remote hosts.
Use file_stat to inspect file/directory metadata on remote hosts.
Use file_hash to calculate cryptographic checksums (SHA256, SHA1, MD5) of remote files.
Use file_pull_prepare to generate one-time download tickets for remote files.

Never request SSH passwords or private keys from the user through tool arguments.
Do not assume an arbitrary hostname is reachable; only configured target IDs are supported.`

// Server encapsulates the MCP server instance, tools, and HTTP handlers.
type Server struct {
	mcpServer       *mcp.Server
	streamHandler   *mcp.StreamableHTTPHandler
	registry        target.TargetRegistry
	executor        executor.RemoteExecutor
	jobManager      jobs.JobManager
	transferManager transfer.TransferManager
	auth            security.Authenticator
	authMgr         *security.Manager
	auditLogger     *audit.Logger
	cfg             *config.Config
	requestSem      chan struct{}
	rateLimiter     *security.RateLimiter
}

// NewServer initializes the MCP server and registers all tools.
func NewServer(
	cfg *config.Config,
	registry target.TargetRegistry,
	execEngine executor.RemoteExecutor,
	jobMgr jobs.JobManager,
	transferMgr transfer.TransferManager,
	auth security.Authenticator,
	auditLogger *audit.Logger,
) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}

	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:        "remote-executor-mcp",
		Title:       "Remote Executor MCP",
		Description: "Remote execution and target management MCP gateway",
		Version:     "1.0.0",
	}, &mcp.ServerOptions{
		Instructions: ServerInstructions,
	})

	baseURL := cfg.PublicBaseURL()
	if baseURL == "" {
		slog.Warn("server.public_base_url is not set; file_pull_prepare will fail until configured")
	}

	// Register tools
	tools.RegisterTargetsTools(mcpServer, registry)
	tools.RegisterExecTool(mcpServer, registry, execEngine)
	if jobMgr != nil {
		tools.RegisterJobsTools(mcpServer, registry, jobMgr)
	}
	if transferMgr != nil {
		tools.RegisterTransferTools(mcpServer, transferMgr, baseURL)
	}

	maxReqs := cfg.Runtime.MaxConcurrentRequests
	if maxReqs <= 0 {
		maxReqs = 8
	}

	s := &Server{
		mcpServer:       mcpServer,
		registry:        registry,
		executor:        execEngine,
		jobManager:      jobMgr,
		transferManager: transferMgr,
		auth:            auth,
		auditLogger:     auditLogger,
		cfg:             cfg,
		requestSem:      make(chan struct{}, maxReqs),
		rateLimiter:     security.NewRateLimiter(cfg.Runtime.MaxRequestsPerMinute, cfg.Runtime.RequestBurst),
	}

	streamHandler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return s.mcpServer
	}, &mcp.StreamableHTTPOptions{
		// ChatGPT connector expects a finite application/json initialize body, not an open SSE stream.
		JSONResponse: true,
		// Each HTTP request is independently authenticated (Capability/Bearer); do not bind auth to MCP-Session-Id.
		Stateless: true,
		// Requests arrive via Docker/OpenResty with a public Host header.
		DisableLocalhostProtection: true,
	})

	s.streamHandler = streamHandler
	return s, nil
}

// AttachAdminTools registers control-plane target management tools.
func (s *Server) AttachAdminTools(svc *management.Service) {
	tools.RegisterAdminTools(s.mcpServer, svc)
}

// UseAuthManager attaches the capability/bearer digest registry (atomic reload).
func (s *Server) UseAuthManager(mgr *security.Manager) {
	s.authMgr = mgr
}

// MCPServer returns the underlying MCP server instance.
func (s *Server) MCPServer() *mcp.Server {
	return s.mcpServer
}

// Handler returns an http.Handler serving MCP Streamable HTTP, health checks, and auth.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Health endpoints
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)

	// File download endpoint for one-time signed tokens
	mux.HandleFunc("/files/", s.handleFileDownload)

	// MCP Endpoint
	mcpPath := s.cfg.Server.MCPPath
	if mcpPath == "" {
		mcpPath = "/mcp"
	}
	if !strings.HasPrefix(mcpPath, "/") {
		mcpPath = "/" + mcpPath
	}

	// Wrap stream handler with concurrency limiter. Auth is applied per-route.
	core := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case s.requestSem <- struct{}{}:
			defer func() { <-s.requestSem }()
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"code":    "TOO_MANY_REQUESTS",
					"message": "server concurrent request limit reached",
				},
			})
			return
		}
		s.streamHandler.ServeHTTP(w, r)
	})

	origins := s.cfg.Server.Auth.AllowedOrigins
	bearerChain := security.CORSAndOrigin(origins,
		security.BearerAuth(s.authMgr, s.auth, s.auditLogger, s.rateLimiter, core),
	)
	mux.Handle(mcpPath, bearerChain)

	if s.authMgr != nil && s.cfg.Server.Auth.CapabilityEnabled {
		capChain := security.CORSAndOrigin(origins,
			security.CapabilityAuth(s.authMgr, s.auditLogger, s.rateLimiter, core),
		)
		mux.Handle(mcpPath+"/", capChain)
	}

	mux.HandleFunc("/.well-known/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{"code": "NOT_FOUND", "message": "not found"},
		})
	})

	return recoveryMiddleware(mux)
}

func (s *Server) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ticket := strings.TrimPrefix(r.URL.Path, "/files/")
	ticket = strings.Trim(ticket, "/")
	if ticket == "" || s.transferManager == nil {
		writeDownloadNotFound(w)
		return
	}

	if err := s.transferManager.ServeDownload(w, r, ticket); err != nil {
		if errors.Is(err, transfer.ErrInvalidToken) {
			writeDownloadNotFound(w)
			return
		}
		slog.Error("failed to serve file download", "ticket_ref", transfer.TicketRef(ticket), "error", err)
		if !headersSent(w) {
			writeDownloadNotFound(w)
		}
	}
}

func writeDownloadNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    "NOT_FOUND",
			"message": "download ticket not found or expired",
		},
	})
}

func headersSent(w http.ResponseWriter) bool {
	// Best-effort: if Content-Type for download was set, body may have started.
	return w.Header().Get("Content-Type") == "application/octet-stream"
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	targetsCount := len(s.registry.List(r.Context()))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":        "ok",
		"targets_count": targetsCount,
	})
}

func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("recovered from panic in HTTP handler", "panic", rec, "path", security.RedactPath(r.URL.Path))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]any{
						"code":    "INTERNAL_ERROR",
						"message": "internal server error",
					},
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}
