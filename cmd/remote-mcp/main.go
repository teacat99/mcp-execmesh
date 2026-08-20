package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/teacat99/mcp-execmesh/internal/audit"
	"github.com/teacat99/mcp-execmesh/internal/authcli"
	"github.com/teacat99/mcp-execmesh/internal/config"
	"github.com/teacat99/mcp-execmesh/internal/executor"
	"github.com/teacat99/mcp-execmesh/internal/jobs"
	"github.com/teacat99/mcp-execmesh/internal/management"
	servermcp "github.com/teacat99/mcp-execmesh/internal/mcp"
	"github.com/teacat99/mcp-execmesh/internal/security"
	"github.com/teacat99/mcp-execmesh/internal/ssh"
	"github.com/teacat99/mcp-execmesh/internal/target"
	"github.com/teacat99/mcp-execmesh/internal/transfer"
)

var (
	version   = "1.0.0"
	gitCommit = "unknown"
	buildDate = "unknown"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "auth" {
		if err := authcli.Run(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	var (
		configPath   = flag.String("config", "configs/config.example.yaml", "Path to YAML configuration file")
		validateOnly = flag.Bool("validate-only", false, "Validate configuration file and exit")
		showVersion  = flag.Bool("version", false, "Print version and build info")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("Remote Executor MCP (mcp-execmesh) v%s (commit: %s, built: %s)\n", version, gitCommit, buildDate)
		os.Exit(0)
	}

	// 1. Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// 2. Validate configuration
	if err := config.Validate(cfg, config.ValidationOptions{CheckFilesExist: true}); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration validation failed: %v\n", err)
		os.Exit(1)
	}

	if *validateOnly {
		fmt.Printf("Configuration %q is valid. %d target(s) configured.\n", *configPath, len(cfg.Targets))
		os.Exit(0)
	}

	// 3. Setup Structured Logging
	setupLogger(cfg.Server.LogLevel)
	slog.Info("starting remote-executor-mcp",
		"version", version,
		"config", *configPath,
		"targets_count", len(cfg.Targets),
		"listen", cfg.Server.Listen,
	)

	// 4. Initialize Target Registry & SSH Credentials
	registry, err := target.NewRegistry(cfg)
	if err != nil {
		slog.Error("failed to initialize target registry", "error", err)
		os.Exit(1)
	}

	// 5. Initialize Audit Logger
	auditLogger, err := audit.NewLogger(cfg.Security.AuditLogPath, cfg.Security.MaskSensitiveCommands)
	if err != nil {
		slog.Error("failed to initialize audit logger", "error", err)
		os.Exit(1)
	}
	defer auditLogger.Close()

	// 6. Initialize SSH Manager, Executor, Job Manager & Transfer Manager
	sshManager := ssh.NewManager(cfg.Runtime.MaxConcurrentSSH)
	policy := security.DefaultCommandPolicy()
	execEngine := executor.NewExecutor(sshManager, cfg.Runtime, auditLogger, policy)
	jobManager := jobs.NewManager(registry, sshManager, cfg.Jobs, cfg.Runtime, auditLogger, policy)
	transferManager := transfer.NewTransferManager(registry, sshManager, cfg.Security, cfg.Runtime, auditLogger, nil)

	// 7. Initialize Authenticator
	authenticator, err := security.NewAuthenticator(cfg.Server.Auth)
	if err != nil {
		slog.Error("failed to initialize server authenticator", "error", err)
		os.Exit(1)
	}

	legacyToken := cfg.Server.Auth.BearerToken
	if legacyToken == "" && cfg.Server.Auth.TokenFile != "" {
		legacyToken, err = config.LoadPassword(cfg.Server.Auth.TokenFile)
		if err != nil {
			slog.Error("failed to load auth token file", "error", err)
			os.Exit(1)
		}
	}
	authMgr, err := security.NewManager(security.ManagerOptions{
		CapabilityFile: cfg.Server.Auth.CapabilityRegistryFile,
		BearerFile:     cfg.Server.Auth.BearerRegistryFile,
		LegacyType:     cfg.Server.Auth.Type,
		LegacyBearer:   legacyToken,
		LegacyAPIKey:   legacyToken,
	})
	if err != nil {
		slog.Error("failed to initialize auth registry", "error", err)
		os.Exit(1)
	}

	mcpServer, err := servermcp.NewServer(cfg, registry, execEngine, jobManager, transferManager, authenticator, auditLogger)
	if err != nil {
		slog.Error("failed to create MCP server", "error", err)
		os.Exit(1)
	}
	mcpServer.UseAuthManager(authMgr)

	var liveCfg atomic.Pointer[config.Config]
	liveCfg.Store(cfg)
	reloadRuntime := func() error {
		newCfg, err := config.LoadConfig(*configPath)
		if err != nil {
			return err
		}
		if err := config.Validate(newCfg, config.ValidationOptions{CheckFilesExist: true}); err != nil {
			return err
		}
		if err := registry.Reload(newCfg); err != nil {
			return err
		}
		if err := authMgr.Reload(); err != nil {
			return err
		}
		liveCfg.Store(newCfg)
		return nil
	}
	adminSvc := management.NewService(registry, auditLogger, func() *config.Config {
		return liveCfg.Load()
	}, reloadRuntime, nil)
	mcpServer.AttachAdminTools(adminSvc)

	// 9. Start HTTP Server
	httpServer := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      mcpServer.Handler(),
		ReadTimeout:  cfg.Server.ReadTimeout.Duration(),
		WriteTimeout: cfg.Server.WriteTimeout.Duration(),
		IdleTimeout:  cfg.Server.IdleTimeout.Duration(),
	}

	serverErr := make(chan error, 1)
	go func() {
		slog.Info("MCP Streamable HTTP server listening", "address", cfg.Server.Listen, "mcp_endpoint", cfg.Server.MCPPath)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	// 10. Graceful Shutdown on Signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

	for {
		select {
		case err := <-serverErr:
			slog.Error("server failed unexpectedly", "error", err)
			os.Exit(1)
		case sig := <-sigChan:
			if sig == syscall.SIGHUP {
				slog.Info("reload signal received")
				if err := reloadRuntime(); err != nil {
					slog.Error("reload aborted, keeping previous runtime", "error", err)
					continue
				}
				slog.Info("reload completed")
				continue
			}
			slog.Info("shutdown signal received", "signal", sig.String())
			goto shutdown
		}
	}

shutdown:

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful server shutdown failed", "error", err)
	} else {
		slog.Info("server shutdown completed successfully")
	}
}

func setupLogger(levelStr string) {
	var lvl slog.Level
	switch levelStr {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: lvl,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			switch a.Key {
			case slog.MessageKey, "path", "url", "token":
				a.Value = slog.StringValue(security.RedactString(fmt.Sprint(a.Value.Any())))
			}
			return a
		},
	})
	slog.SetDefault(slog.New(handler))
}
