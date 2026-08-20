package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var targetIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// ValidationOptions controls extra validation steps.
type ValidationOptions struct {
	CheckFilesExist bool
}

// Validate checks the configuration for correctness and security compliance.
func Validate(cfg *Config, opts ...ValidationOptions) error {
	if cfg == nil {
		return errors.New("configuration is nil")
	}

	opt := ValidationOptions{CheckFilesExist: false}
	if len(opts) > 0 {
		opt = opts[0]
	}

	var errs []string

	// 1. Version
	if cfg.Version != 1 {
		errs = append(errs, fmt.Sprintf("unsupported config version: %d (expected 1)", cfg.Version))
	}

	// 2. Server validation
	if strings.TrimSpace(cfg.Server.Listen) == "" {
		errs = append(errs, "server.listen cannot be empty")
	}
	if strings.TrimSpace(cfg.Server.MCPPath) == "" || !strings.HasPrefix(cfg.Server.MCPPath, "/") {
		errs = append(errs, "server.mcp_path must start with '/' and cannot be empty")
	}
	switch strings.ToLower(cfg.Server.LogLevel) {
	case "", "debug", "info", "warn", "error":
		// valid
	default:
		errs = append(errs, fmt.Sprintf("invalid server.log_level %q (expected debug/info/warn/error)", cfg.Server.LogLevel))
	}
	switch strings.ToLower(cfg.Server.Auth.Type) {
	case "", "none", "bearer", "api_key":
		// valid
	default:
		errs = append(errs, fmt.Sprintf("invalid server.auth.type %q (expected none/bearer/api_key)", cfg.Server.Auth.Type))
	}
	if cfg.Server.Auth.CapabilityEnabled && strings.TrimSpace(cfg.Server.Auth.CapabilityRegistryFile) == "" {
		errs = append(errs, "server.auth.capability_registry_file is required when capability_enabled is true")
	}
	if pub := cfg.PublicBaseURL(); pub != "" {
		if _, err := ValidatePublicBaseURL(pub, true); err != nil {
			errs = append(errs, fmt.Sprintf("public_base_url: %v", err))
		}
	}

	// 3. Runtime limits
	if cfg.Runtime.MaxConcurrentRequests < 1 {
		errs = append(errs, "runtime.max_concurrent_requests must be at least 1")
	}
	if cfg.Runtime.MaxConcurrentSSH < 1 {
		errs = append(errs, "runtime.max_concurrent_ssh must be at least 1")
	}
	if cfg.Runtime.MaxConcurrentTransfers < 1 {
		errs = append(errs, "runtime.max_concurrent_transfers must be at least 1")
	}
	if cfg.Runtime.MaxStdoutBytes < 1024 {
		errs = append(errs, "runtime.max_stdout_bytes must be at least 1024 bytes (1 KiB)")
	}
	if cfg.Runtime.MaxStderrBytes < 1024 {
		errs = append(errs, "runtime.max_stderr_bytes must be at least 1024 bytes (1 KiB)")
	}
	if cfg.Runtime.TransferBufferBytes < 1024 {
		errs = append(errs, "runtime.transfer_buffer_bytes must be at least 1024 bytes")
	}

	// 4. Targets validation
	seenIDs := make(map[string]struct{})
	for i, t := range cfg.Targets {
		prefix := fmt.Sprintf("targets[%d] (%s)", i, t.ID)

		// Target ID
		if strings.TrimSpace(t.ID) == "" {
			errs = append(errs, fmt.Sprintf("targets[%d].id cannot be empty", i))
		} else if !targetIDRegex.MatchString(t.ID) {
			errs = append(errs, fmt.Sprintf("%s: target ID %q contains invalid characters (only alphanumeric, '-' and '_' allowed)", prefix, t.ID))
		} else if _, seen := seenIDs[t.ID]; seen {
			errs = append(errs, fmt.Sprintf("%s: duplicate target ID %q", prefix, t.ID))
		} else {
			seenIDs[t.ID] = struct{}{}
		}

		// Host & Port
		if strings.TrimSpace(t.Host) == "" {
			errs = append(errs, fmt.Sprintf("%s: host cannot be empty", prefix))
		}
		if t.Port < 1 || t.Port > 65535 {
			errs = append(errs, fmt.Sprintf("%s: port %d out of valid range 1-65535", prefix, t.Port))
		}

		// User
		if strings.TrimSpace(t.User) == "" {
			errs = append(errs, fmt.Sprintf("%s: user cannot be empty", prefix))
		}

		// Auth: either inline auth.type or auth_ref (resolved before Validate).
		if strings.TrimSpace(t.AuthRef) != "" && strings.TrimSpace(t.Auth.Type) == "" {
			errs = append(errs, fmt.Sprintf("%s: auth_ref %q did not resolve to a credential", prefix, t.AuthRef))
		}
		switch t.Auth.Type {
		case "private_key":
			if strings.TrimSpace(t.Auth.PrivateKeyFile) == "" {
				errs = append(errs, fmt.Sprintf("%s: auth.private_key_file is required for private_key auth", prefix))
			} else if opt.CheckFilesExist {
				if err := checkFileReadable(t.Auth.PrivateKeyFile); err != nil {
					errs = append(errs, fmt.Sprintf("%s: auth.private_key_file error: %v", prefix, err))
				}
				if t.Auth.PrivateKeyPassphraseFile != "" {
					if err := checkFileReadable(t.Auth.PrivateKeyPassphraseFile); err != nil {
						errs = append(errs, fmt.Sprintf("%s: auth.private_key_passphrase_file error: %v", prefix, err))
					}
				}
			}
		case "password":
			if strings.TrimSpace(t.Auth.PasswordFile) == "" {
				errs = append(errs, fmt.Sprintf("%s: auth.password_file is required for password auth", prefix))
			} else if opt.CheckFilesExist {
				if err := checkFileReadable(t.Auth.PasswordFile); err != nil {
					errs = append(errs, fmt.Sprintf("%s: auth.password_file error: %v", prefix, err))
				}
			}
		default:
			errs = append(errs, fmt.Sprintf("%s: unsupported auth.type %q (expected 'private_key' or 'password')", prefix, t.Auth.Type))
		}

		// Host Key check
		if cfg.Security.RequireKnownHosts || t.HostKey.Strict {
			if strings.TrimSpace(t.HostKey.KnownHostsFile) == "" {
				errs = append(errs, fmt.Sprintf("%s: host_key.known_hosts_file is required when strict host key check is enabled", prefix))
			} else if opt.CheckFilesExist {
				if err := checkFileReadable(t.HostKey.KnownHostsFile); err != nil {
					errs = append(errs, fmt.Sprintf("%s: host_key.known_hosts_file error: %v", prefix, err))
				}
			}
		}

		// Shell
		if strings.TrimSpace(t.Shell) == "" {
			errs = append(errs, fmt.Sprintf("%s: shell cannot be empty", prefix))
		}

		// DefaultCwd (if given, should be cleaned absolute path)
		if t.DefaultCwd != "" {
			clean := filepath.Clean(t.DefaultCwd)
			if !strings.HasPrefix(clean, "/") {
				errs = append(errs, fmt.Sprintf("%s: default_cwd %q must be an absolute path", prefix, t.DefaultCwd))
			}
		}

		// AllowedPaths
		for j, p := range t.AllowedPaths {
			clean := filepath.Clean(p)
			if !strings.HasPrefix(clean, "/") {
				errs = append(errs, fmt.Sprintf("%s: allowed_paths[%d] %q must be an absolute path", prefix, j, p))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation failed with %d error(s):\n - %s", len(errs), strings.Join(errs, "\n - "))
	}

	return nil
}

func checkFileReadable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("path %q is a directory, not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	_ = f.Close()
	return nil
}

// ValidateHostPort checks if a host:port string is syntactically valid.
func ValidateHostPort(host string, port int) error {
	if host == "" {
		return errors.New("host cannot be empty")
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d is out of range [1, 65535]", port)
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	_, _, err := net.SplitHostPort(addr)
	return err
}
