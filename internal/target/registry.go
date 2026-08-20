package target

import (
	"context"
	"fmt"
	"sync"

	"github.com/teacat/mcp-execmesh/internal/config"
	"github.com/teacat/mcp-execmesh/internal/ssh"
)

// TargetRegistry provides interface for discovering and retrieving targets.
type TargetRegistry interface {
	List(ctx context.Context) []TargetSummary
	Get(ctx context.Context, id string) (*Target, error)
	Reload(cfg *config.Config) error
}

// Registry is the in-memory thread-safe registry of targets.
type Registry struct {
	mu      sync.RWMutex
	targets map[string]*Target
}

// NewRegistry initializes the target registry from configuration.
func NewRegistry(cfg *config.Config) (*Registry, error) {
	r := &Registry{
		targets: make(map[string]*Target),
	}
	if err := r.Reload(cfg); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload re-parses and re-initializes all targets from a fresh config.
func (r *Registry) Reload(cfg *config.Config) error {
	newMap := make(map[string]*Target)

	for _, tc := range cfg.Targets {
		authMethods, err := ssh.CreateAuthMethods(tc.Auth)
		if err != nil {
			return fmt.Errorf("target %q auth initialization failed: %w", tc.ID, err)
		}

		hostKeyCb, err := ssh.NewHostKeyCallback(tc.HostKey.KnownHostsFile, tc.HostKey.Strict)
		if err != nil {
			return fmt.Errorf("target %q host key initialization failed: %w", tc.ID, err)
		}

		t := &Target{
			ID:              tc.ID,
			Name:            tc.Name,
			Host:            tc.Host,
			Port:            tc.Port,
			User:            tc.User,
			AuthMethod:      authMethods,
			HostKeyCallback: hostKeyCb,
			DefaultCwd:      tc.DefaultCwd,
			Shell:           tc.Shell,
			Tags:            tc.Tags,
			Limits: TargetLimits{
				MaxExecSeconds: tc.Limits.MaxExecSeconds,
				MaxUploadBytes: tc.Limits.MaxUploadBytes,
			},
			Capabilities: TargetCapabilities{
				Exec:   tc.Capabilities.Exec,
				Upload: tc.Capabilities.Upload,
				Jobs:   tc.Capabilities.Jobs,
			},
			AllowedPaths: tc.AllowedPaths,
			Env:          tc.Env,
			Enabled:      tc.IsEnabled(),
			AuthRef:      tc.AuthRef,
			KnownHostRef: tc.KnownHostRef,
		}

		newMap[t.ID] = t
	}

	r.mu.Lock()
	r.targets = newMap
	r.mu.Unlock()

	return nil
}

// List returns safe summaries for all registered targets.
func (r *Registry) List(ctx context.Context) []TargetSummary {
	r.mu.RLock()
	defer r.mu.RUnlock()

	res := make([]TargetSummary, 0, len(r.targets))
	for _, t := range r.targets {
		res = append(res, t.Summary())
	}
	return res
}

// Get returns the Target for a given target ID.
func (r *Registry) Get(ctx context.Context, id string) (*Target, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	t, exists := r.targets[id]
	if !exists {
		return nil, fmt.Errorf("target %q not found", id)
	}
	return t, nil
}
