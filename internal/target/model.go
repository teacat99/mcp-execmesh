package target

import (
	"fmt"
	"time"

	"github.com/teacat99/mcp-execmesh/internal/ssh"
	cryptossh "golang.org/x/crypto/ssh"
)

// Target represents a validated target with resolved SSH credentials in memory.
type Target struct {
	ID              string
	Name            string
	Host            string
	Port            int
	User            string
	AuthMethod      []cryptossh.AuthMethod
	HostKeyCallback cryptossh.HostKeyCallback
	DefaultCwd      string
	Shell           string
	Tags            []string
	Limits          TargetLimits
	Capabilities    TargetCapabilities
	AllowedPaths    []string
	Env             map[string]string
	Enabled         bool
	AuthRef         string
	KnownHostRef    string
}

// TargetLimits represents resource and execution limits for a target.
type TargetLimits struct {
	MaxExecSeconds int
	MaxUploadBytes int64
}

// TargetCapabilities defines allowed features on this target.
type TargetCapabilities struct {
	Exec   bool `json:"exec"`
	Upload bool `json:"upload"`
	Jobs   bool `json:"jobs"`
}

// TargetSummary is a safe summary returned by targets_list.
type TargetSummary struct {
	ID           string             `json:"id"`
	Name         string             `json:"name"`
	Tags         []string           `json:"tags"`
	DefaultCwd   string             `json:"default_cwd,omitempty"`
	Capabilities TargetCapabilities `json:"capabilities"`
	Enabled      bool               `json:"enabled"`
}

// TargetDetail is detailed information returned by target_info.
type TargetDetail struct {
	ID           string             `json:"id"`
	Name         string             `json:"name"`
	Tags         []string           `json:"tags"`
	DefaultCwd   string             `json:"default_cwd,omitempty"`
	Shell        string             `json:"shell,omitempty"`
	Capabilities TargetCapabilities `json:"capabilities"`
	Limits       TargetLimitsDTO    `json:"limits"`
	Enabled      bool               `json:"enabled"`
	AuthRef      string             `json:"auth_ref,omitempty"`
	KnownHostRef string             `json:"known_host_ref,omitempty"`
}

// TargetLimitsDTO is the public limits view in target_info.
type TargetLimitsDTO struct {
	MaxExecSeconds int   `json:"max_exec_seconds"`
	MaxUploadBytes int64 `json:"max_upload_bytes"`
}

// Address returns host:port formatted string.
func (t *Target) Address() string {
	return fmt.Sprintf("%s:%d", t.Host, t.Port)
}

// Summary returns the safe summary representation.
func (t *Target) Summary() TargetSummary {
	return TargetSummary{
		ID:           t.ID,
		Name:         t.Name,
		Tags:         t.Tags,
		DefaultCwd:   t.DefaultCwd,
		Capabilities: t.Capabilities,
		Enabled:      t.Enabled,
	}
}

// Detail returns the detailed representation for target_info.
func (t *Target) Detail() TargetDetail {
	return TargetDetail{
		ID:           t.ID,
		Name:         t.Name,
		Tags:         t.Tags,
		DefaultCwd:   t.DefaultCwd,
		Shell:        t.Shell,
		Capabilities: t.Capabilities,
		Limits: TargetLimitsDTO{
			MaxExecSeconds: t.Limits.MaxExecSeconds,
			MaxUploadBytes: t.Limits.MaxUploadBytes,
		},
		Enabled:      t.Enabled,
		AuthRef:      t.AuthRef,
		KnownHostRef: t.KnownHostRef,
	}
}

// RequireActive rejects disabled targets for data-plane tools.
func (t *Target) RequireActive() error {
	if t == nil {
		return fmt.Errorf("target not found")
	}
	if !t.Enabled {
		return fmt.Errorf("target %q is disabled", t.ID)
	}
	return nil
}

// ConnectOptions builds ssh.ConnectOptions from the target configuration.
func (t *Target) ConnectOptions(timeout time.Duration) ssh.ConnectOptions {
	return ssh.ConnectOptions{
		Address:         t.Address(),
		User:            t.User,
		AuthMethods:     t.AuthMethod,
		HostKeyCallback: t.HostKeyCallback,
		Shell:           t.Shell,
		Timeout:         timeout,
	}
}
