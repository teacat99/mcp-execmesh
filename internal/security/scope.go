package security

import (
	"errors"
	"fmt"
)

const (
	ScopeTargetsRead      = "targets:read"
	ScopeExecRun          = "exec:run"
	ScopeJobsRead         = "jobs:read"
	ScopeJobsWrite        = "jobs:write"
	ScopeFilesRead        = "files:read"
	ScopeFilesWrite       = "files:write"
	ScopeAdminTargets     = "admin:targets"
	ScopeAdminCredentials = "admin:credentials"
	ScopeAdminKnownHosts  = "admin:known_hosts"
)

// DataPlaneScopes is the default grant for Capability create and legacy Bearer.
// Admin scopes are never implied.
var DataPlaneScopes = []string{
	ScopeTargetsRead,
	ScopeExecRun,
	ScopeJobsRead,
	ScopeJobsWrite,
	ScopeFilesRead,
	ScopeFilesWrite,
}

var AdminScopes = []string{
	ScopeAdminTargets,
	ScopeAdminCredentials,
	ScopeAdminKnownHosts,
}

var AllScopes = append(append([]string{}, DataPlaneScopes...), AdminScopes...)

var (
	ErrForbidden       = errors.New("forbidden")
	ErrTargetDenied    = errors.New("target not allowed")
	ErrMissingScope    = errors.New("missing required scope")
	ErrUnauthenticated = errors.New("unauthenticated")
)

// Authorize checks scope and optional target ACL. Nil / none principals remain unrestricted
// so existing trusted-local and unit tests keep working.
func Authorize(p *Principal, scope, targetID string) error {
	if p == nil || isUnrestricted(p) {
		return nil
	}
	if !p.HasScope(scope) {
		return fmt.Errorf("%w: %s", ErrMissingScope, scope)
	}
	if targetID != "" && !p.AllowsTarget(targetID) {
		return fmt.Errorf("%w: %s", ErrTargetDenied, targetID)
	}
	return nil
}

func AuthorizeAny(p *Principal, targetID string, scopes ...string) error {
	if p == nil || isUnrestricted(p) {
		return nil
	}
	var last error
	for _, s := range scopes {
		err := Authorize(p, s, targetID)
		if err == nil {
			return nil
		}
		last = err
		if errors.Is(err, ErrTargetDenied) {
			return err
		}
	}
	if last == nil {
		return fmt.Errorf("%w: %v", ErrMissingScope, scopes)
	}
	return last
}

func ValidScope(scope string) bool {
	for _, s := range AllScopes {
		if s == scope {
			return true
		}
	}
	return false
}

func ScopeSet(scopes []string) map[string]struct{} {
	out := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		if s == "" {
			continue
		}
		out[s] = struct{}{}
	}
	return out
}

func TargetSet(targets []string) map[string]struct{} {
	out := make(map[string]struct{}, len(targets))
	if len(targets) == 0 {
		out["*"] = struct{}{}
		return out
	}
	for _, t := range targets {
		if t == "" {
			continue
		}
		out[t] = struct{}{}
	}
	return out
}
