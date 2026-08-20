package management

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/teacat99/mcp-execmesh/internal/audit"
	"github.com/teacat99/mcp-execmesh/internal/config"
	"github.com/teacat99/mcp-execmesh/internal/management/knownhosts"
	"github.com/teacat99/mcp-execmesh/internal/security"
	"github.com/teacat99/mcp-execmesh/internal/target"
)

type Reloader func() error

type Service struct {
	lock     *FileLock
	tester   Tester
	registry target.TargetRegistry
	audit    *audit.Logger
	reload   Reloader
	cfgFn    func() *config.Config
}

func NewService(registry target.TargetRegistry, auditLogger *audit.Logger, cfgFn func() *config.Config, reload Reloader, tester Tester) *Service {
	if tester == nil {
		tester = SSHTester{}
	}
	return &Service{
		registry: registry,
		audit:    auditLogger,
		cfgFn:    cfgFn,
		reload:   reload,
		tester:   tester,
	}
}

func (s *Service) cfg() *config.Config { return s.cfgFn() }

func (s *Service) ensureLock() *FileLock {
	if s.lock == nil {
		s.lock = NewFileLock(s.cfg().Server.DataDir)
	}
	return s.lock
}

func (s *Service) auditOp(p *security.Principal, tool, targetID, result, errMsg string, ms int64) {
	subject := ""
	if p != nil {
		subject = p.Subject
	}
	s.audit.Log(audit.Record{
		Subject:      subject,
		Tool:         tool,
		Target:       targetID,
		Result:       result,
		DurationMS:   ms,
		ErrorMessage: errMsg,
	})
}

func boolPtr(v bool) *bool { return &v }

type TargetAddInput struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Host         string         `json:"host"`
	Port         int            `json:"port"`
	User         string         `json:"user"`
	AuthRef      string         `json:"auth_ref"`
	KnownHostRef string         `json:"known_host_ref"`
	DefaultCwd   string         `json:"default_cwd"`
	Shell        string         `json:"shell"`
	Tags         []string       `json:"tags"`
	ValidateOnly bool           `json:"validate_only"`
	Limits       map[string]any `json:"limits,omitempty"`
}

type TargetUpdateInput struct {
	Target  string         `json:"target"`
	Changes map[string]any `json:"changes"`
}

func (s *Service) AddTarget(ctx context.Context, p *security.Principal, in TargetAddInput) (map[string]any, error) {
	start := time.Now()
	if err := security.Authorize(p, security.ScopeAdminTargets, in.ID); err != nil {
		s.auditOp(p, "target_add", in.ID, "denied", err.Error(), time.Since(start).Milliseconds())
		return nil, err
	}
	if strings.TrimSpace(in.ID) == "" || strings.TrimSpace(in.Host) == "" || strings.TrimSpace(in.User) == "" || strings.TrimSpace(in.AuthRef) == "" {
		return nil, fmt.Errorf("id, host, user, and auth_ref are required")
	}
	if in.Port == 0 {
		in.Port = 22
	}

	lock := s.ensureLock()
	if err := lock.Lock(); err != nil {
		return nil, err
	}
	defer lock.Unlock()

	cfg := s.cfg()
	for _, t := range cfg.Targets {
		if t.ID == in.ID {
			return nil, fmt.Errorf("target %q already exists", in.ID)
		}
	}
	cred, ok := config.CredentialByID(cfg, in.AuthRef)
	if !ok {
		return nil, fmt.Errorf("unknown credential %q", in.AuthRef)
	}
	khFile := s.defaultKnownHosts(cfg)
	if khFile == "" {
		return nil, fmt.Errorf("known_hosts file is not configured")
	}
	ref := in.KnownHostRef
	if ref == "" {
		ref = in.Host
	}
	entries, err := knownhosts.ParseFile(khFile)
	if err != nil {
		return nil, err
	}
	if !knownhosts.HasName(entries, ref) && !knownhosts.HasName(entries, in.Host) {
		return nil, fmt.Errorf("known_host_ref %q is not present in known_hosts", ref)
	}

	en := true
	tc := config.TargetConfig{
		ID:           in.ID,
		Name:         in.Name,
		Host:         in.Host,
		Port:         in.Port,
		User:         in.User,
		AuthRef:      in.AuthRef,
		KnownHostRef: ref,
		DefaultCwd:   in.DefaultCwd,
		Shell:        in.Shell,
		Tags:         in.Tags,
		Enabled:      &en,
		HostKey: config.HostKeyConfig{
			KnownHostsFile: khFile,
			Strict:         true,
		},
		Auth: config.TargetAuthConfig{
			Type:                     cred.Type,
			PrivateKeyFile:           cred.PrivateKeyFile,
			PrivateKeyPassphraseFile: cred.PrivateKeyPassphraseFile,
			PasswordFile:             cred.PasswordFile,
		},
	}
	tmp := *cfg
	tmp.Targets = append(append([]config.TargetConfig{}, cfg.Targets...), tc)
	config.ApplyTargetDefaults(&tmp)
	tc = tmp.Targets[len(tmp.Targets)-1]
	if err := config.Validate(&tmp, config.ValidationOptions{CheckFilesExist: true}); err != nil {
		s.auditOp(p, "target_add", in.ID, "error", err.Error(), time.Since(start).Milliseconds())
		return nil, err
	}

	testRes, err := s.tester.Test(ctx, tc)
	if err != nil {
		s.auditOp(p, "target_add", in.ID, "error", err.Error(), time.Since(start).Milliseconds())
		return nil, err
	}
	if !testRes.Success {
		s.auditOp(p, "target_add", in.ID, "error", testRes.Error, time.Since(start).Milliseconds())
		return map[string]any{"committed": false, "test": testRes}, fmt.Errorf("ssh validation failed: %s", testRes.Error)
	}
	if in.ValidateOnly {
		s.auditOp(p, "target_add", in.ID, "success", "validate_only", time.Since(start).Milliseconds())
		return map[string]any{"committed": false, "validate_only": true, "test": testRes}, nil
	}

	if strings.TrimSpace(cfg.TargetsFile) == "" {
		return nil, fmt.Errorf("targets_file is not configured; cannot persist target_add")
	}
	if _, err := BackupFile(cfg.TargetsFile, filepath.Join(cfg.Server.DataDir, "backups"), "targets"); err != nil {
		return nil, err
	}
	newTargets := append(append([]config.TargetConfig{}, cfg.Targets...), tc)
	if err := config.SaveTargetsFile(cfg.TargetsFile, stripResolvedAuth(newTargets)); err != nil {
		s.auditOp(p, "target_add", in.ID, "error", err.Error(), time.Since(start).Milliseconds())
		return nil, err
	}
	if err := s.reload(); err != nil {
		s.auditOp(p, "target_add", in.ID, "error", "reload: "+err.Error(), time.Since(start).Milliseconds())
		return nil, fmt.Errorf("target written but reload failed, previous runtime kept if reload is atomic: %w", err)
	}
	s.auditOp(p, "target_add", in.ID, "success", "", time.Since(start).Milliseconds())
	return map[string]any{"committed": true, "target": in.ID, "test": testRes}, nil
}

func stripResolvedAuth(targets []config.TargetConfig) []config.TargetConfig {
	out := make([]config.TargetConfig, len(targets))
	for i, t := range targets {
		cp := t
		if cp.AuthRef != "" {
			cp.Auth = config.TargetAuthConfig{}
		}
		out[i] = cp
	}
	return out
}

func (s *Service) defaultKnownHosts(cfg *config.Config) string {
	if strings.TrimSpace(cfg.Security.KnownHostsFile) != "" {
		return cfg.Security.KnownHostsFile
	}
	for _, t := range cfg.Targets {
		if t.HostKey.KnownHostsFile != "" {
			return t.HostKey.KnownHostsFile
		}
	}
	return ""
}

func (s *Service) mutateTargets(p *security.Principal, tool, id string, fn func([]config.TargetConfig) ([]config.TargetConfig, error)) error {
	start := time.Now()
	if err := security.Authorize(p, security.ScopeAdminTargets, id); err != nil {
		s.auditOp(p, tool, id, "denied", err.Error(), time.Since(start).Milliseconds())
		return err
	}
	lock := s.ensureLock()
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Unlock()
	cfg := s.cfg()
	if strings.TrimSpace(cfg.TargetsFile) == "" {
		return fmt.Errorf("targets_file is not configured")
	}
	next, err := fn(append([]config.TargetConfig{}, cfg.Targets...))
	if err != nil {
		s.auditOp(p, tool, id, "error", err.Error(), time.Since(start).Milliseconds())
		return err
	}
	if _, err := BackupFile(cfg.TargetsFile, filepath.Join(cfg.Server.DataDir, "backups"), "targets"); err != nil {
		return err
	}
	if err := config.SaveTargetsFile(cfg.TargetsFile, stripResolvedAuth(next)); err != nil {
		s.auditOp(p, tool, id, "error", err.Error(), time.Since(start).Milliseconds())
		return err
	}
	if err := s.reload(); err != nil {
		s.auditOp(p, tool, id, "error", "reload: "+err.Error(), time.Since(start).Milliseconds())
		return err
	}
	s.auditOp(p, tool, id, "success", "", time.Since(start).Milliseconds())
	return nil
}

func (s *Service) setEnabled(p *security.Principal, id string, enabled bool, tool string) error {
	return s.mutateTargets(p, tool, id, func(targets []config.TargetConfig) ([]config.TargetConfig, error) {
		for i := range targets {
			if targets[i].ID == id {
				targets[i].Enabled = boolPtr(enabled)
				return targets, nil
			}
		}
		return nil, fmt.Errorf("target %q not found", id)
	})
}

func (s *Service) EnableTarget(p *security.Principal, id string) error {
	return s.setEnabled(p, id, true, "target_enable")
}

func (s *Service) DisableTarget(p *security.Principal, id string) error {
	return s.setEnabled(p, id, false, "target_disable")
}

func (s *Service) RemoveTarget(p *security.Principal, id string) error {
	return s.mutateTargets(p, "target_remove", id, func(targets []config.TargetConfig) ([]config.TargetConfig, error) {
		out := make([]config.TargetConfig, 0, len(targets))
		found := false
		for _, t := range targets {
			if t.ID == id {
				found = true
				continue
			}
			out = append(out, t)
		}
		if !found {
			return nil, fmt.Errorf("target %q not found", id)
		}
		return out, nil
	})
}

func (s *Service) UpdateTarget(ctx context.Context, p *security.Principal, in TargetUpdateInput) error {
	start := time.Now()
	if err := security.Authorize(p, security.ScopeAdminTargets, in.Target); err != nil {
		s.auditOp(p, "target_update", in.Target, "denied", err.Error(), time.Since(start).Milliseconds())
		return err
	}
	needsTest := false
	for _, k := range []string{"host", "port", "user", "auth_ref", "known_host_ref"} {
		if _, ok := in.Changes[k]; ok {
			needsTest = true
		}
	}
	return s.mutateTargets(p, "target_update", in.Target, func(targets []config.TargetConfig) ([]config.TargetConfig, error) {
		idx := -1
		for i := range targets {
			if targets[i].ID == in.Target {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil, fmt.Errorf("target %q not found", in.Target)
		}
		if _, ok := in.Changes["id"]; ok {
			return nil, fmt.Errorf("target id cannot be changed")
		}
		t := targets[idx]
		if v, ok := in.Changes["name"].(string); ok {
			t.Name = v
		}
		if v, ok := in.Changes["default_cwd"].(string); ok {
			t.DefaultCwd = v
		}
		if v, ok := in.Changes["shell"].(string); ok {
			t.Shell = v
		}
		if v, ok := in.Changes["host"].(string); ok {
			t.Host = v
		}
		if v, ok := in.Changes["user"].(string); ok {
			t.User = v
		}
		if v, ok := in.Changes["auth_ref"].(string); ok {
			t.AuthRef = v
		}
		if v, ok := in.Changes["known_host_ref"].(string); ok {
			t.KnownHostRef = v
		}
		switch v := in.Changes["port"].(type) {
		case float64:
			t.Port = int(v)
		case int:
			t.Port = v
		}
		if v, ok := in.Changes["tags"].([]any); ok {
			tags := make([]string, 0, len(v))
			for _, item := range v {
				if s, ok := item.(string); ok {
					tags = append(tags, s)
				}
			}
			t.Tags = tags
		}
		cfg := s.cfg()
		if t.AuthRef != "" {
			cred, ok := config.CredentialByID(cfg, t.AuthRef)
			if !ok {
				return nil, fmt.Errorf("unknown credential %q", t.AuthRef)
			}
			t.Auth = config.TargetAuthConfig{
				Type: cred.Type, PrivateKeyFile: cred.PrivateKeyFile,
				PrivateKeyPassphraseFile: cred.PrivateKeyPassphraseFile,
				PasswordFile:             cred.PasswordFile,
			}
		}
		if t.HostKey.KnownHostsFile == "" {
			t.HostKey.KnownHostsFile = s.defaultKnownHosts(cfg)
			t.HostKey.Strict = true
		}
		tmp := config.Config{Runtime: cfg.Runtime, Targets: []config.TargetConfig{t}}
		config.ApplyTargetDefaults(&tmp)
		t = tmp.Targets[0]
		if needsTest {
			res, err := s.tester.Test(ctx, t)
			if err != nil {
				return nil, err
			}
			if !res.Success {
				return nil, fmt.Errorf("ssh validation failed: %s", res.Error)
			}
		}
		targets[idx] = t
		return targets, nil
	})
}

func (s *Service) TestTarget(ctx context.Context, p *security.Principal, id string) (*TestResult, error) {
	start := time.Now()
	if err := security.Authorize(p, security.ScopeAdminTargets, id); err != nil {
		s.auditOp(p, "target_test", id, "denied", err.Error(), time.Since(start).Milliseconds())
		return nil, err
	}
	cfg := s.cfg()
	var tc *config.TargetConfig
	for i := range cfg.Targets {
		if cfg.Targets[i].ID == id {
			tc = &cfg.Targets[i]
			break
		}
	}
	if tc == nil {
		return nil, fmt.Errorf("target %q not found", id)
	}
	res, err := s.tester.Test(ctx, *tc)
	if err != nil {
		s.auditOp(p, "target_test", id, "error", err.Error(), time.Since(start).Milliseconds())
		return nil, err
	}
	result := "success"
	if !res.Success {
		result = "error"
	}
	s.auditOp(p, "target_test", id, result, res.Error, time.Since(start).Milliseconds())
	return res, nil
}

func (s *Service) ListCredentials(p *security.Principal) ([]map[string]any, error) {
	if err := security.AuthorizeAny(p, "", security.ScopeAdminCredentials, security.ScopeAdminTargets); err != nil {
		s.auditOp(p, "credentials_list", "", "denied", err.Error(), 0)
		return nil, err
	}
	cfg := s.cfg()
	out := make([]map[string]any, 0, len(cfg.Credentials))
	for _, c := range cfg.Credentials {
		available := false
		switch c.Type {
		case "private_key":
			available = fileReadable(c.PrivateKeyFile)
		case "password":
			available = fileReadable(c.PasswordFile)
		}
		out = append(out, map[string]any{
			"id":        c.ID,
			"type":      c.Type,
			"available": available,
		})
	}
	s.auditOp(p, "credentials_list", "", "success", "", 0)
	return out, nil
}

func fileReadable(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func (s *Service) KnownHostInfo(p *security.Principal, name string) ([]knownhosts.Entry, error) {
	if err := security.Authorize(p, security.ScopeAdminKnownHosts, ""); err != nil {
		if err2 := security.Authorize(p, security.ScopeAdminTargets, ""); err2 != nil {
			s.auditOp(p, "known_host_info", name, "denied", err.Error(), 0)
			return nil, err
		}
	}
	cfg := s.cfg()
	path := s.defaultKnownHosts(cfg)
	if path == "" {
		return nil, fmt.Errorf("known_hosts file is not configured")
	}
	entries, err := knownhosts.ParseFile(path)
	if err != nil {
		return nil, err
	}
	if name != "" {
		entries = knownhosts.FilterByName(entries, name)
	}
	s.auditOp(p, "known_host_info", name, "success", "", 0)
	return entries, nil
}

func (s *Service) KnownHostAdd(p *security.Principal, name, algorithm, publicKey string) error {
	start := time.Now()
	if err := security.Authorize(p, security.ScopeAdminKnownHosts, ""); err != nil {
		s.auditOp(p, "known_host_add", name, "denied", err.Error(), time.Since(start).Milliseconds())
		return err
	}
	lock := s.ensureLock()
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Unlock()
	path := s.defaultKnownHosts(s.cfg())
	if path == "" {
		return fmt.Errorf("known_hosts file is not configured")
	}
	if _, err := BackupFile(path, filepath.Join(s.cfg().Server.DataDir, "backups"), "known_hosts"); err != nil {
		return err
	}
	if err := knownhosts.AppendKey(path, name, algorithm, publicKey); err != nil {
		s.auditOp(p, "known_host_add", name, "error", err.Error(), time.Since(start).Milliseconds())
		return err
	}
	s.auditOp(p, "known_host_add", name, "success", "", time.Since(start).Milliseconds())
	return nil
}

func (s *Service) KnownHostRemove(p *security.Principal, name string) error {
	start := time.Now()
	if err := security.Authorize(p, security.ScopeAdminKnownHosts, ""); err != nil {
		s.auditOp(p, "known_host_remove", name, "denied", err.Error(), time.Since(start).Milliseconds())
		return err
	}
	lock := s.ensureLock()
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Unlock()
	path := s.defaultKnownHosts(s.cfg())
	if _, err := BackupFile(path, filepath.Join(s.cfg().Server.DataDir, "backups"), "known_hosts"); err != nil {
		return err
	}
	if err := knownhosts.RemoveName(path, name); err != nil {
		s.auditOp(p, "known_host_remove", name, "error", err.Error(), time.Since(start).Milliseconds())
		return err
	}
	s.auditOp(p, "known_host_remove", name, "success", "", time.Since(start).Milliseconds())
	return nil
}

func (s *Service) ConfigReload(p *security.Principal) error {
	start := time.Now()
	if err := security.Authorize(p, security.ScopeAdminTargets, ""); err != nil {
		s.auditOp(p, "config_reload", "", "denied", err.Error(), time.Since(start).Milliseconds())
		return err
	}
	if err := s.reload(); err != nil {
		s.auditOp(p, "config_reload", "", "error", err.Error(), time.Since(start).Milliseconds())
		return err
	}
	s.auditOp(p, "config_reload", "", "success", "", time.Since(start).Milliseconds())
	return nil
}
