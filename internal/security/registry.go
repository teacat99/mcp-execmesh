package security

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

const MaxActiveTokens = 2

type TokenRecord struct {
	TokenSHA256 string `yaml:"token_sha256"`
	CreatedAt   string `yaml:"created_at,omitempty"`
}

type CapabilityFile struct {
	Version      int                  `yaml:"version"`
	Capabilities []CapabilityFileEntry `yaml:"capabilities"`
}

type CapabilityFileEntry struct {
	ID           string        `yaml:"id"`
	Family       string        `yaml:"family,omitempty"`
	TokenSHA256  string        `yaml:"token_sha256,omitempty"`
	ActiveTokens []TokenRecord `yaml:"active_tokens,omitempty"`
	Enabled      bool          `yaml:"enabled"`
	Subject      string        `yaml:"subject"`
	CreatedAt    string        `yaml:"created_at,omitempty"`
	ExpiresAt    *string       `yaml:"expires_at"`
	Scopes       []string      `yaml:"scopes"`
	Targets      []string      `yaml:"targets"`
}

type BearerFile struct {
	Version      int                 `yaml:"version"`
	BearerTokens []BearerFileEntry   `yaml:"bearer_tokens"`
}

type BearerFileEntry struct {
	ID          string   `yaml:"id"`
	TokenSHA256 string   `yaml:"token_sha256"`
	Enabled     bool     `yaml:"enabled"`
	Subject     string   `yaml:"subject"`
	CreatedAt   string   `yaml:"created_at,omitempty"`
	ExpiresAt   *string  `yaml:"expires_at"`
	Scopes      []string `yaml:"scopes"`
	Targets     []string `yaml:"targets"`
}

type identity struct {
	ID        string
	Subject   string
	AuthType  string
	Enabled   bool
	Scopes    map[string]struct{}
	Targets   map[string]struct{}
	ExpiresAt *time.Time
}

type snapshot struct {
	byDigest map[[32]byte]*identity
}

// Manager is an atomic auth registry for capability and bearer digests.
type Manager struct {
	current        atomic.Pointer[snapshot]
	capabilityFile string
	bearerFile     string
	legacyBearer   string
	legacyAPIKey   string
	legacyType     string
}

type ManagerOptions struct {
	CapabilityFile string
	BearerFile     string
	LegacyType     string
	LegacyBearer   string
	LegacyAPIKey   string
}

func NewManager(opts ManagerOptions) (*Manager, error) {
	m := &Manager{
		capabilityFile: opts.CapabilityFile,
		bearerFile:     opts.BearerFile,
		legacyBearer:   opts.LegacyBearer,
		legacyAPIKey:   opts.LegacyAPIKey,
		legacyType:     strings.ToLower(opts.LegacyType),
	}
	if err := m.Reload(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) Reload() error {
	snap := &snapshot{byDigest: make(map[[32]byte]*identity)}

	if m.capabilityFile != "" {
		cf, err := LoadCapabilityFile(m.capabilityFile)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if cf != nil {
			if err := indexCapabilities(snap, cf); err != nil {
				return err
			}
		}
	}
	if m.bearerFile != "" {
		bf, err := LoadBearerFile(m.bearerFile)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if bf != nil {
			if err := indexBearers(snap, bf); err != nil {
				return err
			}
		}
	}

	switch m.legacyType {
	case "bearer":
		if m.legacyBearer != "" {
			id := fullAccessIdentity("legacy-bearer", "bearer-user", "bearer")
			snap.byDigest[HashToken(m.legacyBearer)] = id
		}
	case "api_key":
		if m.legacyAPIKey != "" {
			id := fullAccessIdentity("legacy-api-key", "api-key-user", "api_key")
			snap.byDigest[HashToken(m.legacyAPIKey)] = id
		}
	}

	m.current.Store(snap)
	return nil
}

func fullAccessIdentity(id, subject, authType string) *identity {
	return &identity{
		ID:       id,
		Subject:  subject,
		AuthType: authType,
		Enabled:  true,
		Scopes:   ScopeSet(DataPlaneScopes),
		Targets:  TargetSet([]string{"*"}),
	}
}

func indexCapabilities(snap *snapshot, cf *CapabilityFile) error {
	for i := range cf.Capabilities {
		ent := &cf.Capabilities[i]
		idents, err := identityFromCapability(ent)
		if err != nil {
			return err
		}
		for digest, id := range idents {
			if _, exists := snap.byDigest[digest]; exists {
				return fmt.Errorf("duplicate token digest for capability %q", ent.ID)
			}
			snap.byDigest[digest] = id
		}
	}
	return nil
}

func identityFromCapability(ent *CapabilityFileEntry) (map[[32]byte]*identity, error) {
	exp, err := parseOptionalTime(ent.ExpiresAt)
	if err != nil {
		return nil, err
	}
	subject := ent.Subject
	if subject == "" {
		subject = ent.ID
	}
	base := &identity{
		ID:        ent.ID,
		Subject:   subject,
		AuthType:  "capability",
		Enabled:   ent.Enabled,
		Scopes:    ScopeSet(ent.Scopes),
		Targets:   TargetSet(ent.Targets),
		ExpiresAt: exp,
	}
	out := make(map[[32]byte]*identity)
	digests := collectDigests(ent.TokenSHA256, ent.ActiveTokens)
	if len(digests) == 0 {
		return out, nil
	}
	for _, d := range digests {
		idCopy := *base
		out[d] = &idCopy
	}
	return out, nil
}

func collectDigests(primary string, tokens []TokenRecord) [][32]byte {
	var out [][32]byte
	seen := make(map[[32]byte]struct{})
	add := func(hexStr string) {
		if hexStr == "" {
			return
		}
		d, err := ParseDigestHex(hexStr)
		if err != nil {
			return
		}
		if _, ok := seen[d]; ok {
			return
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	add(primary)
	for _, t := range tokens {
		add(t.TokenSHA256)
	}
	return out
}

func indexBearers(snap *snapshot, bf *BearerFile) error {
	for i := range bf.BearerTokens {
		ent := &bf.BearerTokens[i]
		digest, err := ParseDigestHex(ent.TokenSHA256)
		if err != nil {
			return fmt.Errorf("bearer %q: invalid token_sha256", ent.ID)
		}
		if _, exists := snap.byDigest[digest]; exists {
			return fmt.Errorf("duplicate token digest for bearer %q", ent.ID)
		}
		exp, err := parseOptionalTime(ent.ExpiresAt)
		if err != nil {
			return err
		}
		subject := ent.Subject
		if subject == "" {
			subject = ent.ID
		}
		snap.byDigest[digest] = &identity{
			ID:        ent.ID,
			Subject:   subject,
			AuthType:  "bearer",
			Enabled:   ent.Enabled,
			Scopes:    ScopeSet(ent.Scopes),
			Targets:   TargetSet(ent.Targets),
			ExpiresAt: exp,
		}
	}
	return nil
}

func parseOptionalTime(s *string) (*time.Time, error) {
	if s == nil || strings.TrimSpace(*s) == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(*s))
	if err != nil {
		return nil, fmt.Errorf("invalid expires_at %q: %w", *s, err)
	}
	return &t, nil
}

func (m *Manager) VerifyCapability(token, remoteIP string) (*Principal, error) {
	return m.verify(token, "capability", remoteIP)
}

func (m *Manager) VerifyBearer(token, remoteIP string) (*Principal, error) {
	p, err := m.verify(token, "bearer", remoteIP)
	if err != nil {
		p, err = m.verify(token, "api_key", remoteIP)
	}
	return p, err
}

func (m *Manager) verify(token, wantType, remoteIP string) (*Principal, error) {
	snap := m.current.Load()
	if snap == nil {
		return nil, ErrInvalidCapability
	}
	id, ok := snap.byDigest[HashToken(token)]
	if !ok || id == nil {
		return nil, ErrInvalidCapability
	}
	if id.AuthType != wantType {
		return nil, ErrInvalidCapability
	}
	if !id.Enabled {
		return nil, ErrInvalidCapability
	}
	if id.ExpiresAt != nil && time.Now().After(*id.ExpiresAt) {
		return nil, ErrInvalidCapability
	}
	scopes := make(map[string]struct{}, len(id.Scopes))
	for k, v := range id.Scopes {
		scopes[k] = v
	}
	targets := make(map[string]struct{}, len(id.Targets))
	for k, v := range id.Targets {
		targets[k] = v
	}
	return &Principal{
		ID:       id.ID,
		Subject:  id.Subject,
		AuthType: id.AuthType,
		RemoteIP: remoteIP,
		Scopes:   scopes,
		Targets:  targets,
	}, nil
}

func LoadCapabilityFile(path string) (*CapabilityFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cf CapabilityFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("parse capabilities file: %w", err)
	}
	if cf.Version == 0 {
		cf.Version = 1
	}
	return &cf, nil
}

func LoadBearerFile(path string) (*BearerFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var bf BearerFile
	if err := yaml.Unmarshal(data, &bf); err != nil {
		return nil, fmt.Errorf("parse bearer tokens file: %w", err)
	}
	if bf.Version == 0 {
		bf.Version = 1
	}
	return &bf, nil
}

func SaveCapabilityFile(path string, cf *CapabilityFile) error {
	return writeYAML0600(path, cf)
}

func SaveBearerFile(path string, bf *BearerFile) error {
	return writeYAML0600(path, bf)
}

func writeYAML0600(path string, v any) error {
	data, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	// Write in place so bind-mounted files (Docker) do not fail on rename.
	return os.WriteFile(path, data, 0600)
}

func (m *Manager) CapabilityFile() string { return m.capabilityFile }
func (m *Manager) BearerFile() string     { return m.bearerFile }
