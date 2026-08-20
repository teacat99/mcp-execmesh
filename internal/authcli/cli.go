package authcli

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/teacat/mcp-execmesh/internal/config"
	"github.com/teacat/mcp-execmesh/internal/security"
)

const usage = `Usage:
  remote-mcp auth capability create --id ID [--scope S]... [--target T]... [--config FILE]
  remote-mcp auth capability list [--config FILE]
  remote-mcp auth capability revoke --id ID [--config FILE]
  remote-mcp auth capability rotate --id ID [--config FILE]

Treat generated URLs as passwords. They are displayed once and never stored.
`

func Run(args []string) error {
	if len(args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("missing auth subcommand")
	}
	if args[0] != "capability" {
		return fmt.Errorf("unsupported auth resource %q (expected capability)", args[0])
	}
	switch args[1] {
	case "create":
		return runCreate(args[2:])
	case "list":
		return runList(args[2:])
	case "revoke":
		return runRevoke(args[2:])
	case "rotate":
		return runRotate(args[2:])
	default:
		return fmt.Errorf("unknown capability command %q", args[1])
	}
}

func loadCfg(path string) (*config.Config, error) {
	cfg, err := config.LoadConfig(path)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func capFile(cfg *config.Config) (string, error) {
	path := cfg.Server.Auth.CapabilityRegistryFile
	if path == "" {
		return "", fmt.Errorf("server.auth.capability_registry_file is not set")
	}
	return path, nil
}

func publicURL(cfg *config.Config, token string) string {
	base := cfg.PublicBaseURL()
	if base == "" {
		base = "http://" + cfg.Server.Listen
		if strings.HasPrefix(cfg.Server.Listen, "0.0.0.0:") {
			base = "http://127.0.0.1" + strings.TrimPrefix(cfg.Server.Listen, "0.0.0.0")
		}
	}
	return base + "/mcp/" + token
}

func loadOrEmpty(path string) (*security.CapabilityFile, error) {
	cf, err := security.LoadCapabilityFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &security.CapabilityFile{Version: 1}, nil
		}
		return nil, err
	}
	return cf, nil
}

func runCreate(args []string) error {
	fs := flag.NewFlagSet("capability create", flag.ContinueOnError)
	id := fs.String("id", "", "capability id")
	configPath := fs.String("config", "configs/config.example.yaml", "server config path")
	expires := fs.String("expires", "", "optional RFC3339 expiry")
	var scopes, targets multiFlag
	fs.Var(&scopes, "scope", "allowed scope (repeatable)")
	fs.Var(&targets, "target", "allowed target id or * (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("--id is required")
	}
	if len(scopes) == 0 {
		scopes = security.DataPlaneScopes
	}
	for _, s := range scopes {
		if !security.ValidScope(s) {
			return fmt.Errorf("invalid scope %q", s)
		}
	}
	if len(targets) == 0 {
		targets = []string{"*"}
	}

	cfg, err := loadCfg(*configPath)
	if err != nil {
		return err
	}
	path, err := capFile(cfg)
	if err != nil {
		return err
	}
	cf, err := loadOrEmpty(path)
	if err != nil {
		return err
	}
	for _, e := range cf.Capabilities {
		if e.ID == *id {
			return fmt.Errorf("capability id %q already exists", *id)
		}
	}

	token, err := security.GenerateCapability()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var exp *string
	if strings.TrimSpace(*expires) != "" {
		if _, err := time.Parse(time.RFC3339, *expires); err != nil {
			return fmt.Errorf("invalid --expires: %w", err)
		}
		e := *expires
		exp = &e
	}
	entry := security.CapabilityFileEntry{
		ID:          *id,
		Family:      *id,
		TokenSHA256: security.HashTokenHex(token),
		Enabled:     true,
		Subject:     *id,
		CreatedAt:   now,
		ExpiresAt:   exp,
		Scopes:      scopes,
		Targets:     targets,
		ActiveTokens: []security.TokenRecord{
			{TokenSHA256: security.HashTokenHex(token), CreatedAt: now},
		},
	}
	cf.Version = 1
	cf.Capabilities = append(cf.Capabilities, entry)
	if err := security.SaveCapabilityFile(path, cf); err != nil {
		return err
	}

	fmt.Printf("Capability created successfully.\n\nID:\n%s\n\nServer URL:\n%s\n\nIMPORTANT:\nThis URL will only be displayed once.\nTreat it as a password.\n", *id, publicURL(cfg, token))
	return nil
}

func runList(args []string) error {
	fs := flag.NewFlagSet("capability list", flag.ContinueOnError)
	configPath := fs.String("config", "configs/config.example.yaml", "server config path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadCfg(*configPath)
	if err != nil {
		return err
	}
	path, err := capFile(cfg)
	if err != nil {
		return err
	}
	cf, err := loadOrEmpty(path)
	if err != nil {
		return err
	}
	fmt.Printf("%-20s %-8s %-22s %s\n", "ID", "ENABLED", "EXPIRES", "TARGETS")
	for _, e := range cf.Capabilities {
		expires := "never"
		if e.ExpiresAt != nil && *e.ExpiresAt != "" {
			expires = *e.ExpiresAt
		}
		enabled := "no"
		if e.Enabled {
			enabled = "yes"
		}
		tg := strings.Join(e.Targets, ",")
		if tg == "" {
			tg = "*"
		}
		fmt.Printf("%-20s %-8s %-22s %s\n", e.ID, enabled, expires, tg)
	}
	return nil
}

func runRevoke(args []string) error {
	fs := flag.NewFlagSet("capability revoke", flag.ContinueOnError)
	id := fs.String("id", "", "capability id")
	configPath := fs.String("config", "configs/config.example.yaml", "server config path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("--id is required")
	}
	cfg, err := loadCfg(*configPath)
	if err != nil {
		return err
	}
	path, err := capFile(cfg)
	if err != nil {
		return err
	}
	cf, err := loadOrEmpty(path)
	if err != nil {
		return err
	}
	found := false
	for i := range cf.Capabilities {
		if cf.Capabilities[i].ID == *id {
			cf.Capabilities[i].Enabled = false
			found = true
		}
	}
	if !found {
		return fmt.Errorf("capability %q not found", *id)
	}
	if err := security.SaveCapabilityFile(path, cf); err != nil {
		return err
	}
	fmt.Printf("Capability %s revoked. Subsequent requests will fail.\n", *id)
	return nil
}

func runRotate(args []string) error {
	fs := flag.NewFlagSet("capability rotate", flag.ContinueOnError)
	id := fs.String("id", "", "capability id")
	configPath := fs.String("config", "configs/config.example.yaml", "server config path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("--id is required")
	}
	cfg, err := loadCfg(*configPath)
	if err != nil {
		return err
	}
	path, err := capFile(cfg)
	if err != nil {
		return err
	}
	cf, err := loadOrEmpty(path)
	if err != nil {
		return err
	}
	idx := -1
	for i := range cf.Capabilities {
		if cf.Capabilities[i].ID == *id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("capability %q not found", *id)
	}
	ent := &cf.Capabilities[idx]
	if !ent.Enabled {
		return fmt.Errorf("capability %q is revoked; create a new one instead", *id)
	}
	active := ent.ActiveTokens
	if ent.TokenSHA256 != "" && len(active) == 0 {
		active = []security.TokenRecord{{TokenSHA256: ent.TokenSHA256, CreatedAt: ent.CreatedAt}}
	}
	if len(active) >= security.MaxActiveTokens {
		return fmt.Errorf("capability %q already has 2 active tokens; revoke the old one after clients switch", *id)
	}
	token, err := security.GenerateCapability()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	active = append(active, security.TokenRecord{TokenSHA256: security.HashTokenHex(token), CreatedAt: now})
	ent.ActiveTokens = active
	ent.TokenSHA256 = active[len(active)-1].TokenSHA256
	if err := security.SaveCapabilityFile(path, cf); err != nil {
		return err
	}
	fmt.Printf("Capability rotated. Both old and new tokens remain valid until you revoke the old one.\n\nID:\n%s\n\nNew Server URL:\n%s\n\nIMPORTANT:\nThis URL will only be displayed once.\nTreat it as a password.\n", *id, publicURL(cfg, token))
	return nil
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
