package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ApplyTargetDefaults fills port/shell/capabilities/limits for all targets.
func ApplyTargetDefaults(cfg *Config) {
	for i := range cfg.Targets {
		t := &cfg.Targets[i]
		if t.Port == 0 {
			t.Port = 22
		}
		if t.Shell == "" {
			t.Shell = "/bin/sh"
		}
		if !t.Capabilities.Exec && !t.Capabilities.Upload && !t.Capabilities.Jobs {
			t.Capabilities.Exec = true
			t.Capabilities.Upload = true
			t.Capabilities.Jobs = true
		}
		if t.Limits.MaxExecSeconds == 0 {
			t.Limits.MaxExecSeconds = int(cfg.Runtime.SyncExecTimeout.Duration().Seconds())
			if t.Limits.MaxExecSeconds == 0 {
				t.Limits.MaxExecSeconds = 300
			}
		}
		if t.Limits.MaxUploadBytes == 0 {
			t.Limits.MaxUploadBytes = cfg.Runtime.MaxUploadBytes
		}
		if strings.TrimSpace(t.HostKey.KnownHostsFile) == "" && cfg.Security.RequireKnownHosts {
			// left empty; validate will catch when strict
		}
	}
}

func loadSidecars(cfg *Config) error {
	if strings.TrimSpace(cfg.CredentialsFile) != "" {
		creds, err := LoadCredentialsFile(cfg.CredentialsFile)
		if err != nil {
			return err
		}
		cfg.Credentials = creds
	}
	if strings.TrimSpace(cfg.TargetsFile) != "" {
		if len(cfg.Targets) > 0 {
			return fmt.Errorf("targets_file %q is set but config.yaml also lists targets; keep a single source", cfg.TargetsFile)
		}
		targets, err := LoadTargetsFile(cfg.TargetsFile)
		if err != nil {
			return err
		}
		cfg.Targets = targets
	}
	if err := ResolveAuthRefs(cfg); err != nil {
		return err
	}
	ApplyTargetDefaults(cfg)
	return nil
}

func LoadCredentialsFile(path string) ([]CredentialConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials file %q: %w", path, err)
	}
	var file credentialsFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("failed to parse credentials YAML: %w", err)
	}
	if file.Version == 0 {
		file.Version = 1
	}
	return file.Credentials, nil
}

func LoadTargetsFile(path string) ([]TargetConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read targets file %q: %w", path, err)
	}
	var file targetsFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("failed to parse targets YAML: %w", err)
	}
	if file.Version == 0 {
		file.Version = 1
	}
	return file.Targets, nil
}

func SaveTargetsFile(path string, targets []TargetConfig) error {
	file := targetsFile{Version: 1, Targets: targets}
	data, err := yaml.Marshal(&file)
	if err != nil {
		return err
	}
	return WriteFileInPlace(path, data, 0600)
}

func SaveCredentialsFile(path string, creds []CredentialConfig) error {
	file := credentialsFile{Version: 1, Credentials: creds}
	data, err := yaml.Marshal(&file)
	if err != nil {
		return err
	}
	return WriteFileInPlace(path, data, 0600)
}

// ResolveAuthRefs copies credential files into TargetConfig.Auth. Inline auth remains valid.
func ResolveAuthRefs(cfg *Config) error {
	byID := make(map[string]CredentialConfig, len(cfg.Credentials))
	for _, c := range cfg.Credentials {
		if strings.TrimSpace(c.ID) == "" {
			return fmt.Errorf("credential id cannot be empty")
		}
		if _, exists := byID[c.ID]; exists {
			return fmt.Errorf("duplicate credential id %q", c.ID)
		}
		byID[c.ID] = c
	}
	for i := range cfg.Targets {
		t := &cfg.Targets[i]
		if strings.TrimSpace(t.AuthRef) == "" {
			continue
		}
		c, ok := byID[t.AuthRef]
		if !ok {
			return fmt.Errorf("target %q references unknown credential %q", t.ID, t.AuthRef)
		}
		t.Auth = TargetAuthConfig{
			Type:                     c.Type,
			PrivateKeyFile:           c.PrivateKeyFile,
			PrivateKeyPassphraseFile: c.PrivateKeyPassphraseFile,
			PasswordFile:             c.PasswordFile,
		}
	}
	return nil
}

func CredentialByID(cfg *Config, id string) (CredentialConfig, bool) {
	for _, c := range cfg.Credentials {
		if c.ID == id {
			return c, true
		}
	}
	return CredentialConfig{}, false
}

func WriteFileInPlace(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}
