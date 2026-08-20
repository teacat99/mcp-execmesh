package security

import (
	"errors"
	"fmt"
	"strings"
)

// CommandPolicy defines constraints on executable commands.
type CommandPolicy struct {
	MaxCommandLength int
	Blacklist        []string
}

// DefaultCommandPolicy returns default command policy settings.
func DefaultCommandPolicy() *CommandPolicy {
	return &CommandPolicy{
		MaxCommandLength: 32768, // 32 KiB max command string
		Blacklist:        nil,
	}
}

// ValidateCommand validates command string against length and blacklist.
func (p *CommandPolicy) ValidateCommand(cmd string) error {
	trimmed := strings.TrimSpace(cmd)
	if trimmed == "" {
		return errors.New("command cannot be empty")
	}

	if len(cmd) > p.MaxCommandLength {
		return fmt.Errorf("command length (%d bytes) exceeds maximum allowed length (%d bytes)", len(cmd), p.MaxCommandLength)
	}

	for _, banned := range p.Blacklist {
		if strings.Contains(cmd, banned) {
			return fmt.Errorf("command contains forbidden substring %q", banned)
		}
	}

	return nil
}
