package ssh

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// NewHostKeyCallback creates an SSH HostKeyCallback based on the known_hosts file and strict mode.
func NewHostKeyCallback(knownHostsPath string, strict bool) (ssh.HostKeyCallback, error) {
	if !strict && knownHostsPath == "" {
		// Insecure mode (only if strictly configured by user and strict=false)
		return ssh.InsecureIgnoreHostKey(), nil
	}

	if knownHostsPath == "" {
		return nil, fmt.Errorf("known_hosts_file cannot be empty when strict host key verification is enabled")
	}

	if _, err := os.Stat(knownHostsPath); err != nil {
		return nil, fmt.Errorf("failed to access known_hosts file %q: %w", knownHostsPath, err)
	}

	callback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse known_hosts file %q: %w", knownHostsPath, err)
	}

	if !strict {
		// Fallback callback that checks known_hosts but doesn't fail on unknown
		return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			err := callback(hostname, remote, key)
			if err != nil {
				// If not strict, allow new keys
				var keyErr *knownhosts.KeyError
				if ok := isKeyError(err, &keyErr); ok && len(keyErr.Want) == 0 {
					return nil
				}
			}
			return err
		}, nil
	}

	return callback, nil
}

func isKeyError(err error, target **knownhosts.KeyError) bool {
	if kErr, ok := err.(*knownhosts.KeyError); ok {
		*target = kErr
		return true
	}
	return false
}
