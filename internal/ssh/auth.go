package ssh

import (
	"fmt"

	"github.com/teacat/mcp-execmesh/internal/config"
	"golang.org/x/crypto/ssh"
)

// CreateAuthMethods resolves credentials from target auth config into ssh.AuthMethod slice.
func CreateAuthMethods(authCfg config.TargetAuthConfig) ([]ssh.AuthMethod, error) {
	switch authCfg.Type {
	case "private_key":
		keyBytes, passBytes, err := config.LoadPrivateKeyData(authCfg.PrivateKeyFile, authCfg.PrivateKeyPassphraseFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key: %w", err)
		}

		var signer ssh.Signer
		if len(passBytes) > 0 {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, passBytes)
		} else {
			signer, err = ssh.ParsePrivateKey(keyBytes)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}

		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil

	case "password":
		password, err := config.LoadPassword(authCfg.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read password: %w", err)
		}
		return []ssh.AuthMethod{ssh.Password(password)}, nil

	default:
		return nil, fmt.Errorf("unsupported auth type %q", authCfg.Type)
	}
}
