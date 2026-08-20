package config

import (
	"bytes"
	"fmt"
	"os"
)

// SecretBytes wraps sensitive bytes to prevent accidental leakage in formatting/logs.
type SecretBytes []byte

func (s SecretBytes) String() string {
	return "[REDACTED_SECRET]"
}

func (s SecretBytes) GoString() string {
	return "[REDACTED_SECRET]"
}

// SecretString wraps sensitive strings to prevent accidental leakage.
type SecretString string

func (s SecretString) String() string {
	return "[REDACTED_SECRET]"
}

func (s SecretString) GoString() string {
	return "[REDACTED_SECRET]"
}

// LoadSecretFile reads a secret file from disk.
func LoadSecretFile(filePath string) ([]byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret file %q: %w", filePath, err)
	}
	return data, nil
}

// LoadPassword reads a password file and strips trailing newlines/carriage returns.
func LoadPassword(filePath string) (string, error) {
	data, err := LoadSecretFile(filePath)
	if err != nil {
		return "", err
	}
	cleaned := bytes.TrimRight(data, "\r\n")
	return string(cleaned), nil
}

// LoadPrivateKeyData reads a private key file and optional passphrase file.
func LoadPrivateKeyData(keyPath string, passphrasePath string) ([]byte, []byte, error) {
	keyBytes, err := LoadSecretFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load private key: %w", err)
	}

	var passphraseBytes []byte
	if passphrasePath != "" {
		passData, err := LoadSecretFile(passphrasePath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load private key passphrase: %w", err)
		}
		passphraseBytes = bytes.TrimRight(passData, "\r\n")
	}

	return keyBytes, passphraseBytes, nil
}
