package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

const (
	CapabilityPrefix      = "cap_v1_"
	capabilityRandomBytes = 32
	mcpPrefix             = "/mcp/"
)

var (
	ErrInvalidCapability = errors.New("invalid capability")
	capabilityRegex      = regexp.MustCompile(`^cap_v1_[A-Za-z0-9_-]{43}$`)
	capabilityInPath     = regexp.MustCompile(`/mcp/cap_v1_[A-Za-z0-9_-]{20,}`)
	downloadTicketInPath = regexp.MustCompile(`/files/[A-Za-z0-9_-]{20,}`)
)

// GenerateCapability returns a high-entropy opaque capability token.
func GenerateCapability() (string, error) {
	b := make([]byte, capabilityRandomBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	return CapabilityPrefix + token, nil
}

func HashToken(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

func HashTokenHex(token string) string {
	sum := HashToken(token)
	return hex.EncodeToString(sum[:])
}

func ParseDigestHex(s string) ([32]byte, error) {
	var out [32]byte
	s = strings.TrimSpace(strings.ToLower(s))
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return out, ErrInvalidCapability
	}
	copy(out[:], raw)
	return out, nil
}

// ParseCapabilityPath extracts a capability from /mcp/cap_v1_...
func ParseCapabilityPath(path string) (string, error) {
	if path == "" {
		return "", ErrInvalidCapability
	}
	decoded, err := url.PathUnescape(path)
	if err != nil {
		return "", ErrInvalidCapability
	}
	cleaned := strings.TrimSuffix(decoded, "/")
	if strings.Contains(cleaned, "..") || strings.Contains(cleaned, "//") {
		return "", ErrInvalidCapability
	}
	if !strings.HasPrefix(cleaned, mcpPrefix) {
		return "", ErrInvalidCapability
	}
	token := strings.TrimPrefix(cleaned, mcpPrefix)
	if strings.Contains(token, "/") {
		return "", ErrInvalidCapability
	}
	if !capabilityRegex.MatchString(token) {
		return "", ErrInvalidCapability
	}
	return token, nil
}

func IsCapabilityToken(token string) bool {
	return capabilityRegex.MatchString(token)
}

// RedactPath replaces capability and download ticket segments in URL paths for logs.
func RedactPath(path string) string {
	if path == "" {
		return path
	}
	path = capabilityInPath.ReplaceAllString(path, "/mcp/[CAPABILITY]")
	return downloadTicketInPath.ReplaceAllString(path, "/files/[TICKET]")
}

func RedactString(s string) string {
	if s == "" {
		return s
	}
	s = capabilityInPath.ReplaceAllString(s, "/mcp/[CAPABILITY]")
	s = downloadTicketInPath.ReplaceAllString(s, "/files/[TICKET]")
	s = capabilityRegex.ReplaceAllString(s, "[CAPABILITY]")
	return s
}
