package config

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
)

var (
	ErrPublicBaseURLNotConfigured = errors.New("PUBLIC_BASE_URL_NOT_CONFIGURED")
	ErrInvalidPublicBaseURL       = errors.New("invalid public_base_url")
)

// PublicBaseURL returns the configured public base URL (server.public_base_url, else auth.public_base_url).
func (c *Config) PublicBaseURL() string {
	if c == nil {
		return ""
	}
	if u := strings.TrimSpace(c.Server.PublicBaseURL); u != "" {
		return strings.TrimRight(u, "/")
	}
	return strings.TrimRight(strings.TrimSpace(c.Server.Auth.PublicBaseURL), "/")
}

// ValidatePublicBaseURL parses and validates a public base URL for download links.
func ValidatePublicBaseURL(raw string, allowHTTP bool) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%w: public_base_url is required for file downloads", ErrPublicBaseURLNotConfigured)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPublicBaseURL, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("%w: must be an absolute URL with scheme and host", ErrInvalidPublicBaseURL)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowHTTP {
			return nil, fmt.Errorf("%w: must use https", ErrInvalidPublicBaseURL)
		}
		host := strings.ToLower(u.Hostname())
		if host != "localhost" && host != "127.0.0.1" {
			return nil, fmt.Errorf("%w: http is only allowed for localhost", ErrInvalidPublicBaseURL)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported scheme %q", ErrInvalidPublicBaseURL, u.Scheme)
	}
	if u.RawQuery != "" {
		return nil, fmt.Errorf("%w: must not contain query parameters", ErrInvalidPublicBaseURL)
	}
	if u.Fragment != "" {
		return nil, fmt.Errorf("%w: must not contain fragment", ErrInvalidPublicBaseURL)
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

// JoinPublicURL builds an absolute URL under public_base_url (supports path prefix).
func JoinPublicURL(publicBaseURL string, elem ...string) (string, error) {
	u, err := ValidatePublicBaseURL(publicBaseURL, true)
	if err != nil {
		return "", err
	}
	trimmed := strings.Trim(u.Path, "/")
	parts := make([]string, 0, len(elem)+1)
	if trimmed != "" {
		parts = append(parts, trimmed)
	}
	for _, e := range elem {
		e = strings.Trim(e, "/")
		if e != "" {
			parts = append(parts, e)
		}
	}
	u.Path = "/" + path.Join(parts...)
	return u.String(), nil
}
