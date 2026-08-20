package security

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

var (
	ErrSchemeNotAllowed    = errors.New("url scheme is not allowed")
	ErrPrivateIPBlocked    = errors.New("download url resolves to a private, loopback, or reserved IP address")
	ErrTooManyRedirects    = errors.New("too many http redirects")
	ErrInvalidHost         = errors.New("invalid url host")
	ErrRedirectToForbidden = errors.New("redirected to disallowed scheme or destination")
)

// IP network ranges for private, loopback, link-local, and reserved networks
var privateIPBlocks []*net.IPNet

func init() {
	cidrs := []string{
		"127.0.0.0/8",          // IPv4 loopback
		"10.0.0.0/8",           // IPv4 private
		"172.16.0.0/12",        // IPv4 private
		"192.168.0.0/16",       // IPv4 private
		"169.254.0.0/16",       // IPv4 link-local / APIPA
		"0.0.0.0/8",            // IPv4 broadcast / current net
		"224.0.0.0/4",          // IPv4 multicast
		"240.0.0.0/4",          // IPv4 reserved
		"255.255.255.255/32",   // IPv4 limited broadcast
		"::1/128",              // IPv6 loopback
		"fc00::/7",             // IPv6 unique local
		"fe80::/10",            // IPv6 link-local
		"ff00::/8",             // IPv6 multicast
		"::/128",               // IPv6 unspecified
	}
	for _, cidr := range cidrs {
		_, block, err := net.ParseCIDR(cidr)
		if err == nil {
			privateIPBlocks = append(privateIPBlocks, block)
		}
	}
}

// IsPrivateIP checks whether the given IP is private, loopback, link-local, or reserved.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// Normalize IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() || ip.IsUnspecified() {
		return true
	}
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// SafeHTTPClientOptions configures safe HTTP client behaviors to protect against SSRF.
type SafeHTTPClientOptions struct {
	AllowedSchemes       []string
	BlockPrivate         bool
	MaxRedirects         int
	ConnectTimeout       time.Duration
	TLSHandshakeTimeout  time.Duration
	ResponseTimeout      time.Duration
}

// DefaultSafeHTTPClientOptions returns sensible defaults for secure file downloads.
func DefaultSafeHTTPClientOptions() SafeHTTPClientOptions {
	return SafeHTTPClientOptions{
		AllowedSchemes:      []string{"https"},
		BlockPrivate:        true,
		MaxRedirects:        3,
		ConnectTimeout:      10 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		ResponseTimeout:     60 * time.Second,
	}
}

// ValidateURL performs initial scheme and host validation on a raw URL string.
func ValidateURL(rawURL string, opts SafeHTTPClientOptions) (*url.URL, error) {
	if rawURL == "" {
		return nil, errors.New("url cannot be empty")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}

	schemeAllowed := false
	for _, s := range opts.AllowedSchemes {
		if strings.EqualFold(u.Scheme, s) {
			schemeAllowed = true
			break
		}
	}
	if !schemeAllowed {
		return nil, fmt.Errorf("%w: %s (allowed: %v)", ErrSchemeNotAllowed, u.Scheme, opts.AllowedSchemes)
	}

	hostname := u.Hostname()
	if hostname == "" {
		return nil, ErrInvalidHost
	}

	// If hostname is directly an IP, validate it immediately
	if ip := net.ParseIP(hostname); ip != nil {
		if opts.BlockPrivate && IsPrivateIP(ip) {
			return nil, fmt.Errorf("%w: %s", ErrPrivateIPBlocked, hostname)
		}
	}

	return u, nil
}

// NewSafeHTTPClient creates an *http.Client with built-in DNS inspection, IP filtering, and redirect controls.
func NewSafeHTTPClient(opts SafeHTTPClientOptions) *http.Client {
	if len(opts.AllowedSchemes) == 0 {
		opts.AllowedSchemes = []string{"https"}
	}
	if opts.MaxRedirects <= 0 {
		opts.MaxRedirects = 3
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = 10 * time.Second
	}
	if opts.TLSHandshakeTimeout <= 0 {
		opts.TLSHandshakeTimeout = 10 * time.Second
	}

	dialer := &net.Dialer{
		Timeout:   opts.ConnectTimeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			if !opts.BlockPrivate {
				return nil
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				host = address
			}
			ip := net.ParseIP(host)
			if ip != nil && IsPrivateIP(ip) {
				return fmt.Errorf("%w: %s", ErrPrivateIPBlocked, address)
			}
			return nil
		},
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   opts.TLSHandshakeTimeout,
		ResponseHeaderTimeout: opts.ResponseTimeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   2,
		DisableKeepAlives:     false,
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= opts.MaxRedirects {
				return fmt.Errorf("%w (max %d)", ErrTooManyRedirects, opts.MaxRedirects)
			}
			// Validate redirect target URL
			if _, err := ValidateURL(req.URL.String(), opts); err != nil {
				return fmt.Errorf("%w: %v", ErrRedirectToForbidden, err)
			}
			return nil
		},
	}

	return client
}
