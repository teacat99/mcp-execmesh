package transfer

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"regexp"
)

const downloadTicketRandomBytes = 32

var (
	ErrInvalidDownloadTicket = errors.New("invalid download ticket")
	downloadTicketRegex      = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// GenerateDownloadTicket returns a 256-bit URL-safe opaque ticket.
func GenerateDownloadTicket() (string, error) {
	buf := make([]byte, downloadTicketRandomBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func validDownloadTicket(ticket string) bool {
	return downloadTicketRegex.MatchString(ticket)
}
