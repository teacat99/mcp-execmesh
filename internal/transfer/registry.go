package transfer

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

type downloadTicket struct {
	TargetID  string
	Path      string
	ExpiresAt time.Time
}

type downloadRegistry struct {
	mu      sync.Mutex
	tickets map[[32]byte]*downloadTicket
	max     int
}

func newDownloadRegistry(maxActive int) *downloadRegistry {
	if maxActive <= 0 {
		maxActive = 100
	}
	return &downloadRegistry{
		tickets: make(map[[32]byte]*downloadTicket),
		max:     maxActive,
	}
}

func hashTicket(ticket string) [32]byte {
	return sha256.Sum256([]byte(ticket))
}

func (r *downloadRegistry) purgeExpired(now time.Time) {
	for digest, ent := range r.tickets {
		if now.After(ent.ExpiresAt) {
			delete(r.tickets, digest)
		}
	}
}

func (r *downloadRegistry) register(ticket string, ent *downloadTicket) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	r.purgeExpired(now)
	if len(r.tickets) >= r.max {
		return ErrDownloadTicketLimit
	}
	digest := hashTicket(ticket)
	if _, exists := r.tickets[digest]; exists {
		return ErrDownloadTicketLimit
	}
	r.tickets[digest] = ent
	return nil
}

// claim removes and returns the ticket entry if valid and not expired.
func (r *downloadRegistry) claim(ticket string) (*downloadTicket, error) {
	if !validDownloadTicket(ticket) {
		return nil, ErrInvalidToken
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	digest := hashTicket(ticket)
	ent, ok := r.tickets[digest]
	if !ok || ent == nil {
		return nil, ErrInvalidToken
	}
	if time.Now().After(ent.ExpiresAt) {
		delete(r.tickets, digest)
		return nil, ErrInvalidToken
	}
	cp := *ent
	delete(r.tickets, digest)
	return &cp, nil
}

// TicketRef returns a short non-reversible reference for logs.
func TicketRef(ticket string) string {
	sum := sha256.Sum256([]byte(ticket))
	return hex.EncodeToString(sum[:3])
}
