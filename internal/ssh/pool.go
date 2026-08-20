package ssh

import (
	"context"
	"fmt"
	"sync"
)

// Manager manages SSH connections with concurrency limiting.
type Manager struct {
	maxConcurrentSSH int
	semaphore        chan struct{}
	mu               sync.Mutex
}

// NewManager creates an SSH manager with concurrency limits.
func NewManager(maxConcurrentSSH int) *Manager {
	if maxConcurrentSSH <= 0 {
		maxConcurrentSSH = 4
	}
	return &Manager{
		maxConcurrentSSH: maxConcurrentSSH,
		semaphore:        make(chan struct{}, maxConcurrentSSH),
	}
}

// Acquire connects to an SSH server within concurrency bounds.
func (m *Manager) Acquire(ctx context.Context, opts ConnectOptions) (*Client, func(), error) {
	select {
	case m.semaphore <- struct{}{}:
	case <-ctx.Done():
		return nil, nil, fmt.Errorf("timed out waiting for available SSH slot: %w", ctx.Err())
	}

	client, err := Dial(ctx, opts)
	if err != nil {
		<-m.semaphore
		return nil, nil, err
	}

	release := func() {
		_ = client.Close()
		<-m.semaphore
	}

	return client, release, nil
}
