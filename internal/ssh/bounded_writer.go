package ssh

import (
	"sync"
)

// LimitedBuffer implements io.Writer with a strict maximum byte limit to protect memory.
// Excess bytes are discarded without error, and truncated flag is set to true.
type LimitedBuffer struct {
	mu           sync.Mutex
	buf          []byte
	maxBytes     int64
	truncated    bool
	totalWritten int64
}

// NewLimitedBuffer creates a bounded buffer that will never exceed maxBytes.
func NewLimitedBuffer(maxBytes int64) *LimitedBuffer {
	if maxBytes <= 0 {
		maxBytes = 65536 // default fallback 64 KiB
	}
	// Pre-allocate a small buffer, grow up to maxBytes
	initialCap := int(maxBytes)
	if initialCap > 4096 {
		initialCap = 4096
	}
	return &LimitedBuffer{
		buf:      make([]byte, 0, initialCap),
		maxBytes: maxBytes,
	}
}

// Write appends bytes up to maxBytes, setting truncated flag if limit is exceeded.
func (l *LimitedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	n := len(p)
	l.totalWritten += int64(n)

	remaining := l.maxBytes - int64(len(l.buf))
	if remaining <= 0 {
		l.truncated = true
		return n, nil
	}

	if int64(len(p)) > remaining {
		l.buf = append(l.buf, p[:remaining]...)
		l.truncated = true
	} else {
		l.buf = append(l.buf, p...)
	}

	return n, nil
}

// String returns the buffered content as a string.
func (l *LimitedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return string(l.buf)
}

// Bytes returns a copy of the buffered content.
func (l *LimitedBuffer) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	res := make([]byte, len(l.buf))
	copy(res, l.buf)
	return res
}

// IsTruncated returns true if output exceeded maxBytes.
func (l *LimitedBuffer) IsTruncated() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.truncated
}

// TotalWritten returns the total count of bytes passed to Write.
func (l *LimitedBuffer) TotalWritten() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.totalWritten
}
