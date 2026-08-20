package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Record represents a single structured audit entry.
type Record struct {
	Timestamp     string `json:"timestamp"`
	RequestID     string `json:"request_id,omitempty"`
	Subject       string `json:"subject,omitempty"`
	Tool          string `json:"tool"`
	Target        string `json:"target,omitempty"`
	CommandSHA256 string `json:"command_sha256,omitempty"`
	Command       string `json:"command,omitempty"`
	Cwd           string `json:"cwd,omitempty"`
	Result        string `json:"result"` // "success", "error", "denied"
	ExitCode      *int   `json:"exit_code,omitempty"`
	DurationMS    int64  `json:"duration_ms"`
	ErrorMessage  string `json:"error_message,omitempty"`
}

// Logger writes structured JSON audit records to an output destination.
type Logger struct {
	mu           sync.Mutex
	out          io.Writer
	closer       io.Closer
	maskCommands bool
}

// NewLogger creates an audit logger writing to the specified file path or stdout.
func NewLogger(filePath string, maskCommands bool) (*Logger, error) {
	var out io.Writer = os.Stdout
	var closer io.Closer

	if filePath != "" && filePath != "stdout" {
		f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to open audit log file %q: %w", filePath, err)
		}
		out = f
		closer = f
	}

	return &Logger{
		out:          out,
		closer:       closer,
		maskCommands: maskCommands,
	}, nil
}

// Log writes a record to the audit destination in JSON format.
func (l *Logger) Log(rec Record) {
	if l == nil {
		return
	}

	if rec.Timestamp == "" {
		rec.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}

	if rec.Command != "" {
		sum := sha256.Sum256([]byte(rec.Command))
		rec.CommandSHA256 = hex.EncodeToString(sum[:])
		if l.maskCommands {
			rec.Command = "[MASKED]"
		}
	}

	data, err := json.Marshal(rec)
	if err != nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.out.Write(append(data, '\n'))
}

// Close closes the audit logger's underlying writer if it holds an open file.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}
