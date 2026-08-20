package management

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileLock serializes control-plane config mutations.
type FileLock struct {
	mu   sync.Mutex
	path string
	file *os.File
}

func NewFileLock(dataDir string) *FileLock {
	return &FileLock{path: filepath.Join(dataDir, "target-manager.lock")}
}

func (l *FileLock) Lock() error {
	l.mu.Lock()
	if err := os.MkdirAll(filepath.Dir(l.path), 0700); err != nil {
		l.mu.Unlock()
		return err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		l.mu.Unlock()
		return err
	}
	l.file = f
	return nil
}

func (l *FileLock) Unlock() {
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
	l.mu.Unlock()
}

func BackupFile(src, backupDir, prefix string) (string, error) {
	if src == "" {
		return "", fmt.Errorf("backup source path is empty")
	}
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return "", nil
	}
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return "", err
	}
	dst := filepath.Join(backupDir, fmt.Sprintf("%s-%s.yaml", prefix, time.Now().UTC().Format("20060102T150405Z")))
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return "", err
	}
	return dst, out.Sync()
}
