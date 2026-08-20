package transfer

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/sftp"
	"github.com/teacat/mcp-execmesh/internal/audit"
	"github.com/teacat/mcp-execmesh/internal/config"
	"github.com/teacat/mcp-execmesh/internal/security"
	"github.com/teacat/mcp-execmesh/internal/ssh"
	"github.com/teacat/mcp-execmesh/internal/target"
)

var (
	ErrTargetNotFound       = errors.New("target not found")
	ErrUploadNotAllowed     = errors.New("file upload capability is disabled on target")
	ErrPathDisallowed       = errors.New("remote path is not within target's allowed paths")
	ErrFileAlreadyExists    = errors.New("remote file already exists and overwrite is false")
	ErrFileSizeExceedsLimit = errors.New("file size exceeds maximum allowed limit")
	ErrInvalidDownloadURL   = errors.New("invalid or disallowed download url")
	ErrInvalidToken         = errors.New("invalid or expired download token")
	ErrInvalidDownloadTTL   = errors.New("INVALID_DOWNLOAD_TTL")
	ErrDownloadTicketLimit  = errors.New("DOWNLOAD_TICKET_LIMIT_REACHED")
)

type TransferManager interface {
	Push(ctx context.Context, req PushRequest) (*PushResponse, error)
	Stat(ctx context.Context, req StatRequest) (*StatResponse, error)
	Hash(ctx context.Context, req HashRequest) (*HashResponse, error)
	PullPrepare(ctx context.Context, req PullPrepareRequest, publicBaseURL string) (*PullPrepareResponse, error)
	ServeDownload(w http.ResponseWriter, r *http.Request, token string) error
}

type transferManager struct {
	targets     target.TargetRegistry
	sshManager  *ssh.Manager
	secCfg      config.SecurityConfig
	runtimeCfg  config.RuntimeConfig
	auditLogger *audit.Logger
	transferSem chan struct{}
	httpClient  *http.Client
	downloads   *downloadRegistry
}

// NewTransferManager creates a new TransferManager instance.
func NewTransferManager(
	targets target.TargetRegistry,
	sshManager *ssh.Manager,
	secCfg config.SecurityConfig,
	runtimeCfg config.RuntimeConfig,
	auditLogger *audit.Logger,
	customHTTPClient *http.Client,
) TransferManager {
	maxTransfers := runtimeCfg.MaxConcurrentTransfers
	if maxTransfers <= 0 {
		maxTransfers = 1
	}

	httpClient := customHTTPClient
	if httpClient == nil {
		httpOpts := security.SafeHTTPClientOptions{
			AllowedSchemes:      secCfg.AllowedFileDownloadSchemes,
			BlockPrivate:        secCfg.BlockPrivateDownloadAddresses,
			MaxRedirects:        secCfg.MaxDownloadRedirects,
			ConnectTimeout:      10 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			ResponseTimeout:     120 * time.Second,
		}
		httpClient = security.NewSafeHTTPClient(httpOpts)
	}

	return &transferManager{
		targets:     targets,
		sshManager:  sshManager,
		secCfg:      secCfg,
		runtimeCfg:  runtimeCfg,
		auditLogger: auditLogger,
		transferSem: make(chan struct{}, maxTransfers),
		httpClient:  httpClient,
		downloads:   newDownloadRegistry(runtimeCfg.MaxActiveDownloadTickets),
	}
}

// countingReader enforces a hard maximum byte limit while streaming.
type countingReader struct {
	r     io.Reader
	count int64
	max   int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.count += int64(n)
	if c.max > 0 && c.count > c.max {
		return n, fmt.Errorf("%w: read %d bytes (limit %d bytes)", ErrFileSizeExceedsLimit, c.count, c.max)
	}
	return n, err
}

func (m *transferManager) Push(ctx context.Context, req PushRequest) (*PushResponse, error) {
	start := time.Now()
	var finalErr error
	var uploadedSize int64
	var sha256Hex string

	defer func() {
		durMS := time.Since(start).Milliseconds()
		result := "success"
		errMsg := ""
		if finalErr != nil {
			result = "error"
			errMsg = finalErr.Error()
		}
		if m.auditLogger != nil {
			m.auditLogger.Log(audit.Record{
				Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
				Tool:         "file_push",
				Target:       req.Target,
				Result:       result,
				DurationMS:   durMS,
				ErrorMessage: errMsg,
				Command:      fmt.Sprintf("file_push path=%s size=%d sha256=%s", req.RemotePath, uploadedSize, sha256Hex),
			})
		}
	}()

	// 1. Acquire transfer concurrency slot
	select {
	case m.transferSem <- struct{}{}:
		defer func() { <-m.transferSem }()
	case <-ctx.Done():
		finalErr = ctx.Err()
		return nil, finalErr
	}

	// 2. Validate Target
	tgt, err := m.targets.Get(ctx, req.Target)
	if err != nil {
		finalErr = fmt.Errorf("%w: %q", ErrTargetNotFound, req.Target)
		return nil, finalErr
	}
	if err := tgt.RequireActive(); err != nil {
		finalErr = err
		return nil, finalErr
	}
	if !tgt.Capabilities.Upload {
		finalErr = fmt.Errorf("%w: %q", ErrUploadNotAllowed, req.Target)
		return nil, finalErr
	}

	// 3. Validate Remote Path
	cleanRemotePath, err := security.CleanAndValidatePath(req.RemotePath, tgt.DefaultCwd)
	if err != nil {
		finalErr = fmt.Errorf("invalid remote_path: %w", err)
		return nil, finalErr
	}
	if !security.IsPathAllowed(cleanRemotePath, tgt.AllowedPaths) {
		finalErr = fmt.Errorf("%w: %q", ErrPathDisallowed, cleanRemotePath)
		return nil, finalErr
	}

	// 4. Determine Max Upload Limit
	maxUploadBytes := m.runtimeCfg.MaxUploadBytes
	if tgt.Limits.MaxUploadBytes > 0 && tgt.Limits.MaxUploadBytes < maxUploadBytes {
		maxUploadBytes = tgt.Limits.MaxUploadBytes
	}

	// 5. Parse File Mode
	modeStr := strings.TrimSpace(req.Mode)
	if modeStr == "" {
		modeStr = "0644"
	}
	parsedMode, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		finalErr = fmt.Errorf("invalid mode %q: must be octal string (e.g. 0755, 0644)", req.Mode)
		return nil, finalErr
	}
	fileMode := os.FileMode(parsedMode)

	// 6. Validate Download URL
	if req.File.DownloadURL == "" {
		finalErr = errors.New("file.download_url cannot be empty")
		return nil, finalErr
	}
	httpOpts := security.SafeHTTPClientOptions{
		AllowedSchemes: m.secCfg.AllowedFileDownloadSchemes,
		BlockPrivate:   m.secCfg.BlockPrivateDownloadAddresses,
		MaxRedirects:   m.secCfg.MaxDownloadRedirects,
	}
	if _, err := security.ValidateURL(req.File.DownloadURL, httpOpts); err != nil {
		finalErr = fmt.Errorf("%w: %v", ErrInvalidDownloadURL, err)
		return nil, finalErr
	}

	// 7. Establish SSH & SFTP connection
	sshTimeout := m.runtimeCfg.SyncExecTimeout.Duration()
	if sshTimeout <= 0 {
		sshTimeout = 30 * time.Second
	}
	sshClient, releaseSSH, err := m.sshManager.Acquire(ctx, tgt.ConnectOptions(sshTimeout))
	if err != nil {
		finalErr = fmt.Errorf("failed to dial ssh for target %q: %w", req.Target, err)
		return nil, finalErr
	}
	defer releaseSSH()

	sftpClient, err := sftp.NewClient(sshClient.RawClient())
	if err != nil {
		finalErr = fmt.Errorf("failed to initialize sftp client for target %q: %w", req.Target, err)
		return nil, finalErr
	}
	defer sftpClient.Close()

	// 8. Ensure parent remote directory exists
	remoteDir := path.Dir(cleanRemotePath)
	if remoteDir != "." && remoteDir != "/" {
		if err := sftpClient.MkdirAll(remoteDir); err != nil {
			finalErr = fmt.Errorf("failed to create remote directory %q: %w", remoteDir, err)
			return nil, finalErr
		}
	}

	// 9. Check if destination already exists
	_, statErr := sftpClient.Stat(cleanRemotePath)
	destExists := statErr == nil
	if destExists && !req.Overwrite {
		finalErr = fmt.Errorf("%w: %q", ErrFileAlreadyExists, cleanRemotePath)
		return nil, finalErr
	}

	// 10. Execute HTTP GET with streaming
	httpReq, err := http.NewRequestWithContext(ctx, "GET", req.File.DownloadURL, nil)
	if err != nil {
		finalErr = fmt.Errorf("failed to create http request: %w", err)
		return nil, finalErr
	}
	httpReq.Header.Set("User-Agent", "MCP-ExecMesh-Transfer/1.0")

	httpResp, err := m.httpClient.Do(httpReq)
	if err != nil {
		finalErr = fmt.Errorf("failed to fetch download_url: %w", err)
		return nil, finalErr
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		finalErr = fmt.Errorf("download_url returned unexpected HTTP status %d %s", httpResp.StatusCode, httpResp.Status)
		return nil, finalErr
	}

	// Check Content-Length if present
	if httpResp.ContentLength > 0 && maxUploadBytes > 0 && httpResp.ContentLength > maxUploadBytes {
		finalErr = fmt.Errorf("%w: Content-Length %d exceeds max %d bytes", ErrFileSizeExceedsLimit, httpResp.ContentLength, maxUploadBytes)
		return nil, finalErr
	}

	// 11. Create remote temporary file in the same directory
	tempName := fmt.Sprintf(".%s.mcp-upload-%s", path.Base(cleanRemotePath), uuid.New().String()[:8])
	tempPath := path.Join(remoteDir, tempName)

	tempFile, err := sftpClient.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		finalErr = fmt.Errorf("failed to open remote temporary file %q: %w", tempPath, err)
		return nil, finalErr
	}

	tempFileCleaned := false
	defer func() {
		if !tempFileCleaned {
			_ = sftpClient.Remove(tempPath)
		}
	}()

	// 12. Stream HTTP response to SFTP with SHA256 and byte limit
	hasher := sha256.New()
	tee := io.TeeReader(httpResp.Body, hasher)
	limitedReader := &countingReader{
		r:   tee,
		max: maxUploadBytes,
	}

	bufferSize := m.runtimeCfg.TransferBufferBytes
	if bufferSize <= 0 {
		bufferSize = 65536 // 64 KiB
	}
	copyBuf := make([]byte, bufferSize)

	written, err := io.CopyBuffer(tempFile, limitedReader, copyBuf)
	if closeErr := tempFile.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		finalErr = fmt.Errorf("failed during streaming upload to %q: %w", tempPath, err)
		return nil, finalErr
	}

	uploadedSize = written
	sha256Hex = hex.EncodeToString(hasher.Sum(nil))

	// 13. Apply chmod to the uploaded temp file
	if err := sftpClient.Chmod(tempPath, fileMode); err != nil {
		finalErr = fmt.Errorf("failed to chmod remote file %q: %w", tempPath, err)
		return nil, finalErr
	}

	// 14. Atomic rename to destination path
	if destExists && req.Overwrite {
		// On POSIX SFTP, if target exists, some implementations require removing destination first
		_ = sftpClient.Remove(cleanRemotePath)
	}
	if err := sftpClient.Rename(tempPath, cleanRemotePath); err != nil {
		finalErr = fmt.Errorf("failed to atomically rename %q to %q: %w", tempPath, cleanRemotePath, err)
		return nil, finalErr
	}

	tempFileCleaned = true

	return &PushResponse{
		Target:     req.Target,
		RemotePath: cleanRemotePath,
		Size:       uploadedSize,
		SHA256:     sha256Hex,
		Mode:       fmt.Sprintf("%04o", fileMode.Perm()),
	}, nil
}

func (m *transferManager) Stat(ctx context.Context, req StatRequest) (*StatResponse, error) {
	// 1. Validate Target
	tgt, err := m.targets.Get(ctx, req.Target)
	if err != nil {
		return nil, fmt.Errorf("%w: %q", ErrTargetNotFound, req.Target)
	}
	if err := tgt.RequireActive(); err != nil {
		return nil, err
	}

	// 2. Validate Remote Path
	cleanRemotePath, err := security.CleanAndValidatePath(req.Path, tgt.DefaultCwd)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}
	if !security.IsPathAllowed(cleanRemotePath, tgt.AllowedPaths) {
		return nil, fmt.Errorf("%w: %q", ErrPathDisallowed, cleanRemotePath)
	}

	// 3. Establish SSH & SFTP connection
	sshTimeout := m.runtimeCfg.SyncExecTimeout.Duration()
	if sshTimeout <= 0 {
		sshTimeout = 30 * time.Second
	}
	sshClient, releaseSSH, err := m.sshManager.Acquire(ctx, tgt.ConnectOptions(sshTimeout))
	if err != nil {
		return nil, fmt.Errorf("failed to dial ssh for target %q: %w", req.Target, err)
	}
	defer releaseSSH()

	sftpClient, err := sftp.NewClient(sshClient.RawClient())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize sftp client for target %q: %w", req.Target, err)
	}
	defer sftpClient.Close()

	fi, err := sftpClient.Stat(cleanRemotePath)
	if err != nil {
		if os.IsNotExist(err) || strings.Contains(strings.ToLower(err.Error()), "not exist") || strings.Contains(strings.ToLower(err.Error()), "no such file") {
			return &StatResponse{
				Target: req.Target,
				Path:   cleanRemotePath,
				Exists: false,
			}, nil
		}
		return nil, fmt.Errorf("failed to stat remote path %q: %w", cleanRemotePath, err)
	}

	typeStr := "file"
	if fi.IsDir() {
		typeStr = "dir"
	} else if fi.Mode()&os.ModeSymlink != 0 {
		typeStr = "symlink"
	}

	return &StatResponse{
		Target: req.Target,
		Path:   cleanRemotePath,
		Exists: true,
		Type:   typeStr,
		Size:   fi.Size(),
		Mode:   fmt.Sprintf("%04o", fi.Mode().Perm()),
		MTime:  fi.ModTime().UTC().Format(time.RFC3339),
		SHA256: nil, // Intentionally nil for performance
	}, nil
}

func (m *transferManager) Hash(ctx context.Context, req HashRequest) (*HashResponse, error) {
	tgt, err := m.targets.Get(ctx, req.Target)
	if err != nil {
		return nil, fmt.Errorf("%w: %q", ErrTargetNotFound, req.Target)
	}
	if err := tgt.RequireActive(); err != nil {
		return nil, err
	}

	cleanRemotePath, err := security.CleanAndValidatePath(req.Path, tgt.DefaultCwd)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}
	if !security.IsPathAllowed(cleanRemotePath, tgt.AllowedPaths) {
		return nil, fmt.Errorf("%w: %q", ErrPathDisallowed, cleanRemotePath)
	}

	algo := strings.ToLower(strings.TrimSpace(req.Algorithm))
	var h hash.Hash
	switch algo {
	case "", "sha256":
		algo = "sha256"
		h = sha256.New()
	case "sha1":
		h = sha1.New()
	case "md5":
		h = md5.New()
	default:
		return nil, fmt.Errorf("unsupported hash algorithm %q (supported: sha256, sha1, md5)", req.Algorithm)
	}

	sshTimeout := m.runtimeCfg.SyncExecTimeout.Duration()
	if sshTimeout <= 0 {
		sshTimeout = 30 * time.Second
	}
	sshClient, releaseSSH, err := m.sshManager.Acquire(ctx, tgt.ConnectOptions(sshTimeout))
	if err != nil {
		return nil, fmt.Errorf("failed to dial ssh for target %q: %w", req.Target, err)
	}
	defer releaseSSH()

	sftpClient, err := sftp.NewClient(sshClient.RawClient())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize sftp client for target %q: %w", req.Target, err)
	}
	defer sftpClient.Close()

	file, err := sftpClient.Open(cleanRemotePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open remote file %q: %w", cleanRemotePath, err)
	}
	defer file.Close()

	bufSize := m.runtimeCfg.TransferBufferBytes
	if bufSize <= 0 {
		bufSize = 65536
	}
	buf := make([]byte, bufSize)

	written, err := io.CopyBuffer(h, file, buf)
	if err != nil {
		return nil, fmt.Errorf("failed during remote file hash calculation: %w", err)
	}

	return &HashResponse{
		Target:    req.Target,
		Path:      cleanRemotePath,
		Algorithm: algo,
		Hash:      hex.EncodeToString(h.Sum(nil)),
		Size:      written,
	}, nil
}

func (m *transferManager) PullPrepare(ctx context.Context, req PullPrepareRequest, publicBaseURL string) (*PullPrepareResponse, error) {
	start := time.Now()
	var auditErr string
	defer func() {
		if m.auditLogger == nil {
			return
		}
		result := "success"
		if auditErr != "" {
			result = "error"
		}
		m.auditLogger.Log(audit.Record{
			Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
			Tool:         "file_pull_prepare",
			Target:       req.Target,
			Result:       result,
			DurationMS:   time.Since(start).Milliseconds(),
			ErrorMessage: auditErr,
			Command:      fmt.Sprintf("file_pull_prepare path=%s ttl=%d", req.Path, req.TTLSeconds),
		})
	}()

	if strings.TrimSpace(publicBaseURL) == "" {
		auditErr = config.ErrPublicBaseURLNotConfigured.Error()
		return nil, config.ErrPublicBaseURLNotConfigured
	}
	if _, err := config.ValidatePublicBaseURL(publicBaseURL, true); err != nil {
		auditErr = err.Error()
		return nil, err
	}

	ttlSec := req.TTLSeconds
	defaultTTL := m.runtimeCfg.DefaultDownloadTicketTTL
	if defaultTTL <= 0 {
		defaultTTL = 900
	}
	maxTTL := m.runtimeCfg.MaxDownloadTicketTTL
	if maxTTL <= 0 {
		maxTTL = 3600
	}
	if ttlSec <= 0 {
		ttlSec = defaultTTL
	}
	if ttlSec < 30 || ttlSec > maxTTL {
		auditErr = ErrInvalidDownloadTTL.Error()
		return nil, ErrInvalidDownloadTTL
	}
	ttl := time.Duration(ttlSec) * time.Second

	tgt, err := m.targets.Get(ctx, req.Target)
	if err != nil {
		auditErr = err.Error()
		return nil, fmt.Errorf("%w: %q", ErrTargetNotFound, req.Target)
	}
	if err := tgt.RequireActive(); err != nil {
		auditErr = err.Error()
		return nil, err
	}

	cleanRemotePath, err := security.CleanAndValidatePath(req.Path, tgt.DefaultCwd)
	if err != nil {
		auditErr = err.Error()
		return nil, fmt.Errorf("invalid path: %w", err)
	}
	if !security.IsPathAllowed(cleanRemotePath, tgt.AllowedPaths) {
		auditErr = ErrPathDisallowed.Error()
		return nil, fmt.Errorf("%w: %q", ErrPathDisallowed, cleanRemotePath)
	}

	sshTimeout := m.runtimeCfg.SyncExecTimeout.Duration()
	if sshTimeout <= 0 {
		sshTimeout = 30 * time.Second
	}
	sshClient, releaseSSH, err := m.sshManager.Acquire(ctx, tgt.ConnectOptions(sshTimeout))
	if err != nil {
		auditErr = err.Error()
		return nil, fmt.Errorf("failed to dial ssh for target %q: %w", req.Target, err)
	}
	defer releaseSSH()

	sftpClient, err := sftp.NewClient(sshClient.RawClient())
	if err != nil {
		auditErr = err.Error()
		return nil, fmt.Errorf("failed to initialize sftp client for target %q: %w", req.Target, err)
	}
	defer sftpClient.Close()

	resolvedPath, err := resolveRemoteFilePath(sftpClient, cleanRemotePath, tgt.AllowedPaths)
	if err != nil {
		auditErr = err.Error()
		return nil, err
	}

	fi, err := sftpClient.Stat(resolvedPath)
	if err != nil {
		auditErr = err.Error()
		return nil, fmt.Errorf("failed to stat remote file %q: %w", resolvedPath, err)
	}
	if fi.IsDir() {
		auditErr = "path is a directory"
		return nil, fmt.Errorf("remote path %q is a directory, not a file", resolvedPath)
	}

	ticket, err := GenerateDownloadTicket()
	if err != nil {
		auditErr = err.Error()
		return nil, fmt.Errorf("failed to generate download ticket: %w", err)
	}
	expiresAt := time.Now().Add(ttl)
	if err := m.downloads.register(ticket, &downloadTicket{
		TargetID:  req.Target,
		Path:      resolvedPath,
		ExpiresAt: expiresAt,
	}); err != nil {
		auditErr = err.Error()
		return nil, err
	}

	downloadURL, err := config.JoinPublicURL(publicBaseURL, "files", ticket)
	if err != nil {
		auditErr = err.Error()
		return nil, err
	}

	return &PullPrepareResponse{
		DownloadURL: downloadURL,
		Target:      req.Target,
		Path:        resolvedPath,
		ExpiresAt:   expiresAt.UTC().Format(time.RFC3339),
		Size:        fi.Size(),
	}, nil
}

func (m *transferManager) ServeDownload(w http.ResponseWriter, r *http.Request, ticket string) error {
	start := time.Now()
	var auditTarget, auditPath string
	var auditSize int64
	var auditErr string
	defer func() {
		if m.auditLogger == nil {
			return
		}
		result := "success"
		if auditErr != "" {
			result = "error"
		}
		m.auditLogger.Log(audit.Record{
			Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
			Tool:         "file_download",
			Target:       auditTarget,
			Result:       result,
			DurationMS:   time.Since(start).Milliseconds(),
			ErrorMessage: auditErr,
			Command:      fmt.Sprintf("file_download path=%s size=%d ticket_ref=%s", auditPath, auditSize, TicketRef(ticket)),
		})
	}()

	entry, err := m.downloads.claim(ticket)
	if err != nil {
		auditErr = err.Error()
		return err
	}
	auditTarget = entry.TargetID
	auditPath = entry.Path

	select {
	case m.transferSem <- struct{}{}:
		defer func() { <-m.transferSem }()
	case <-r.Context().Done():
		auditErr = r.Context().Err().Error()
		return r.Context().Err()
	}

	ctx := r.Context()
	tgt, err := m.targets.Get(ctx, entry.TargetID)
	if err != nil {
		auditErr = err.Error()
		return fmt.Errorf("%w: %q", ErrTargetNotFound, entry.TargetID)
	}
	if err := tgt.RequireActive(); err != nil {
		auditErr = err.Error()
		return err
	}

	cleanPath, err := security.CleanAndValidatePath(entry.Path, tgt.DefaultCwd)
	if err != nil {
		auditErr = err.Error()
		return err
	}
	if !security.IsPathAllowed(cleanPath, tgt.AllowedPaths) {
		auditErr = ErrPathDisallowed.Error()
		return fmt.Errorf("%w: %q", ErrPathDisallowed, cleanPath)
	}

	sshTimeout := m.runtimeCfg.SyncExecTimeout.Duration()
	if sshTimeout <= 0 {
		sshTimeout = 30 * time.Second
	}
	sshClient, releaseSSH, err := m.sshManager.Acquire(ctx, tgt.ConnectOptions(sshTimeout))
	if err != nil {
		auditErr = err.Error()
		return fmt.Errorf("failed to dial ssh for target %q: %w", entry.TargetID, err)
	}
	defer releaseSSH()

	sftpClient, err := sftp.NewClient(sshClient.RawClient())
	if err != nil {
		auditErr = err.Error()
		return fmt.Errorf("failed to initialize sftp client: %w", err)
	}
	defer sftpClient.Close()

	resolvedPath, err := resolveRemoteFilePath(sftpClient, cleanPath, tgt.AllowedPaths)
	if err != nil {
		auditErr = err.Error()
		return err
	}

	fi, err := sftpClient.Stat(resolvedPath)
	if err != nil {
		auditErr = err.Error()
		return fmt.Errorf("failed to stat remote file: %w", err)
	}
	if fi.IsDir() {
		auditErr = "path is a directory"
		return fmt.Errorf("remote path is a directory")
	}
	auditSize = fi.Size()

	filename := safeDownloadFilename(resolvedPath)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fi.Size()))
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return nil
	}

	file, err := sftpClient.Open(resolvedPath)
	if err != nil {
		auditErr = err.Error()
		return fmt.Errorf("failed to open remote file: %w", err)
	}
	defer file.Close()

	w.WriteHeader(http.StatusOK)

	bufSize := m.runtimeCfg.TransferBufferBytes
	if bufSize <= 0 {
		bufSize = 65536
	}
	buf := make([]byte, bufSize)

	_, err = io.CopyBuffer(w, file, buf)
	if err != nil {
		auditErr = err.Error()
	}
	return err
}

// Dummy filepath import suppression if unused
var _ = filepath.Separator
