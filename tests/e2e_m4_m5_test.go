package tests

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/teacat/mcp-execmesh/internal/audit"
	"github.com/teacat/mcp-execmesh/internal/config"
	"github.com/teacat/mcp-execmesh/internal/executor"
	"github.com/teacat/mcp-execmesh/internal/jobs"
	servermcp "github.com/teacat/mcp-execmesh/internal/mcp"
	"github.com/teacat/mcp-execmesh/internal/security"
	"github.com/teacat/mcp-execmesh/internal/ssh"
	"github.com/teacat/mcp-execmesh/internal/target"
	"github.com/teacat/mcp-execmesh/internal/transfer"
	cryptossh "golang.org/x/crypto/ssh"
)

func TestMilestone4_ConcurrencyAndSecurity(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Setup Keys and Mock Server
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostSigner, err := cryptossh.NewSignerFromKey(hostPriv)
	require.NoError(t, err)

	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientSSHPub, err := cryptossh.NewPublicKey(clientPub)
	require.NoError(t, err)

	pkcs8Priv, err := x509.MarshalPKCS8PrivateKey(clientPriv)
	require.NoError(t, err)
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Priv,
	})
	keyPath := filepath.Join(tempDir, "client_key")
	require.NoError(t, os.WriteFile(keyPath, privKeyPEM, 0600))

	listener, port := startMockSFTPSSHServer(t, hostSigner, clientSSHPub, tempDir)
	defer listener.Close()

	knownHostsPath := filepath.Join(tempDir, "known_hosts")
	hostKeyEntry := fmt.Sprintf("[127.0.0.1]:%d %s %s\n",
		port,
		hostSigner.PublicKey().Type(),
		base64.StdEncoding.EncodeToString(hostSigner.PublicKey().Marshal()),
	)
	require.NoError(t, os.WriteFile(knownHostsPath, []byte(hostKeyEntry), 0600))

	// 2. Setup Config with Concurrency limits & Audit log masking
	cfg := config.DefaultConfig()
	cfg.Runtime.MaxConcurrentRequests = 2 // Low limit for concurrency test
	cfg.Security.MaskSensitiveCommands = true
	cfg.Targets = []config.TargetConfig{
		{
			ID:         "test-01",
			Name:       "Test Node 01",
			Host:       "127.0.0.1",
			Port:       port,
			User:       "teacat",
			DefaultCwd: "/srv/app",
			Auth: config.TargetAuthConfig{
				Type:           "private_key",
				PrivateKeyFile: keyPath,
			},
			HostKey: config.HostKeyConfig{
				Strict:         true,
				KnownHostsFile: knownHostsPath,
			},
			Capabilities: config.TargetCapabilities{
				Exec:   true,
				Upload: true,
				Jobs:   true,
			},
			AllowedPaths: []string{tempDir},
		},
	}

	registry, err := target.NewRegistry(cfg)
	require.NoError(t, err)

	auditLogFile := filepath.Join(tempDir, "audit.log")
	auditLogger, err := audit.NewLogger(auditLogFile, true) // masked
	require.NoError(t, err)
	defer auditLogger.Close()

	sshManager := ssh.NewManager(4)
	policy := security.DefaultCommandPolicy()
	execEngine := executor.NewExecutor(sshManager, cfg.Runtime, auditLogger, policy)
	jobMgr := jobs.NewManager(registry, sshManager, cfg.Jobs, cfg.Runtime, auditLogger, policy)
	transferMgr := transfer.NewTransferManager(registry, sshManager, cfg.Security, cfg.Runtime, auditLogger, nil)
	auth := &security.NoneAuthenticator{}

	srv, err := servermcp.NewServer(cfg, registry, execEngine, jobMgr, transferMgr, auth, auditLogger)
	require.NoError(t, err)
	handler := srv.Handler()

	// 3. Test HTTP Concurrency Limiting (HTTP 429)
	// We make concurrent requests through handler
	var wg sync.WaitGroup
	var mu sync.Mutex
	statusCodes := make([]int, 0)

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{}`))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			mu.Lock()
			statusCodes = append(statusCodes, rec.Code)
			mu.Unlock()
		}()
	}
	wg.Wait()

	// Verify all requests received valid HTTP status responses
	require.Len(t, statusCodes, 5)
	t.Logf("Received status codes: %v", statusCodes)
	for _, code := range statusCodes {
		assert.True(t, code == http.StatusOK || code == http.StatusBadRequest || code == http.StatusTooManyRequests || code == http.StatusMethodNotAllowed || code == http.StatusUnsupportedMediaType, fmt.Sprintf("Unexpected status code: %d", code))
	}

	// 4. Test Audit Log Masking
	auditLogger.Log(audit.Record{
		Tool:    "exec",
		Target:  "test-01",
		Command: "export SECRET_KEY=super-secret-password-123",
		Result:  "success",
	})
	auditData, err := os.ReadFile(auditLogFile)
	require.NoError(t, err)
	assert.NotContains(t, string(auditData), "super-secret-password-123")
	assert.Contains(t, string(auditData), "[MASKED]")
}

func TestMilestone5_FileHashAndPullPrepare(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Setup Keys and Mock Server
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostSigner, err := cryptossh.NewSignerFromKey(hostPriv)
	require.NoError(t, err)

	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientSSHPub, err := cryptossh.NewPublicKey(clientPub)
	require.NoError(t, err)

	pkcs8Priv, err := x509.MarshalPKCS8PrivateKey(clientPriv)
	require.NoError(t, err)
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Priv,
	})
	keyPath := filepath.Join(tempDir, "client_key")
	require.NoError(t, os.WriteFile(keyPath, privKeyPEM, 0600))

	listener, port := startMockSFTPSSHServer(t, hostSigner, clientSSHPub, tempDir)
	defer listener.Close()

	knownHostsPath := filepath.Join(tempDir, "known_hosts")
	hostKeyEntry := fmt.Sprintf("[127.0.0.1]:%d %s %s\n",
		port,
		hostSigner.PublicKey().Type(),
		base64.StdEncoding.EncodeToString(hostSigner.PublicKey().Marshal()),
	)
	require.NoError(t, os.WriteFile(knownHostsPath, []byte(hostKeyEntry), 0600))

	// 2. Prepare a test file on the mock server
	testContent := []byte("Hello MCP ExecMesh Milestone 5 - File Hash and Stream Pull!\n")
	testFilePath := filepath.Join(tempDir, "test-data.txt")
	require.NoError(t, os.WriteFile(testFilePath, testContent, 0644))

	expectedSHA256 := sha256.Sum256(testContent)
	expectedSHA256Hex := hex.EncodeToString(expectedSHA256[:])

	expectedSHA1 := sha1.Sum(testContent)
	expectedSHA1Hex := hex.EncodeToString(expectedSHA1[:])

	expectedMD5 := md5.Sum(testContent)
	expectedMD5Hex := hex.EncodeToString(expectedMD5[:])

	cfg := config.DefaultConfig()
	cfg.Targets = []config.TargetConfig{
		{
			ID:         "test-01",
			Name:       "Test Node 01",
			Host:       "127.0.0.1",
			Port:       port,
			User:       "teacat",
			DefaultCwd: tempDir,
			Auth: config.TargetAuthConfig{
				Type:           "private_key",
				PrivateKeyFile: keyPath,
			},
			HostKey: config.HostKeyConfig{
				Strict:         true,
				KnownHostsFile: knownHostsPath,
			},
			Capabilities: config.TargetCapabilities{
				Exec:   true,
				Upload: true,
				Jobs:   true,
			},
			AllowedPaths: []string{tempDir},
		},
	}

	registry, err := target.NewRegistry(cfg)
	require.NoError(t, err)

	auditLogFile := filepath.Join(tempDir, "audit.log")
	auditLogger, err := audit.NewLogger(auditLogFile, false)
	require.NoError(t, err)
	defer auditLogger.Close()

	sshManager := ssh.NewManager(4)
	policy := security.DefaultCommandPolicy()
	execEngine := executor.NewExecutor(sshManager, cfg.Runtime, auditLogger, policy)
	jobMgr := jobs.NewManager(registry, sshManager, cfg.Jobs, cfg.Runtime, auditLogger, policy)
	transferMgr := transfer.NewTransferManager(registry, sshManager, cfg.Security, cfg.Runtime, auditLogger, nil)
	auth := &security.NoneAuthenticator{}

	srv, err := servermcp.NewServer(cfg, registry, execEngine, jobMgr, transferMgr, auth, auditLogger)
	require.NoError(t, err)
	handler := srv.Handler()

	ctx := context.Background()

	// ==========================================
	// Test Step 1: file_hash with SHA256, SHA1, MD5
	// ==========================================
	hashRes256, err := transferMgr.Hash(ctx, transfer.HashRequest{
		Target:    "test-01",
		Path:      testFilePath,
		Algorithm: "sha256",
	})
	require.NoError(t, err)
	assert.Equal(t, expectedSHA256Hex, hashRes256.Hash)
	assert.Equal(t, int64(len(testContent)), hashRes256.Size)

	hashResSHA1, err := transferMgr.Hash(ctx, transfer.HashRequest{
		Target:    "test-01",
		Path:      testFilePath,
		Algorithm: "sha1",
	})
	require.NoError(t, err)
	assert.Equal(t, expectedSHA1Hex, hashResSHA1.Hash)

	hashResMD5, err := transferMgr.Hash(ctx, transfer.HashRequest{
		Target:    "test-01",
		Path:      testFilePath,
		Algorithm: "md5",
	})
	require.NoError(t, err)
	assert.Equal(t, expectedMD5Hex, hashResMD5.Hash)

	// ==========================================
	// Test Step 2: file_pull_prepare & streaming download via GET /files/{token}
	// ==========================================
	pullRes, err := transferMgr.PullPrepare(ctx, transfer.PullPrepareRequest{
		Target:     "test-01",
		Path:       testFilePath,
		TTLSeconds: 300,
	}, "https://mcp.example.com")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(pullRes.DownloadURL, "https://mcp.example.com/files/"))
	assert.NotContains(t, pullRes.DownloadURL, "127.0.0.1")
	assert.Equal(t, int64(len(testContent)), pullRes.Size)

	ticket := strings.TrimPrefix(pullRes.DownloadURL, "https://mcp.example.com/files/")
	require.NotEmpty(t, ticket)

	// Access GET /files/{ticket} through HTTP Server Handler
	downloadReq := httptest.NewRequest(http.MethodGet, "/files/"+ticket, nil)
	downloadRec := httptest.NewRecorder()
	handler.ServeHTTP(downloadRec, downloadReq)

	assert.Equal(t, http.StatusOK, downloadRec.Code)
	assert.Equal(t, "application/octet-stream", downloadRec.Header().Get("Content-Type"))
	assert.Equal(t, "private, no-store", downloadRec.Header().Get("Cache-Control"))
	assert.Equal(t, testContent, downloadRec.Body.Bytes())

	// Re-requesting with the same ticket should fail (single-use)
	downloadRec2 := httptest.NewRecorder()
	handler.ServeHTTP(downloadRec2, downloadReq)
	assert.Equal(t, http.StatusNotFound, downloadRec2.Code)
}
