package tests

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/teacat99/mcp-execmesh/internal/audit"
	"github.com/teacat99/mcp-execmesh/internal/config"
	"github.com/teacat99/mcp-execmesh/internal/ssh"
	"github.com/teacat99/mcp-execmesh/internal/target"
	"github.com/teacat99/mcp-execmesh/internal/transfer"
	cryptossh "golang.org/x/crypto/ssh"
)

// startMockSFTPSSHServer spins up a mock SSH server with both exec and SFTP subsystem support.
func startMockSFTPSSHServer(t *testing.T, hostSigner cryptossh.Signer, clientPubKey cryptossh.PublicKey, rootDir string) (net.Listener, int) {
	serverConfig := &cryptossh.ServerConfig{
		PublicKeyCallback: func(conn cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
			if bytes.Equal(key.Marshal(), clientPubKey.Marshal()) {
				return &cryptossh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unknown key")
		},
	}
	serverConfig.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			nConn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleSFTPSSHConn(nConn, serverConfig, rootDir)
		}
	}()

	return listener, port
}

func handleSFTPSSHConn(nConn net.Conn, config *cryptossh.ServerConfig, rootDir string) {
	sshConn, chans, reqs, err := cryptossh.NewServerConn(nConn, config)
	if err != nil {
		_ = nConn.Close()
		return
	}
	defer sshConn.Close()

	go cryptossh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(cryptossh.UnknownChannelType, "unknown")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}

		go func(ch cryptossh.Channel, in <-chan *cryptossh.Request) {
			defer ch.Close()

			for req := range in {
				switch req.Type {
				case "subsystem":
					subsystem := string(req.Payload[4:]) // string payload in SSH wire format
					if subsystem == "sftp" {
						_ = req.Reply(true, nil)
						sftpServer, err := sftp.NewServer(ch)
						if err == nil {
							_ = sftpServer.Serve()
						}
						return
					}
					_ = req.Reply(false, nil)
				default:
					_ = req.Reply(false, nil)
				}
			}
		}(channel, requests)
	}
}

func TestMilestone3_E2E_TransferAndMemory(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Generate SSH Keys
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

	// 2. Start Mock SFTP SSH Server
	listener, port := startMockSFTPSSHServer(t, hostSigner, clientSSHPub, tempDir)
	defer listener.Close()

	knownHostsPath := filepath.Join(tempDir, "known_hosts")
	hostKeyEntry := fmt.Sprintf("[127.0.0.1]:%d %s %s\n",
		port,
		hostSigner.PublicKey().Type(),
		base64.StdEncoding.EncodeToString(hostSigner.PublicKey().Marshal()),
	)
	require.NoError(t, os.WriteFile(knownHostsPath, []byte(hostKeyEntry), 0600))

	// 3. Setup Mock HTTP Download Server
	testFileContent := []byte("Remote Executor MCP - Milestone 3 File Push Payload\nVersion 1.0.0\n")
	expectedSHA256 := sha256.Sum256(testFileContent)
	expectedSHA256Hex := hex.EncodeToString(expectedSHA256[:])

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app.bin":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(testFileContent)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(testFileContent)
		case "/huge-1gb.bin":
			// Generate 1GB data stream on the fly (1024 * 1024 * 1024 = 1073741824 bytes)
			totalBytes := int64(1024 * 1024 * 1024)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", fmt.Sprintf("%d", totalBytes))
			w.WriteHeader(http.StatusOK)

			chunk := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64 KiB chunk
			var sent int64
			for sent < totalBytes {
				toSend := int64(len(chunk))
				if sent+toSend > totalBytes {
					toSend = totalBytes - sent
				}
				n, err := w.Write(chunk[:toSend])
				if err != nil {
					return
				}
				sent += int64(n)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer httpServer.Close()

	// 4. Initialize Configuration & Registry
	cfg := config.DefaultConfig()
	cfg.Security.RequireKnownHosts = true
	cfg.Security.BlockPrivateDownloadAddresses = false // allow httptest 127.0.0.1 for this test
	cfg.Security.AllowedFileDownloadSchemes = []string{"http", "https"}
	cfg.Runtime.TransferBufferBytes = 65536
	cfg.Runtime.MaxUploadBytes = 5 * 1024 * 1024 * 1024 // 5 GB

	remoteAppDir := filepath.Join(tempDir, "remote_root", "srv", "app")
	require.NoError(t, os.MkdirAll(remoteAppDir, 0755))

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
			Limits: config.TargetLimitsConfig{
				MaxExecSeconds: 30,
				MaxUploadBytes: 5 * 1024 * 1024 * 1024,
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
	transferMgr := transfer.NewTransferManager(registry, sshManager, cfg.Security, cfg.Runtime, auditLogger, httpServer.Client())

	ctx := context.Background()
	remoteDestPath := filepath.Join(remoteAppDir, "app.bin")

	// ==========================================
	// Test Step 1: Standard file_push
	// ==========================================
	pushRes, err := transferMgr.Push(ctx, transfer.PushRequest{
		Target: "test-01",
		File: transfer.DownloadFileSpec{
			DownloadURL: httpServer.URL + "/app.bin",
			FileID:      "file_12345",
			FileName:    "app.bin",
		},
		RemotePath: remoteDestPath,
		Overwrite:  false,
		Mode:       "0755",
	})
	require.NoError(t, err)
	assert.Equal(t, "test-01", pushRes.Target)
	assert.Equal(t, remoteDestPath, pushRes.RemotePath)
	assert.Equal(t, int64(len(testFileContent)), pushRes.Size)
	assert.Equal(t, expectedSHA256Hex, pushRes.SHA256)
	assert.Equal(t, "0755", pushRes.Mode)

	// Verify file on disk
	diskData, err := os.ReadFile(remoteDestPath)
	require.NoError(t, err)
	assert.Equal(t, testFileContent, diskData)

	// ==========================================
	// Test Step 2: file_stat
	// ==========================================
	statRes, err := transferMgr.Stat(ctx, transfer.StatRequest{
		Target: "test-01",
		Path:   remoteDestPath,
	})
	require.NoError(t, err)
	assert.True(t, statRes.Exists)
	assert.Equal(t, "file", statRes.Type)
	assert.Equal(t, int64(len(testFileContent)), statRes.Size)
	assert.Equal(t, "0755", statRes.Mode)

	// ==========================================
	// Test Step 3: Overwrite protection
	// ==========================================
	// Overwrite = false should fail
	_, err = transferMgr.Push(ctx, transfer.PushRequest{
		Target: "test-01",
		File: transfer.DownloadFileSpec{
			DownloadURL: httpServer.URL + "/app.bin",
			FileID:      "file_12345",
		},
		RemotePath: remoteDestPath,
		Overwrite:  false,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, transfer.ErrFileAlreadyExists)

	// Overwrite = true should succeed
	pushRes2, err := transferMgr.Push(ctx, transfer.PushRequest{
		Target: "test-01",
		File: transfer.DownloadFileSpec{
			DownloadURL: httpServer.URL + "/app.bin",
			FileID:      "file_12345",
		},
		RemotePath: remoteDestPath,
		Overwrite:  true,
		Mode:       "0644",
	})
	require.NoError(t, err)
	assert.Equal(t, "0644", pushRes2.Mode)

	// ==========================================
	// Test Step 3.1: file_push_url Direct URL Push
	// ==========================================
	urlDestPath := filepath.Join(remoteAppDir, "app-url.bin")
	pushURLRes, err := transferMgr.Push(ctx, transfer.PushRequest{
		Target: "test-01",
		File: transfer.DownloadFileSpec{
			DownloadURL: httpServer.URL + "/app.bin",
		},
		RemotePath: urlDestPath,
		Overwrite:  true,
		Mode:       "0640",
	})
	require.NoError(t, err)
	assert.Equal(t, urlDestPath, pushURLRes.RemotePath)
	assert.Equal(t, int64(len(testFileContent)), pushURLRes.Size)
	assert.Equal(t, expectedSHA256Hex, pushURLRes.SHA256)
	assert.Equal(t, "0640", pushURLRes.Mode)

	urlDiskData, err := os.ReadFile(urlDestPath)
	require.NoError(t, err)
	assert.Equal(t, testFileContent, urlDiskData)

	// ==========================================
	// Test Step 4: 1GB Large File Streaming & Memory Verification
	// ==========================================
	hugeDestPath := filepath.Join(remoteAppDir, "huge-1gb.bin")

	// Trigger GC and measure baseline memory
	runtime.GC()
	var mBefore runtime.MemStats
	runtime.ReadMemStats(&mBefore)

	hugePushRes, err := transferMgr.Push(ctx, transfer.PushRequest{
		Target: "test-01",
		File: transfer.DownloadFileSpec{
			DownloadURL: httpServer.URL + "/huge-1gb.bin",
			FileID:      "file_huge_1gb",
		},
		RemotePath: hugeDestPath,
		Overwrite:  true,
		Mode:       "0644",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1024*1024*1024), hugePushRes.Size)

	// Measure memory after 1GB streaming
	runtime.GC()
	var mAfter runtime.MemStats
	runtime.ReadMemStats(&mAfter)

	// HeapAlloc should remain bounded (far below 50MB, typically < 10MB) despite transferring 1GB
	heapAllocMB := float64(mAfter.HeapAlloc) / (1024 * 1024)
	t.Logf("Memory stats after 1GB streaming: HeapAlloc = %.2f MB (Before: %.2f MB)",
		heapAllocMB, float64(mBefore.HeapAlloc)/(1024*1024))
	assert.Less(t, heapAllocMB, float64(40), "Heap memory must remain bounded under 40MB during 1GB transfer")

	// Verify stat on huge file
	hugeStatRes, err := transferMgr.Stat(ctx, transfer.StatRequest{
		Target: "test-01",
		Path:   hugeDestPath,
	})
	require.NoError(t, err)
	assert.True(t, hugeStatRes.Exists)
	assert.Equal(t, int64(1024*1024*1024), hugeStatRes.Size)
}
