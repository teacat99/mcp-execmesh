package tests

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/teacat99/mcp-execmesh/internal/audit"
	"github.com/teacat99/mcp-execmesh/internal/config"
	"github.com/teacat99/mcp-execmesh/internal/executor"
	"github.com/teacat99/mcp-execmesh/internal/jobs"
	servermcp "github.com/teacat99/mcp-execmesh/internal/mcp"
	"github.com/teacat99/mcp-execmesh/internal/security"
	"github.com/teacat99/mcp-execmesh/internal/ssh"
	"github.com/teacat99/mcp-execmesh/internal/target"
	cryptossh "golang.org/x/crypto/ssh"
)

func startMockSSHServerM2(t *testing.T, hostSigner cryptossh.Signer, clientPubKey cryptossh.PublicKey, tempDir string) (net.Listener, int) {
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
			go handleSSHConnM2(nConn, serverConfig, tempDir)
		}
	}()

	return listener, port
}

func handleSSHConnM2(nConn net.Conn, config *cryptossh.ServerConfig, tempDir string) {
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
				case "exec":
					cmdLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
					cmdStr := string(req.Payload[4 : 4+cmdLen])
					_ = req.Reply(true, nil)

					// Simulate remote job operations
					if strings.Contains(cmdStr, "meta.json") && strings.Contains(cmdStr, "nohup") {
						// Launching a job: create mock files
						jobDir := filepath.Join(tempDir, "mock_job_dir")
						_ = os.MkdirAll(jobDir, 0755)
						_ = os.WriteFile(filepath.Join(jobDir, "pid"), []byte("9999\n"), 0644)
						_ = os.WriteFile(filepath.Join(jobDir, "stdout.log"), []byte("Building project...\nCompiled 142 modules.\nBuild complete in 1.2s.\n"), 0644)
						_ = os.WriteFile(filepath.Join(jobDir, "stderr.log"), []byte(""), 0644)
						_ = os.WriteFile(filepath.Join(jobDir, "exit_code"), []byte("0\n"), 0644)
						_ = os.WriteFile(filepath.Join(jobDir, "finished"), []byte("2026-08-19T10:30:00Z\n"), 0644)
						_ = os.WriteFile(filepath.Join(jobDir, "meta.json"), []byte(`{"job_id":"job_test_001","target_id":"test-01","command":"npm run build","cwd":"/srv/app","started_at":"2026-08-19T10:29:58Z","pid":9999}`), 0644)

						_, _ = ch.Write([]byte("9999\n"))
						_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						return
					} else if strings.Contains(cmdStr, "---JOB_STATUS---") {
						// Query status
						resp := `---JOB_STATUS---
PID:9999
EC:0
FINISHED:2026-08-19T10:30:00Z
STDOUT_SZ:65
STDERR_SZ:0
RUNNING:0
META:{"job_id":"job_test_001","target_id":"test-01","command":"npm run build","cwd":"/srv/app","started_at":"2026-08-19T10:29:58Z","pid":9999}
`
						_, _ = ch.Write([]byte(resp))
						_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						return
					} else if strings.Contains(cmdStr, "---DATA_START---") {
						// Read output slice
						data := "Building project...\nCompiled 142 modules.\nBuild complete in 1.2s.\n"
						resp := fmt.Sprintf("TOTAL_SIZE:%d\n---DATA_START---\n%s", len(data), data)
						_, _ = ch.Write([]byte(resp))
						_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						return
					} else if strings.Contains(cmdStr, "CANCELLED") || strings.Contains(cmdStr, "kill -TERM") {
						// Cancel job
						_, _ = ch.Write([]byte("CANCELLED\n"))
						_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						return
					} else if strings.Contains(cmdStr, "EXISTS") {
						// Target scanning probe
						_, _ = ch.Write([]byte("EXISTS\n"))
						_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						return
					} else {
						_, _ = ch.Write([]byte("OK\n"))
						_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						return
					}
				default:
					_ = req.Reply(false, nil)
				}
			}
		}(channel, requests)
	}
}

func TestMilestone2_EndToEnd_Acceptance(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Generate SSH Keys
	srvPubKey, srvPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	srvSigner, err := cryptossh.NewSignerFromKey(srvPrivKey)
	require.NoError(t, err)

	clientPubKey, clientPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientSSHPubKey, err := cryptossh.NewPublicKey(clientPubKey)
	require.NoError(t, err)

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(clientPrivKey)
	require.NoError(t, err)
	privKeyPem := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}
	privKeyFile := filepath.Join(tempDir, "test_ed25519")
	require.NoError(t, os.WriteFile(privKeyFile, pem.EncodeToMemory(privKeyPem), 0600))

	// 2. Start Mock SSH Server
	listener, port := startMockSSHServerM2(t, srvSigner, clientSSHPubKey, tempDir)
	defer listener.Close()

	// 3. Known Hosts
	sshSrvPubKey, err := cryptossh.NewPublicKey(srvPubKey)
	require.NoError(t, err)
	knownHostsEntry := fmt.Sprintf("[%s]:%d %s %s\n", "127.0.0.1", port, sshSrvPubKey.Type(), base64.StdEncoding.EncodeToString(sshSrvPubKey.Marshal()))
	knownHostsFile := filepath.Join(tempDir, "known_hosts")
	require.NoError(t, os.WriteFile(knownHostsFile, []byte(knownHostsEntry), 0600))

	// 4. Config
	auditLogFile := filepath.Join(tempDir, "audit.log")
	cfg := config.DefaultConfig()
	cfg.Server.Listen = "127.0.0.1:0"
	cfg.Jobs.RemoteBaseDir = filepath.Join(tempDir, "jobs")
	cfg.Security.AuditLogPath = auditLogFile
	cfg.Targets = []config.TargetConfig{
		{
			ID:   "test-01",
			Name: "Test Node 01",
			Host: "127.0.0.1",
			Port: port,
			User: "deploy",
			Auth: config.TargetAuthConfig{
				Type:           "private_key",
				PrivateKeyFile: privKeyFile,
			},
			HostKey: config.HostKeyConfig{
				KnownHostsFile: knownHostsFile,
				Strict:         true,
			},
			DefaultCwd: "/srv/app",
			Shell:      "/bin/sh",
			Capabilities: config.TargetCapabilities{
				Exec:   true,
				Upload: true,
				Jobs:   true,
			},
		},
	}

	require.NoError(t, config.Validate(cfg, config.ValidationOptions{CheckFilesExist: true}))

	// 5. Initialize Services
	registry, err := target.NewRegistry(cfg)
	require.NoError(t, err)

	auditLogger, err := audit.NewLogger(auditLogFile, false)
	require.NoError(t, err)
	defer auditLogger.Close()

	sshManager := ssh.NewManager(cfg.Runtime.MaxConcurrentSSH)
	policy := security.DefaultCommandPolicy()
	execEngine := executor.NewExecutor(sshManager, cfg.Runtime, auditLogger, policy)
	jobMgr := jobs.NewManager(registry, sshManager, cfg.Jobs, cfg.Runtime, auditLogger, policy)
	auth := &security.NoneAuthenticator{}

	srv, err := servermcp.NewServer(cfg, registry, execEngine, jobMgr, nil, auth, auditLogger)
	require.NoError(t, err)
	require.NotNil(t, srv)

	ctx := context.Background()

	// 6. Test exec_start
	startReq := jobs.JobStartRequest{
		Target:  "test-01",
		Command: "npm run build",
		Cwd:     "/srv/app",
	}
	tgt, err := registry.Get(ctx, "test-01")
	require.NoError(t, err)

	startRes, err := jobMgr.Start(ctx, nil, tgt, startReq)
	require.NoError(t, err)
	assert.NotEmpty(t, startRes.JobID)
	assert.Equal(t, "test-01", startRes.Target)
	assert.Equal(t, jobs.StateRunning, startRes.State)

	jobID := startRes.JobID

	// 7. Test job_status
	statusRes, err := jobMgr.Status(ctx, nil, jobID, "test-01")
	require.NoError(t, err)
	assert.Equal(t, jobID, statusRes.JobID)
	assert.Equal(t, "test-01", statusRes.Target)
	assert.Equal(t, jobs.StateSucceeded, statusRes.State)
	assert.NotNil(t, statusRes.ExitCode)
	assert.Equal(t, 0, *statusRes.ExitCode)
	assert.Equal(t, int64(65), statusRes.StdoutBytes)

	// 8. Test job_output pagination
	outputReq := jobs.JobOutputRequest{
		JobID:  jobID,
		Stream: "stdout",
		Offset: 0,
		Limit:  1024,
	}
	outputRes, err := jobMgr.Output(ctx, nil, outputReq, "test-01")
	require.NoError(t, err)
	assert.Equal(t, jobID, outputRes.JobID)
	assert.Equal(t, "stdout", outputRes.Stream)
	assert.Contains(t, outputRes.Data, "Building project...")
	assert.Equal(t, int64(0), outputRes.Offset)
	assert.True(t, outputRes.EOF)

	// 9. Test job_cancel
	cancelRes, err := jobMgr.Cancel(ctx, nil, jobID, "test-01")
	require.NoError(t, err)
	assert.Equal(t, jobID, cancelRes.JobID)
	assert.Equal(t, jobs.StateCancelled, cancelRes.State)

	// 10. Milestone 2 Key Requirement: Simulate MCP Gateway restart & verify recovery
	// Create a brand new JobManager instance with empty in-memory state
	freshJobMgr := jobs.NewManager(registry, sshManager, cfg.Jobs, cfg.Runtime, auditLogger, policy)

	// Status query on restarted Gateway should successfully recover target from probe & remote files
	recoveredStatus, err := freshJobMgr.Status(ctx, nil, jobID, "")
	require.NoError(t, err)
	assert.Equal(t, jobID, recoveredStatus.JobID)
	assert.Equal(t, "test-01", recoveredStatus.Target)
	assert.Equal(t, jobs.StateSucceeded, recoveredStatus.State)
}
