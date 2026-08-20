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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/teacat/mcp-execmesh/internal/audit"
	"github.com/teacat/mcp-execmesh/internal/config"
	"github.com/teacat/mcp-execmesh/internal/executor"
	servermcp "github.com/teacat/mcp-execmesh/internal/mcp"
	"github.com/teacat/mcp-execmesh/internal/security"
	"github.com/teacat/mcp-execmesh/internal/ssh"
	"github.com/teacat/mcp-execmesh/internal/target"
	cryptossh "golang.org/x/crypto/ssh"
)

// startMockSSHServer starts a local SSH server for testing.
func startMockSSHServer(t *testing.T, hostSigner cryptossh.Signer, clientPubKey cryptossh.PublicKey) (net.Listener, int) {
	serverConfig := &cryptossh.ServerConfig{
		PublicKeyCallback: func(conn cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
			if bytes.Equal(key.Marshal(), clientPubKey.Marshal()) {
				return &cryptossh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", conn.User())
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

			go handleSSHConn(nConn, serverConfig)
		}
	}()

	return listener, port
}

func handleSSHConn(nConn net.Conn, config *cryptossh.ServerConfig) {
	sshConn, chans, reqs, err := cryptossh.NewServerConn(nConn, config)
	if err != nil {
		_ = nConn.Close()
		return
	}
	defer sshConn.Close()

	go cryptossh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(cryptossh.UnknownChannelType, "unknown channel type")
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
					// Extract command string
					cmdLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
					cmdStr := string(req.Payload[4 : 4+cmdLen])
					_ = req.Reply(true, nil)

					if strings.Contains(cmdStr, "uname -a") {
						_, _ = ch.Write([]byte("Linux test-01 6.6.0-mock x86_64 GNU/Linux\n"))
						_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						return
					} else if strings.Contains(cmdStr, "generate-large-output") {
						// Write 10 KiB of output
						largeData := bytes.Repeat([]byte("A"), 10240)
						_, _ = ch.Write(largeData)
						_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						return
					} else if strings.Contains(cmdStr, "fail-command") {
						_, _ = ch.Stderr().Write([]byte("command not found: fail-command\n"))
						_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 127})
						return
					} else {
						_, _ = ch.Write([]byte("executed: " + cmdStr + "\n"))
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

func TestMilestone1_EndToEnd_Acceptance(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Generate Server ED25519 Key
	srvPubKey, srvPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	srvSigner, err := cryptossh.NewSignerFromKey(srvPrivKey)
	require.NoError(t, err)

	// 2. Generate Client ED25519 Key
	clientPubKey, clientPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientSSHPubKey, err := cryptossh.NewPublicKey(clientPubKey)
	require.NoError(t, err)

	// Encode client private key into PKCS#8 PEM format
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(clientPrivKey)
	require.NoError(t, err)
	privKeyPem := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}
	privKeyFile := filepath.Join(tempDir, "test_ed25519")
	require.NoError(t, os.WriteFile(privKeyFile, pem.EncodeToMemory(privKeyPem), 0600))

	// 3. Start Mock SSH Server
	listener, port := startMockSSHServer(t, srvSigner, clientSSHPubKey)
	defer listener.Close()

	// 4. Create known_hosts file
	sshSrvPubKey, err := cryptossh.NewPublicKey(srvPubKey)
	require.NoError(t, err)
	knownHostsEntry := fmt.Sprintf("[%s]:%d %s %s\n", "127.0.0.1", port, sshSrvPubKey.Type(), base64.StdEncoding.EncodeToString(sshSrvPubKey.Marshal()))
	knownHostsFile := filepath.Join(tempDir, "known_hosts")
	require.NoError(t, os.WriteFile(knownHostsFile, []byte(knownHostsEntry), 0600))

	// 5. Build Configuration
	auditLogFile := filepath.Join(tempDir, "audit.log")
	cfg := config.DefaultConfig()
	cfg.Server.Listen = "127.0.0.1:0"
	cfg.Server.LogLevel = "debug"
	cfg.Runtime.SyncExecTimeout = config.Duration(10 * time.Second)
	cfg.Runtime.MaxStdoutBytes = 2048 // 2 KiB limit for truncation test
	cfg.Runtime.MaxStderrBytes = 2048
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
			DefaultCwd: "/srv/test",
			Shell:      "/bin/sh",
			Tags:       []string{"test", "linux"},
			Capabilities: config.TargetCapabilities{
				Exec:   true,
				Upload: true,
				Jobs:   true,
			},
		},
	}

	// Validate config
	err = config.Validate(cfg, config.ValidationOptions{CheckFilesExist: true})
	require.NoError(t, err)

	// 6. Initialize Stack
	registry, err := target.NewRegistry(cfg)
	require.NoError(t, err)

	auditLogger, err := audit.NewLogger(auditLogFile, false)
	require.NoError(t, err)
	defer auditLogger.Close()

	sshManager := ssh.NewManager(cfg.Runtime.MaxConcurrentSSH)
	execEngine := executor.NewExecutor(sshManager, cfg.Runtime, auditLogger, security.DefaultCommandPolicy())
	auth := &security.NoneAuthenticator{}

	srv, err := servermcp.NewServer(cfg, registry, execEngine, nil, nil, auth, auditLogger)
	require.NoError(t, err)
	require.NotNil(t, srv)

	ctx := context.Background()

	// 7. Verify targets_list
	list := registry.List(ctx)
	require.Len(t, list, 1)
	assert.Equal(t, "test-01", list[0].ID)
	assert.Equal(t, "Test Node 01", list[0].Name)
	assert.Equal(t, "/srv/test", list[0].DefaultCwd)
	assert.True(t, list[0].Capabilities.Exec)

	// 8. Verify target_info
	tgt, err := registry.Get(ctx, "test-01")
	require.NoError(t, err)
	detail := tgt.Detail()
	assert.Equal(t, "test-01", detail.ID)
	assert.Equal(t, "/srv/test", detail.DefaultCwd)
	assert.Equal(t, "/bin/sh", detail.Shell)

	// 9. Milestone 1 Core Acceptance: Execute `uname -a` on test-01
	execReq := executor.ExecRequest{
		Target:  "test-01",
		Command: "uname -a",
	}
	execRes, err := execEngine.Exec(ctx, nil, tgt, execReq)
	require.NoError(t, err)
	require.NotNil(t, execRes)

	assert.Equal(t, 0, execRes.ExitCode)
	assert.Contains(t, execRes.Stdout, "Linux test-01 6.6.0-mock x86_64 GNU/Linux")
	assert.Empty(t, execRes.Stderr)
	assert.False(t, execRes.StdoutTruncated)
	assert.False(t, execRes.StderrTruncated)
	assert.Greater(t, execRes.DurationMS, int64(-1))

	// 10. Verify Bounded Output Truncation
	execReqLarge := executor.ExecRequest{
		Target:  "test-01",
		Command: "generate-large-output",
	}
	execResLarge, err := execEngine.Exec(ctx, nil, tgt, execReqLarge)
	require.NoError(t, err)
	require.NotNil(t, execResLarge)

	assert.Equal(t, 0, execResLarge.ExitCode)
	assert.True(t, execResLarge.StdoutTruncated, "output should be truncated to max_stdout_bytes")
	assert.Equal(t, 2048, len(execResLarge.Stdout))

	// 11. Verify Error Exit Code & Stderr
	execReqFail := executor.ExecRequest{
		Target:  "test-01",
		Command: "fail-command",
	}
	execResFail, err := execEngine.Exec(ctx, nil, tgt, execReqFail)
	require.NoError(t, err)
	assert.Equal(t, 127, execResFail.ExitCode)
	assert.Contains(t, execResFail.Stderr, "command not found")

	// 12. Verify Audit Log content and zero secret leak
	auditLogger.Close()
	auditBytes, err := os.ReadFile(auditLogFile)
	require.NoError(t, err)
	auditContent := string(auditBytes)

	assert.Contains(t, auditContent, "uname -a")
	assert.Contains(t, auditContent, "test-01")
	assert.NotContains(t, auditContent, string(privKeyPem.Bytes))
	assert.NotContains(t, auditContent, "PRIVATE KEY")

	// 13. Verify Strict HostKey Rejection
	diffPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshDiffPubKey, err := cryptossh.NewPublicKey(diffPubKey)
	require.NoError(t, err)
	badKnownHostsEntry := fmt.Sprintf("[%s]:%d %s %s\n", "127.0.0.1", port, sshDiffPubKey.Type(), base64.StdEncoding.EncodeToString(sshDiffPubKey.Marshal()))

	badKnownHostsFile := filepath.Join(tempDir, "bad_known_hosts")
	require.NoError(t, os.WriteFile(badKnownHostsFile, []byte(badKnownHostsEntry), 0600))

	badCfg := *cfg
	badCfg.Targets = []config.TargetConfig{cfg.Targets[0]}
	badCfg.Targets[0].HostKey.KnownHostsFile = badKnownHostsFile

	badRegistry, err := target.NewRegistry(&badCfg)
	require.NoError(t, err)
	badTgt, err := badRegistry.Get(ctx, "test-01")
	require.NoError(t, err)

	_, err = execEngine.Exec(ctx, nil, badTgt, execReq)
	require.Error(t, err, "execution should fail due to strict host key mismatch")
	assert.Contains(t, err.Error(), "SSH handshake")
}
