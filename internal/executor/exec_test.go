package executor

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/teacat99/mcp-execmesh/internal/config"
	"github.com/teacat99/mcp-execmesh/internal/security"
	"github.com/teacat99/mcp-execmesh/internal/ssh"
	"github.com/teacat99/mcp-execmesh/internal/target"
)

func TestExecutor_CapabilityAndPathValidation(t *testing.T) {
	runtimeCfg := config.RuntimeConfig{
		MaxConcurrentSSH: 2,
		SyncExecTimeout:  config.Duration(5 * time.Second),
		MaxStdoutBytes:   4096,
		MaxStderrBytes:   4096,
	}
	sshManager := ssh.NewManager(2)
	policy := security.DefaultCommandPolicy()
	exec := NewExecutor(sshManager, runtimeCfg, nil, policy)

	ctx := context.Background()

	// 1. Target with exec disabled
	disabledTarget := &target.Target{
		ID:   "no-exec-node",
		Host: "127.0.0.1",
		Port: 22,
		Capabilities: target.TargetCapabilities{
			Exec: false,
		},
	}
	_, err := exec.Exec(ctx, nil, disabledTarget, ExecRequest{
		Target:  "no-exec-node",
		Command: "uname -a",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not allow command execution")

	// 2. Target with allowed paths restriction
	restrictedTarget := &target.Target{
		ID:   "restricted-node",
		Host: "127.0.0.1",
		Port: 22,
		Capabilities: target.TargetCapabilities{
			Exec: true,
		},
		AllowedPaths: []string{"/srv/app"},
	}
	_, err = exec.Exec(ctx, nil, restrictedTarget, ExecRequest{
		Target:  "restricted-node",
		Command: "ls",
		Cwd:     "/etc",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "outside of allowed paths")

	// 3. Command policy rejection
	_, err = exec.Exec(ctx, nil, restrictedTarget, ExecRequest{
		Target:  "restricted-node",
		Command: "",
	})
	require.Error(t, err)
}
