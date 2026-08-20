package executor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/teacat99/mcp-execmesh/internal/audit"
	"github.com/teacat99/mcp-execmesh/internal/config"
	"github.com/teacat99/mcp-execmesh/internal/security"
	"github.com/teacat99/mcp-execmesh/internal/ssh"
	"github.com/teacat99/mcp-execmesh/internal/target"
)

// ExecRequest contains parameters for synchronous command execution.
type ExecRequest struct {
	Target         string            `json:"target"`
	Command        string            `json:"command"`
	Cwd            string            `json:"cwd,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
	Env            map[string]string `json:"env,omitempty"`
}

// RemoteExecutor defines interface for remote command execution.
type RemoteExecutor interface {
	Exec(ctx context.Context, principal *security.Principal, t *target.Target, req ExecRequest) (*ssh.ExecResult, error)
}

// Executor coordinates SSH command execution, concurrency, and auditing.
type Executor struct {
	sshManager  *ssh.Manager
	runtimeCfg  config.RuntimeConfig
	auditLogger *audit.Logger
	policy      *security.CommandPolicy
}

// NewExecutor creates a new command Executor.
func NewExecutor(
	sshManager *ssh.Manager,
	runtimeCfg config.RuntimeConfig,
	auditLogger *audit.Logger,
	policy *security.CommandPolicy,
) *Executor {
	if policy == nil {
		policy = security.DefaultCommandPolicy()
	}
	return &Executor{
		sshManager:  sshManager,
		runtimeCfg:  runtimeCfg,
		auditLogger: auditLogger,
		policy:      policy,
	}
}

// Exec executes a remote command according to security rules and limits.
func (e *Executor) Exec(ctx context.Context, principal *security.Principal, t *target.Target, req ExecRequest) (*ssh.ExecResult, error) {
	start := time.Now()
	requestID := uuid.New().String()
	subject := "anonymous"
	if principal != nil {
		subject = principal.Subject
	}

	// 1. Validate Target Capability
	if !t.Capabilities.Exec {
		err := fmt.Errorf("target %q does not allow command execution (capability disabled)", t.ID)
		e.auditLog(requestID, subject, t.ID, req.Command, req.Cwd, "denied", nil, time.Since(start).Milliseconds(), err.Error())
		return nil, err
	}

	// 2. Validate Command Policy
	if err := e.policy.ValidateCommand(req.Command); err != nil {
		e.auditLog(requestID, subject, t.ID, req.Command, req.Cwd, "denied", nil, time.Since(start).Milliseconds(), err.Error())
		return nil, fmt.Errorf("command rejected by policy: %w", err)
	}

	// 3. Resolve Working Directory
	cwd := req.Cwd
	if cwd == "" {
		cwd = t.DefaultCwd
	}
	if cwd != "" {
		cleanedCwd, err := security.CleanAndValidatePath(cwd, t.DefaultCwd)
		if err != nil {
			e.auditLog(requestID, subject, t.ID, req.Command, cwd, "denied", nil, time.Since(start).Milliseconds(), err.Error())
			return nil, fmt.Errorf("invalid working directory %q: %w", cwd, err)
		}
		cwd = cleanedCwd
		if len(t.AllowedPaths) > 0 && !security.IsPathAllowed(cwd, t.AllowedPaths) {
			err := fmt.Errorf("working directory %q is outside of allowed paths for target %q", cwd, t.ID)
			e.auditLog(requestID, subject, t.ID, req.Command, cwd, "denied", nil, time.Since(start).Milliseconds(), err.Error())
			return nil, err
		}
	}

	// 4. Calculate Execution Timeout
	timeout := e.runtimeCfg.SyncExecTimeout.Duration()
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if req.TimeoutSeconds > 0 {
		reqTimeout := time.Duration(req.TimeoutSeconds) * time.Second
		if reqTimeout < timeout {
			timeout = reqTimeout
		}
	}
	if t.Limits.MaxExecSeconds > 0 {
		maxLimit := time.Duration(t.Limits.MaxExecSeconds) * time.Second
		if maxLimit < timeout {
			timeout = maxLimit
		}
	}

	// 5. Merge Environment Variables
	mergedEnv := make(map[string]string)
	for k, v := range t.Env {
		mergedEnv[k] = v
	}
	for k, v := range req.Env {
		mergedEnv[k] = v
	}

	// 6. Acquire SSH connection
	connectOpts := t.ConnectOptions(10 * time.Second)
	client, release, err := e.sshManager.Acquire(ctx, connectOpts)
	if err != nil {
		e.auditLog(requestID, subject, t.ID, req.Command, cwd, "error", nil, time.Since(start).Milliseconds(), err.Error())
		return nil, fmt.Errorf("failed to establish SSH connection to target %q: %w", t.ID, err)
	}
	defer release()

	// 7. Execute Command with Bounded Limits
	maxStdout := e.runtimeCfg.MaxStdoutBytes
	if maxStdout <= 0 {
		maxStdout = 65536 // 64 KiB default
	}
	maxStderr := e.runtimeCfg.MaxStderrBytes
	if maxStderr <= 0 {
		maxStderr = 65536 // 64 KiB default
	}

	execOpts := ssh.ExecOptions{
		Command:        req.Command,
		Cwd:            cwd,
		Env:            mergedEnv,
		MaxStdoutBytes: maxStdout,
		MaxStderrBytes: maxStderr,
		Timeout:        timeout,
	}

	result, err := client.Exec(ctx, execOpts)
	durationMS := time.Since(start).Milliseconds()

	if err != nil {
		var exitCode *int
		if result != nil {
			ec := result.ExitCode
			exitCode = &ec
		}
		e.auditLog(requestID, subject, t.ID, req.Command, cwd, "error", exitCode, durationMS, err.Error())
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return result, err
		}
		return nil, err
	}

	ec := result.ExitCode
	e.auditLog(requestID, subject, t.ID, req.Command, cwd, "success", &ec, durationMS, "")
	return result, nil
}

func (e *Executor) auditLog(reqID, subject, targetID, cmd, cwd, result string, exitCode *int, durationMS int64, errMsg string) {
	if e.auditLogger == nil {
		return
	}
	e.auditLogger.Log(audit.Record{
		RequestID:    reqID,
		Subject:      subject,
		Tool:         "exec",
		Target:       targetID,
		Command:      cmd,
		Cwd:          cwd,
		Result:       result,
		ExitCode:     exitCode,
		DurationMS:   durationMS,
		ErrorMessage: errMsg,
	})
}
