package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// ConnectOptions holds connection parameters for dialing an SSH server.
type ConnectOptions struct {
	Address         string
	User            string
	AuthMethods     []ssh.AuthMethod
	HostKeyCallback ssh.HostKeyCallback
	Shell           string
	Timeout         time.Duration
}

// ExecResult holds the outcome of a remote SSH command execution.
type ExecResult struct {
	ExitCode        int    `json:"exit_code"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
	DurationMS      int64  `json:"duration_ms"`
}

// Client wraps an active SSH client connection.
type Client struct {
	rawClient *ssh.Client
	shell     string
}

// Dial connects to a remote SSH server with specified options.
func Dial(ctx context.Context, opts ConnectOptions) (*Client, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	clientConfig := &ssh.ClientConfig{
		User:            opts.User,
		Auth:            opts.AuthMethods,
		HostKeyCallback: opts.HostKeyCallback,
		Timeout:         timeout,
	}

	dialer := net.Dialer{Timeout: timeout}
	netConn, err := dialer.DialContext(ctx, "tcp", opts.Address)
	if err != nil {
		return nil, fmt.Errorf("TCP connection to %s failed: %w", opts.Address, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(netConn, opts.Address, clientConfig)
	if err != nil {
		_ = netConn.Close()
		return nil, fmt.Errorf("SSH handshake with %s failed: %w", opts.Address, err)
	}

	client := ssh.NewClient(sshConn, chans, reqs)
	shell := opts.Shell
	if shell == "" {
		shell = "/bin/sh"
	}

	return &Client{
		rawClient: client,
		shell:     shell,
	}, nil
}

// Close terminates the underlying SSH connection.
func (c *Client) Close() error {
	if c.rawClient != nil {
		return c.rawClient.Close()
	}
	return nil
}

// RawClient returns the underlying golang.org/x/crypto/ssh.Client for subsystems like SFTP.
func (c *Client) RawClient() *ssh.Client {
	return c.rawClient
}

// ExecOptions defines options for running a remote command.
type ExecOptions struct {
	Command        string
	Cwd            string
	Env            map[string]string
	MaxStdoutBytes int64
	MaxStderrBytes int64
	Timeout        time.Duration
}

// Exec executes a command on the remote target using a new SSH session.
func (c *Client) Exec(ctx context.Context, opts ExecOptions) (*ExecResult, error) {
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	session, err := c.rawClient.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	// Setup bounded stdout and stderr buffers to strictly prevent memory bloat
	stdoutBuf := NewLimitedBuffer(opts.MaxStdoutBytes)
	stderrBuf := NewLimitedBuffer(opts.MaxStderrBytes)
	session.Stdout = stdoutBuf
	session.Stderr = stderrBuf

	// Prepare remote command execution (wrap with cwd and shell if provided)
	shellCmd := buildCommand(opts.Command, opts.Cwd, opts.Env, c.shell)

	start := time.Now()

	// Channel to signal command completion
	done := make(chan error, 1)
	go func() {
		done <- session.Run(shellCmd)
	}()

	var runErr error
	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGTERM)
		_ = session.Close()
		runErr = ctx.Err()
	case err := <-done:
		runErr = err
	}

	durationMS := time.Since(start).Milliseconds()

	exitCode := 0
	if runErr != nil {
		var exitErr *ssh.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitStatus()
		} else if errors.Is(runErr, context.DeadlineExceeded) || errors.Is(runErr, context.Canceled) {
			return &ExecResult{
				ExitCode:        -1,
				Stdout:          stdoutBuf.String(),
				Stderr:          fmt.Sprintf("command timed out after %d ms: %v", durationMS, runErr),
				StdoutTruncated: stdoutBuf.IsTruncated(),
				StderrTruncated: stderrBuf.IsTruncated(),
				DurationMS:      durationMS,
			}, runErr
		} else {
			return nil, fmt.Errorf("SSH command execution failed: %w", runErr)
		}
	}

	return &ExecResult{
		ExitCode:        exitCode,
		Stdout:          stdoutBuf.String(),
		Stderr:          stderrBuf.String(),
		StdoutTruncated: stdoutBuf.IsTruncated(),
		StderrTruncated: stderrBuf.IsTruncated(),
		DurationMS:      durationMS,
	}, nil
}

// buildCommand constructs a safe command string running in the target's shell.
func buildCommand(cmd, cwd string, env map[string]string, shell string) string {
	var sb strings.Builder

	for k, v := range env {
		escapedVal := strings.ReplaceAll(v, "'", "'\\''")
		sb.WriteString(fmt.Sprintf("export %s='%s'; ", k, escapedVal))
	}

	if cwd != "" {
		escapedCwd := strings.ReplaceAll(cwd, "'", "'\\''")
		sb.WriteString(fmt.Sprintf("cd '%s' && ", escapedCwd))
	}

	sb.WriteString(cmd)
	return sb.String()
}
