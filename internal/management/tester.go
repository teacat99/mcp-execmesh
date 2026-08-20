package management

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/teacat99/mcp-execmesh/internal/config"
	"github.com/teacat99/mcp-execmesh/internal/ssh"
)

type TestResult struct {
	Success         bool   `json:"success"`
	SSH             bool   `json:"ssh"`
	HostKeyVerified bool   `json:"host_key_verified"`
	Authenticated   bool   `json:"authenticated"`
	DefaultCwdValid bool   `json:"default_cwd_valid"`
	DurationMS      int64  `json:"duration_ms"`
	Error           string `json:"error,omitempty"`
}

type Tester interface {
	Test(ctx context.Context, tc config.TargetConfig) (*TestResult, error)
}

type SSHTester struct{}

func (SSHTester) Test(ctx context.Context, tc config.TargetConfig) (*TestResult, error) {
	start := time.Now()
	out := &TestResult{}
	authMethods, err := ssh.CreateAuthMethods(tc.Auth)
	if err != nil {
		out.Error = err.Error()
		out.DurationMS = time.Since(start).Milliseconds()
		return out, nil
	}
	cb, err := ssh.NewHostKeyCallback(tc.HostKey.KnownHostsFile, tc.HostKey.Strict)
	if err != nil {
		out.Error = err.Error()
		out.DurationMS = time.Since(start).Milliseconds()
		return out, nil
	}
	client, err := ssh.Dial(ctx, ssh.ConnectOptions{
		Address:         fmt.Sprintf("%s:%d", tc.Host, tc.Port),
		User:            tc.User,
		AuthMethods:     authMethods,
		HostKeyCallback: cb,
		Shell:           tc.Shell,
		Timeout:         15 * time.Second,
	})
	if err != nil {
		msg := err.Error()
		out.Error = msg
		if strings.Contains(msg, "knownhosts") {
			out.SSH = true
		}
		out.DurationMS = time.Since(start).Milliseconds()
		return out, nil
	}
	defer client.Close()
	out.SSH = true
	out.HostKeyVerified = true
	out.Authenticated = true

	cwd := tc.DefaultCwd
	if cwd == "" {
		cwd = "/"
	}
	res, err := client.Exec(ctx, ssh.ExecOptions{
		Command:        "printf execmesh-ok && pwd",
		Cwd:            cwd,
		MaxStdoutBytes: 4096,
		MaxStderrBytes: 4096,
		Timeout:        15 * time.Second,
	})
	if err != nil {
		out.Error = err.Error()
		out.DurationMS = time.Since(start).Milliseconds()
		return out, nil
	}
	if res.ExitCode != 0 {
		out.Error = fmt.Sprintf("probe exit_code=%d stderr=%s", res.ExitCode, res.Stderr)
		out.DurationMS = time.Since(start).Milliseconds()
		return out, nil
	}
	out.DefaultCwdValid = strings.Contains(res.Stdout, "execmesh-ok")
	out.Success = out.DefaultCwdValid
	out.DurationMS = time.Since(start).Milliseconds()
	return out, nil
}
