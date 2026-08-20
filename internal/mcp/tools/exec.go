package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/teacat99/mcp-execmesh/internal/executor"
	"github.com/teacat99/mcp-execmesh/internal/security"
	"github.com/teacat99/mcp-execmesh/internal/target"
)

// ExecInput defines parameters for the exec tool.
type ExecInput struct {
	Target         string            `json:"target" jsonschema:"The target host identifier configured on the MCP server"`
	Command        string            `json:"command" jsonschema:"The command to execute on the remote host"`
	Cwd            string            `json:"cwd,omitempty" jsonschema:"Optional working directory on the remote host"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty" jsonschema:"Optional command execution timeout in seconds"`
	Env            map[string]string `json:"env,omitempty" jsonschema:"Optional environment variables to set for the command"`
}

// ExecOutput defines the structured result of the exec tool.
type ExecOutput struct {
	Target          string `json:"target"`
	ExitCode        int    `json:"exit_code"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
	DurationMS      int64  `json:"duration_ms"`
}

// RegisterExecTool registers the synchronous exec tool with the MCP server.
func RegisterExecTool(server *mcp.Server, registry target.TargetRegistry, execEngine executor.RemoteExecutor) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "exec",
		Description: "Execute a short synchronous command on a configured remote target host over SSH.",
		Annotations: &mcp.ToolAnnotations{
			Title:           "Execute Remote Command",
			ReadOnlyHint:    false,
			DestructiveHint: &trueVal,
			OpenWorldHint:   &trueVal,
			IdempotentHint:  false,
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ExecInput) (*mcp.CallToolResult, ExecOutput, error) {
		if input.Target == "" {
			return nil, ExecOutput{}, fmt.Errorf("target is required")
		}
		if input.Command == "" {
			return nil, ExecOutput{}, fmt.Errorf("command is required")
		}
		if err := authorize(ctx, security.ScopeExecRun, input.Target); err != nil {
			return nil, ExecOutput{}, err
		}

		t, err := registry.Get(ctx, input.Target)
		if err != nil {
			return nil, ExecOutput{}, err
		}
		if err := t.RequireActive(); err != nil {
			return nil, ExecOutput{}, err
		}

		principal := principalFromCtx(ctx)

		execReq := executor.ExecRequest{
			Target:         input.Target,
			Command:        input.Command,
			Cwd:            input.Cwd,
			TimeoutSeconds: input.TimeoutSeconds,
			Env:            input.Env,
		}

		res, err := execEngine.Exec(ctx, principal, t, execReq)
		if err != nil && res == nil {
			return nil, ExecOutput{}, err
		}

		output := ExecOutput{
			Target:          input.Target,
			ExitCode:        res.ExitCode,
			Stdout:          res.Stdout,
			Stderr:          res.Stderr,
			StdoutTruncated: res.StdoutTruncated,
			StderrTruncated: res.StderrTruncated,
			DurationMS:      res.DurationMS,
		}

		return nil, output, nil
	})
}
