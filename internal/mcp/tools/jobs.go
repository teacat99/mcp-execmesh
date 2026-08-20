package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/teacat99/mcp-execmesh/internal/jobs"
	"github.com/teacat99/mcp-execmesh/internal/security"
	"github.com/teacat99/mcp-execmesh/internal/target"
)

// ExecStartInput defines parameters for exec_start tool.
type ExecStartInput struct {
	Target  string            `json:"target" jsonschema:"The target host identifier"`
	Command string            `json:"command" jsonschema:"The command to execute in the background"`
	Cwd     string            `json:"cwd,omitempty" jsonschema:"Optional working directory"`
	Env     map[string]string `json:"env,omitempty" jsonschema:"Optional environment variables"`
}

// JobStatusInput defines parameters for job_status tool.
type JobStatusInput struct {
	JobID  string `json:"job_id" jsonschema:"The unique job identifier (e.g. job_...)"`
	Target string `json:"target,omitempty" jsonschema:"Optional target host identifier for fast routing"`
}

// JobOutputInput defines parameters for job_output tool.
type JobOutputInput struct {
	JobID  string `json:"job_id" jsonschema:"The unique job identifier"`
	Target string `json:"target,omitempty" jsonschema:"Optional target host identifier"`
	Stream string `json:"stream,omitempty" jsonschema:"Stream to read: 'stdout' or 'stderr' (default: stdout)"`
	Offset int64  `json:"offset,omitempty" jsonschema:"Starting byte offset (default: 0)"`
	Limit  int    `json:"limit,omitempty" jsonschema:"Maximum bytes to read (default: 65536, max: 131072)"`
}

// JobCancelInput defines parameters for job_cancel tool.
type JobCancelInput struct {
	JobID  string `json:"job_id" jsonschema:"The unique job identifier to cancel"`
	Target string `json:"target,omitempty" jsonschema:"Optional target host identifier"`
}

// RegisterJobsTools registers all asynchronous job tools with the MCP server.
func RegisterJobsTools(server *mcp.Server, registry target.TargetRegistry, jobMgr jobs.JobManager) {
	// 1. exec_start
	mcp.AddTool(server, &mcp.Tool{
		Name:        "exec_start",
		Description: "Start a long-running command asynchronously on a remote target host.",
		Annotations: &mcp.ToolAnnotations{
			Title:           "Start Asynchronous Job",
			ReadOnlyHint:    false,
			DestructiveHint: &trueVal,
			OpenWorldHint:   &trueVal,
			IdempotentHint:  false,
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ExecStartInput) (*mcp.CallToolResult, jobs.JobStartResponse, error) {
		if input.Target == "" {
			return nil, jobs.JobStartResponse{}, fmt.Errorf("target is required")
		}
		if input.Command == "" {
			return nil, jobs.JobStartResponse{}, fmt.Errorf("command is required")
		}
		if err := authorize(ctx, security.ScopeExecRun, input.Target); err != nil {
			return nil, jobs.JobStartResponse{}, err
		}

		t, err := registry.Get(ctx, input.Target)
		if err != nil {
			return nil, jobs.JobStartResponse{}, err
		}
		if err := t.RequireActive(); err != nil {
			return nil, jobs.JobStartResponse{}, err
		}

		var principal = principalFromCtx(ctx)

		startReq := jobs.JobStartRequest{
			Target:  input.Target,
			Command: input.Command,
			Cwd:     input.Cwd,
			Env:     input.Env,
		}

		res, err := jobMgr.Start(ctx, principal, t, startReq)
		if err != nil {
			return nil, jobs.JobStartResponse{}, err
		}

		return nil, *res, nil
	})

	// 2. job_status
	mcp.AddTool(server, &mcp.Tool{
		Name:        "job_status",
		Description: "Query the status, pid, exit code, and output sizes of an asynchronous job.",
		Annotations: &mcp.ToolAnnotations{
			Title:           "Get Job Status",
			ReadOnlyHint:    true,
			DestructiveHint: &falseVal,
			OpenWorldHint:   &falseVal,
			IdempotentHint:  true,
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input JobStatusInput) (*mcp.CallToolResult, jobs.JobStatusResponse, error) {
		if input.JobID == "" {
			return nil, jobs.JobStatusResponse{}, fmt.Errorf("job_id is required")
		}
		if err := authorize(ctx, security.ScopeJobsRead, input.Target); err != nil {
			return nil, jobs.JobStatusResponse{}, err
		}

		principal := principalFromCtx(ctx)

		res, err := jobMgr.Status(ctx, principal, input.JobID, input.Target)
		if err != nil {
			return nil, jobs.JobStatusResponse{}, err
		}

		return nil, *res, nil
	})

	// 3. job_output
	mcp.AddTool(server, &mcp.Tool{
		Name:        "job_output",
		Description: "Read paginated log output (stdout or stderr) for an asynchronous job.",
		Annotations: &mcp.ToolAnnotations{
			Title:           "Read Job Output",
			ReadOnlyHint:    true,
			DestructiveHint: &falseVal,
			OpenWorldHint:   &falseVal,
			IdempotentHint:  true,
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input JobOutputInput) (*mcp.CallToolResult, jobs.JobOutputResponse, error) {
		if input.JobID == "" {
			return nil, jobs.JobOutputResponse{}, fmt.Errorf("job_id is required")
		}
		stream := input.Stream
		if stream == "" {
			stream = "stdout"
		}
		if err := authorize(ctx, security.ScopeJobsRead, input.Target); err != nil {
			return nil, jobs.JobOutputResponse{}, err
		}

		principal := principalFromCtx(ctx)

		outputReq := jobs.JobOutputRequest{
			JobID:  input.JobID,
			Target: input.Target,
			Stream: stream,
			Offset: input.Offset,
			Limit:  input.Limit,
		}

		res, err := jobMgr.Output(ctx, principal, outputReq, input.Target)
		if err != nil {
			return nil, jobs.JobOutputResponse{}, err
		}

		return nil, *res, nil
	})

	// 4. job_cancel
	mcp.AddTool(server, &mcp.Tool{
		Name:        "job_cancel",
		Description: "Cancel a running asynchronous job on the remote host.",
		Annotations: &mcp.ToolAnnotations{
			Title:           "Cancel Asynchronous Job",
			ReadOnlyHint:    false,
			DestructiveHint: &trueVal,
			OpenWorldHint:   &falseVal,
			IdempotentHint:  true,
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input JobCancelInput) (*mcp.CallToolResult, jobs.JobCancelResponse, error) {
		if input.JobID == "" {
			return nil, jobs.JobCancelResponse{}, fmt.Errorf("job_id is required")
		}
		if err := authorize(ctx, security.ScopeJobsWrite, input.Target); err != nil {
			return nil, jobs.JobCancelResponse{}, err
		}

		principal := principalFromCtx(ctx)

		res, err := jobMgr.Cancel(ctx, principal, input.JobID, input.Target)
		if err != nil {
			return nil, jobs.JobCancelResponse{}, err
		}

		return nil, *res, nil
	})
}
