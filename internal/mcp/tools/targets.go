package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/teacat99/mcp-execmesh/internal/security"
	"github.com/teacat99/mcp-execmesh/internal/target"
)

// TargetsListInput is the input schema for targets_list tool (empty object).
type TargetsListInput struct{}

// TargetsListOutput is the output schema for targets_list tool.
type TargetsListOutput struct {
	Targets []target.TargetSummary `json:"targets"`
}

// TargetInfoInput is the input schema for target_info tool.
type TargetInfoInput struct {
	Target string `json:"target" jsonschema:"The unique identifier of the target server"`
}

// TargetInfoOutput is the output schema for target_info tool.
type TargetInfoOutput struct {
	Target target.TargetDetail `json:"target"`
}

var (
	falseVal = false
	trueVal  = true
)

// RegisterTargetsTools adds targets_list and target_info tools to the MCP server.
func RegisterTargetsTools(server *mcp.Server, registry target.TargetRegistry) {
	// 1. targets_list
	mcp.AddTool(server, &mcp.Tool{
		Name:        "targets_list",
		Description: "List all configured target remote hosts and their capabilities.",
		Annotations: &mcp.ToolAnnotations{
			Title:           "List Targets",
			ReadOnlyHint:    true,
			DestructiveHint: &falseVal,
			OpenWorldHint:   &falseVal,
			IdempotentHint:  true,
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input TargetsListInput) (*mcp.CallToolResult, TargetsListOutput, error) {
		if err := authorize(ctx, security.ScopeTargetsRead, ""); err != nil {
			return nil, TargetsListOutput{}, err
		}
		summaries := filterTargets(ctx, registry.List(ctx))
		return nil, TargetsListOutput{Targets: summaries}, nil
	})

	// 2. target_info
	mcp.AddTool(server, &mcp.Tool{
		Name:        "target_info",
		Description: "Get detailed information, capabilities, and execution limits for a specific target.",
		Annotations: &mcp.ToolAnnotations{
			Title:           "Get Target Information",
			ReadOnlyHint:    true,
			DestructiveHint: &falseVal,
			OpenWorldHint:   &falseVal,
			IdempotentHint:  true,
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input TargetInfoInput) (*mcp.CallToolResult, TargetInfoOutput, error) {
		if input.Target == "" {
			return nil, TargetInfoOutput{}, fmt.Errorf("target parameter is required")
		}
		if err := authorize(ctx, security.ScopeTargetsRead, input.Target); err != nil {
			return nil, TargetInfoOutput{}, err
		}

		t, err := registry.Get(ctx, input.Target)
		if err != nil {
			return nil, TargetInfoOutput{}, err
		}

		return nil, TargetInfoOutput{Target: t.Detail()}, nil
	})
}
