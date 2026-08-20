package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/teacat/mcp-execmesh/internal/security"
	"github.com/teacat/mcp-execmesh/internal/transfer"
)

// FilePushInput defines parameters for file_push tool.
type FilePushInput struct {
	Target     string                    `json:"target" jsonschema:"The target host identifier"`
	File       transfer.DownloadFileSpec `json:"file" jsonschema:"File specification containing download_url and file_id"`
	RemotePath string                    `json:"remote_path" jsonschema:"Destination absolute path on target host"`
	Overwrite  bool                      `json:"overwrite,omitempty" jsonschema:"Whether to overwrite existing remote file"`
	Mode       string                    `json:"mode,omitempty" jsonschema:"Permission mode in octal string (e.g. 0755, 0644)"`
}

// FileStatInput defines parameters for file_stat tool.
type FileStatInput struct {
	Target string `json:"target" jsonschema:"The target host identifier"`
	Path   string `json:"path" jsonschema:"The remote path to inspect"`
}

// FileHashInput defines parameters for file_hash tool.
type FileHashInput struct {
	Target    string `json:"target" jsonschema:"The target host identifier"`
	Path      string `json:"path" jsonschema:"The remote file path to compute hash for"`
	Algorithm string `json:"algorithm,omitempty" jsonschema:"Hash algorithm: 'sha256' (default), 'sha1', or 'md5'"`
}

// FilePullPrepareInput defines parameters for file_pull_prepare tool.
type FilePullPrepareInput struct {
	Target     string `json:"target" jsonschema:"The target host identifier"`
	Path       string `json:"path" jsonschema:"The remote file path to prepare for download"`
	TTLSeconds int    `json:"ttl_seconds,omitempty" jsonschema:"Ticket validity in seconds (default: 900, max: 3600)"`
}

// RegisterTransferTools registers file_push, file_stat, file_hash, and file_pull_prepare tools with the MCP server.
func RegisterTransferTools(server *mcp.Server, transferMgr transfer.TransferManager, publicBaseURL string) {
	// 1. file_push
	mcp.AddTool(server, &mcp.Tool{
		Name:        "file_push",
		Description: "Stream and transfer a file from a download URL to a remote target host using SFTP with bounded memory and SHA-256 verification.",
		Meta: map[string]any{
			"openai/fileParams": []string{"file"},
		},
		Annotations: &mcp.ToolAnnotations{
			Title:           "Push File (Streaming)",
			ReadOnlyHint:    false,
			DestructiveHint: &trueVal,
			OpenWorldHint:   &trueVal,
			IdempotentHint:  false,
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input FilePushInput) (*mcp.CallToolResult, *transfer.PushResponse, error) {
		if input.Target == "" {
			return nil, nil, fmt.Errorf("target is required")
		}
		if input.RemotePath == "" {
			return nil, nil, fmt.Errorf("remote_path is required")
		}
		if input.File.DownloadURL == "" {
			return nil, nil, fmt.Errorf("file.download_url is required")
		}
		if err := authorize(ctx, security.ScopeFilesWrite, input.Target); err != nil {
			return nil, nil, err
		}

		res, err := transferMgr.Push(ctx, transfer.PushRequest{
			Target:     input.Target,
			File:       input.File,
			RemotePath: input.RemotePath,
			Overwrite:  input.Overwrite,
			Mode:       input.Mode,
		})
		if err != nil {
			return nil, nil, err
		}

		return nil, res, nil
	})

	// 2. file_stat
	mcp.AddTool(server, &mcp.Tool{
		Name:        "file_stat",
		Description: "Inspect metadata (existence, type, size, permissions, modification time) of a remote file or directory on a target host.",
		Annotations: &mcp.ToolAnnotations{
			Title:           "Stat Remote File",
			ReadOnlyHint:    true,
			DestructiveHint: &falseVal,
			OpenWorldHint:   &falseVal,
			IdempotentHint:  true,
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input FileStatInput) (*mcp.CallToolResult, *transfer.StatResponse, error) {
		if input.Target == "" {
			return nil, nil, fmt.Errorf("target is required")
		}
		if input.Path == "" {
			return nil, nil, fmt.Errorf("path is required")
		}
		if err := authorize(ctx, security.ScopeFilesRead, input.Target); err != nil {
			return nil, nil, err
		}

		res, err := transferMgr.Stat(ctx, transfer.StatRequest{
			Target: input.Target,
			Path:   input.Path,
		})
		if err != nil {
			return nil, nil, err
		}

		return nil, res, nil
	})

	// 3. file_hash
	mcp.AddTool(server, &mcp.Tool{
		Name:        "file_hash",
		Description: "Calculate cryptographic checksum (SHA256, SHA1, MD5) of a remote file via streaming without loading file into gateway memory.",
		Annotations: &mcp.ToolAnnotations{
			Title:           "Hash Remote File",
			ReadOnlyHint:    true,
			DestructiveHint: &falseVal,
			OpenWorldHint:   &falseVal,
			IdempotentHint:  true,
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input FileHashInput) (*mcp.CallToolResult, *transfer.HashResponse, error) {
		if input.Target == "" {
			return nil, nil, fmt.Errorf("target is required")
		}
		if input.Path == "" {
			return nil, nil, fmt.Errorf("path is required")
		}
		if err := authorize(ctx, security.ScopeFilesRead, input.Target); err != nil {
			return nil, nil, err
		}

		res, err := transferMgr.Hash(ctx, transfer.HashRequest{
			Target:    input.Target,
			Path:      input.Path,
			Algorithm: input.Algorithm,
		})
		if err != nil {
			return nil, nil, err
		}

		return nil, res, nil
	})

	// 4. file_pull_prepare
	mcp.AddTool(server, &mcp.Tool{
		Name:        "file_pull_prepare",
		Description: "Generate a secure, short-lived single-use download token to retrieve a file from a remote host via streaming HTTP GET.",
		Annotations: &mcp.ToolAnnotations{
			Title:           "Prepare File Download",
			ReadOnlyHint:    true,
			DestructiveHint: &falseVal,
			OpenWorldHint:   &falseVal,
			IdempotentHint:  false,
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input FilePullPrepareInput) (*mcp.CallToolResult, *transfer.PullPrepareResponse, error) {
		if input.Target == "" {
			return nil, nil, fmt.Errorf("target is required")
		}
		if input.Path == "" {
			return nil, nil, fmt.Errorf("path is required")
		}
		if err := authorize(ctx, security.ScopeFilesRead, input.Target); err != nil {
			return nil, nil, err
		}

		res, err := transferMgr.PullPrepare(ctx, transfer.PullPrepareRequest{
			Target:     input.Target,
			Path:       input.Path,
			TTLSeconds: input.TTLSeconds,
		}, publicBaseURL)
		if err != nil {
			return nil, nil, err
		}

		return nil, res, nil
	})
}
