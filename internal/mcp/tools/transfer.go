package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/teacat99/mcp-execmesh/internal/security"
	"github.com/teacat99/mcp-execmesh/internal/transfer"
)

// FilePushInput defines parameters for file_push tool.
type FilePushInput struct {
	Target     string                    `json:"target" jsonschema:"The target host identifier"`
	File       transfer.DownloadFileSpec `json:"file" jsonschema:"User-provided file. OpenAI fileParams clients may expose this as a local file reference to the model and resolve it to download_url/file_id before invoking MCP."`
	RemotePath string                    `json:"remote_path" jsonschema:"Destination absolute path on target host"`
	Overwrite  bool                      `json:"overwrite,omitempty" jsonschema:"Whether to overwrite existing remote file (default: false)"`
	Mode       string                    `json:"mode,omitempty" jsonschema:"Permission mode in octal string (e.g. 0755, 0644)"`
}

// FilePushURLInput defines parameters for file_push_url tool.
type FilePushURLInput struct {
	Target     string `json:"target" jsonschema:"The target host identifier"`
	URL        string `json:"url" jsonschema:"Direct HTTPS/HTTP download URL of the file to transfer"`
	RemotePath string `json:"remote_path" jsonschema:"Destination absolute path on target host"`
	Overwrite  bool   `json:"overwrite,omitempty" jsonschema:"Whether to overwrite existing remote file (default: false)"`
	Mode       string `json:"mode,omitempty" jsonschema:"Permission mode in octal string (e.g. 0755, 0644)"`
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
	TTLSeconds int    `json:"ttl_seconds,omitempty" jsonschema:"Download ticket validity in seconds (default: 900, max: 3600)"`
}

// RegisterTransferTools registers file_push, file_push_url, file_stat, file_hash, and file_pull_prepare tools with the MCP server.
func RegisterTransferTools(server *mcp.Server, transferMgr transfer.TransferManager, publicBaseURL string) {
	// 1. file_push
	mcp.AddTool(server, &mcp.Tool{
		Name:        "file_push",
		Description: "Transfer a user-provided file to a configured remote target using streaming SFTP. With OpenAI fileParams clients, pass the provided/local file reference; the client resolves it to a temporary download URL before MCP invocation.",
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
		if input.File.FileID == "" {
			return nil, nil, fmt.Errorf("file.file_id is required")
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

	// 2. file_push_url
	mcp.AddTool(server, &mcp.Tool{
		Name:        "file_push_url",
		Description: "Download a file from an arbitrary HTTP/HTTPS URL and stream it directly to a configured remote target host using SFTP with bounded memory, SSRF protection, and SHA-256 verification.",
		Annotations: &mcp.ToolAnnotations{
			Title:           "Push File From URL",
			ReadOnlyHint:    false,
			DestructiveHint: &trueVal,
			OpenWorldHint:   &trueVal,
			IdempotentHint:  false,
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input FilePushURLInput) (*mcp.CallToolResult, *transfer.PushResponse, error) {
		if input.Target == "" {
			return nil, nil, fmt.Errorf("target is required")
		}
		if input.URL == "" {
			return nil, nil, fmt.Errorf("url is required")
		}
		if input.RemotePath == "" {
			return nil, nil, fmt.Errorf("remote_path is required")
		}
		if err := authorize(ctx, security.ScopeFilesWrite, input.Target); err != nil {
			return nil, nil, err
		}

		res, err := transferMgr.Push(ctx, transfer.PushRequest{
			Target: input.Target,
			File: transfer.DownloadFileSpec{
				DownloadURL: input.URL,
			},
			RemotePath: input.RemotePath,
			Overwrite:  input.Overwrite,
			Mode:       input.Mode,
		})
		if err != nil {
			return nil, nil, err
		}

		return nil, res, nil
	})

	// 3. file_stat
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

	// 4. file_hash
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

	// 5. file_pull_prepare
	mcp.AddTool(server, &mcp.Tool{
		Name:        "file_pull_prepare",
		Description: "Generate a secure, short-lived single-use download URL for a remote file.",
		Annotations: &mcp.ToolAnnotations{
			Title:           "Prepare File Download",
			ReadOnlyHint:    true,
			DestructiveHint: &falseVal,
			OpenWorldHint:   &trueVal,
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
