package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/teacat99/mcp-execmesh/internal/management"
)

type TargetAddToolInput struct {
	ID           string   `json:"id" jsonschema:"New target id"`
	Name         string   `json:"name,omitempty" jsonschema:"Display name"`
	Host         string   `json:"host" jsonschema:"SSH hostname or IP"`
	Port         int      `json:"port,omitempty" jsonschema:"SSH port, default 22"`
	User         string   `json:"user" jsonschema:"SSH username"`
	AuthRef      string   `json:"auth_ref" jsonschema:"Credential id from credentials_list"`
	KnownHostRef string   `json:"known_host_ref,omitempty" jsonschema:"known_hosts name; defaults to host"`
	DefaultCwd   string   `json:"default_cwd,omitempty"`
	Shell        string   `json:"shell,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	ValidateOnly bool     `json:"validate_only,omitempty" jsonschema:"If true, test SSH but do not write config"`
}

type TargetIDInput struct {
	Target string `json:"target" jsonschema:"Target id"`
}

type TargetUpdateToolInput struct {
	Target  string         `json:"target"`
	Changes map[string]any `json:"changes"`
}

type KnownHostInfoInput struct {
	Name string `json:"name,omitempty" jsonschema:"known_hosts name to filter"`
}

type KnownHostAddInput struct {
	Name      string `json:"name" jsonschema:"Host name as stored in known_hosts"`
	Algorithm string `json:"algorithm" jsonschema:"ssh-ed25519, ssh-rsa, or ecdsa-sha2-nistp256"`
	PublicKey string `json:"public_key" jsonschema:"Base64 SSH public key blob"`
}

type KnownHostRemoveInput struct {
	Name string `json:"name"`
}

type ConfigReloadInput struct{}

func RegisterAdminTools(server *mcp.Server, svc *management.Service) {
	if svc == nil {
		return
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "target_add",
		Description: "Admin: add a target by referencing an existing credential and known_hosts entry. SSH is tested before commit. Never pass private keys or passwords.",
		Annotations: &mcp.ToolAnnotations{Title: "Add Target", ReadOnlyHint: false, DestructiveHint: &falseVal, OpenWorldHint: &trueVal, IdempotentHint: false},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input TargetAddToolInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := svc.AddTarget(ctx, principalFromCtx(ctx), management.TargetAddInput{
			ID: input.ID, Name: input.Name, Host: input.Host, Port: input.Port, User: input.User,
			AuthRef: input.AuthRef, KnownHostRef: input.KnownHostRef, DefaultCwd: input.DefaultCwd,
			Shell: input.Shell, Tags: input.Tags, ValidateOnly: input.ValidateOnly,
		})
		if err != nil {
			return nil, out, err
		}
		return nil, out, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "target_update",
		Description: "Admin: update a target. Changing host/port/user/auth_ref/known_host_ref re-runs SSH validation.",
		Annotations: &mcp.ToolAnnotations{Title: "Update Target", ReadOnlyHint: false, DestructiveHint: &trueVal, OpenWorldHint: &trueVal, IdempotentHint: false},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input TargetUpdateToolInput) (*mcp.CallToolResult, map[string]any, error) {
		if input.Target == "" {
			return nil, nil, fmt.Errorf("target is required")
		}
		if err := svc.UpdateTarget(ctx, principalFromCtx(ctx), management.TargetUpdateInput{Target: input.Target, Changes: input.Changes}); err != nil {
			return nil, nil, err
		}
		return nil, map[string]any{"updated": input.Target}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "target_enable",
		Description: "Admin: enable a disabled target.",
		Annotations: &mcp.ToolAnnotations{Title: "Enable Target", ReadOnlyHint: false, DestructiveHint: &falseVal, IdempotentHint: true},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input TargetIDInput) (*mcp.CallToolResult, map[string]any, error) {
		if err := svc.EnableTarget(principalFromCtx(ctx), input.Target); err != nil {
			return nil, nil, err
		}
		return nil, map[string]any{"enabled": input.Target}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "target_disable",
		Description: "Admin: disable a target. Data-plane tools cannot use it until re-enabled. Credentials and known_hosts are kept.",
		Annotations: &mcp.ToolAnnotations{Title: "Disable Target", ReadOnlyHint: false, DestructiveHint: &trueVal, IdempotentHint: true},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input TargetIDInput) (*mcp.CallToolResult, map[string]any, error) {
		if err := svc.DisableTarget(principalFromCtx(ctx), input.Target); err != nil {
			return nil, nil, err
		}
		return nil, map[string]any{"disabled": input.Target}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "target_remove",
		Description: "Admin: remove a target from configuration. Does not delete credentials or known_hosts entries.",
		Annotations: &mcp.ToolAnnotations{Title: "Remove Target", ReadOnlyHint: false, DestructiveHint: &trueVal, IdempotentHint: true},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input TargetIDInput) (*mcp.CallToolResult, map[string]any, error) {
		if err := svc.RemoveTarget(principalFromCtx(ctx), input.Target); err != nil {
			return nil, nil, err
		}
		return nil, map[string]any{"removed": input.Target}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "target_test",
		Description: "Admin: test SSH, host key, and default working directory for a target.",
		Annotations: &mcp.ToolAnnotations{Title: "Test Target", ReadOnlyHint: true, DestructiveHint: &falseVal, OpenWorldHint: &trueVal, IdempotentHint: true},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input TargetIDInput) (*mcp.CallToolResult, *management.TestResult, error) {
		res, err := svc.TestTarget(ctx, principalFromCtx(ctx), input.Target)
		return nil, res, err
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "credentials_list",
		Description: "Admin: list credential ids and types. Never returns secret paths or key material.",
		Annotations: &mcp.ToolAnnotations{Title: "List Credentials", ReadOnlyHint: true, DestructiveHint: &falseVal, IdempotentHint: true},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input struct{}) (*mcp.CallToolResult, map[string]any, error) {
		list, err := svc.ListCredentials(principalFromCtx(ctx))
		if err != nil {
			return nil, nil, err
		}
		return nil, map[string]any{"credentials": list}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "known_host_info",
		Description: "Admin: list known_hosts names and SHA256 fingerprints (no private keys).",
		Annotations: &mcp.ToolAnnotations{Title: "Known Hosts Info", ReadOnlyHint: true, DestructiveHint: &falseVal, IdempotentHint: true},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input KnownHostInfoInput) (*mcp.CallToolResult, map[string]any, error) {
		entries, err := svc.KnownHostInfo(principalFromCtx(ctx), input.Name)
		if err != nil {
			return nil, nil, err
		}
		return nil, map[string]any{"entries": entries}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "known_host_add",
		Description: "Admin: append an administrator-supplied host public key. Does not scan or auto-trust.",
		Annotations: &mcp.ToolAnnotations{Title: "Add Known Host Key", ReadOnlyHint: false, DestructiveHint: &falseVal, IdempotentHint: true},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input KnownHostAddInput) (*mcp.CallToolResult, map[string]any, error) {
		if err := svc.KnownHostAdd(principalFromCtx(ctx), input.Name, input.Algorithm, input.PublicKey); err != nil {
			return nil, nil, err
		}
		return nil, map[string]any{"added": input.Name, "algorithm": input.Algorithm}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "known_host_remove",
		Description: "Admin: remove all known_hosts lines for a name. Does not delete targets.",
		Annotations: &mcp.ToolAnnotations{Title: "Remove Known Host Key", ReadOnlyHint: false, DestructiveHint: &trueVal, IdempotentHint: true},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input KnownHostRemoveInput) (*mcp.CallToolResult, map[string]any, error) {
		if err := svc.KnownHostRemove(principalFromCtx(ctx), input.Name); err != nil {
			return nil, nil, err
		}
		return nil, map[string]any{"removed": input.Name}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "config_reload",
		Description: "Admin: reload targets, credentials, and known_hosts from disk. On failure the previous runtime registry is kept.",
		Annotations: &mcp.ToolAnnotations{Title: "Reload Config", ReadOnlyHint: false, DestructiveHint: &trueVal, IdempotentHint: true},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ConfigReloadInput) (*mcp.CallToolResult, map[string]any, error) {
		if err := svc.ConfigReload(principalFromCtx(ctx)); err != nil {
			return nil, nil, err
		}
		return nil, map[string]any{"reloaded": true}, nil
	})
}
