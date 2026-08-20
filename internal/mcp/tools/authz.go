package tools

import (
	"context"

	"github.com/teacat99/mcp-execmesh/internal/security"
	"github.com/teacat99/mcp-execmesh/internal/target"
)

func principalFromCtx(ctx context.Context) *security.Principal {
	return security.PrincipalFromContext(ctx)
}

func authorize(ctx context.Context, scope, targetID string) error {
	return security.Authorize(principalFromCtx(ctx), scope, targetID)
}

func filterTargets(ctx context.Context, summaries []target.TargetSummary) []target.TargetSummary {
	p := principalFromCtx(ctx)
	out := make([]target.TargetSummary, 0, len(summaries))
	for _, s := range summaries {
		if p == nil || p.AllowsTarget(s.ID) {
			out = append(out, s)
		}
	}
	return out
}
