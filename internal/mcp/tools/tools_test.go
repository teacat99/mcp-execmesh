package tools

import (
	"context"
	"net/http"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/teacat99/mcp-execmesh/internal/config"
	"github.com/teacat99/mcp-execmesh/internal/executor"
	"github.com/teacat99/mcp-execmesh/internal/jobs"
	"github.com/teacat99/mcp-execmesh/internal/security"
	"github.com/teacat99/mcp-execmesh/internal/ssh"
	"github.com/teacat99/mcp-execmesh/internal/target"
	"github.com/teacat99/mcp-execmesh/internal/transfer"
)

type mockRegistry struct {
	targets map[string]*target.Target
}

func (m *mockRegistry) List(ctx context.Context) []target.TargetSummary {
	var res []target.TargetSummary
	for _, t := range m.targets {
		res = append(res, t.Summary())
	}
	return res
}

func (m *mockRegistry) Get(ctx context.Context, id string) (*target.Target, error) {
	t, ok := m.targets[id]
	if !ok {
		return nil, assert.AnError
	}
	return t, nil
}

func (m *mockRegistry) Reload(cfg *config.Config) error {
	return nil
}

type mockExecutor struct{}

func (m *mockExecutor) Exec(ctx context.Context, p *security.Principal, t *target.Target, req executor.ExecRequest) (*ssh.ExecResult, error) {
	return &ssh.ExecResult{
		ExitCode:        0,
		Stdout:          "Linux test-node 6.6.0 #1 SMP x86_64 GNU/Linux\n",
		Stderr:          "",
		StdoutTruncated: false,
		StderrTruncated: false,
		DurationMS:      42,
	}, nil
}

type mockJobManager struct{}

func (m *mockJobManager) Start(ctx context.Context, p *security.Principal, t *target.Target, req jobs.JobStartRequest) (*jobs.JobStartResponse, error) {
	return &jobs.JobStartResponse{JobID: "job_123", Target: t.ID, State: jobs.StateRunning}, nil
}

func (m *mockJobManager) Status(ctx context.Context, p *security.Principal, jobID, targetHint string) (*jobs.JobStatusResponse, error) {
	return &jobs.JobStatusResponse{JobID: jobID, Target: "test-01", State: jobs.StateRunning}, nil
}

func (m *mockJobManager) Output(ctx context.Context, p *security.Principal, req jobs.JobOutputRequest, targetHint string) (*jobs.JobOutputResponse, error) {
	return &jobs.JobOutputResponse{JobID: req.JobID, Stream: req.Stream, Data: "log data", EOF: true}, nil
}

func (m *mockJobManager) Cancel(ctx context.Context, p *security.Principal, jobID, targetHint string) (*jobs.JobCancelResponse, error) {
	return &jobs.JobCancelResponse{JobID: jobID, Target: "test-01", State: jobs.StateCancelled, Message: "cancelled"}, nil
}

type mockTransferManager struct{}

func (m *mockTransferManager) Push(ctx context.Context, req transfer.PushRequest) (*transfer.PushResponse, error) {
	return &transfer.PushResponse{
		Target:     req.Target,
		RemotePath: req.RemotePath,
		Size:       1024,
		SHA256:     "mock-sha256",
		Mode:       "0755",
	}, nil
}

func (m *mockTransferManager) Stat(ctx context.Context, req transfer.StatRequest) (*transfer.StatResponse, error) {
	return &transfer.StatResponse{
		Target: req.Target,
		Path:   req.Path,
		Exists: true,
		Type:   "file",
		Size:   1024,
		Mode:   "0644",
	}, nil
}

func (m *mockTransferManager) Hash(ctx context.Context, req transfer.HashRequest) (*transfer.HashResponse, error) {
	return &transfer.HashResponse{
		Target:    req.Target,
		Path:      req.Path,
		Algorithm: "sha256",
		Hash:      "mock-hash",
		Size:      1024,
	}, nil
}

func (m *mockTransferManager) PullPrepare(ctx context.Context, req transfer.PullPrepareRequest, publicBaseURL string) (*transfer.PullPrepareResponse, error) {
	return &transfer.PullPrepareResponse{
		DownloadURL: publicBaseURL + "/files/mock-ticket",
		Target:      req.Target,
		Path:        req.Path,
		ExpiresAt:   "2026-08-19T12:00:00Z",
		Size:        1024,
	}, nil
}

func (m *mockTransferManager) ServeDownload(w http.ResponseWriter, r *http.Request, token string) error {
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte("mock download content"))
	return err
}

func TestToolsRegistration(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test-server"}, &mcp.ServerOptions{})
	reg := &mockRegistry{
		targets: map[string]*target.Target{
			"test-01": {
				ID:         "test-01",
				Name:       "Test Node 01",
				DefaultCwd: "/srv/test",
				Capabilities: target.TargetCapabilities{
					Exec:   true,
					Upload: true,
					Jobs:   true,
				},
				Tags: []string{"test"},
			},
		},
	}
	exec := &mockExecutor{}
	jobMgr := &mockJobManager{}
	transferMgr := &mockTransferManager{}

	RegisterTargetsTools(server, reg)
	RegisterExecTool(server, reg, exec)
	RegisterJobsTools(server, reg, jobMgr)
	RegisterTransferTools(server, transferMgr, "http://localhost:8080")

	// Verify server can be created without panic
	assert.NotNil(t, server)
}
