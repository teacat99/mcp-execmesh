package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/teacat99/mcp-execmesh/internal/audit"
	"github.com/teacat99/mcp-execmesh/internal/config"
	"github.com/teacat99/mcp-execmesh/internal/security"
	"github.com/teacat99/mcp-execmesh/internal/ssh"
	"github.com/teacat99/mcp-execmesh/internal/target"
)

var jobIDRegex = regexp.MustCompile(`^job_[a-zA-Z0-9_-]+$`)

// JobManager defines the interface for managing remote asynchronous jobs.
type JobManager interface {
	Start(ctx context.Context, principal *security.Principal, t *target.Target, req JobStartRequest) (*JobStartResponse, error)
	Status(ctx context.Context, principal *security.Principal, jobID, targetHint string) (*JobStatusResponse, error)
	Output(ctx context.Context, principal *security.Principal, req JobOutputRequest, targetHint string) (*JobOutputResponse, error)
	Cancel(ctx context.Context, principal *security.Principal, jobID, targetHint string) (*JobCancelResponse, error)
}

// LocalJobIndexEntry keeps minimum metadata in memory for quick target resolution.
type LocalJobIndexEntry struct {
	JobID       string
	TargetID    string
	CreatedAt   time.Time
	CommandHash string
}

// Manager manages remote jobs lifecycle, logging, and concurrency.
type Manager struct {
	mu          sync.RWMutex
	jobIndex    map[string]LocalJobIndexEntry
	registry    target.TargetRegistry
	sshManager  *ssh.Manager
	jobsCfg     config.JobsConfig
	runtimeCfg  config.RuntimeConfig
	auditLogger *audit.Logger
	policy      *security.CommandPolicy
}

// NewManager creates a new asynchronous Job Manager.
func NewManager(
	registry target.TargetRegistry,
	sshManager *ssh.Manager,
	jobsCfg config.JobsConfig,
	runtimeCfg config.RuntimeConfig,
	auditLogger *audit.Logger,
	policy *security.CommandPolicy,
) *Manager {
	if jobsCfg.RemoteBaseDir == "" {
		jobsCfg.RemoteBaseDir = ".remote-mcp/jobs"
	}
	if policy == nil {
		policy = security.DefaultCommandPolicy()
	}
	return &Manager{
		jobIndex:    make(map[string]LocalJobIndexEntry),
		registry:    registry,
		sshManager:  sshManager,
		jobsCfg:     jobsCfg,
		runtimeCfg:  runtimeCfg,
		auditLogger: auditLogger,
		policy:      policy,
	}
}

// GenerateJobID generates a unique, sortable job identifier.
func GenerateJobID() string {
	now := time.Now().UTC().Format("20060102150405")
	u := strings.ReplaceAll(uuid.New().String(), "-", "")[:12]
	return fmt.Sprintf("job_%s_%s", now, u)
}

// Start launches a new detached asynchronous job on the remote target.
func (m *Manager) Start(ctx context.Context, principal *security.Principal, t *target.Target, req JobStartRequest) (*JobStartResponse, error) {
	start := time.Now()
	requestID := uuid.New().String()
	subject := "anonymous"
	if principal != nil {
		subject = principal.Subject
	}

	// 1. Verify Target Capability
	if !t.Capabilities.Jobs {
		err := fmt.Errorf("target %q does not allow asynchronous jobs (jobs capability disabled)", t.ID)
		m.auditLog(requestID, subject, "exec_start", t.ID, "", req.Command, req.Cwd, "denied", time.Since(start).Milliseconds(), err.Error())
		return nil, err
	}

	// 2. Validate Command Policy
	if err := m.policy.ValidateCommand(req.Command); err != nil {
		m.auditLog(requestID, subject, "exec_start", t.ID, "", req.Command, req.Cwd, "denied", time.Since(start).Milliseconds(), err.Error())
		return nil, fmt.Errorf("command rejected by policy: %w", err)
	}

	// 3. Resolve Working Directory
	cwd := req.Cwd
	if cwd == "" {
		cwd = t.DefaultCwd
	}
	if cwd != "" {
		cleanedCwd, err := security.CleanAndValidatePath(cwd, t.DefaultCwd)
		if err != nil {
			m.auditLog(requestID, subject, "exec_start", t.ID, "", req.Command, cwd, "denied", time.Since(start).Milliseconds(), err.Error())
			return nil, fmt.Errorf("invalid working directory %q: %w", cwd, err)
		}
		cwd = cleanedCwd
		if len(t.AllowedPaths) > 0 && !security.IsPathAllowed(cwd, t.AllowedPaths) {
			err := fmt.Errorf("working directory %q is outside of allowed paths for target %q", cwd, t.ID)
			m.auditLog(requestID, subject, "exec_start", t.ID, "", req.Command, cwd, "denied", time.Since(start).Milliseconds(), err.Error())
			return nil, err
		}
	}

	// 4. Merge Environment Variables
	mergedEnv := make(map[string]string)
	for k, v := range t.Env {
		mergedEnv[k] = v
	}
	for k, v := range req.Env {
		mergedEnv[k] = v
	}

	// 5. Generate Job ID & Metadata
	jobID := GenerateJobID()
	cmdSum := sha256.Sum256([]byte(req.Command))
	cmdHash := hex.EncodeToString(cmdSum[:])

	meta := JobMeta{
		JobID:       jobID,
		TargetID:    t.ID,
		Command:     req.Command,
		Cwd:         cwd,
		StartedAt:   time.Now().UTC(),
		CommandHash: cmdHash,
	}

	// 6. Build Launch Script
	launchScript, err := BuildLaunchScript(m.jobsCfg.RemoteBaseDir, jobID, meta, req.Command, cwd, mergedEnv, t.Shell)
	if err != nil {
		return nil, fmt.Errorf("failed to build launch script: %w", err)
	}

	// 7. Acquire SSH Connection and Launch Detached Job
	connectOpts := t.ConnectOptions(10 * time.Second)
	client, release, err := m.sshManager.Acquire(ctx, connectOpts)
	if err != nil {
		m.auditLog(requestID, subject, "exec_start", t.ID, jobID, req.Command, cwd, "error", time.Since(start).Milliseconds(), err.Error())
		return nil, fmt.Errorf("failed to connect to target %q: %w", t.ID, err)
	}
	defer release()

	execOpts := ssh.ExecOptions{
		Command:        launchScript,
		MaxStdoutBytes: 4096,
		MaxStderrBytes: 4096,
		Timeout:        15 * time.Second,
	}

	res, err := client.Exec(ctx, execOpts)
	if err != nil {
		m.auditLog(requestID, subject, "exec_start", t.ID, jobID, req.Command, cwd, "error", time.Since(start).Milliseconds(), err.Error())
		return nil, fmt.Errorf("failed to launch remote job: %w", err)
	}

	if res.ExitCode != 0 {
		errMsg := fmt.Sprintf("job launch script exited with code %d: %s", res.ExitCode, res.Stderr)
		m.auditLog(requestID, subject, "exec_start", t.ID, jobID, req.Command, cwd, "error", time.Since(start).Milliseconds(), errMsg)
		return nil, errors.New(errMsg)
	}

	// 8. Record in Local Index
	m.mu.Lock()
	m.jobIndex[jobID] = LocalJobIndexEntry{
		JobID:       jobID,
		TargetID:    t.ID,
		CreatedAt:   meta.StartedAt,
		CommandHash: cmdHash,
	}
	m.mu.Unlock()

	m.auditLog(requestID, subject, "exec_start", t.ID, jobID, req.Command, cwd, "success", time.Since(start).Milliseconds(), "")

	return &JobStartResponse{
		JobID:     jobID,
		Target:    t.ID,
		State:     StateRunning,
		StartedAt: meta.StartedAt.Format(time.RFC3339Nano),
	}, nil
}

// Status queries the current status and metrics of a job from the remote host.
func (m *Manager) Status(ctx context.Context, principal *security.Principal, jobID, targetHint string) (*JobStatusResponse, error) {
	if !jobIDRegex.MatchString(jobID) {
		return nil, fmt.Errorf("invalid job_id format %q", jobID)
	}

	t, err := m.resolveTarget(ctx, jobID, targetHint)
	if err != nil {
		return nil, err
	}

	queryScript := BuildQueryScript(m.jobsCfg.RemoteBaseDir, jobID)

	connectOpts := t.ConnectOptions(10 * time.Second)
	client, release, err := m.sshManager.Acquire(ctx, connectOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to target %q: %w", t.ID, err)
	}
	defer release()

	execOpts := ssh.ExecOptions{
		Command:        queryScript,
		MaxStdoutBytes: 8192,
		MaxStderrBytes: 4096,
		Timeout:        10 * time.Second,
	}

	res, err := client.Exec(ctx, execOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to query remote job: %w", err)
	}

	jobInfo, err := ParseQueryOutput(res.Stdout)
	if err != nil {
		return nil, fmt.Errorf("failed to parse remote job status: %w", err)
	}

	if jobInfo.NotFound {
		return nil, fmt.Errorf("job %q not found on target %q", jobID, t.ID)
	}

	// Determine job state
	state := StateRunning
	if jobInfo.FinishedAt != "" {
		if jobInfo.ExitCode != nil {
			if *jobInfo.ExitCode == 0 {
				state = StateSucceeded
			} else if *jobInfo.ExitCode == 137 || *jobInfo.ExitCode == 143 {
				state = StateCancelled
			} else {
				state = StateFailed
			}
		} else {
			state = StateFailed
		}
	} else if !jobInfo.IsRunning && jobInfo.Pid != nil {
		// Process is not running and no finished file yet -> failed/terminated
		state = StateFailed
	}

	startedAt := ""
	if jobInfo.Meta != nil {
		startedAt = jobInfo.Meta.StartedAt.Format(time.RFC3339Nano)
	}

	return &JobStatusResponse{
		JobID:       jobID,
		Target:      t.ID,
		State:       state,
		Pid:         jobInfo.Pid,
		ExitCode:    jobInfo.ExitCode,
		StartedAt:   startedAt,
		FinishedAt:  jobInfo.FinishedAt,
		StdoutBytes: jobInfo.StdoutSize,
		StderrBytes: jobInfo.StderrSize,
	}, nil
}

// Output reads a chunked slice of job logs from the remote host.
func (m *Manager) Output(ctx context.Context, principal *security.Principal, req JobOutputRequest, targetHint string) (*JobOutputResponse, error) {
	if !jobIDRegex.MatchString(req.JobID) {
		return nil, fmt.Errorf("invalid job_id format %q", req.JobID)
	}

	stream := strings.ToLower(req.Stream)
	if stream != "stdout" && stream != "stderr" {
		return nil, fmt.Errorf("invalid stream %q (expected 'stdout' or 'stderr')", req.Stream)
	}

	if req.Offset < 0 {
		req.Offset = 0
	}

	// Enforce hard server-side limit
	maxAllowedLimit := int(m.runtimeCfg.MaxJobOutputReadBytes)
	if maxAllowedLimit <= 0 {
		maxAllowedLimit = 131072 // 128 KiB
	}
	limit := req.Limit
	if limit <= 0 || limit > maxAllowedLimit {
		limit = maxAllowedLimit
	}

	t, err := m.resolveTarget(ctx, req.JobID, targetHint)
	if err != nil {
		return nil, err
	}

	readScript := BuildReadOutputScript(m.jobsCfg.RemoteBaseDir, req.JobID, stream, req.Offset, limit)

	connectOpts := t.ConnectOptions(10 * time.Second)
	client, release, err := m.sshManager.Acquire(ctx, connectOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to target %q: %w", t.ID, err)
	}
	defer release()

	execOpts := ssh.ExecOptions{
		Command:        readScript,
		MaxStdoutBytes: int64(limit) + 1024,
		MaxStderrBytes: 4096,
		Timeout:        10 * time.Second,
	}

	res, err := client.Exec(ctx, execOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to read remote job output: %w", err)
	}

	totalSize, data, notFound, err := ParseReadOutput(res.Stdout)
	if err != nil {
		return nil, err
	}
	if notFound {
		return nil, fmt.Errorf("job %q log file not found on target %q", req.JobID, t.ID)
	}

	bytesRead := int64(len(data))
	nextOffset := req.Offset + bytesRead
	eof := nextOffset >= totalSize

	return &JobOutputResponse{
		JobID:      req.JobID,
		Stream:     stream,
		Data:       data,
		Offset:     req.Offset,
		NextOffset: nextOffset,
		EOF:        eof,
	}, nil
}

// Cancel terminates a running job on the remote host.
func (m *Manager) Cancel(ctx context.Context, principal *security.Principal, jobID, targetHint string) (*JobCancelResponse, error) {
	if !jobIDRegex.MatchString(jobID) {
		return nil, fmt.Errorf("invalid job_id format %q", jobID)
	}

	t, err := m.resolveTarget(ctx, jobID, targetHint)
	if err != nil {
		return nil, err
	}

	cancelScript := BuildCancelScript(m.jobsCfg.RemoteBaseDir, jobID)

	connectOpts := t.ConnectOptions(10 * time.Second)
	client, release, err := m.sshManager.Acquire(ctx, connectOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to target %q: %w", t.ID, err)
	}
	defer release()

	execOpts := ssh.ExecOptions{
		Command:        cancelScript,
		MaxStdoutBytes: 4096,
		MaxStderrBytes: 4096,
		Timeout:        10 * time.Second,
	}

	res, err := client.Exec(ctx, execOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to cancel remote job: %w", err)
	}

	trimmed := strings.TrimSpace(res.Stdout)
	if strings.Contains(trimmed, "NOT_FOUND") {
		return nil, fmt.Errorf("job %q not found on target %q", jobID, t.ID)
	}

	msg := "job successfully cancelled"
	state := StateCancelled
	if strings.Contains(trimmed, "ALREADY_FINISHED") {
		msg = "job was already finished"
	}

	m.auditLog(uuid.New().String(), "anonymous", "job_cancel", t.ID, jobID, "", "", "success", 0, msg)

	return &JobCancelResponse{
		JobID:   jobID,
		Target:  t.ID,
		State:   state,
		Message: msg,
	}, nil
}

func (m *Manager) resolveTarget(ctx context.Context, jobID, targetHint string) (*target.Target, error) {
	// 1. Check targetHint if provided
	if targetHint != "" {
		return m.registry.Get(ctx, targetHint)
	}

	// 2. Check local memory index
	m.mu.RLock()
	entry, found := m.jobIndex[jobID]
	m.mu.RUnlock()

	if found {
		return m.registry.Get(ctx, entry.TargetID)
	}

	// 3. Scan all configured targets if restarted and no targetHint
	allTargets := m.registry.List(ctx)
	if len(allTargets) == 1 {
		return m.registry.Get(ctx, allTargets[0].ID)
	}

	for _, ts := range allTargets {
		tgt, err := m.registry.Get(ctx, ts.ID)
		if err != nil {
			continue
		}

		queryScript := fmt.Sprintf("[ -d '%s/%s' ] && echo 'EXISTS'", m.jobsCfg.RemoteBaseDir, jobID)
		connectOpts := tgt.ConnectOptions(5 * time.Second)
		client, release, err := m.sshManager.Acquire(ctx, connectOpts)
		if err != nil {
			continue
		}

		res, err := client.Exec(ctx, ssh.ExecOptions{
			Command:        queryScript,
			MaxStdoutBytes: 1024,
			MaxStderrBytes: 1024,
			Timeout:        5 * time.Second,
		})
		release()

		if err == nil && strings.Contains(res.Stdout, "EXISTS") {
			// Cache in local index for subsequent calls
			m.mu.Lock()
			m.jobIndex[jobID] = LocalJobIndexEntry{
				JobID:    jobID,
				TargetID: tgt.ID,
			}
			m.mu.Unlock()
			return tgt, nil
		}
	}

	return nil, fmt.Errorf("job %q not found in local index or any registered target", jobID)
}

func (m *Manager) auditLog(reqID, subject, tool, targetID, jobID, cmd, cwd, result string, durationMS int64, errMsg string) {
	if m.auditLogger == nil {
		return
	}
	m.auditLogger.Log(audit.Record{
		RequestID:    reqID,
		Subject:      subject,
		Tool:         tool,
		Target:       targetID,
		Command:      cmd,
		Cwd:          cwd,
		Result:       result,
		DurationMS:   durationMS,
		ErrorMessage: errMsg,
	})
}
