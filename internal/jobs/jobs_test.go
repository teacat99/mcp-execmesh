package jobs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateJobID(t *testing.T) {
	id1 := GenerateJobID()
	id2 := GenerateJobID()

	assert.True(t, jobIDRegex.MatchString(id1))
	assert.True(t, jobIDRegex.MatchString(id2))
	assert.NotEqual(t, id1, id2)
}

func TestBuildLaunchScript(t *testing.T) {
	meta := JobMeta{
		JobID:     "job_123",
		TargetID:  "node-01",
		Command:   "make test",
		Cwd:       "/srv/app",
		StartedAt: time.Now().UTC(),
	}

	script, err := BuildLaunchScript(".remote-mcp/jobs", "job_123", meta, "make test", "/srv/app", map[string]string{"ENV": "test"}, "/bin/sh")
	require.NoError(t, err)
	assert.Contains(t, script, ".remote-mcp/jobs/job_123")
	assert.Contains(t, script, "export ENV='test'")
	assert.Contains(t, script, "cd '/srv/app'")
	assert.Contains(t, script, "make test")
	assert.Contains(t, script, "stdout.log")
	assert.Contains(t, script, "exit_code")
	assert.Contains(t, script, "finished")
}

func TestParseQueryOutput(t *testing.T) {
	raw := `
---JOB_STATUS---
PID:1423
EC:0
FINISHED:2026-08-19T10:00:00Z
STDOUT_SZ:512
STDERR_SZ:12
RUNNING:0
META:{"job_id":"job_123","target_id":"node-01","command":"echo hi","cwd":"/srv","started_at":"2026-08-19T09:59:00Z","pid":1423}
`
	info, err := ParseQueryOutput(raw)
	require.NoError(t, err)
	assert.False(t, info.NotFound)
	assert.NotNil(t, info.Pid)
	assert.Equal(t, 1423, *info.Pid)
	assert.NotNil(t, info.ExitCode)
	assert.Equal(t, 0, *info.ExitCode)
	assert.Equal(t, "2026-08-19T10:00:00Z", info.FinishedAt)
	assert.Equal(t, int64(512), info.StdoutSize)
	assert.Equal(t, int64(12), info.StderrSize)
	assert.False(t, info.IsRunning)
	assert.NotNil(t, info.Meta)
	assert.Equal(t, "job_123", info.Meta.JobID)
	assert.Equal(t, "node-01", info.Meta.TargetID)
}

func TestParseQueryOutput_NotFound(t *testing.T) {
	raw := "NOT_FOUND\n"
	info, err := ParseQueryOutput(raw)
	require.NoError(t, err)
	assert.True(t, info.NotFound)
}

func TestParseReadOutput(t *testing.T) {
	raw := "TOTAL_SIZE:100\n---DATA_START---\nHello World"
	totalSize, data, notFound, err := ParseReadOutput(raw)
	require.NoError(t, err)
	assert.False(t, notFound)
	assert.Equal(t, int64(100), totalSize)
	assert.Equal(t, "Hello World", data)
}

func TestParseReadOutput_NotFound(t *testing.T) {
	raw := "NOT_FOUND\n"
	_, _, notFound, err := ParseReadOutput(raw)
	require.NoError(t, err)
	assert.True(t, notFound)
}
