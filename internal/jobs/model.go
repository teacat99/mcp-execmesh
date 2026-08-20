package jobs

import "time"

// JobState represents the execution state of an asynchronous job.
type JobState string

const (
	StatePending   JobState = "pending"
	StateRunning   JobState = "running"
	StateSucceeded JobState = "succeeded"
	StateFailed    JobState = "failed"
	StateCancelled JobState = "cancelled"
	StateUnknown   JobState = "unknown"
)

// JobMeta is stored on the remote host in meta.json.
type JobMeta struct {
	JobID        string    `json:"job_id"`
	TargetID     string    `json:"target_id"`
	Command      string    `json:"command"`
	Cwd          string    `json:"cwd"`
	StartedAt    time.Time `json:"started_at"`
	Pid          int       `json:"pid"`
	CommandHash  string    `json:"command_hash,omitempty"`
}

// JobStartRequest contains parameters for starting an asynchronous job.
type JobStartRequest struct {
	Target  string            `json:"target"`
	Command string            `json:"command"`
	Cwd     string            `json:"cwd,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
}

// JobStartResponse is returned immediately when exec_start succeeds.
type JobStartResponse struct {
	JobID     string   `json:"job_id"`
	Target    string   `json:"target"`
	State     JobState `json:"state"`
	StartedAt string   `json:"started_at"`
}

// JobStatusResponse represents full job status returned by job_status.
type JobStatusResponse struct {
	JobID       string   `json:"job_id"`
	Target      string   `json:"target"`
	State       JobState `json:"state"`
	Pid         *int     `json:"pid,omitempty"`
	ExitCode    *int     `json:"exit_code"`
	StartedAt   string   `json:"started_at,omitempty"`
	FinishedAt  string   `json:"finished_at,omitempty"`
	StdoutBytes int64    `json:"stdout_bytes"`
	StderrBytes int64    `json:"stderr_bytes"`
}

// JobOutputRequest defines parameters for reading job log output.
type JobOutputRequest struct {
	JobID  string `json:"job_id"`
	Target string `json:"target,omitempty"`
	Stream string `json:"stream"` // "stdout" or "stderr"
	Offset int64  `json:"offset"`
	Limit  int    `json:"limit"`
}

// JobOutputResponse contains chunked log data and pagination cursors.
type JobOutputResponse struct {
	JobID      string `json:"job_id"`
	Stream     string `json:"stream"`
	Data       string `json:"data"`
	Offset     int64  `json:"offset"`
	NextOffset int64  `json:"next_offset"`
	EOF        bool   `json:"eof"`
}

// JobCancelResponse is returned after cancelling a job.
type JobCancelResponse struct {
	JobID   string   `json:"job_id"`
	Target  string   `json:"target"`
	State   JobState `json:"state"`
	Message string   `json:"message"`
}
