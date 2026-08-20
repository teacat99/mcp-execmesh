package jobs

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// RemoteJobInfo is parsed from the remote status query output.
type RemoteJobInfo struct {
	NotFound   bool
	Pid        *int
	ExitCode   *int
	FinishedAt string
	StdoutSize int64
	StderrSize int64
	IsRunning  bool
	Meta       *JobMeta
}

// BuildLaunchScript creates the shell command string to detach and start a job on the remote host.
func BuildLaunchScript(jobsBaseDir, jobID string, meta JobMeta, command, cwd string, env map[string]string, shell string) (string, error) {
	jobDir := filepath.Join(jobsBaseDir, jobID)

	metaJSONBytes, err := json.Marshal(meta)
	if err != nil {
		return "", fmt.Errorf("failed to serialize meta json: %w", err)
	}
	metaJSON := string(metaJSONBytes)

	var envBuilder strings.Builder
	for k, v := range env {
		escapedVal := strings.ReplaceAll(v, "'", "'\\''")
		envBuilder.WriteString(fmt.Sprintf("export %s='%s'\n", k, escapedVal))
	}

	escapedCwd := strings.ReplaceAll(cwd, "'", "'\\''")
	cwdCmd := ""
	if cwd != "" {
		cwdCmd = fmt.Sprintf("cd '%s' && ", escapedCwd)
	}

	escapedCommand := strings.ReplaceAll(command, "'", "'\\''")

	script := fmt.Sprintf(`
mkdir -p '%s' && cat << 'MCP_EOF' > '%s/meta.json'
%s
MCP_EOF

nohup sh -c '
%s
%s( %s ) > "%s/stdout.log" 2> "%s/stderr.log" &
PID=$!
echo $PID > "%s/pid"
wait $PID
EC=$?
echo $EC > "%s/exit_code"
date -u +"%%Y-%%m-%%dT%%H:%%M:%%SZ" > "%s/finished"
' >/dev/null 2>&1 &

sleep 0.1
if [ -f '%s/pid' ]; then
  cat '%s/pid'
else
  echo "STARTED"
fi
`, jobDir, jobDir, metaJSON, envBuilder.String(), cwdCmd, escapedCommand, jobDir, jobDir, jobDir, jobDir, jobDir, jobDir, jobDir)

	return script, nil
}

// BuildQueryScript creates the remote query command string to fetch job status and metrics.
func BuildQueryScript(jobsBaseDir, jobID string) string {
	jobDir := filepath.Join(jobsBaseDir, jobID)
	return fmt.Sprintf(`
if [ ! -d '%s' ]; then
  echo "NOT_FOUND"
  exit 0
fi
PID=""
[ -f '%s/pid' ] && PID=$(cat '%s/pid')
EC=""
[ -f '%s/exit_code' ] && EC=$(cat '%s/exit_code')
FINISHED=""
[ -f '%s/finished' ] && FINISHED=$(cat '%s/finished')
STDOUT_SZ=0
[ -f '%s/stdout.log' ] && STDOUT_SZ=$(wc -c < '%s/stdout.log' 2>/dev/null | tr -d ' ')
STDERR_SZ=0
[ -f '%s/stderr.log' ] && STDERR_SZ=$(wc -c < '%s/stderr.log' 2>/dev/null | tr -d ' ')
IS_RUNNING=0
if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
  IS_RUNNING=1
fi
META=""
[ -f '%s/meta.json' ] && META=$(cat '%s/meta.json')

echo "---JOB_STATUS---"
echo "PID:$PID"
echo "EC:$EC"
echo "FINISHED:$FINISHED"
echo "STDOUT_SZ:$STDOUT_SZ"
echo "STDERR_SZ:$STDERR_SZ"
echo "RUNNING:$IS_RUNNING"
echo "META:$META"
`, jobDir, jobDir, jobDir, jobDir, jobDir, jobDir, jobDir, jobDir, jobDir, jobDir, jobDir, jobDir, jobDir)
}

// ParseQueryOutput parses the structured output from BuildQueryScript.
func ParseQueryOutput(raw string) (*RemoteJobInfo, error) {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "NOT_FOUND") {
		return &RemoteJobInfo{NotFound: true}, nil
	}

	info := &RemoteJobInfo{}
	lines := strings.Split(trimmed, "\n")
	metaPrefix := "META:"

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PID:") {
			pidStr := strings.TrimPrefix(line, "PID:")
			if p, err := strconv.Atoi(pidStr); err == nil && p > 0 {
				info.Pid = &p
			}
		} else if strings.HasPrefix(line, "EC:") {
			ecStr := strings.TrimPrefix(line, "EC:")
			if ec, err := strconv.Atoi(ecStr); err == nil {
				info.ExitCode = &ec
			}
		} else if strings.HasPrefix(line, "FINISHED:") {
			finStr := strings.TrimPrefix(line, "FINISHED:")
			if finStr != "" {
				info.FinishedAt = finStr
			}
		} else if strings.HasPrefix(line, "STDOUT_SZ:") {
			szStr := strings.TrimPrefix(line, "STDOUT_SZ:")
			if sz, err := strconv.ParseInt(szStr, 10, 64); err == nil {
				info.StdoutSize = sz
			}
		} else if strings.HasPrefix(line, "STDERR_SZ:") {
			szStr := strings.TrimPrefix(line, "STDERR_SZ:")
			if sz, err := strconv.ParseInt(szStr, 10, 64); err == nil {
				info.StderrSize = sz
			}
		} else if strings.HasPrefix(line, "RUNNING:") {
			rStr := strings.TrimPrefix(line, "RUNNING:")
			info.IsRunning = rStr == "1"
		} else if strings.HasPrefix(line, metaPrefix) {
			metaStr := strings.TrimPrefix(line, metaPrefix)
			if metaStr != "" {
				var meta JobMeta
				if err := json.Unmarshal([]byte(metaStr), &meta); err == nil {
					info.Meta = &meta
				}
			}
		}
	}

	return info, nil
}

// BuildReadOutputScript creates a remote command to read a specific slice of job output.
func BuildReadOutputScript(jobsBaseDir, jobID, stream string, offset int64, limit int) string {
	logFile := filepath.Join(jobsBaseDir, jobID, stream+".log")
	return fmt.Sprintf(`
if [ ! -f '%s' ]; then
  echo "NOT_FOUND"
  exit 0
fi
SZ=$(wc -c < '%s' 2>/dev/null | tr -d ' ')
echo "TOTAL_SIZE:$SZ"
echo "---DATA_START---"
tail -c +%d '%s' 2>/dev/null | head -c %d
`, logFile, logFile, offset+1, logFile, limit)
}

// ParseReadOutput parses the output from BuildReadOutputScript.
func ParseReadOutput(raw string) (totalSize int64, data string, notFound bool, err error) {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "NOT_FOUND") {
		return 0, "", true, nil
	}

	const marker = "---DATA_START---\n"
	idx := strings.Index(raw, marker)
	if idx == -1 {
		return 0, "", false, fmt.Errorf("invalid read output format from remote")
	}

	header := raw[:idx]
	data = raw[idx+len(marker):]

	for _, line := range strings.Split(header, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "TOTAL_SIZE:") {
			szStr := strings.TrimPrefix(line, "TOTAL_SIZE:")
			sz, err := strconv.ParseInt(szStr, 10, 64)
			if err != nil {
				return 0, "", false, fmt.Errorf("failed to parse TOTAL_SIZE %q: %w", szStr, err)
			}
			totalSize = sz
			break
		}
	}

	return totalSize, data, false, nil
}

// BuildCancelScript creates the shell command to terminate a running job on the remote host.
func BuildCancelScript(jobsBaseDir, jobID string) string {
	jobDir := filepath.Join(jobsBaseDir, jobID)
	return fmt.Sprintf(`
if [ ! -d '%s' ]; then
  echo "NOT_FOUND"
  exit 0
fi
PID=""
[ -f '%s/pid' ] && PID=$(cat '%s/pid')
if [ -z "$PID" ]; then
  echo "NO_PID"
  exit 0
fi
if kill -0 "$PID" 2>/dev/null; then
  kill -TERM "$PID" 2>/dev/null
  sleep 1
  if kill -0 "$PID" 2>/dev/null; then
    kill -KILL "$PID" 2>/dev/null
  fi
  date -u +"%%Y-%%m-%%dT%%H:%%M:%%SZ" > '%s/finished'
  echo 137 > '%s/exit_code'
  echo "CANCELLED"
else
  echo "ALREADY_FINISHED"
fi
`, jobDir, jobDir, jobDir, jobDir, jobDir)
}
