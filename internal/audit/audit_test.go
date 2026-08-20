package audit

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		out:          &buf,
		maskCommands: false,
	}

	exitCode := 0
	logger.Log(Record{
		Tool:       "exec",
		Target:     "test-01",
		Command:    "uname -a",
		Result:     "success",
		ExitCode:   &exitCode,
		DurationMS: 15,
	})

	var rec Record
	err := json.Unmarshal(buf.Bytes(), &rec)
	require.NoError(t, err)
	assert.Equal(t, "exec", rec.Tool)
	assert.Equal(t, "test-01", rec.Target)
	assert.Equal(t, "uname -a", rec.Command)
	assert.NotEmpty(t, rec.CommandSHA256)
	assert.Equal(t, "success", rec.Result)
	assert.Equal(t, 0, *rec.ExitCode)
}

func TestAuditLogger_Masked(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		out:          &buf,
		maskCommands: true,
	}

	logger.Log(Record{
		Tool:    "exec",
		Target:  "test-01",
		Command: "secret_command --password foo",
		Result:  "success",
	})

	var rec Record
	err := json.Unmarshal(buf.Bytes(), &rec)
	require.NoError(t, err)
	assert.Equal(t, "[MASKED]", rec.Command)
	assert.NotEmpty(t, rec.CommandSHA256)
}
