package ssh

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLimitedBuffer_NoTruncation(t *testing.T) {
	buf := NewLimitedBuffer(100)
	n, err := buf.Write([]byte("hello world"))
	assert.NoError(t, err)
	assert.Equal(t, 11, n)
	assert.Equal(t, "hello world", buf.String())
	assert.False(t, buf.IsTruncated())
	assert.Equal(t, int64(11), buf.TotalWritten())
}

func TestLimitedBuffer_Truncation(t *testing.T) {
	buf := NewLimitedBuffer(10)

	n, err := buf.Write([]byte("12345"))
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.False(t, buf.IsTruncated())

	n, err = buf.Write([]byte("67890EXTRA"))
	assert.NoError(t, err)
	assert.Equal(t, 10, n)
	assert.True(t, buf.IsTruncated())
	assert.Equal(t, "1234567890", buf.String())
	assert.Equal(t, int64(15), buf.TotalWritten())

	// Additional writes should be discarded without error
	n, err = buf.Write([]byte("MORE"))
	assert.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.True(t, buf.IsTruncated())
	assert.Equal(t, "1234567890", buf.String())
	assert.Equal(t, int64(19), buf.TotalWritten())
}

func TestBuildCommand(t *testing.T) {
	cmd := buildCommand("uname -a", "/srv/app", map[string]string{"FOO": "bar"}, "/bin/sh")
	assert.Equal(t, "export FOO='bar'; cd '/srv/app' && uname -a", cmd)

	cmd2 := buildCommand("echo 'hi'", "", nil, "/bin/sh")
	assert.Equal(t, "echo 'hi'", cmd2)
}
