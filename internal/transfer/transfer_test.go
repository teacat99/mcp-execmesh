package transfer

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCountingReader_WithinLimit(t *testing.T) {
	data := []byte("hello world, this is a test data stream")
	r := &countingReader{
		r:     bytes.NewReader(data),
		count: 0,
		max:   100,
	}

	buf := make([]byte, 10)
	var total int64
	for {
		n, err := r.Read(buf)
		total += int64(n)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
	}

	assert.Equal(t, int64(len(data)), total)
	assert.Equal(t, int64(len(data)), r.count)
}

func TestCountingReader_ExceedsLimit(t *testing.T) {
	data := []byte("hello world, this is a test data stream")
	r := &countingReader{
		r:     bytes.NewReader(data),
		count: 0,
		max:   10, // Limit is 10 bytes
	}

	buf := make([]byte, 8)
	// First read 8 bytes - OK
	n, err := r.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 8, n)

	// Second read 8 bytes - Total 16 > 10, should error
	_, err = r.Read(buf)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFileSizeExceedsLimit)
}
