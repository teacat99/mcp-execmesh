package transfer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDownloadRegistrySingleUse(t *testing.T) {
	reg := newDownloadRegistry(10)
	ticket, err := GenerateDownloadTicket()
	require.NoError(t, err)
	exp := time.Now().Add(time.Minute)
	require.NoError(t, reg.register(ticket, &downloadTicket{TargetID: "t1", Path: "/a", ExpiresAt: exp}))

	ent, err := reg.claim(ticket)
	require.NoError(t, err)
	assert.Equal(t, "t1", ent.TargetID)

	_, err = reg.claim(ticket)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestDownloadRegistryMaxLimit(t *testing.T) {
	reg := newDownloadRegistry(1)
	t1, _ := GenerateDownloadTicket()
	t2, _ := GenerateDownloadTicket()
	exp := time.Now().Add(time.Minute)
	require.NoError(t, reg.register(t1, &downloadTicket{TargetID: "a", Path: "/a", ExpiresAt: exp}))
	err := reg.register(t2, &downloadTicket{TargetID: "b", Path: "/b", ExpiresAt: exp})
	assert.ErrorIs(t, err, ErrDownloadTicketLimit)
}
