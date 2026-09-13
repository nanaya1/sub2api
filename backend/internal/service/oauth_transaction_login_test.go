package service

import (
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestAttachOAuthTransactionUser(t *testing.T) {
	x := &OAuthAuthorizationTransactionRecord{Status: "pending_login", ExpiresAt: time.Now().Add(time.Minute)}
	require.NoError(t, AttachOAuthTransactionUser(x, 7))
	require.Equal(t, int64(7), x.UserID)
	require.Equal(t, "pending_consent", x.Status)
	require.Error(t, AttachOAuthTransactionUser(x, 8))
}
