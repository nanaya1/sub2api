package service

import (
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestOAuthTransactionState(t *testing.T) {
	x := &OAuthAuthorizationTransactionRecord{Status: "pending_login", ExpiresAt: time.Now().Add(time.Minute)}
	require.NoError(t, TransitionOAuthTransaction(x, "pending_consent"))
	require.NoError(t, TransitionOAuthTransaction(x, "approved"))
	require.Error(t, TransitionOAuthTransaction(x, "denied"))
}
