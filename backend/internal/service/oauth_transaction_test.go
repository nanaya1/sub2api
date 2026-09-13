package service

import (
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestNewOAuthAuthorizationTransaction(t *testing.T) {
	now := time.Unix(100, 0)
	x, e := NewOAuthAuthorizationTransaction(OAuthTransactionInput{ClientID: 3, RedirectURI: "https://app/cb", Scopes: []string{"openid"}, State: "state", Challenge: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", BrowserSession: "browser", Now: now, TTL: time.Minute})
	require.NoError(t, e)
	require.Len(t, x.TransactionID, 43)
	require.Len(t, x.CSRFTokenHash, 43)
	// The plaintext CSRF must be returned to the caller but never persisted on the
	// record; only its hash is stored.
	require.NotEmpty(t, x.CSRFToken, "plaintext CSRF must be returned for the consent form")
	require.NotEqual(t, x.CSRFToken, x.CSRFTokenHash)
	require.Equal(t, "pending_login", x.Status)
	require.True(t, x.ExpiresAt.Equal(now.Add(time.Minute)))
	// A nil input must not produce a record.
	_, e = NewOAuthAuthorizationTransaction(OAuthTransactionInput{})
	require.Error(t, e)
}
