package service

import (
	"github.com/stretchr/testify/require"
	"net/url"
	"testing"
)

func TestOAuthCallbackURLPreservesState(t *testing.T) {
	got, e := OAuthCallbackURL("https://app.example/cb?x=1", "code-value", "a+b%2Fc")
	require.NoError(t, e)
	u, e := url.Parse(got)
	require.NoError(t, e)
	require.Equal(t, "code-value", u.Query().Get("code"))
	require.Equal(t, "a+b%2Fc", u.Query().Get("state"))
	require.Equal(t, "1", u.Query().Get("x"))
}
func TestOAuthDeniedCallback(t *testing.T) {
	got, e := OAuthCallbackURL("https://app.example/cb", "", "state")
	require.NoError(t, e)
	require.Contains(t, got, "error=access_denied")
}
