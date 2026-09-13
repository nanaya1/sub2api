package service

import (
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestOAuthConsentValidation(t *testing.T) {
	x := &OAuthAuthorizationTransactionRecord{Status: "pending_consent", UserID: 7, BrowserSessionHash: HashOAuthSecret("browser"), CSRFTokenHash: HashOAuthSecret("csrf"), ExpiresAt: time.Now().Add(time.Minute)}
	require.NoError(t, ValidateOAuthConsent(x, 7, "browser", "csrf"))
	require.Error(t, ValidateOAuthConsent(x, 8, "browser", "csrf"))
	require.Error(t, ValidateOAuthConsent(x, 7, "wrong", "csrf"))
	require.Error(t, ValidateOAuthConsent(x, 7, "browser", "wrong"))
}
