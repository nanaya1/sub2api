package service

import (
	"crypto/subtle"
	"time"
)

func ValidateOAuthConsent(x *OAuthAuthorizationTransactionRecord, userID int64, browser, csrf string) error {
	if x == nil || x.Status != "pending_consent" || x.UserID != userID || !x.ExpiresAt.After(time.Now()) {
		return ErrInvalidGrant
	}
	if subtle.ConstantTimeCompare([]byte(x.BrowserSessionHash), []byte(HashOAuthSecret(browser))) != 1 || subtle.ConstantTimeCompare([]byte(x.CSRFTokenHash), []byte(HashOAuthSecret(csrf))) != 1 {
		return ErrInvalidGrant
	}
	return nil
}
