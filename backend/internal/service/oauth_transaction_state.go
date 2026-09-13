package service

import "time"

func TransitionOAuthTransaction(x *OAuthAuthorizationTransactionRecord, to string) error {
	if x == nil {
		return ErrInvalidRequest
	}
	if !x.ExpiresAt.After(time.Now()) && x.Status != "expired" {
		x.Status = "expired"
		return ErrInvalidGrant
	}
	switch x.Status {
	case "pending_login":
		if to != "pending_consent" && to != "denied" {
			return ErrInvalidRequest
		}
	case "pending_consent":
		if to != "approved" && to != "denied" {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidGrant
	}
	x.Status = to
	return nil
}
