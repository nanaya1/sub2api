package service

func AttachOAuthTransactionUser(x *OAuthAuthorizationTransactionRecord, userID int64) error {
	if x == nil || userID <= 0 {
		return ErrInvalidRequest
	}
	if x.Status != "pending_login" {
		return ErrInvalidGrant
	}
	if err := TransitionOAuthTransaction(x, "pending_consent"); err != nil {
		return err
	}
	x.UserID = userID
	return nil
}
