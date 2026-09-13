package service

import (
	"context"
	"time"
)

type OAuthTransactionCreator interface {
	CreateAuthorizationTransaction(context.Context, *OAuthAuthorizationTransactionRecord) error
}

type OAuthTransactionService struct {
	Repo OAuthServerRepository
	TTL  time.Duration
	Now  func() time.Time
}

// now returns a single clock reading for the current request, defaulting to UTC.
func (s *OAuthTransactionService) now() time.Time {
	if s != nil && s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

// ttl returns the transaction lifetime, defaulting to the authorization code TTL.
func (s *OAuthTransactionService) ttl() time.Duration {
	if s != nil && s.TTL > 0 {
		return s.TTL
	}
	return OAuthAuthorizationCodeTTL
}

func (s *OAuthTransactionService) Create(ctx context.Context, in OAuthTransactionInput) (*OAuthTransactionResult, error) {
	if s == nil || s.Repo == nil {
		return nil, ErrServerError
	}
	now := s.now()
	ttl := s.ttl()
	in.Now, in.TTL = now, ttl
	x, err := NewOAuthAuthorizationTransaction(in)
	if err != nil {
		return nil, err
	}
	if err = s.Repo.CreateAuthorizationTransaction(ctx, x.OAuthAuthorizationTransactionRecord); err != nil {
		return nil, ErrServerError
	}
	return x, nil
}

// Resume binds the authenticated web user to a transaction that is still in the
// `pending_login` state. It transitions the transaction to `pending_consent` so
// the consent screen (GET /oauth2/consent) can later serve it to the verified
// owner. All ownership and liveness checks are performed by the repository inside
// a single SQL transaction lock; this method only supplies the clock reading.
func (s *OAuthTransactionService) Resume(ctx context.Context, in OAuthResumeInput) error {
	if s == nil || s.Repo == nil {
		return ErrServerError
	}
	if in.TransactionID == "" || in.UserID <= 0 {
		return ErrInvalidRequest
	}
	repoIn := OAuthResumeRepoInput{
		TransactionID:  in.TransactionID,
		UserID:         in.UserID,
		BrowserSession: in.BrowserSession,
		Now:            s.now(),
	}
	return s.Repo.ResumeAuthorizationTransaction(ctx, repoIn)
}

// codeTTL returns the authorization code lifetime, defaulting to the package
// constant. A single Now() is computed by the caller so all timestamps in one
// request are derived from one clock reading.
func (s *OAuthTransactionService) codeTTL() time.Duration {
	if s.TTL > 0 {
		return s.TTL
	}
	return OAuthAuthorizationCodeTTL
}

// Decide closes the authorization transaction: it validates the approver, locks
// the transaction row, and atomically (within one SQL transaction) either upserts
// consent + inserts the authorization code hash + consumes the transaction, or
// records a terminal "denied" state. The plaintext code is returned only after the
// repository commits successfully, so callers can never observe a code for an
// uncommitted or rolled-back decision.
func (s *OAuthTransactionService) Decide(ctx context.Context, in OAuthDecisionInput) (*OAuthDecisionOutput, error) {
	if s == nil || s.Repo == nil {
		return nil, ErrServerError
	}
	if in.UserID <= 0 {
		return nil, ErrInvalidRequest
	}
	if in.Decision != "approve" && in.Decision != "deny" {
		return nil, ErrInvalidRequest
	}
	now := s.now()
	repoIn := OAuthDecisionRepoInput{
		TransactionID:  in.TransactionID,
		UserID:         in.UserID,
		Decision:       in.Decision,
		BrowserSession: in.BrowserSession,
		CSRFToken:      in.CSRFToken,
		Now:            now,
	}
	var code string
	if in.Decision == "approve" {
		c, err := GenerateOAuthSecret()
		if err != nil {
			return nil, ErrServerError
		}
		code = c
		repoIn.CodeHash = HashOAuthSecret(c)
		repoIn.CodeTTL = s.codeTTL()
	}
	repoOut, err := s.Repo.DecideAuthorizationTransaction(ctx, repoIn)
	if err != nil {
		return nil, err
	}
	// Attach the plaintext code only after the repository committed.
	return &OAuthDecisionOutput{
		Code:        code,
		RedirectURI: repoOut.RedirectURI,
		State:       repoOut.State,
	}, nil
}
