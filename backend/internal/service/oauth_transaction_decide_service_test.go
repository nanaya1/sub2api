package service

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

// fakeDecisionRepo implements OAuthServerRepository by embedding the interface and
// overriding only the method under test, so the service can be exercised without a
// database.
func testOAuthSecretHasher(t *testing.T) *OAuthSecretHasher {
	t.Helper()
	hasher, err := NewOAuthSecretHasher(config.OAuthServerConfig{HashKeyVersion: 2, HashKey: "oauth-test-hmac-key-32-bytes-long"})
	require.NoError(t, err)
	return hasher
}

type fakeDecisionRepo struct {
	OAuthServerRepository
	call *OAuthDecisionRepoInput
	resp *OAuthDecisionRepoOutput
	err  error
}

func (f *fakeDecisionRepo) DecideAuthorizationTransaction(_ context.Context, in OAuthDecisionRepoInput) (*OAuthDecisionRepoOutput, error) {
	f.call = &in
	return f.resp, f.err
}

func TestOAuthTransactionServiceDecideApprove(t *testing.T) {
	repo := &fakeDecisionRepo{resp: &OAuthDecisionRepoOutput{RedirectURI: "https://app/cb", State: "state"}}
	svc := &OAuthTransactionService{Repo: repo, Hasher: testOAuthSecretHasher(t)}
	out, err := svc.Decide(context.Background(), OAuthDecisionInput{
		TransactionID: "tx", UserID: 7, Decision: "approve", BrowserSession: "browser", CSRFToken: "csrf",
	})
	require.NoError(t, err)
	require.NotEmpty(t, out.Code, "plaintext code must be returned only after commit")
	require.Equal(t, "https://app/cb", out.RedirectURI)
	require.Equal(t, "state", out.State)
	require.Equal(t, "approve", repo.call.Decision)
	require.Equal(t, int64(7), repo.call.UserID)
	require.Equal(t, "browser", repo.call.BrowserSession)
	require.Equal(t, "csrf", repo.call.CSRFToken)
	require.NotEmpty(t, repo.call.CodeHash, "the repository must receive only the code hash")
	require.NotEqual(t, out.Code, repo.call.CodeHash)
	require.Equal(t, 2, repo.call.CodeHashVersion)
}

func TestOAuthTransactionServiceDecideDeny(t *testing.T) {
	repo := &fakeDecisionRepo{resp: &OAuthDecisionRepoOutput{RedirectURI: "https://app/cb", State: "state"}}
	svc := &OAuthTransactionService{Repo: repo, Hasher: testOAuthSecretHasher(t)}
	out, err := svc.Decide(context.Background(), OAuthDecisionInput{
		TransactionID: "tx", UserID: 7, Decision: "deny", BrowserSession: "browser", CSRFToken: "csrf",
	})
	require.NoError(t, err)
	require.Empty(t, out.Code, "deny must not issue an authorization code")
	require.Empty(t, repo.call.CodeHash)
}

func TestOAuthTransactionServiceDecideRejectsBadInput(t *testing.T) {
	repo := &fakeDecisionRepo{}
	svc := &OAuthTransactionService{Repo: repo, Hasher: testOAuthSecretHasher(t)}
	_, err := svc.Decide(context.Background(), OAuthDecisionInput{UserID: 0, Decision: "approve"})
	require.ErrorIs(t, err, ErrInvalidRequest)
	_, err = svc.Decide(context.Background(), OAuthDecisionInput{UserID: 7, Decision: "maybe"})
	require.ErrorIs(t, err, ErrInvalidRequest)
	require.Nil(t, repo.call, "repository must not be called for invalid input")
}

func TestOAuthTransactionServiceDecidePropagatesRepoError(t *testing.T) {
	repo := &fakeDecisionRepo{err: ErrInvalidGrant}
	svc := &OAuthTransactionService{Repo: repo, Hasher: testOAuthSecretHasher(t)}
	_, err := svc.Decide(context.Background(), OAuthDecisionInput{TransactionID: "tx", UserID: 7, Decision: "approve", BrowserSession: "b", CSRFToken: "c"})
	require.ErrorIs(t, err, ErrInvalidGrant)
}
