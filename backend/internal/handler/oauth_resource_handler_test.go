package handler

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeManagedKeyRepo returns an already-provisioned managed key so
// GetOrCreateManagedKey short-circuits without touching the DB.
type fakeManagedKeyRepo struct{}

type missingManagedKeyRepo struct{ fakeManagedKeyRepo }

func (missingManagedKeyRepo) FindManagedKey(context.Context, int64, int64) (*service.OAuthManagedKeyRecord, error) {
	return nil, sql.ErrNoRows
}

func TestOAuthResourceHandler_FirstCreationRequiresWrite(t *testing.T) {
	h := NewOAuthResourceHandler(&service.OAuthResourceService{Managed: missingManagedKeyRepo{}})
	c, rec := newResourceTestContext(http.MethodGet, "/api/v1/oauth/tokens", &service.AccessTokenRecord{UserID: 1, ClientID: 2, Scopes: []string{"tokens:read"}})
	h.Tokens(c)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), "tokens:write")
}

func (fakeManagedKeyRepo) FindManagedKey(ctx context.Context, userID, clientID int64) (*service.OAuthManagedKeyRecord, error) {
	return &service.OAuthManagedKeyRecord{UserID: userID, ClientID: clientID, Key: "sk-fake-managed", Status: service.StatusActive, RevokedAt: nil}, nil
}
func (fakeManagedKeyRepo) CreateManagedKey(ctx context.Context, userID, clientID int64, key *service.APIKey) (*service.OAuthManagedKeyRecord, error) {
	return &service.OAuthManagedKeyRecord{UserID: userID, ClientID: clientID, Key: key.Key}, nil
}

func newResourceTestContext(method, path string, tok *service.AccessTokenRecord) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(method, path, nil)
	if tok != nil {
		c.Set("oauth_access_token", tok)
	}
	return c, rec
}

func TestOAuthResourceHandler_Tokens_ScopeEnforced(t *testing.T) {
	h := &OAuthResourceHandler{resources: &service.OAuthResourceService{Managed: fakeManagedKeyRepo{}}}

	// 无 token -> 401
	c, rec := newResourceTestContext(http.MethodGet, "/api/v1/oauth/tokens", nil)
	h.Tokens(c)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// 有 token 但缺少 tokens:read -> 403 insufficient_scope
	c, rec = newResourceTestContext(http.MethodGet, "/api/v1/oauth/tokens", &service.AccessTokenRecord{UserID: 1, ClientID: 2, Scopes: []string{"openid", "profile"}})
	h.Tokens(c)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "insufficient_scope")

	// 缺少事务依赖必须关闭访问，不能通过测试替身绕过订阅验证。
	c, rec = newResourceTestContext(http.MethodGet, "/api/v1/oauth/tokens", &service.AccessTokenRecord{UserID: 1, ClientID: 2, Scopes: []string{"openid", "tokens:read"}})
	h.Tokens(c)
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "sk-fake-managed")
}

type oauthProfileRepo struct{ service.UserRepository }

func (oauthProfileRepo) GetUserAvatar(context.Context, int64) (*service.UserAvatar, error) {
	return nil, nil
}
func (oauthProfileRepo) GetByID(context.Context, int64) (*service.User, error) {
	return &service.User{ID: 1, Username: "local", Email: "private@localhost", Balance: 10, Status: service.StatusActive}, nil
}
func TestOAuthResourceHandler_ProfileAndBalanceContract(t *testing.T) {
	h := NewOAuthResourceHandler(&service.OAuthResourceService{Users: service.NewUserService(oauthProfileRepo{}, nil, nil, nil)})
	c, rec := newResourceTestContext("GET", "/api/v1/oauth/balance", &service.AccessTokenRecord{UserID: 1, Scopes: []string{"balance:read"}})
	h.Balance(c)
	require.JSONEq(t, `{"success":true,"data":{"available_balance":10,"frozen_balance":0}}`, rec.Body.String())
	c, rec = newResourceTestContext("GET", "/api/user/self", &service.AccessTokenRecord{UserID: 1, Scopes: []string{"profile"}})
	h.Self(c)
	require.NotContains(t, rec.Body.String(), "private@localhost")
	require.NotContains(t, rec.Body.String(), "balance")
}

func TestOAuthResourceHandler_BalanceAndSelf_ScopeEnforced(t *testing.T) {
	h := &OAuthResourceHandler{resources: &service.OAuthResourceService{Managed: fakeManagedKeyRepo{}}}

	c, rec := newResourceTestContext(http.MethodGet, "/api/v1/oauth/balance", &service.AccessTokenRecord{UserID: 1, ClientID: 2, Scopes: []string{"openid"}})
	h.Balance(c)
	assert.Equal(t, http.StatusForbidden, rec.Code, "balance requires balance:read")

	c, rec = newResourceTestContext(http.MethodGet, "/api/user/self", &service.AccessTokenRecord{UserID: 1, ClientID: 2, Scopes: []string{"openid"}})
	h.Self(c)
	assert.Equal(t, http.StatusForbidden, rec.Code, "self requires profile")
}
