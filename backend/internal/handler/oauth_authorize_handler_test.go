package handler

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"net/url"
	"testing"
)

type authorizeStub struct{}

func (authorizeStub) ValidateClient(_ context.Context, id, redirect string, scopes []string) (*service.OAuthClientRecord, error) {
	return &service.OAuthClientRecord{ID: 3, ClientID: id}, nil
}
func TestOAuthAuthorizeRejectsMissingParams(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/oauth2/authorize", NewOAuthAuthorizeHandler(authorizeStub{}).Authorize)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/oauth2/authorize?client_id=x", nil))
	require.Equal(t, 400, w.Code)
}
func TestOAuthAuthorizeRejectsMissingStateAndMethod(t *testing.T) {
	r := gin.New()
	r.GET("/oauth2/authorize", NewOAuthAuthorizeHandler(authorizeStub{}).Authorize)
	q := url.Values{"response_type": {"code"}, "client_id": {"x"}, "redirect_uri": {"https://app/cb"}, "code_challenge": {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/oauth2/authorize?"+q.Encode(), nil))
	require.Equal(t, 400, w.Code)
}
