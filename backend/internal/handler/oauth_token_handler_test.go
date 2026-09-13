package handler

import (
	"context"
	"errors"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"strings"
	"testing"
)

type oauthTokenMock struct {
	err   error
	calls int
}

func (s *oauthTokenMock) ExchangeCode(context.Context, string, string, string, string) (*service.OAuthTokenResponse, error) {
	s.calls++
	return &service.OAuthTokenResponse{AccessToken: "test", TokenType: "Bearer", ExpiresIn: 900}, s.err
}
func (s *oauthTokenMock) Refresh(context.Context, string, string) (*service.OAuthTokenResponse, error) {
	s.calls++
	return nil, s.err
}
func TestOAuthTokenHTTP(t *testing.T) {
	for _, tc := range []struct {
		name, body, ctype string
		err               error
		status, calls     int
	}{
		{"code", "grant_type=authorization_code&client_id=x&code=c&redirect_uri=meacowork%3A%2F%2Foauth%2Fcallback&code_verifier=v", "application/x-www-form-urlencoded", nil, 200, 1},
		{"duplicate", "grant_type=refresh_token&grant_type=authorization_code", "application/x-www-form-urlencoded", nil, 400, 0},
		{"json", "{}", "application/json", nil, 400, 0},
		{"unsupported", "grant_type=password", "application/x-www-form-urlencoded", nil, 400, 0},
		{"transient", "grant_type=refresh_token&client_id=x&refresh_token=t", "application/x-www-form-urlencoded", errors.New("db secret must not leak"), 500, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &oauthTokenMock{err: tc.err}
			h := NewOAuthTokenHandler(s)
			r := gin.New()
			r.POST("/oauth2/token", h.Token)
			w := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.ctype)
			r.ServeHTTP(w, req)
			require.Equal(t, tc.status, w.Code)
			require.Equal(t, tc.calls, s.calls)
			require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			require.NotContains(t, w.Body.String(), "db secret")
		})
	}
}
