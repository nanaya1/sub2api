package handler

import (
	"context"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"strings"
	"testing"
)

type revokeMock struct {
	token, client string
	err           error
}

func (m *revokeMock) Revoke(_ context.Context, token, client string) error {
	m.token = token
	m.client = client
	return m.err
}
func TestOAuthRevokeHTTP(t *testing.T) {
	for _, tc := range []struct {
		body   string
		status int
		err    error
	}{
		{"token=secret&token_type_hint=access_token", 200, nil},
		{"token=secret&client_id=desktop", 200, nil},
		{"token=a&token=b", 400, nil},
		{"", 400, nil},
		{"token=secret", 500, errors.New("private database error")},
	} {
		t.Run(tc.body, func(t *testing.T) {
			s := &revokeMock{err: tc.err}
			h := NewOAuthRevokeHandler(s)
			r := gin.New()
			r.POST("/oauth2/revoke", h.Revoke)
			req := httptest.NewRequest("POST", "/oauth2/revoke", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			require.Equal(t, tc.status, w.Code)
			require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			require.NotContains(t, w.Body.String(), "private")
			if tc.status == 200 {
				require.Equal(t, "secret", s.token)
				require.Empty(t, w.Body.String())
			}
		})
	}
}
