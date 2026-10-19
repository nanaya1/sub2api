package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type cookieTransactionStub struct{}

func (cookieTransactionStub) Create(_ context.Context, in service.OAuthTransactionInput) (*service.OAuthTransactionResult, error) {
	return &service.OAuthTransactionResult{
		OAuthAuthorizationTransactionRecord: &service.OAuthAuthorizationTransactionRecord{TransactionID: "test-transaction"},
		CSRFToken:                           "test-csrf",
	}, nil
}

// 2026-10-19：验证 HTTP 显式兼容模式及默认 Secure 行为，两个 Cookie 必须同步。
func TestOAuthCookieSecureConfiguration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, mode := range []string{"default", "https", "http"} {
		t.Run(mode, func(t *testing.T) {
			h := NewOAuthAuthorizeHandlerWithTransactions(authorizeStub{}, cookieTransactionStub{})
			if mode != "default" {
				h.SetCookieSecure(mode == "https")
			}
			r := gin.New()
			r.GET("/oauth2/auth", h.Authorize)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/oauth2/auth?response_type=code&client_id=x&redirect_uri=meacowork%3A%2F%2Foauth%2Fcallback&state=test&code_challenge=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&code_challenge_method=S256", nil))
			require.Equal(t, http.StatusFound, w.Code)
			cookies := w.Result().Cookies()
			require.Len(t, cookies, 2)
			for _, cookie := range cookies {
				require.Contains(t, []string{"oauth_browser", "oauth_csrf"}, cookie.Name)
				require.Equal(t, mode != "http", cookie.Secure, cookie.Name)
				require.True(t, cookie.HttpOnly)
				require.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
			}
		})
	}
}
