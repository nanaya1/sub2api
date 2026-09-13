package routes

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/handler"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"testing"
)

type authorizeStub struct{}

func (authorizeStub) ValidateClient(context.Context, string, string, []string) (*service.OAuthClientRecord, error) {
	return &service.OAuthClientRecord{ID: 1}, nil
}
func TestOAuthServerRouteSwitch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, enabled := range []bool{false, true} {
		r := gin.New()
		h := &handler.Handlers{OAuthAuthorize: handler.NewOAuthAuthorizeHandler(authorizeStub{}), OAuthConsent: handler.NewOAuthConsentHandler(nil, nil), OAuthResume: handler.NewOAuthResumeHandler(nil), OAuthResource: handler.NewOAuthResourceHandler(nil), OAuthToken: handler.NewOAuthTokenHandler(nil), OAuthRevoke: handler.NewOAuthRevokeHandler(nil)}
		RegisterOAuthServerRoutes(r, h, config.OAuthServerConfig{Enabled: enabled}, nil)
		for _, path := range []string{"/oauth2/auth", "/oauth2/authorize", "/oauth2/token", "/oauth2/revoke"} {
			method := "POST"
			if path == "/oauth2/auth" || path == "/oauth2/authorize" {
				method = "GET"
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(method, path, nil))
			want := 404
			if enabled {
				want = 400
			}
			require.Equal(t, want, w.Code, path)
			if enabled {
				require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			}
		}
	}
}
