package middleware

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

type OAuthBearerAuthenticator interface {
	AuthenticateBearer(context.Context, string) (*service.AccessTokenRecord, error)
}

const ContextKeyOAuthAccessToken ContextKey = "oauth_access_token"

func NewOAuthBearerMiddleware(auth OAuthBearerAuthenticator) gin.HandlerFunc {
	return func(c *gin.Context) {
		parts := strings.Fields(c.GetHeader("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			AbortWithError(c, http.StatusUnauthorized, "UNAUTHORIZED", "OAuth Bearer authorization required")
			return
		}
		record, err := auth.AuthenticateBearer(c.Request.Context(), parts[1])
		if err != nil {
			AbortWithError(c, http.StatusUnauthorized, "INVALID_TOKEN", "Invalid or expired OAuth access token")
			return
		}
		c.Set(string(ContextKeyOAuthAccessToken), record)
		c.Set(string(ContextKeyUser), AuthSubject{UserID: record.UserID})
		c.Next()
	}
}

func GetOAuthAccessTokenFromContext(c *gin.Context) (*service.AccessTokenRecord, bool) {
	v, ok := c.Get(string(ContextKeyOAuthAccessToken))
	if !ok {
		return nil, false
	}
	r, ok := v.(*service.AccessTokenRecord)
	return r, ok
}
