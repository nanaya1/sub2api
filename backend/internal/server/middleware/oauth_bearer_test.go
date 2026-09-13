package middleware

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"testing"
	"time"
)

type oauthAuthStub struct{}

func (oauthAuthStub) AuthenticateBearer(context.Context, string) (*service.AccessTokenRecord, error) {
	return &service.AccessTokenRecord{UserID: 9, FamilyID: uuid.New(), ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func TestOAuthBearerMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(NewOAuthBearerMiddleware(oauthAuthStub{}))
	r.GET("/", func(c *gin.Context) { c.Status(204) })
	q := httptest.NewRequest("GET", "/", nil)
	q.Header.Set("Authorization", "Bearer token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, q)
	require.Equal(t, 204, w.Code)
}
