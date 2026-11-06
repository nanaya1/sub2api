package routes

import (
	"crypto/subtle"
	"github.com/Wei-Shaw/sub2api/internal/handler"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
)

// RegisterCoworkPortalRoutes 模型门户独立开关和密钥，不扩大Provisioning权限。
func RegisterCoworkPortalRoutes(r *gin.Engine, h *handler.Handlers, enabled bool, key string, limiter *middleware.PanelRateLimiter) {
	portal := handler.NewCoworkPortalHandler(h)
	group := r.Group("/internal/v1/cowork")
	group.Use(func(c *gin.Context) {
		if !enabled || len(key) < 32 {
			c.AbortWithStatusJSON(503, gin.H{"code": 503, "reason": "PORTAL_UNAVAILABLE"})
			return
		}
		provided := c.GetHeader("X-Cowork-Portal-Key")
		if subtle.ConstantTimeCompare([]byte(provided), []byte(key)) != 1 {
			c.AbortWithStatusJSON(401, gin.H{"code": 401, "reason": "PORTAL_UNAUTHORIZED"})
			return
		}
		c.Next()
	})
	group.Use(portal.Authenticate)
	if limiter != nil {
		group.Use(limiter.Global(), limiter.Heavy())
	}
	group.POST("/portal", portal.Handle)
}
