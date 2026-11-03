package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// ProvisioningAuthMiddleware 认证主服务调用的内部投影接口。
// 采用独立 API Key，避免复用管理员 Key 或伪造管理员 Session。
type ProvisioningAuthMiddleware func(*gin.Context)

func NewProvisioningAuthMiddleware(enabled bool, expectedKey string) ProvisioningAuthMiddleware {
	return func(c *gin.Context) {
		if !enabled || strings.TrimSpace(expectedKey) == "" {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"code": http.StatusServiceUnavailable, "message": "provisioning is disabled"})
			return
		}
		provided := c.GetHeader("X-Provisioning-Key")
		if provided == "" { provided = c.GetHeader("Authorization") }
		provided = strings.TrimSpace(strings.TrimPrefix(provided, "Bearer "))
		if subtle.ConstantTimeCompare([]byte(provided), []byte(expectedKey)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": http.StatusUnauthorized, "message": "invalid provisioning credentials"})
			return
		}
		c.Next()
	}
}
