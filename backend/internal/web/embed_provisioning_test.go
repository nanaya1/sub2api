//go:build embed

package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// TestProvisioningBypassesFrontend 验证两种内嵌前端均放行投影请求，仍由独立密钥中间件鉴权
func TestProvisioningBypassesFrontend(t *testing.T) {
	for _, mode := range []string{"settings", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			provider := &mockSettingsProvider{settings: map[string]string{"site_name": "test"}}
			frontend := provisioningTestFrontend(t, mode, provider)
			for _, operation := range []string{"user/upsert", "user/disable", "group/upsert", "group/disable", "group/remove", "group/replace-members"} {
				t.Run(operation, func(t *testing.T) {
					for _, auth := range []struct {
						name    string
						enabled bool
						key     string
						status  int
					}{
						{"valid", true, "test-provisioning-key", http.StatusOK},
						{"missing", true, "", http.StatusUnauthorized},
						{"invalid", true, "invalid-key", http.StatusUnauthorized},
						{"disabled", false, "test-provisioning-key", http.StatusServiceUnavailable},
					} {
						t.Run(auth.name, func(t *testing.T) {
							r := gin.New()
							r.Use(frontend)
							path := "/internal/v1/provisioning/" + operation
							called := false
							group := r.Group("/internal/v1/provisioning")
							group.Use(gin.HandlerFunc(middleware.NewProvisioningAuthMiddleware(auth.enabled, "test-provisioning-key")))
							group.POST("/"+operation, func(c *gin.Context) {
								called = true
								c.JSON(http.StatusOK, gin.H{"code": 0, "data": gin.H{"local_group_id": 7}})
							})
							req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"version":14}`))
							req.Header.Set("Content-Type", "application/json")
							req.Header.Set("X-Provisioning-Key", auth.key)
							rec := httptest.NewRecorder()
							r.ServeHTTP(rec, req)
							require.Equal(t, auth.status, rec.Code)
							require.Contains(t, rec.Header().Get("Content-Type"), "application/json")
							require.Equal(t, auth.status == http.StatusOK, called)
							if called {
								require.JSONEq(t, `{"code":0,"data":{"local_group_id":7}}`, rec.Body.String())
							}
						})
					}
				})
			}
			// 内部请求不应触发首页渲染或公开设置查询
			require.Zero(t, provider.called)
		})
	}
}

// TestUnknownInternalRouteDoesNotRenderFrontend 验证未知内部路径保持 404，普通页面仍由前端处理
func TestUnknownInternalRouteDoesNotRenderFrontend(t *testing.T) {
	for _, mode := range []string{"settings", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			provider := &mockSettingsProvider{settings: map[string]string{"site_name": "test"}}
			r := gin.New()
			r.Use(provisioningTestFrontend(t, mode, provider))
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/provisioning/unknown", nil))
			require.Equal(t, http.StatusNotFound, rec.Code)
			require.NotContains(t, rec.Header().Get("Content-Type"), "text/html")
			require.Zero(t, provider.called)

			rec = httptest.NewRecorder()
			r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/internal-help", nil))
			require.Equal(t, http.StatusOK, rec.Code)
			require.Contains(t, rec.Header().Get("Content-Type"), "text/html")
		})
	}
}

// provisioningTestFrontend 构造与生产一致的设置注入或兼容模式前端中间件
func provisioningTestFrontend(t *testing.T, mode string, provider *mockSettingsProvider) gin.HandlerFunc {
	t.Helper()
	if mode == "legacy" {
		return ServeEmbeddedFrontend()
	}
	frontend, err := NewFrontendServer(provider)
	require.NoError(t, err)
	return frontend.Middleware()
}
