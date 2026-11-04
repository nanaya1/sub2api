package routes

import (
	"github.com/Wei-Shaw/sub2api/internal/handler"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
)

// RegisterProvisioningRoutes 注册主服务到当前平台的内部投影接口。
func RegisterProvisioningRoutes(r *gin.Engine, h *handler.Handlers, auth middleware.ProvisioningAuthMiddleware) {
	group := r.Group("/internal/v1/provisioning")
	group.Use(gin.HandlerFunc(auth))
	group.POST("/user/upsert", h.Provisioning.UpsertUser)
	group.POST("/group/upsert", h.Provisioning.UpsertGroup)
	group.POST("/group/replace-members", h.Provisioning.ReplaceGroupMembers)
	group.POST("/user/disable", h.Provisioning.DisableUser)
	group.POST("/group/disable", h.Provisioning.DisableGroup)
	group.POST("/group/remove", h.Provisioning.RemoveGroup)
}
