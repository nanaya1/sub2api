package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// ProvisioningHandler 提供主服务调用的内部用户/分组投影接口。
type ProvisioningHandler struct {
	service *service.ProvisioningService
}

func NewProvisioningHandler(provisioningService *service.ProvisioningService) *ProvisioningHandler {
	return &ProvisioningHandler{service: provisioningService}
}

type provisioningUserRequest struct {
	Source         string `json:"source" binding:"required"`
	ExternalUserID string `json:"external_user_id" binding:"required"`
	Email          string `json:"email"`
	Username       string `json:"username"`
	Status         string `json:"status"`
	Version        int64  `json:"version"`
}

type provisioningGroupRequest struct {
	Source              string  `json:"source" binding:"required"`
	TenantKey           string  `json:"tenant_key" binding:"required"`
	ExternalGroupID     string  `json:"external_group_id" binding:"required"`
	Name                string  `json:"name"`
	Description         string  `json:"description"`
	Status              string  `json:"status"`
	Version             int64   `json:"version"`
	ModelGroupIDs       []int64 `json:"model_group_ids"`
	TenantGroupIDs      []int64 `json:"tenant_group_ids"`
	TenantPolicyVersion int64   `json:"tenant_policy_version"`
	TenantStatus        string  `json:"tenant_status"`
}

type provisioningUserGroupsRequest struct {
	Source         string  `json:"source" binding:"required"`
	ExternalUserID string  `json:"external_user_id" binding:"required"`
	ModelGroupIDs  []int64 `json:"model_group_ids"`
	Version        int64   `json:"version" binding:"required,gt=0"`
}

func (h *ProvisioningHandler) UpsertUser(c *gin.Context) {
	var req provisioningUserRequest
	if err := decodeProvisioningRequest(c, &req); err != nil {
		response.Error(c, http.StatusBadRequest, "invalid provisioning user request")
		return
	}
	result, err := h.service.UpsertUser(c.Request.Context(), service.ProvisioningUserUpsertInput{Source: req.Source, ExternalUserID: req.ExternalUserID, Email: req.Email, Username: req.Username, Status: req.Status, Version: req.Version})
	if err != nil {
		writeProvisioningError(c, err)
		return
	}
	response.Success(c, result)
}

func (h *ProvisioningHandler) UpsertGroup(c *gin.Context) {
	var req provisioningGroupRequest
	if err := decodeProvisioningRequest(c, &req); err != nil {
		response.Error(c, http.StatusBadRequest, "invalid provisioning group request")
		return
	}
	result, err := h.service.UpsertGroup(c.Request.Context(), service.ProvisioningGroupUpsertInput{Source: req.Source, TenantKey: req.TenantKey, ExternalGroupID: req.ExternalGroupID, Name: req.Name, Description: req.Description, Status: req.Status, Version: req.Version, ModelGroupIDs: req.ModelGroupIDs, TenantGroupIDs: req.TenantGroupIDs, TenantStatus: req.TenantStatus, TenantPolicyVersion: req.TenantPolicyVersion})
	if err != nil {
		writeProvisioningError(c, err)
		return
	}
	response.Success(c, result)
}

// ReplaceUserGroups 接收全局用户的跨企业完整分组集合，空数组明确清空授权
func (h *ProvisioningHandler) ReplaceUserGroups(c *gin.Context) {
	var req provisioningUserGroupsRequest
	if err := decodeProvisioningRequest(c, &req); err != nil {
		response.Error(c, http.StatusBadRequest, "invalid provisioning user groups request")
		return
	}
	result, err := h.service.ReplaceUserGroups(c.Request.Context(), service.ProvisioningUserGroupsInput{Source: req.Source, ExternalUserID: req.ExternalUserID, ModelGroupIDs: req.ModelGroupIDs, Version: req.Version})
	if err != nil {
		writeProvisioningError(c, err)
		return
	}
	response.Success(c, result)
}

// RemoveUser 只接收全局账号删除事件，不接受企业成员停用事件
func (h *ProvisioningHandler) RemoveUser(c *gin.Context) {
	var req provisioningUserRequest
	if err := decodeProvisioningRequest(c, &req); err != nil {
		response.Error(c, http.StatusBadRequest, "invalid provisioning user request")
		return
	}
	result, err := h.service.RemoveUser(c.Request.Context(), req.Source, req.ExternalUserID, req.Version)
	if err != nil {
		writeProvisioningError(c, err)
		return
	}
	response.Success(c, result)
}

// RemoveGroup 接收主服务分组删除事件，重复请求保持幂等
func (h *ProvisioningHandler) RemoveGroup(c *gin.Context) {
	var req provisioningGroupRequest
	if err := decodeProvisioningRequest(c, &req); err != nil {
		response.Error(c, http.StatusBadRequest, "invalid provisioning group request")
		return
	}
	result, err := h.service.UpsertGroup(c.Request.Context(), service.ProvisioningGroupUpsertInput{Source: req.Source, TenantKey: req.TenantKey, ExternalGroupID: req.ExternalGroupID, Name: req.Name, Description: req.Description, Status: "deleted", Version: req.Version, ModelGroupIDs: req.ModelGroupIDs, TenantGroupIDs: req.TenantGroupIDs, TenantStatus: req.TenantStatus, TenantPolicyVersion: req.TenantPolicyVersion})
	if err != nil {
		writeProvisioningError(c, err)
		return
	}
	response.Success(c, result)
}

func writeProvisioningError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrProvisioningInvalidRequest):
		response.Error(c, http.StatusBadRequest, "invalid provisioning request")
	case errors.Is(err, service.ErrProvisioningBindingNotFound):
		response.Error(c, http.StatusNotFound, "provisioning binding not found")
	default:
		response.ErrorFrom(c, err)
	}
}

func decodeProvisioningRequest(c *gin.Context, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return service.ErrProvisioningInvalidRequest
	}
	return nil
}
