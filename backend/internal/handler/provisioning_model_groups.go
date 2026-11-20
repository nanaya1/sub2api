package handler

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/gin-gonic/gin"
)

// ModelGroupCatalog 仅返回管理员维护的模型分组安全目录，不暴露账号、Key 或管理凭据。
func (h *ProvisioningHandler) ModelGroupCatalog(c *gin.Context) {
	var request struct {
		Source   string `json:"source"`
		Page     int    `json:"page"`
		PageSize int    `json:"page_size"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 64*1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || request.Source == "" {
		response.Error(c, 400, "invalid model group catalog request")
		return
	}
	result, err := h.service.ModelGroupCatalog(c.Request.Context(), request.Page, request.PageSize)
	if err != nil {
		writeProvisioningError(c, err)
		return
	}
	response.Success(c, result)
}
