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

// Inspect 只读核对端点沿用独立Provisioning鉴权，严格限制请求并脱敏所有失败
func (h *ProvisioningHandler) Inspect(c *gin.Context) {
	var input service.ProvisioningInspectInput
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 64*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		response.Error(c, http.StatusBadRequest, "invalid provisioning inspection")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		response.Error(c, http.StatusBadRequest, "invalid provisioning inspection")
		return
	}
	result, err := h.service.Inspect(c.Request.Context(), input)
	if err != nil {
		if errors.Is(err, service.ErrProvisioningInvalidRequest) {
			response.Error(c, http.StatusBadRequest, "invalid provisioning inspection")
			return
		}
		response.Error(c, http.StatusServiceUnavailable, "provisioning inspection unavailable")
		return
	}
	response.Success(c, result)
}
