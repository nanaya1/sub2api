package handler

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"mime"
	"net/http"
)

type OAuthRevocationService interface {
	Revoke(context.Context, string, string) error
}
type OAuthRevokeHandler struct{ service OAuthRevocationService }

func NewOAuthRevokeHandler(s OAuthRevocationService) *OAuthRevokeHandler {
	return &OAuthRevokeHandler{service: s}
}
func (h *OAuthRevokeHandler) Revoke(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	fail := func(err error) {
		oe, ok := service.AsOAuthError(err)
		if !ok {
			oe = service.ErrServerError
		}
		c.JSON(oe.HTTPStatus, gin.H{"error": oe.Code, "error_description": oe.Description})
	}
	ct, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || ct != "application/x-www-form-urlencoded" {
		fail(service.ErrInvalidRequest)
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)
	if err = c.Request.ParseForm(); err != nil {
		fail(service.ErrInvalidRequest)
		return
	}
	form := c.Request.PostForm
	for _, v := range form {
		if len(v) != 1 {
			fail(service.ErrInvalidRequest)
			return
		}
	}
	if form.Get("token") == "" {
		fail(service.ErrInvalidRequest)
		return
	}
	// token_type_hint is only a hint; the repository searches both token types.
	if err = h.service.Revoke(c.Request.Context(), form.Get("token"), form.Get("client_id")); err != nil {
		fail(err)
		return
	}
	c.Status(http.StatusOK)
}
