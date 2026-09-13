package handler

import (
	"context"
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// OAuthResumeService binds the authenticated web user to a pending_login
// transaction so the consent screen can later be served to the verified owner.
type OAuthResumeService interface {
	Resume(context.Context, service.OAuthResumeInput) error
}

// OAuthResumeHandler implements POST /oauth2/resume. It is protected by the
// existing JWT auth middleware, so the approver identity comes from the verified
// web session (never from the transaction row). The oauth_browser cookie proves
// the resume happens on the same browser that started the flow.
type OAuthResumeHandler struct {
	resumer OAuthResumeService
}

func NewOAuthResumeHandler(r OAuthResumeService) *OAuthResumeHandler {
	return &OAuthResumeHandler{resumer: r}
}

func (h *OAuthResumeHandler) Post(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	subject, authenticated := middleware.GetAuthSubjectFromContext(c)
	if !authenticated || subject.UserID <= 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "access_denied"})
		return
	}
	if err := c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	txID := c.PostForm("transaction_id")
	if txID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	browser, browserErr := c.Cookie("oauth_browser")
	if browserErr != nil || browser == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	err := h.resumer.Resume(c.Request.Context(), service.OAuthResumeInput{
		TransactionID:  txID,
		UserID:         subject.UserID,
		BrowserSession: browser,
	})
	if err != nil {
		oauth, ok := service.AsOAuthError(err)
		if !ok {
			oauth = service.ErrServerError
		}
		c.JSON(oauth.HTTPStatus, gin.H{"error": oauth.Code})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "resumed", "transaction_id": txID})
}
