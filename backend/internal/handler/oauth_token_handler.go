package handler

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"mime"
	"net/http"
)

type OAuthTokenService interface {
	ExchangeCode(context.Context, string, string, string, string) (*service.OAuthTokenResponse, error)
	Refresh(context.Context, string, string) (*service.OAuthTokenResponse, error)
}
type OAuthTokenHandler struct{ service OAuthTokenService }

func NewOAuthTokenHandler(s OAuthTokenService) *OAuthTokenHandler {
	return &OAuthTokenHandler{service: s}
}

func (h *OAuthTokenHandler) Service() OAuthTokenService { return h.service }

// Token is not registered by default. Production registration must apply the
// OAuth feature flag and rate limiting, independently from Gateway auth.
func (h *OAuthTokenHandler) Token(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	fail := func(err error) {
		oauth, ok := service.AsOAuthError(err)
		if !ok {
			oauth = service.ErrServerError
		}
		c.JSON(oauth.HTTPStatus, gin.H{"error": oauth.Code, "error_description": oauth.Description})
	}
	contentType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || contentType != "application/x-www-form-urlencoded" {
		fail(service.ErrInvalidRequest)
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)
	if err = c.Request.ParseForm(); err != nil {
		fail(service.ErrInvalidRequest)
		return
	}
	form := c.Request.PostForm // Never accept credentials in URL query parameters.
	for _, values := range form {
		if len(values) != 1 {
			fail(service.ErrInvalidRequest)
			return
		}
	}
	var token *service.OAuthTokenResponse
	switch form.Get("grant_type") {
	case "authorization_code":
		for _, key := range []string{"client_id", "code", "redirect_uri", "code_verifier"} {
			if form.Get(key) == "" {
				fail(service.ErrInvalidRequest)
				return
			}
		}
		token, err = h.service.ExchangeCode(c.Request.Context(), form.Get("client_id"), form.Get("code"), form.Get("redirect_uri"), form.Get("code_verifier"))
	case "refresh_token":
		if form.Get("client_id") == "" || form.Get("refresh_token") == "" {
			fail(service.ErrInvalidRequest)
			return
		}
		// Scope narrowing is not implemented; never silently ignore a requested scope.
		if _, ok := form["scope"]; ok {
			fail(service.ErrInvalidScope)
			return
		}
		token, err = h.service.Refresh(c.Request.Context(), form.Get("client_id"), form.Get("refresh_token"))
	default:
		fail(service.ErrUnsupportedGrantType)
		return
	}
	if err != nil {
		fail(err)
		return
	}
	if token == nil {
		fail(service.ErrServerError)
		return
	}
	c.JSON(http.StatusOK, token)
}
