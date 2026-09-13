package handler

import (
	"errors"
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type OAuthResourceHandler struct{ resources *service.OAuthResourceService }

func NewOAuthResourceHandler(s *service.OAuthResourceService) *OAuthResourceHandler {
	return &OAuthResourceHandler{resources: s}
}

// requireScope aborts with 403 insufficient_scope when the access token lacks the
// requested scope. The bearer middleware has already authenticated the token.
func requireScope(c *gin.Context, tok *service.AccessTokenRecord, scope string) bool {
	if !service.HasScope(tok.Scopes, scope) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient_scope", "required_scope": scope})
		return false
	}
	return true
}

func (h *OAuthResourceHandler) Tokens(c *gin.Context) {
	tok, ok := middleware.GetOAuthAccessTokenFromContext(c)
	if !ok || tok == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	if !requireScope(c, tok, "tokens:read") {
		return
	}
	key, err := h.resources.GetOrCreateManagedKey(c.Request.Context(), tok.UserID, tok.ClientID, service.HasScope(tok.Scopes, "tokens:write"))
	if err != nil {
		if errors.Is(err, service.ErrOAuthManagedWriteRequired) {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient_scope", "required_scope": "tokens:write"})
			return
		}
		if errors.Is(err, service.ErrOAuthNoActiveSubscription) || errors.Is(err, service.ErrOAuthManagedKeyUnavailable) {
			c.JSON(http.StatusForbidden, gin.H{"error": "access_denied", "code": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"data": []string{key}})
}

func (h *OAuthResourceHandler) Balance(c *gin.Context) {
	tok, ok := middleware.GetOAuthAccessTokenFromContext(c)
	if !ok || tok == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	if !requireScope(c, tok, "balance:read") {
		return
	}
	u, err := h.resources.Users.GetProfile(c.Request.Context(), tok.UserID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user_not_found"})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"available_balance": u.Balance, "frozen_balance": u.FrozenBalance}})
}

func (h *OAuthResourceHandler) Self(c *gin.Context) {
	tok, ok := middleware.GetOAuthAccessTokenFromContext(c)
	if !ok || tok == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	if !requireScope(c, tok, "profile") {
		return
	}
	u, err := h.resources.Users.GetProfile(c.Request.Context(), tok.UserID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user_not_found"})
		return
	}
	c.Header("Cache-Control", "no-store")
	profile := gin.H{"id": u.ID, "username": u.Username, "status": u.Status}
	if service.HasScope(tok.Scopes, "email") {
		profile["email"] = u.Email
	}
	c.JSON(http.StatusOK, profile)
}
