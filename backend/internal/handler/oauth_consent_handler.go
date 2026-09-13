package handler

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type OAuthConsentLoader interface {
	FindAuthorizationTransaction(context.Context, string) (*service.OAuthAuthorizationTransactionRecord, error)
}
type OAuthConsentDecider interface {
	Decide(context.Context, service.OAuthDecisionInput) (*service.OAuthDecisionOutput, error)
}

// OAuthConsentHandler serves the consent screen (GET) and records the user's
// decision (POST). The decision is closed by the repository inside a single SQL
// transaction; the handler never treats the transaction's bound user_id as the
// approver's identity, and the CSRF token must be submitted in the form body
// rather than relying on an auto-carried cookie.
type OAuthConsentHandler struct {
	loader  OAuthConsentLoader
	decider OAuthConsentDecider
}

func NewOAuthConsentHandler(l OAuthConsentLoader, d OAuthConsentDecider) *OAuthConsentHandler {
	return &OAuthConsentHandler{loader: l, decider: d}
}

func (h *OAuthConsentHandler) Get(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	id := c.Query("transaction_id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	subject, authenticated := middleware.GetAuthSubjectFromContext(c)
	if !authenticated || subject.UserID <= 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "access_denied"})
		return
	}
	x, e := h.loader.FindAuthorizationTransaction(c.Request.Context(), id)
	if e != nil || x == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	if x.Status != "pending_consent" || x.UserID != subject.UserID || !x.ExpiresAt.After(time.Now()) {
		c.JSON(http.StatusForbidden, gin.H{"error": "access_denied"})
		return
	}
	browser, browserErr := c.Cookie("oauth_browser")
	if browserErr != nil || service.HashOAuthSecret(browser) != x.BrowserSessionHash {
		c.JSON(http.StatusForbidden, gin.H{"error": "access_denied"})
		return
	}
	csrf, csrfErr := c.Cookie("oauth_csrf")
	if csrfErr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "access_denied"})
		return
	}
	// The CSRF plaintext is returned in the response body so the consent form can
	// echo it back as the anti-CSRF form field. No CSRF cookie is (re)issued here.
	c.JSON(http.StatusOK, gin.H{
		"client_id":      x.ClientID,
		"scopes":         x.Scopes,
		"transaction_id": x.TransactionID,
		"csrf":           csrf,
		"user_id":        subject.UserID,
	})
}

func (h *OAuthConsentHandler) Post(c *gin.Context) {
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
	decision := c.PostForm("decision")
	// CSRF must be submitted in the form body. It is never derived from an
	// auto-carried cookie, which alone would be an insufficient CSRF defense.
	csrf := c.PostForm("csrf")
	if txID == "" || decision == "" || csrf == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	browser, _ := c.Cookie("oauth_browser")
	out, err := h.decider.Decide(c.Request.Context(), service.OAuthDecisionInput{
		TransactionID:  txID,
		UserID:         subject.UserID,
		Decision:       decision,
		BrowserSession: browser,
		CSRFToken:      csrf,
	})
	if err != nil {
		oauth, ok := service.AsOAuthError(err)
		if !ok {
			oauth = service.ErrServerError
		}
		c.JSON(oauth.HTTPStatus, gin.H{"error": oauth.Code})
		return
	}
	// The consent decision is submitted via the first-party JWT API (axios), so
	// the browser will not auto-follow a 302. Return the final redirect target as
	// JSON and let the SPA navigate the top-level document to the OAuth client's
	// redirect URI (which may be a custom-scheme deep link such as meacowork://).
	var target string
	if decision == "deny" {
		target = out.RedirectURI + "?error=access_denied&state=" + url.QueryEscape(out.State)
	} else {
		target = out.RedirectURI + "?code=" + url.QueryEscape(out.Code) + "&state=" + url.QueryEscape(out.State)
	}
	c.JSON(http.StatusOK, gin.H{"redirect_to": target})
}
