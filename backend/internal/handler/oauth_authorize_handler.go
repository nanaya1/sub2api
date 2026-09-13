package handler

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type OAuthAuthorizeClientService interface {
	ValidateClient(context.Context, string, string, []string) (*service.OAuthClientRecord, error)
}
type OAuthAuthorizeTransactionService interface {
	Create(context.Context, service.OAuthTransactionInput) (*service.OAuthTransactionResult, error)
}
type OAuthAuthorizeHandler struct {
	clients      OAuthAuthorizeClientService
	transactions OAuthAuthorizeTransactionService
}

func NewOAuthAuthorizeHandlerWithTransactions(c OAuthAuthorizeClientService, t OAuthAuthorizeTransactionService) *OAuthAuthorizeHandler {
	return &OAuthAuthorizeHandler{clients: c, transactions: t}
}

func NewOAuthAuthorizeHandler(c OAuthAuthorizeClientService) *OAuthAuthorizeHandler {
	return &OAuthAuthorizeHandler{clients: c}
}
func (h *OAuthAuthorizeHandler) Authorize(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if c.Query("response_type") != "code" || c.Query("client_id") == "" || c.Query("redirect_uri") == "" || c.Query("state") == "" || c.Query("code_challenge") == "" || c.Query("code_challenge_method") != "S256" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	scopes := []string{}
	if s := c.Query("scope"); s != "" {
		scopes = strings.Fields(s)
	}
	client, e := h.clients.ValidateClient(c.Request.Context(), c.Query("client_id"), c.Query("redirect_uri"), scopes)
	if e != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	if h.transactions == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "authorization_pending"})
		return
	}
	input := service.OAuthTransactionInput{ClientID: client.ID, RedirectURI: c.Query("redirect_uri"), Scopes: scopes, State: c.Query("state"), Challenge: c.Query("code_challenge"), ChallengeMethod: c.Query("code_challenge_method"), BrowserSession: oauthBrowserCookie(c)}
	if input.ChallengeMethod == "" {
		input.ChallengeMethod = "S256"
	}
	if input.BrowserSession == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	res, err := h.transactions.Create(c.Request.Context(), input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	// Return the plaintext CSRF to the browser via a cookie so the consent page
	// can echo it back as the anti-CSRF form field. The cookie alone is NOT a
	// valid CSRF credential: the consent POST must present the value in the form
	// body, which the server verifies against the stored hash.
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("oauth_csrf", res.CSRFToken, int(input.TTL.Seconds()), "/", "", true, true)
	// Hand the browser off to the first-party consent page, carrying only the
	// opaque transaction id. The OAuth state and the CSRF token are deliberately
	// NOT placed in the URL: state stays server-side and CSRF travels via the
	// HttpOnly cookie + consent GET JSON. If the user is not yet authenticated
	// the consent page uses the existing /login?redirect=... return mechanism.
	c.Redirect(http.StatusFound, "/oauth/consent?transaction_id="+url.QueryEscape(res.TransactionID))
}
