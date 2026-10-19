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
	// 2026-10-19：使用反向标志使旧构造方式仍默认 Secure。
	allowInsecureCookies bool
	clients      OAuthAuthorizeClientService
	transactions OAuthAuthorizeTransactionService
}

func NewOAuthAuthorizeHandlerWithTransactions(c OAuthAuthorizeClientService, t OAuthAuthorizeTransactionService) *OAuthAuthorizeHandler {
	return &OAuthAuthorizeHandler{clients: c, transactions: t}
}

func NewOAuthAuthorizeHandler(c OAuthAuthorizeClientService) *OAuthAuthorizeHandler {
	return &OAuthAuthorizeHandler{clients: c}
}
// 2026-10-19：由路由注册注入部署配置，避免根据不可信代理头自动降级。
func (h *OAuthAuthorizeHandler) SetCookieSecure(secure bool) {
	h.allowInsecureCookies = !secure
}

func (h *OAuthAuthorizeHandler) Authorize(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if c.Query("response_type") != "code" || c.Query("client_id") == "" || c.Query("redirect_uri") == "" || c.Query("state") == "" || c.Query("code_challenge") == "" || c.Query("code_challenge_method") != "S256" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	scopes := []string{}
	if s := c.Query("scope"); s != "" {
		// 2026-09-14：openid 容忍但忽略——OpenAI 式客户端会写死携带 openid，
		// 本服务不实现 OIDC、不签发 id_token，因此在白名单校验和事务入库前
		// 剔除，保证 ValidateClient 子集校验、consent 展示与 oauth_consents
		// 的 granted scopes 全链路一致（不含 openid）。
		scopes = service.StripIgnoredScopes(strings.Fields(s))
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
	// 2026-10-19：浏览器绑定 Cookie 与 CSRF Cookie 共用显式安全配置。
	// input := service.OAuthTransactionInput{ClientID: client.ID, RedirectURI: c.Query("redirect_uri"), Scopes: scopes, State: c.Query("state"), Challenge: c.Query("code_challenge"), ChallengeMethod: c.Query("code_challenge_method"), BrowserSession: oauthBrowserCookie(c)}
	input := service.OAuthTransactionInput{ClientID: client.ID, RedirectURI: c.Query("redirect_uri"), Scopes: scopes, State: c.Query("state"), Challenge: c.Query("code_challenge"), ChallengeMethod: c.Query("code_challenge_method"), BrowserSession: oauthBrowserCookie(c, !h.allowInsecureCookies)}
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
	// 2026-10-19：与 oauth_browser 同步，默认 Secure，HTTP 部署需显式关闭。
	// c.SetCookie("oauth_csrf", res.CSRFToken, int(input.TTL.Seconds()), "/", "", true, true)
	c.SetCookie("oauth_csrf", res.CSRFToken, int(input.TTL.Seconds()), "/", "", !h.allowInsecureCookies, true)
	// Hand the browser off to the first-party consent page, carrying only the
	// opaque transaction id. The OAuth state and the CSRF token are deliberately
	// NOT placed in the URL: state stays server-side and CSRF travels via the
	// HttpOnly cookie + consent GET JSON. If the user is not yet authenticated
	// the consent page uses the existing /login?redirect=... return mechanism.
	c.Redirect(http.StatusFound, "/oauth/consent?transaction_id="+url.QueryEscape(res.TransactionID))
}
