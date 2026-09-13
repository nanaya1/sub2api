package routes

import (
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/handler"
	servermiddleware "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
)

func RegisterOAuthServerRoutes(r *gin.Engine, h *handler.Handlers, cfg config.OAuthServerConfig, jwtAuth servermiddleware.JWTAuthMiddleware) {
	if !cfg.Enabled || h == nil || h.OAuthAuthorize == nil || h.OAuthToken == nil || h.OAuthRevoke == nil || h.OAuthConsent == nil || h.OAuthResume == nil || h.OAuthResource == nil {
		return
	}
	// Cherry Studio gateway clients use /oauth2/auth; retain the existing alias.
	// The authorization endpoint is public: it creates a transaction and 302s to
	// the first-party consent page, which then enforces authentication.
	r.GET("/oauth2/auth", h.OAuthAuthorize.Authorize)
	r.GET("/oauth2/authorize", h.OAuthAuthorize.Authorize)
	// Consent retrieval, decision, and resume are first-party, authenticated
	// endpoints: they must carry the JWT web session. The CSRF token is delivered
	// to the browser via the consent GET JSON body and echoed back explicitly on
	// the decision POST; the oauth_browser cookie binds the flow to one browser.
	r.GET("/oauth2/consent", gin.HandlerFunc(jwtAuth), h.OAuthConsent.Get)
	r.POST("/oauth2/consent", gin.HandlerFunc(jwtAuth), h.OAuthConsent.Post)
	r.POST("/oauth2/resume", gin.HandlerFunc(jwtAuth), h.OAuthResume.Post)
	r.POST("/oauth2/token", h.OAuthToken.Token)
	r.POST("/oauth2/revoke", h.OAuthRevoke.Revoke)
	authenticator, ok := h.OAuthToken.Service().(servermiddleware.OAuthBearerAuthenticator)
	if !ok {
		return
	}
	bearer := servermiddleware.NewOAuthBearerMiddleware(authenticator)
	r.GET("/api/v1/oauth/tokens", bearer, h.OAuthResource.Tokens)
	r.GET("/api/v1/oauth/balance", bearer, h.OAuthResource.Balance)
	r.GET("/api/user/self", bearer, h.OAuthResource.Self)
}
