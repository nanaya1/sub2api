package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type consentStub struct{}

func (consentStub) FindAuthorizationTransaction(context.Context, string) (*service.OAuthAuthorizationTransactionRecord, error) {
	return &service.OAuthAuthorizationTransactionRecord{Status: "pending_consent", UserID: 7}, nil
}
func TestOAuthConsentRejectsMissingTransaction(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/oauth2/consent", NewOAuthConsentHandler(consentStub{}, nil).Get)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/oauth2/consent", nil))
	require.Equal(t, 400, w.Code)
}

type boundConsentStub struct{}

func (boundConsentStub) FindAuthorizationTransaction(context.Context, string) (*service.OAuthAuthorizationTransactionRecord, error) {
	return &service.OAuthAuthorizationTransactionRecord{TransactionID: "tx", UserID: 7, Status: "pending_consent", ExpiresAt: time.Now().Add(time.Minute), BrowserSessionHash: service.HashOAuthSecret("browser"), CSRFTokenHash: service.HashOAuthSecret("csrf")}, nil
}
func TestOAuthConsentRequiresAuthenticatedOwner(t *testing.T) {
	for _, tc := range []struct {
		name string
		user int64
		want int
	}{{"anonymous", 0, 401}, {"different user", 8, 403}, {"owner", 7, 200}} {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			r := gin.New()
			r.Use(func(c *gin.Context) {
				if tc.user > 0 {
					c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: tc.user})
				}
			})
			r.GET("/consent", NewOAuthConsentHandler(boundConsentStub{}, nil).Get)
			req := httptest.NewRequest("GET", "/consent?transaction_id=tx", nil)
			req.AddCookie(&http.Cookie{Name: "oauth_browser", Value: "browser"})
			req.AddCookie(&http.Cookie{Name: "oauth_csrf", Value: "csrf"})
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			require.Equal(t, tc.want, w.Code)
			require.Empty(t, w.Result().Cookies(), "GET must not replace CSRF with a fixed value")
		})
	}
}

type decisionRecorder struct {
	got service.OAuthDecisionInput
	err error
}

func (d *decisionRecorder) Decide(_ context.Context, in service.OAuthDecisionInput) (*service.OAuthDecisionOutput, error) {
	d.got = in
	return &service.OAuthDecisionOutput{RedirectURI: "meacowork://oauth/callback", State: "state", Code: "plain-code"}, d.err
}

func TestOAuthConsentPostApprovesAndRedirects(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := &decisionRecorder{}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 7})
	})
	h := NewOAuthConsentHandler(boundConsentStub{}, rec)
	r.POST("/consent", h.Post)
	form := "transaction_id=tx&decision=approve&csrf=csrf"
	req := httptest.NewRequest("POST", "/consent", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "oauth_browser", Value: "browser"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, 200, w.Code)
	require.JSONEq(t, `{"redirect_to":"meacowork://oauth/callback?code=plain-code&state=state"}`, w.Body.String())
	require.Equal(t, int64(7), rec.got.UserID)
	require.Equal(t, "csrf", rec.got.CSRFToken)
	require.Equal(t, "approve", rec.got.Decision)
}

func TestOAuthConsentPostDeniesAndRedirects(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := &decisionRecorder{}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 7})
	})
	h := NewOAuthConsentHandler(boundConsentStub{}, rec)
	r.POST("/consent", h.Post)
	form := "transaction_id=tx&decision=deny&csrf=csrf"
	req := httptest.NewRequest("POST", "/consent", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "oauth_browser", Value: "browser"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, 200, w.Code)
	require.JSONEq(t, `{"redirect_to":"meacowork://oauth/callback?error=access_denied&state=state"}`, w.Body.String())
}

func TestOAuthConsentPostRejectsMissingCsrf(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := &decisionRecorder{}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 7})
	})
	h := NewOAuthConsentHandler(boundConsentStub{}, rec)
	r.POST("/consent", h.Post)
	form := "transaction_id=tx&decision=approve"
	req := httptest.NewRequest("POST", "/consent", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "oauth_browser", Value: "browser"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, 400, w.Code)
	require.Empty(t, rec.got.TransactionID, "decision must not be reached without a form CSRF")
}
