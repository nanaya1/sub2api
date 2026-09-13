package handler

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/gin-gonic/gin"
	"net/http"
)

func oauthBrowserCookie(c *gin.Context) string {
	if v, e := c.Cookie("oauth_browser"); e == nil && v != "" {
		return v
	}
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return ""
	}
	v := base64.RawURLEncoding.EncodeToString(b)
	http.SetCookie(c.Writer, &http.Cookie{Name: "oauth_browser", Value: v, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	return v
}
