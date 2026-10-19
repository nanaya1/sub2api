package handler

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/gin-gonic/gin"
	"net/http"
)

// 2026-10-19：保留原调用默认 Secure，HTTP 模式由 handler 显式传入。
func oauthBrowserCookie(c *gin.Context, secure ...bool) string {
	if v, e := c.Cookie("oauth_browser"); e == nil && v != "" {
		return v
	}
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return ""
	}
	v := base64.RawURLEncoding.EncodeToString(b)
	// 2026-10-19：支持显式 HTTP Cookie 模式，原安全默认值保留。
	// http.SetCookie(c.Writer, &http.Cookie{Name: "oauth_browser", Value: v, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	cookieSecure := len(secure) == 0 || secure[0]
	http.SetCookie(c.Writer, &http.Cookie{Name: "oauth_browser", Value: v, Path: "/", HttpOnly: true, Secure: cookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	return v
}
