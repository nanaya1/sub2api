package service

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"
)

func TestOAuthCoreSecurity(t *testing.T) {
	raw, e := GenerateOAuthSecret()
	if e != nil || len(raw) < 40 {
		t.Fatal(e)
	}
	if HashOAuthSecret(raw) == raw {
		t.Fatal("raw token persisted")
	}
	verifier := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	ch := base64.RawURLEncoding.EncodeToString(func() []byte { h := sha256.Sum256([]byte(verifier)); return h[:] }())
	if VerifyPKCE("v", HashOAuthSecret("v")) {
		t.Fatal("short PKCE verifier accepted")
	}
	if VerifyPKCE(verifier+"!", HashOAuthSecret(verifier+"!")) {
		t.Fatal("invalid PKCE alphabet accepted")
	}
	if !VerifyPKCE(verifier, ch) {
		t.Fatal("pkce")
	}
	if ValidateOAuthCodeInput("a", "b", "v", ch, "S256", time.Now().Add(time.Minute), time.Now()) == nil {
		t.Fatal("redirect")
	}
}
func TestOAuthScopes(t *testing.T) {
	if ValidateOAuthScopes([]string{"tokens:write"}, []string{"tokens:read"}) == nil {
		t.Fatal("expanded scope")
	}
	if ValidateOAuthScopes([]string{"tokens:read"}, []string{"tokens:read"}) != nil {
		t.Fatal("valid scope")
	}
}
