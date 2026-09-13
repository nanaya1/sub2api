package service

import "time"

func ValidateOAuthAuthorizeRequest(responseType, clientID, redirectURI, expectedRedirect, scope, method, challenge string, expiry, now time.Time) error {
	if responseType != "code" || clientID == "" || redirectURI != expectedRedirect || method != "S256" || !expiry.After(now) {
		return ErrInvalidRequest
	}
	if err := ValidateScopes(splitOAuthScope(scope)); err != nil {
		return err
	}
	if len(challenge) != 43 {
		return ErrInvalidRequest
	}
	return nil
}
func splitOAuthScope(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ' ' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
