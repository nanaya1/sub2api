package service

import (
	"errors"
	"net/url"
)

func OAuthCallbackURL(raw, code, state string) (string, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme == "" || u.Host == "" {
		return "", errors.New("invalid redirect")
	}
	q := u.Query()
	if code != "" {
		q.Set("code", code)
	} else {
		q.Set("error", "access_denied")
	}
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
