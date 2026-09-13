package service

import (
	"context"
	"errors"
)

type OAuthClientRecord struct {
	ID                          int64
	ClientID                    string
	RedirectURIs, AllowedScopes []string
	Status                      string
	RequirePKCE                 bool
}
type OAuthClientReader interface {
	FindOAuthClient(context.Context, string) (*OAuthClientRecord, error)
}
type OAuthAuthorizeService struct{ Repo OAuthClientReader }

func NewOAuthAuthorizeService(r OAuthClientReader) *OAuthAuthorizeService {
	return &OAuthAuthorizeService{Repo: r}
}
func (s *OAuthAuthorizeService) ValidateClient(ctx context.Context, id, redirect string, scopes []string) (*OAuthClientRecord, error) {
	c, e := s.Repo.FindOAuthClient(ctx, id)
	if e != nil || c == nil || c.Status != "active" {
		return nil, ErrInvalidRequest
	}
	ok := false
	for _, u := range c.RedirectURIs {
		if u == redirect {
			ok = true
		}
	}
	if !ok {
		return nil, ErrInvalidRequest
	}
	for _, want := range scopes {
		found := false
		for _, allow := range c.AllowedScopes {
			if want == allow {
				found = true
			}
		}
		if !found {
			return nil, ErrInvalidScope
		}
	}
	if !c.RequirePKCE {
		return nil, errors.New("oauth client must require pkce")
	}
	return c, nil
}
