package service

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuthErrorCodes(t *testing.T) {
	cases := []struct {
		err  *OAuthError
		code string
		http int
	}{
		{ErrInvalidRequest, "invalid_request", 400},
		{ErrInvalidClient, "invalid_client", 401},
		{ErrInvalidGrant, "invalid_grant", 400},
		{ErrUnauthorizedClient, "unauthorized_client", 400},
		{ErrUnsupportedGrantType, "unsupported_grant_type", 400},
		{ErrInvalidScope, "invalid_scope", 400},
		{ErrAccessDenied, "access_denied", 400},
		{ErrServerError, "server_error", 500},
	}
	for _, c := range cases {
		require.NotNil(t, c.err, "error sentinel %s must be defined", c.code)
		assert.Equal(t, c.code, c.err.Code)
		assert.NotEmpty(t, c.err.Description)
		assert.Equal(t, c.http, c.err.HTTPStatus)
	}
}

func TestAsOAuthError(t *testing.T) {
	oe, ok := AsOAuthError(ErrInvalidScope)
	require.True(t, ok)
	assert.Equal(t, "invalid_scope", oe.Code)

	_, ok = AsOAuthError(errors.New("boom"))
	assert.False(t, ok)
}

func TestOAuthErrorImplementsError(t *testing.T) {
	var err error = ErrInvalidScope
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_scope")
}
