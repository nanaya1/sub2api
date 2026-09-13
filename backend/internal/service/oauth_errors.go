package service

import (
	"errors"
)

// OAuthError 是 OAuth 2.0 / RFC 6749 标准错误码的封装。
// Service 层只返回稳定的领域错误，由后续 Handler 负责映射到 HTTP 响应。
// 本批不实现 OIDC，因此不涉及 id_token 相关错误。
type OAuthError struct {
	// Code 是 RFC 6749 定义的 error 字段值。
	Code string
	// Description 是人类可读的错误描述。
	Description string
	// HTTPStatus 是对应的推荐 HTTP 状态码。
	HTTPStatus int
}

// Error 实现 error 接口。
func (e *OAuthError) Error() string {
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

// 预定义领域错误哨兵。Handler 应使用 AsOAuthError 提取 Code 与 HTTPStatus。
var (
	ErrInvalidRequest       = &OAuthError{Code: "invalid_request", Description: "The request is missing a required parameter or is otherwise malformed", HTTPStatus: 400}
	ErrInvalidClient        = &OAuthError{Code: "invalid_client", Description: "Client authentication failed", HTTPStatus: 401}
	ErrInvalidGrant         = &OAuthError{Code: "invalid_grant", Description: "The provided authorization grant or refresh token is invalid, expired, revoked, or mismatched", HTTPStatus: 400}
	ErrUnauthorizedClient   = &OAuthError{Code: "unauthorized_client", Description: "The client is not authorized to use this grant type", HTTPStatus: 400}
	ErrUnsupportedGrantType = &OAuthError{Code: "unsupported_grant_type", Description: "The grant type is not supported", HTTPStatus: 400}
	ErrInvalidScope         = &OAuthError{Code: "invalid_scope", Description: "The requested scope is invalid, unknown, or malformed", HTTPStatus: 400}
	ErrAccessDenied         = &OAuthError{Code: "access_denied", Description: "The resource owner or authorization server denied the request", HTTPStatus: 400}
	ErrServerError          = &OAuthError{Code: "server_error", Description: "The authorization server encountered an unexpected condition", HTTPStatus: 500}
)

// AsOAuthError 从 err 链中提取 *OAuthError。
func AsOAuthError(err error) (*OAuthError, bool) {
	var oe *OAuthError
	if errors.As(err, &oe) {
		return oe, true
	}
	return nil, false
}
