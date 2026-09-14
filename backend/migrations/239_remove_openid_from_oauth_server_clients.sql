-- 2026-09-14：雪浪 OAuth Authorization Server 暂不签发 OIDC id_token。
-- 从已注册客户端中移除 openid，避免 scope 契约与实际 token 响应不一致。
-- oauth_consents / transactions / refresh tokens 保留历史记录；旧 refresh token
-- 若包含 openid 将在 ValidateScopes 阶段失效，客户端需重新授权。
UPDATE oauth_clients
SET allowed_scopes = allowed_scopes - 'openid',
    updated_at = NOW()
WHERE allowed_scopes ? 'openid';
