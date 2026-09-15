-- ============================================================================
-- 雪浪 OAuth Authorization Server — 客户端种子数据（运维兜底用）
--
-- 背景：
--   * oauth_* 七张表由 migration 238 自动创建（迁移嵌入二进制，启动即应用）。
--   * OAuth Server 启用后，主服务会在迁移完成且开放 HTTP 路由前，根据可信配置
--     自动幂等创建或同步官方客户端；已有 disabled 状态不会被启动过程恢复。
--   * 本脚本仅用于灾难恢复、旧镜像或自动初始化排障，不再是新环境部署的必做步骤。
--   * 实际授权请求的客户端校验仍查本表（client_id / redirect_uris /
--     allowed_scopes / status='active' / require_pkce）。
--
-- 用法（任选其一）：
--   psql:  psql "postgresql://sub2api:sub2api@127.0.0.1:5432/sub2api" \
--            -v client_id='2a348c87-bae1-4756-a62f-b2e97200fd6d' \
--            -f seed-oauth-client.sql
--   或手工替换 :client_id 后在管理数据库客户端里执行。
--
-- 注意：
--   * client_id 必须与 cherry-studio (Electron) 端发起授权请求时携带的
--     client_id 完全一致（当前定稿值：2a348c87-bae1-4756-a62f-b2e97200fd6d）。
--   * redirect_uri 当前仅支持 meacowork://oauth/callback（服务端配置强制校验）。
--   * 幂等：重复执行会跳过已存在的 client_id。
-- ============================================================================

INSERT INTO oauth_clients (
    client_id, name, client_type,
    redirect_uris, allowed_grant_types, allowed_scopes,
    require_pkce, status
) VALUES (
    :'client_id',
    'MeacoWork',
    'public',
    '["meacowork://oauth/callback"]'::jsonb,
    '["authorization_code", "refresh_token"]'::jsonb,
    -- 2026-09-14：服务端暂不签发 id_token，原 allowed_scopes 中的 "openid" 移除。
    -- '["openid", "profile", "email", "offline_access", "balance:read", "usage:read", "tokens:read", "tokens:write"]'::jsonb,
    '["profile", "email", "offline_access", "balance:read", "usage:read", "tokens:read", "tokens:write"]'::jsonb,
    TRUE,
    'active'
)
ON CONFLICT (client_id) DO NOTHING;

-- 执行后自检：应返回 1 行
SELECT client_id, name, status, require_pkce, redirect_uris, allowed_scopes
FROM oauth_clients
WHERE client_id = :'client_id';
