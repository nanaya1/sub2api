-- ============================================================================
-- 雪浪 OAuth Authorization Server — 客户端种子数据（新环境初始化用）
--
-- 背景：
--   * oauth_* 七张表由 migration 238 自动创建（迁移嵌入二进制，启动即应用），
--     但 oauth_clients 是空表，没有任何 migration 会播种客户端行。
--   * config.yaml 的 oauth_server.client_id 仅用于启动非空校验；
--     实际授权请求的客户端校验查本表（client_id / redirect_uris /
--     allowed_scopes / status='active' / require_pkce）。
--   * 因此新环境部署后必须手工执行本脚本一次，否则授权请求一律 403/invalid_client。
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
    '["openid", "profile", "email", "offline_access", "balance:read", "usage:read", "tokens:read", "tokens:write"]'::jsonb,
    TRUE,
    'active'
)
ON CONFLICT (client_id) DO NOTHING;

-- 执行后自检：应返回 1 行
SELECT client_id, name, status, require_pkce, redirect_uris, allowed_scopes
FROM oauth_clients
WHERE client_id = :'client_id';
