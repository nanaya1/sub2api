-- 雪浪 OAuth Authorization Server — 批次 1 数据模型（七张表，单次前向迁移）。
--
-- 设计要点：
--   * client_id 是 oauth_clients 对外暴露的稳定字符串标识；所有子表通过内部 bigint
--     主键（client_id 列）引用 oauth_clients.id，外部字符串与内部 FK 严格区分。
--   * authorization_code / access_token / refresh_token 仅持久化 HMAC hash，绝不存储明文；
--     hash_key_version 记录所用 HMAC 密钥版本，便于后续轮换。
--   * authorization_transaction 必须原样保存 OAuth state（仅用于回传给客户端，禁止写入日志），
--     并以独立的 browser_session_hash 绑定浏览器会话。
--   * 首期仅支持 public client（强制 PKCE S256），client_type 约束为 'public'，不虚称支持
--     confidential。
--   * managed_api_keys 本批次仅保存 (user, client, api_key) 绑定与生命周期时间戳，
--     不引入第二份 API Key 密文（加密可恢复材料留待后续批次）。
--
-- 该迁移在事务内整体执行（迁移运行器默认行为），FK 删除策略显式声明，时间字段统一 timestamptz。

CREATE TABLE IF NOT EXISTS oauth_clients (
    id          BIGSERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    client_id   VARCHAR(128) NOT NULL UNIQUE,
    name        VARCHAR(128) NOT NULL,
    client_type VARCHAR(16)  NOT NULL DEFAULT 'public',
    redirect_uris        JSONB NOT NULL,
    allowed_grant_types  JSONB NOT NULL,
    allowed_scopes       JSONB NOT NULL,
    require_pkce BOOLEAN NOT NULL DEFAULT TRUE,
    status       VARCHAR(16)  NOT NULL DEFAULT 'active',
    CONSTRAINT oauth_clients_client_type_check
        CHECK (client_type = 'public'),
    CONSTRAINT oauth_clients_redirect_uris_check
        CHECK (jsonb_array_length(redirect_uris) > 0),
    CONSTRAINT oauth_clients_allowed_grant_types_check
        CHECK (jsonb_array_length(allowed_grant_types) > 0),
    CONSTRAINT oauth_clients_allowed_scopes_check
        CHECK (jsonb_array_length(allowed_scopes) > 0)
);

CREATE INDEX IF NOT EXISTS idx_oauth_clients_status
    ON oauth_clients (status);

CREATE TABLE IF NOT EXISTS oauth_authorization_transactions (
    id                   BIGSERIAL PRIMARY KEY,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    transaction_id       VARCHAR(128) NOT NULL UNIQUE,
    redirect_uri         TEXT NOT NULL,
    requested_scopes     JSONB NOT NULL,
    -- 原始 OAuth state：必须原样回传客户端，禁止写入日志。
    state                TEXT NOT NULL,
    code_challenge       TEXT NOT NULL,
    code_challenge_method VARCHAR(16) NOT NULL,
    -- 绑定浏览器会话的摘要，独立于 OAuth state。
    browser_session_hash TEXT NOT NULL,
    csrf_token_hash      TEXT NOT NULL,
    user_id              BIGINT REFERENCES users(id) ON DELETE CASCADE,
    status               VARCHAR(16) NOT NULL DEFAULT 'pending_login',
    expires_at           TIMESTAMPTZ NOT NULL,
    consumed_at         TIMESTAMPTZ,
    -- 内部 FK，引用 oauth_clients.id，而非外部 client_id 字符串。
    client_id            BIGINT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    CONSTRAINT oauth_authorization_transactions_code_challenge_method_check
        CHECK (code_challenge_method = 'S256')
);

CREATE INDEX IF NOT EXISTS idx_oauth_authorization_transactions_status_expires_at
    ON oauth_authorization_transactions (status, expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth_authorization_transactions_client_id_created_at
    ON oauth_authorization_transactions (client_id, created_at);
CREATE INDEX IF NOT EXISTS idx_oauth_authorization_transactions_user_id_client_id
    ON oauth_authorization_transactions (user_id, client_id);

CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    id                   BIGSERIAL PRIMARY KEY,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- 仅存储 HMAC hash，绝不保存明文 code。
    code_hash            VARCHAR(255) NOT NULL UNIQUE,
    redirect_uri         TEXT NOT NULL,
    scopes               JSONB NOT NULL,
    code_challenge       TEXT NOT NULL,
    code_challenge_method VARCHAR(16) NOT NULL,
    -- HMAC 密钥版本，便于轮换而不失效在途 code。
    hash_key_version     INTEGER NOT NULL DEFAULT 1,
    expires_at           TIMESTAMPTZ NOT NULL,
    consumed_at         TIMESTAMPTZ,
    user_id              BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id            BIGINT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    CONSTRAINT oauth_authorization_codes_code_challenge_method_check
        CHECK (code_challenge_method = 'S256')
);

CREATE INDEX IF NOT EXISTS idx_oauth_authorization_codes_user_id_client_id
    ON oauth_authorization_codes (user_id, client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_authorization_codes_expires_at
    ON oauth_authorization_codes (expires_at);

CREATE TABLE IF NOT EXISTS oauth_consents (
    id          BIGSERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id   BIGINT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    scopes      JSONB NOT NULL,
    revoked_at  TIMESTAMPTZ,
    CONSTRAINT oauth_consents_user_id_client_id_unique UNIQUE (user_id, client_id)
);

CREATE TABLE IF NOT EXISTS oauth_access_tokens (
    id          BIGSERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- 仅存储 HMAC hash，绝不保存明文 token。
    token_hash  VARCHAR(255) NOT NULL UNIQUE,
    -- HMAC 密钥版本，便于轮换而不失效在途 token。
    hash_key_version INTEGER NOT NULL DEFAULT 1,
    family_id   UUID NOT NULL,
    scopes      JSONB NOT NULL,
    issued_at   TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id   BIGINT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_user_id_client_id
    ON oauth_access_tokens (user_id, client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_family_id
    ON oauth_access_tokens (family_id);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_expires_at
    ON oauth_access_tokens (expires_at);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    id                    BIGSERIAL PRIMARY KEY,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- 仅存储 HMAC hash，绝不保存明文 token。
    token_hash            VARCHAR(255) NOT NULL UNIQUE,
    -- HMAC 密钥版本，便于轮换而不失效在途 token。
    hash_key_version      INTEGER NOT NULL DEFAULT 1,
    family_id             UUID NOT NULL,
    -- 轮换谱系：父 token 与替换者均为自引用 FK（删除时置空）。
    parent_token_id       BIGINT REFERENCES oauth_refresh_tokens(id) ON DELETE SET NULL,
    replaced_by_token_id  BIGINT REFERENCES oauth_refresh_tokens(id) ON DELETE SET NULL,
    scopes                JSONB NOT NULL,
    issued_at             TIMESTAMPTZ NOT NULL,
    expires_at            TIMESTAMPTZ NOT NULL,
    idle_expires_at       TIMESTAMPTZ,
    last_used_at          TIMESTAMPTZ,
    revoked_at            TIMESTAMPTZ,
    user_id               BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id             BIGINT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_user_id_client_id
    ON oauth_refresh_tokens (user_id, client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_family_id
    ON oauth_refresh_tokens (family_id);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_expires_at
    ON oauth_refresh_tokens (expires_at);

CREATE TABLE IF NOT EXISTS oauth_managed_api_keys (
    id          BIGSERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id   BIGINT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    api_key_id  BIGINT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    revoked_at  TIMESTAMPTZ,
    CONSTRAINT oauth_managed_api_keys_user_id_client_id_unique UNIQUE (user_id, client_id),
    CONSTRAINT oauth_managed_api_keys_api_key_id_unique UNIQUE (api_key_id)
);
