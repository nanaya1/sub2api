-- 主服务用户/分组投影映射。
-- 这些表只保存外部身份与当前平台本地 ID，不改变 users/groups 的业务语义。
CREATE TABLE IF NOT EXISTS provisioning_user_bindings (
    source             VARCHAR(100) NOT NULL,
    tenant_key         VARCHAR(200) NOT NULL,
    external_user_id   VARCHAR(200) NOT NULL,
    local_user_id      BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    version            BIGINT NOT NULL DEFAULT 0,
    status             VARCHAR(20) NOT NULL DEFAULT 'active',
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (source, tenant_key, external_user_id),
    UNIQUE (source, tenant_key, local_user_id)
);

CREATE INDEX IF NOT EXISTS idx_provisioning_user_bindings_local_user
    ON provisioning_user_bindings (local_user_id);

CREATE TABLE IF NOT EXISTS provisioning_group_bindings (
    source             VARCHAR(100) NOT NULL,
    tenant_key         VARCHAR(200) NOT NULL,
    external_group_id  VARCHAR(200) NOT NULL,
    local_group_id     BIGINT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    version            BIGINT NOT NULL DEFAULT 0,
    members_version    BIGINT NOT NULL DEFAULT 0,
    status             VARCHAR(20) NOT NULL DEFAULT 'active',
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (source, tenant_key, external_group_id),
    UNIQUE (source, tenant_key, local_group_id)
);

CREATE INDEX IF NOT EXISTS idx_provisioning_group_bindings_local_group
    ON provisioning_group_bindings (local_group_id);
