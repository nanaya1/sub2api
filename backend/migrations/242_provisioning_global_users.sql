-- 用户身份改为来源内全局唯一，企业维度仅保留在分组身份中
-- 发布前由维护人员清空旧同步映射；本迁移不归并历史账号
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM provisioning_user_bindings) THEN
        RAISE EXCEPTION 'clear provisioning_user_bindings before enabling global provisioning users';
    END IF;
END $$;

ALTER TABLE provisioning_user_bindings DROP CONSTRAINT provisioning_user_bindings_pkey;
ALTER TABLE provisioning_user_bindings DROP COLUMN tenant_key;
ALTER TABLE provisioning_user_bindings ALTER COLUMN local_user_id DROP NOT NULL;
ALTER TABLE provisioning_user_bindings ADD COLUMN groups_version BIGINT NOT NULL DEFAULT 0;
ALTER TABLE provisioning_user_bindings ADD PRIMARY KEY (source, external_user_id);
ALTER TABLE provisioning_user_bindings ADD UNIQUE (source, local_user_id);

COMMENT ON COLUMN provisioning_user_bindings.groups_version IS '最近确认的用户完整分组授权版本';
COMMENT ON COLUMN provisioning_user_bindings.local_user_id IS '本地用户ID，首次创建前收到删除事件时为NULL';

-- 公开组限制变化也必须通过持久化 Outbox 失效已有 Key 的鉴权缓存
CREATE OR REPLACE FUNCTION enqueue_user_auth_cache_invalidation()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.status IS NOT DISTINCT FROM NEW.status
       AND OLD.role IS NOT DISTINCT FROM NEW.role
       AND OLD.deleted_at IS NOT DISTINCT FROM NEW.deleted_at
       AND OLD.restrict_public_groups IS NOT DISTINCT FROM NEW.restrict_public_groups THEN
        RETURN NEW;
    END IF;
    INSERT INTO auth_cache_invalidation_outbox (cache_key)
    SELECT encode(sha256(convert_to(k.key, 'UTF8')), 'hex')
    FROM api_keys k WHERE k.user_id = OLD.id AND k.deleted_at IS NULL AND k.key <> '';
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$;

-- 完整授权替换还会清理人工添加的公开组，受限用户的此类撤权同样需要失效缓存
CREATE OR REPLACE FUNCTION enqueue_allowed_group_auth_cache_invalidation()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        INSERT INTO auth_cache_invalidation_outbox (cache_key)
        SELECT encode(sha256(convert_to(k.key, 'UTF8')), 'hex')
        FROM api_keys k JOIN users u ON u.id = k.user_id JOIN groups g ON g.id = k.group_id
        WHERE k.user_id = OLD.user_id AND k.group_id = OLD.group_id
          AND k.deleted_at IS NULL AND k.key <> '' AND (g.is_exclusive OR u.restrict_public_groups);
    END IF;
    IF TG_OP <> 'DELETE' THEN
        INSERT INTO auth_cache_invalidation_outbox (cache_key)
        SELECT encode(sha256(convert_to(k.key, 'UTF8')), 'hex')
        FROM api_keys k JOIN users u ON u.id = k.user_id JOIN groups g ON g.id = k.group_id
        WHERE k.user_id = NEW.user_id AND k.group_id = NEW.group_id
          AND k.deleted_at IS NULL AND k.key <> '' AND (g.is_exclusive OR u.restrict_public_groups);
        RETURN NEW;
    END IF;
    RETURN OLD;
END;
$$;
