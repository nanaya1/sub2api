-- 模型门户写入防重记录，不复用有过期抢占语义的通用幂等记录
CREATE TABLE cowork_portal_operations (
    source VARCHAR(100) NOT NULL,
    external_user_id VARCHAR(200) NOT NULL,
    operation VARCHAR(32) NOT NULL,
    request_id VARCHAR(32) NOT NULL,
    fingerprint VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    resource_id BIGINT,
    payment_result JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (source, external_user_id, operation, request_id)
);
COMMENT ON TABLE cowork_portal_operations IS '模型门户写入防重与结果确认记录';
COMMENT ON COLUMN cowork_portal_operations.source IS '稳定来源';
COMMENT ON COLUMN cowork_portal_operations.external_user_id IS '主系统全局用户ID';
COMMENT ON COLUMN cowork_portal_operations.operation IS '操作类型(key.add-创建Key,recharge.add-创建订单,recharge.redeem-兑换余额)';
COMMENT ON COLUMN cowork_portal_operations.request_id IS '客户端稳定操作ID';
COMMENT ON COLUMN cowork_portal_operations.fingerprint IS '规范请求SHA256摘要，不保存兑换码';
COMMENT ON COLUMN cowork_portal_operations.status IS '状态(PENDING-待确认,COMPLETED-已完成,UNCONFIRMED-结果未确认,REJECTED-已确认拒绝)';
COMMENT ON COLUMN cowork_portal_operations.resource_id IS '已确认结果ID，未确认时为NULL';
COMMENT ON COLUMN cowork_portal_operations.payment_result IS '字段白名单限制的支付发起结果，不保存商户密钥或模型Key';
COMMENT ON COLUMN cowork_portal_operations.created_at IS '创建时间';
COMMENT ON COLUMN cowork_portal_operations.updated_at IS '更新时间';
