# 企业模型分组引用与 SK 归属（轻量方案）

真实模型组、平台、账号池、路由和价格由 sub2api 管理员维护。cowork 只引用真实组，不自动创建、改名、停用或删除 sub2api 模型组，不使用 Composite。

## 配置与创建

1. 平台新增/编辑企业时分配若干真实模型组；企业 OWNER/ADMIN 为业务分组引用其中的子集。
2. 用户在每个企业最多属于一个业务分组，创建 SK 时必须从该业务组当前有效引用中选择一个真实模型组。一把 SK 固定一个模型组/平台，不随机跨平台。
3. SK 实体及明文在 sub2api 的 api_keys；cowork 记录创建意图、用户/企业/业务组/真实模型组和下游 Key ID，不存 SK 明文。历史无归属 Key 不自动认领或清理，cowork 不展示；sub2api 保留其原生使用规则。

## 数据边界

sub2api 本次新增 **0 张表**，撤下原四表方案，不增加企业授权链网关校验，不修改原生登录或普通 Key 管理入口。用户已确认同步用户不能登录 sub2api，无需额外增加登录或自助启用限制。

cowork 新增 **3 张表**：tb_sub2api_tenant_model_policy（企业分配）、tb_sub2api_group_model_grant（业务组引用）、tb_sub2api_model_key（固定归属、创建与撤权状态）。任务复用 tb_sync_outbox，不新建任务表。旧 tb_sub2api_group_binding 仅记录本地业务组收敛进度，remote_group_id 为空，不伪造下游实体。

下游既有 user_allowed_groups 保存有效企业、有效成员和业务组引用与企业分配的交集在所有企业的并集。同步只替换正式授权，不写真实模型组。用户元数据 version 与授权 groups_version 独立，按同一全局用户串行生成快照。

## 撤权与重新授权

cowork 在变更事务中标记失效归属的首次 revoked_at 和 REVOKE_PENDING，并将 key.reconcile 写入既有 Outbox。Worker 调用现有 Portal key.editStatus 设置 inactive，再查询确认；失败/未知继续重试并显示“撤权处理中”。在远端停用确认前不承诺已经阻断调用，实际调用窗口取决于 Worker、网络及下游缓存失效。

企业 A/B 共享模型组时，只停用 A 归属的 Key，B 和原生用户 Key 保持现状。成员停用、换组、移出，业务组删除/引用撤销，企业停用/分配撤销以及账号删除/停用，均按当前事实收敛失效 Key。重新授权不清空首次撤权标记，旧 SK 保持停用，需创建新 SK。cowork 拒绝撤权 Key 的启用、明文查看及编辑；sub2api 管理员保留原生管理权限，人工重新启用不属于本方案的自动保护范围。

单 Key 的用户状态写入和撤权写入共用本地租约，避免在途启用迟于撤权停用完成。网络未知保留租约三分钟；内部 HTTP 上限30秒，下游Portal请求上限30秒。延迟及失败在 Outbox 和 Key 列表可见，不自动声称成功。

## 创建未知结果

cowork 在 HTTP 前保存不可变意图、稳定 requestId 和摘要，同一用户同一 requestId 唯一，不保存原正文、不自动重放创建。sub2api 复用已有 cowork_portal_operations，在 api_keys 创建事务内关联 resource_id；没有新增操作表。断网/崩溃后只读 operation.detail 找回 ID、核对真实所有者和目标组，补齐本地归属。撤权期间晚到的创建结果同样进入停用，不向用户返回失权 Key 明文。

## 查询与核对

用量/Key 请求的 keyIds 只由 cowork 根据本地本人、当前企业的全部历史归属组装，浏览器不能提交该范围。sub2api 在分页/聚合前同时校验真实 user_id 和完整 Key ID 范围；缺失范围拒绝，空数组为空，超过4000整体失败，不截断或放大。group.options 的 modelGroupIds 由内部当前交集组装，并与下游正式授权再次求交。钱包、充值、订单继续个人全局。

inspect 用户返回正式授权 model_group_ids，不再返回业务组策略。业务组核对读取管理员模型目录、cowork配置和本地收敛/撤权进度，不要求下游存在业务组实体。配置写入未知先重新读取；创建未知只查询原操作，不换 requestId 重发。

## 部署与验证

cowork 当前开发基线为2026-11-20，用户确认三表增量已执行，当前 sql/init_update.sql 仅保留说明注释。新库执行 sql/init.sql、sql/index.sql；已到2026-11-13基线但未部署本功能的其他环境，停止授权写入和 Worker、备份后核对并执行 sql/history/2026-11-20/init_update.sql 的适用段，后续新变更再使用当前入口。sub2api 本次无新迁移，不执行被撤下的244四表SQL。不修改已发布迁移，不清理业务数据。两端协议须配套部署，旧在途 groups 快照应停写盘点后重新生成，不把旧格式当空授权。

验证仅使用随机回环临时 PostgreSQL/Redis、受控HTTP及当前源码构建的 sub2api；覆盖共享组撤权隔离、旧Key不恢复、新Key可用、原生Key不受影响、创建恢复、停用失败重试、历史用量及分页隔离。真实支付、模型供应商调用和业务数据迁移不在本地测试范围。
