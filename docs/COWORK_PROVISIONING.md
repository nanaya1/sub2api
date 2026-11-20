# cowork-server 账号与模型组授权同步

完整契约见 [企业模型分组引用与 SK 归属](COWORK_GROUP_REFERENCES.md)。真实模型组只由sub2api管理员维护，cowork不再同步创建、修改、删除模型组。

用户只按source+external_user_id全局唯一，不按邮箱、用户名认领历史账号，不同步密码。用户元数据version与正式授权groups_version独立，同一用户使用事务advisory锁；删除复用正式用户删除并保留墓碑，防止延迟重放复活。

开启PROVISIONING_ENABLED并配置独立PROVISIONING_API_KEY，固定X-Provisioning-Key；POST /internal/v1/provisioning下提供：

- user/upsert：全局账号元数据、状态与version。
- user/remove：全局删除墓碑。
- user/replace-groups：source、external_user_id、version和完整model_group_ids（最多4000），空数组清空，缺失/null/重复/非正ID拒绝；不接受旧groups字段。
- groups/catalog：管理员维护的非Composite、standard余额模型组目录，source/page/page_size，单页最多100。
- inspect：source和最多100个可信用户身份，只读REPEATABLE READ、10秒、最多4000授权，超限整体失败；返回正式user_allowed_groups的model_group_ids。旧业务组核对没有下游实体，cowork改读目录与本地引用/任务状态。

user/replace-groups写入既有user_allowed_groups。cowork按有效企业、有效成员和业务组引用与企业分配的交集计算跨企业并集。主系统业务归属保留，成员停用时仅从有效授权并集中排除。restrict_public_groups始终为true，提交后显式失效鉴权缓存并保留原数据库失效Outbox机制。撤权对应SK的停用由cowork归属表与Outbox负责，不能单靠共享模型组并集判断企业权限。

group/upsert、group/remove以及更早的group/disable、group/replace-members、user/disable不再注册。旧事件不修改payload，不将旧格式默认解释为空授权；停写盘点后显式生成新协议事件。内部JSON拒绝未知字段及尾随数据；写入请求上限128KiB，inspect仍64KiB。不回退前端HTML，不记录请求正文或密钥。

无邮箱用户使用清理后的用户名@sub2api.local：保留字母、数字、中文及._-，其他字符替换短横线，本地部分最多64字节；重名追加身份短哈希并检查占用。真实邮箱优先，身份始终由source+external_user_id决定，不覆盖或认领其他账号。

本次sub2api新增0表，不提供迁移244，不改原生登录、Key管理入口或网关。cowork手工升级三张本地表；SK真实创建仍在api_keys，操作恢复复用已有cowork_portal_operations。本次不清理旧Key、组、用户、余额或订单。

验证：backend运行go test -tags unit ./internal/service -run 'TestCoworkPortal|TestProvisioning|TestPublicRedeem' -count=1，handler/routes/cmd编译与migrations回归按AGENTS.md。数据库验证只使用显式回环空临时库，双系统联调使用临时PostgreSQL/Redis，不连接业务环境。
