# cowork-server 用户与分组投影

用户在所有企业共用一个sub2api账号，身份为source+external_user_id。分组身份为source+tenant_key+external_group_id。source必须稳定；主服务全局配置统一目标地址与密钥，不再按企业切换实例。

## 行为

主系统tb_sys_user新增、资料、启停通过user/upsert同步；删除通过user/remove执行正式软删除并使Key失效。企业成员加入、角色、启停不直接改变下游账号。成员绑定、换组、解绑或移出企业时，主服务发送该全局用户跨所有企业完整组集合，不按账号或成员启停过滤；移出某企业只撤销对应组。

同步组强制专属，同步用户限制公开组。user/replace-groups在一个事务里清空全部旧授权并写入快照，包含人工多加的授权；groups=[]明确清空，省略或null拒绝。Key不会自动换组，撤权后原Key不能继续使用旧组。提交后显式撤销鉴权缓存，持久化失效Outbox兜底。

账号元数据和授权各自维护version、groups_version，过期和同版本请求只返回已有结果；用户和组正式删除后保留身份墓碑，之后的upsert或授权请求不能复活。删除先到时可保存无本地ID的墓碑。主服务据返回的实际版本确认，不按请求版本猜测。账号没有邮箱时用全局身份哈希生成provisioning.invalid占位邮箱，创建随机密码，不复制主系统密码。

## HTTP契约

开启PROVISIONING_ENABLED=true并设置PROVISIONING_API_KEY，鉴权头X-Provisioning-Key。所有接口POST，前缀/internal/v1/provisioning，反向代理须保留/internal/路由。

| 路径 | JSON关键字段 |
| --- | --- |
| /user/upsert | source,external_user_id,version,username,email,status(active/disabled) |
| /user/remove | source,external_user_id,version |
| /user/replace-groups | source,external_user_id,version,groups:[{tenant_key,external_group_id}] |
| /group/upsert | source,tenant_key,external_group_id,version,name,description,status |
| /group/remove | source,tenant_key,external_group_id,version |

用户响应data含source、external_user_id、local_user_id、version、groups_version、status；删除前未创建时local_user_id为0。组响应含对应企业身份、本地ID、版本和状态。授权引用缺失时404且事务回滚，不会先清空原授权。主服务补建依赖后重试。删除组墓碑被授权快照引用时跳过，防止延迟快照复活组。旧/user/disable和/group/replace-members已移除，两端配套发布。

## 升级

停止主服务写入与Worker，由维护人员清理下游旧账号、组及外部映射，清空主服务tb_sync_outbox、tb_sub2api_user_binding、tb_sub2api_group_binding。迁移242要求provisioning_user_bindings为空，发现旧数据明确失败，不自动归并。先发布sub2api并应用内置迁移，再由维护人员执行主库结构升级并发布主服务。

主服务平台管理员显式POST /api/v1/integration/sub2api/initialize（无请求体），按用户→组→完整授权分页入队，再开启Worker。返回值仅表示入队计数。source、目标实例或下游数据重建均须核对完整映射和事件版本；下游映射仍存在时不要重置主库事件序列。

## 验证

backend内执行：`go test -tags unit ./internal/service -run TestProvisioning -count=1`、`go test ./internal/handler ./internal/server/routes ./cmd/server -run '^$'`、`go test ./migrations`。测试覆盖跨企业完整授权、空集合、缺依赖回滚、禁用账号保留组、乱序重放、正式删除和墓碑、缓存失效。真实SQL验证只使用临时PostgreSQL，不自动修改业务库。
