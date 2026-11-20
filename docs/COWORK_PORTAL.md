当前企业模型分组引用与 SK 归属契约见 [分组引用说明](COWORK_GROUP_REFERENCES.md)（2026-11-19）。真实模型组仅由 sub2api 管理员维护；创建 Key 必选获授权的 groupId，历史数据按 Key 固定归属隔离。

# 主系统个人模型门户

此适配复用正式Key、支付、兑换Service，主系统Java提供界面业务接口，本仓库不增加前端页面

## 部署与身份

- 先发布包含243迁移的服务，沿用既有迁移机制创建cowork_portal_operations，再开启门户
- 配置COWORK_PORTAL_ENABLED=true和至少32字符独立COWORK_PORTAL_API_KEY，主系统对应cowork.sub2api.portal-*参数；不要复用Provisioning或OAuth密钥
- docker-compose.local.yml已透传这两个变量，其他部署方式必须自行注入；反向代理需放行受控内部服务路由，不得回落HTML首页
- 必须先完成Provisioning用户与真实模型组完整授权同步，身份按source+external_user_id解析，用户要求active、未删除且restrict_public_groups=true
- 模型路由与账号池仍需运维在管理台配置，cowork不自动创建模型组或绑定账号池
- 支付渠道、币种和回调沿用原有支付配置，回调进入sub2api，主系统不直接更新余额

## 内部协议

固定POST /internal/v1/cowork/portal，X-Cowork-Portal-Key独立鉴权，JSON上限128KiB，整体30秒预算，按用户执行Global/Heavy面板限流，不签发用户JWT，不接收主系统Token

请求包含source、external_user_id、tenant_key、external_group_id、operation、parameters；充值下单的return_url只能由受信主系统配置派生。用户标识不能从客户端身份头或邮箱取得

操作白名单：usage.summary/usage.trend/usage.page，key.page/key.detail/key.add/key.edit/key.editStatus/key.remove/key.reveal，wallet.detail，recharge.options/recharge.add/recharge.redeem/recharge.history，order.page/order.detail/order.cancel，operation.detail

用量和Key查询由cowork按本地不可变企业归属注入完整parameters.keyIds，在SQL聚合/分页前同时限定真实user_id和Key ID；缺失拒绝、空数组为空、最多4000，浏览器不得指定范围。group.options由cowork注入modelGroupIds并与下游正式授权求交。Key创建必填groupId，cowork校验业务组和企业上限，下游校验正式模型组授权，普通响应脱敏，仅创建/显式reveal返回明文，所有已认证响应no-store

钱包和余额订单属于个人全局，订单必须是balance类型，不能借套餐购买或兑换改变同步授权。兑换限流、锁、事务复用正式流程，在该流程内检查余额类型，错误不返回原始正文或凭据

支付启动结果仅返回字段白名单：订单ID/号、状态、resultType、URL、二维码、客户端SDK凭据、意图ID、币种、金额、手续费、到期时间、paymentType/countryCode/paymentEnv/paymentMode。固定桌面场景，不覆盖微信内OAuth/JSAPI或移动支付恢复流程，真实渠道仍需测试环境联调

## 防重与恢复

key.add/recharge.add/recharge.redeem必须携带parameters.requestId，为32位十六进制；以source+external_user_id+operation+request_id唯一，SHA256请求摘要不同直接冲突。领取先独立提交，永久保存，不使用通用幂等记录的过期或抢占机制

COMPLETED重试只读结果：Key按ID重新授权读取；下单读取已保存白名单；兑换返回完成记录。REJECTED仅用于已知在写入前拒绝的业务抛出点，相同ID不重放。PENDING/UNCONFIRMED均不得自动抢占、清理或重放

key.add创建事务内同时关联既有cowork_portal_operations.resource_id，崩溃后可找回结果；未确认的操作不重放。用于后台停用、key.detail及key.add操作只读确认的受信内部请求允许解析已停用/删除用户的原映射；普通登录和原生管理不受影响。

operation.detail只能读取本人记录，不执行原操作。Key创建与既有操作表resource_id已在同一下游事务中关联；两端数据库及外部支付平台不存在统一原子事务，不承诺严格恰好一次。管理员按用户、操作ID、订单/支付流水或兑换历史核对，无法确认时保持记录；不要删除防重行或换ID自动重试。确认完成后依据证据修复资源引用及白名单支付结果，不录入Key明文、兑换码或商户密钥

支付客户端参数可能包含clientSecret，应保护数据库/备份访问权限，不写入运行日志。业务失败只返回固定PORTAL_*原因

## 验证

在backend运行go test -tags unit ./internal/service -run 'TestCoworkPortal|TestProvisioning|TestPublicRedeem' -count=1；运行go test ./internal/handler ./internal/server/routes ./cmd/server ./migrations。TestCoworkPortalDatabase默认跳过，显式COWORK_PORTAL_TEST_DSN仅允许127.0.0.1可丢弃空PG，会创建测试表，禁止指向业务数据库

## 支付环境与主动核查

通用字段paymentEnvironment(production-正式资金,sandbox-支付宝测试资金)覆盖recharge.options的方法、recharge.add、order.page/detail/check及已保存支付结果，历史缺省production，不能复用Airwallex paymentEnv。客户端不能传入环境，部署PAYMENT_ENVIRONMENT与实例environment须匹配，sandbox只允许官方Alipay

新增内部操作`order.check`，parameters仅含id。它先校验本人全局余额订单及环境，再以用户行锁和支付审计跨副本限频10秒，提交后才查原渠道，调用共用支付确认与履约。COMPLETED等状态仅返回事实，GET order.detail和operation.detail保持只读。通知RSA2、商家、订单、金额整数分必须一致；查询用authenticated_app_id表达原渠道的认证上下文，不能把它伪装成接口返回的app_id/seller_id

recharge.add在订单事务内写操作resource_id，提交后才调用渠道。网络异常不将订单改FAILED，操作可为PENDING/UNCONFIRMED并保留resourceId，主系统可按原ID查询或核查。该ID表示已持久化订单，不表示下单支付参数已完整或资金已到账。操作COMPLETED表示下单动作完成，只有订单COMPLETED表示到账

沿用现有结构与此前243迁移，本次无新增SQL；核查事件action为PORTAL_ORDER_CHECK:时间纳秒以兼容(order_id,action)唯一索引。测试只能使用临时库与受控支付，真实沙箱付款仍需独立应用、买家和可达HTTPS回调
