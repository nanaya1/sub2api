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

用量和Key查询由cowork按本地不可变企业归属注入完整parameters.keyIds，在SQL聚合/分页前同时限定真实user_id和Key ID；缺失拒绝、空数组为空、最多4000，浏览器不得指定范围。group.options由cowork注入modelGroupIds并与下游正式授权求交。Key创建必填groupId，cowork校验业务组和企业上限，下游校验正式模型组授权，普通Key管理响应脱敏，创建/显式reveal返回明文，客户端只读配置另按下文受控范围返回，所有已认证响应no-store

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

## 客户端自动配置（2026-11-20）

操作白名单新增只读 `key.clientConfig`，入口及独立Portal密钥保持不变。请求 `parameters.keyIds` 必须是Java从本人当前企业归属中筛选、明确开启自动绑定的完整ID列表；显式空数组允许，缺失/null、非正数、重复及超过100项拒绝。用户及企业仍由可信Portal上下文确定，浏览器不得传入Key范围。

返回 `{keyIds:[全部输入ID],providers:[{id,groupId,name,apiKey,platform,models:[实际模型ID]}]}`。keyIds完整回显用于区分已确认的空快照与部分处理；仅读取本人、正式获授权、未删除、启用、未过期、总额度未耗尽的Key明文。无效项不在providers中；数据库、目录读取失败及前后身份或Key事实变化时整体失败，不返回部分成功。该动作不创建Key、不保存防重操作，不记录明文，响应no-store；不能替代普通创建/reveal的交互规则。

Java本地维护 `coworkAutoBindEnabled`，默认false，sub2api不新增存储。Key开关不作为下游网关鉴权条件，不影响其他用途，也不进入普通下游Key编辑参数。只读配置无需requestId，不可调用写动作补建或重试创建。

模型目录支持openai/grok/anthropic/gemini，其他平台整体失败；真实组须standard且非composite。普通目录由正式平台候选、组精确白名单及账号映射构成，实时账号模型准入及组白名单过滤，通配只匹配具体模型；没有可调度账号则models为空，仓储失败不能回落默认模型。OpenAI固定manifest组复用正式manifest获取。每Key最多4000个具体模型，不能返回通配ID或Cowork使用指引的推荐模型。

客户端可达地址由公开 `api_base_url` 提供，Java按平台组装/v1或/v1beta；不得用内部地址兜底。先部署本动作，再部署Java接口；旧版不支持时Java应报告不可用。无新增SQL，沿用原Portal/Provisioning独立密钥与授权同步。测试增加范围严格校验、数据库失败、通配映射、平台过滤及Key有效性，真实Java联调仍在独立临时PostgreSQL/Redis运行，不连接业务依赖或真实模型。
