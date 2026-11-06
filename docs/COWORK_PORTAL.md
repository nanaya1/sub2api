# 主系统个人模型门户

此适配复用正式Key、支付、兑换Service，主系统Java提供界面业务接口，本仓库不增加前端页面

## 部署与身份

- 先发布包含243迁移的服务，沿用既有迁移机制创建cowork_portal_operations，再开启门户
- 配置COWORK_PORTAL_ENABLED=true和至少32字符独立COWORK_PORTAL_API_KEY，主系统对应cowork.sub2api.portal-*参数；不要复用Provisioning或OAuth密钥
- docker-compose.local.yml已透传这两个变量，其他部署方式必须自行注入；反向代理需放行受控内部服务路由，不得回落HTML首页
- 必须先完成Provisioning用户和分组同步，身份按source+external_user_id解析，用户要求active、未删除且restrict_public_groups=true
- 模型路由与账号池仍需运维在管理台配置，同步默认anthropic不自动调整或绑定账号池
- 支付渠道、币种和回调沿用原有支付配置，回调进入sub2api，主系统不直接更新余额

## 内部协议

固定POST /internal/v1/cowork/portal，X-Cowork-Portal-Key独立鉴权，JSON上限64KiB，整体30秒预算，按用户执行Global/Heavy面板限流，不签发用户JWT，不接收主系统Token

请求包含source、external_user_id、tenant_key、external_group_id、operation、parameters；充值下单的return_url只能由受信主系统配置派生。用户标识不能从客户端身份头或邮箱取得

操作白名单：usage.summary/usage.trend/usage.page，key.page/key.detail/key.add/key.edit/key.editStatus/key.remove/key.reveal，wallet.detail，recharge.options/recharge.add/recharge.redeem/recharge.history，order.page/order.detail/order.cancel，operation.detail

用量和Key查询在SQL聚合/分页前限定user_id、source、tenant_key。保留历史已删除组映射，换组不改写历史用量。Key创建再次核对当前有效组和user_allowed_groups，普通响应脱敏，仅创建/显式reveal返回明文，所有已认证响应no-store

钱包和余额订单属于个人全局，订单必须是balance类型，不能借套餐购买或兑换改变同步授权。兑换限流、锁、事务复用正式流程，在该流程内检查余额类型，错误不返回原始正文或凭据

支付启动结果仅返回字段白名单：订单ID/号、状态、resultType、URL、二维码、客户端SDK凭据、意图ID、币种、金额、手续费、到期时间、paymentType/countryCode/paymentEnv/paymentMode。固定桌面场景，不覆盖微信内OAuth/JSAPI或移动支付恢复流程，真实渠道仍需测试环境联调

## 防重与恢复

key.add/recharge.add/recharge.redeem必须携带parameters.requestId，为32位十六进制；以source+external_user_id+operation+request_id唯一，SHA256请求摘要不同直接冲突。领取先独立提交，永久保存，不使用通用幂等记录的过期或抢占机制

COMPLETED重试只读结果：Key按ID重新授权读取；下单读取已保存白名单；兑换返回完成记录。REJECTED仅用于已知在写入前拒绝的业务抛出点，相同ID不重放。PENDING/UNCONFIRMED均不得自动抢占、清理或重放

operation.detail只能读取本人记录，不执行原操作。没有跨业务表及支付平台的原子事务，不承诺严格恰好一次。管理员按用户、操作ID、订单/支付流水或兑换历史核对，无法确认时保持记录；不要删除防重行或换ID自动重试。确认完成后依据证据修复资源引用及白名单支付结果，不录入Key明文、兑换码或商户密钥

支付客户端参数可能包含clientSecret，应保护数据库/备份访问权限，不写入运行日志。业务失败只返回固定PORTAL_*原因

## 验证

在backend运行go test -tags unit ./internal/service -run 'TestCoworkPortal|TestProvisioning|TestPublicRedeem' -count=1；运行go test ./internal/handler ./internal/server/routes ./cmd/server ./migrations。TestCoworkPortalDatabase默认跳过，显式COWORK_PORTAL_TEST_DSN仅允许127.0.0.1可丢弃空PG，会创建测试表，禁止指向业务数据库
