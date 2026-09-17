# ChemELLM Agent 适配器

该服务把 ChemELLM 托管 Agent 接口转换成 OpenAI Chat Completions 上游，供 Sub2API 作为一个普通 OpenAI API Key 账号接入。

用户仍然只使用 Sub2API 的统一地址，例如 `https://api.xuelanglm.com/v1`，并通过模型名 `chemellm_agent` 选择该能力。Qwen 等原生兼容模型不经过此服务。

## 行为边界

- ChemELLM Agent 要求 `messages` 恰好一项且角色为 `user`。适配器将完整 OpenAI 历史折叠到这一条消息中，默认不依赖服务端 `conversation_id`，因此进程重启不会丢失上下文。
- ChemELLM 自己执行 `exec`、`web_search`、知识库等内置工具。客户端传入的 OpenAI `tools` 不会交给 ChemELLM，也不会生成客户端需要执行的 `tool_calls`。
- 流式输出会过滤 `x_status_event` 和 `x_tool_events`，只返回标准正文、结束帧和 usage，避免严格 OpenAI 客户端解析失败。
- 如果请求显式携带顶层 `conversation_id`，适配器会原样转发；普通客户端不需要使用它。

## Docker Compose 部署

```bash
cd /opt
cp -r /path/to/sub2api/tools/chemellm-agent-adapter .
cd chemellm-agent-adapter

cat > .env <<'EOF'
CHEMELLM_AGENT_TOKEN=替换为ChemELLM Agent用户级令牌
ADAPTER_API_KEY=生成一个仅供Sub2API访问的随机密钥
SUB2API_DOCKER_NETWORK=sub2api-deploy_sub2api-network
EOF

chmod 600 .env
docker compose up -d --build
curl http://127.0.0.1:18081/healthz
```

Compose 默认把适配器加入已经存在的 `sub2api-deploy_sub2api-network`。如果实际网络名不同，先运行 `docker network ls`，再修改 `.env` 中的 `SUB2API_DOCKER_NETWORK`。

Sub2API 运行在 Docker 中时，容器内的 `127.0.0.1` 指向 Sub2API 容器本身。在 Sub2API 账号中使用 Docker 服务名：

```text
http://chemellm-agent-adapter:18081/v1
```

如果适配器使用上面的端口映射运行在宿主机，则 Linux 容器需要使用宿主机网关地址，而不是 `127.0.0.1`。

## systemd 部署

```bash
sudo install -d -o root -g root /opt/chemellm-agent-adapter
sudo install -m 0755 adapter.py /opt/chemellm-agent-adapter/adapter.py
sudo install -m 0644 chemellm-agent-adapter.service /etc/systemd/system/

sudo sh -c 'cat > /etc/chemellm-agent-adapter.env' <<'EOF'
LISTEN=127.0.0.1:18081
PUBLIC_MODEL=chemellm_agent
CHEMELLM_AGENT_TOKEN=替换为ChemELLM Agent用户级令牌
ADAPTER_API_KEY=替换为随机内部密钥
UPSTREAM_TIMEOUT_SECONDS=600
INCLUDE_TOOL_EVENTS=true
EOF

sudo chmod 600 /etc/chemellm-agent-adapter.env
sudo systemctl daemon-reload
sudo systemctl enable --now chemellm-agent-adapter
sudo systemctl status chemellm-agent-adapter
```

service 文件默认以 `sub2api` 用户运行；若节点上实际服务用户不同，请修改 `User` 和 `Group`。

## Sub2API 配置

为该模型单独创建一个 OpenAI API Key 类型账号：

```text
名称：ChemELLM Agent
Base URL：http://chemellm-agent-adapter:18081/v1
API Key：与 ADAPTER_API_KEY 相同
模型：chemellm_agent
Responses 支持模式：Force Chat Completions
```

然后将该账号加入允许 `chemellm_agent` 的分组。不要将 Qwen 账号的 Base URL 改为适配器地址。

## 验证

非流式：

```bash
curl http://127.0.0.1:18081/v1/chat/completions \
  -H "Authorization: Bearer $ADAPTER_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"chemellm_agent","messages":[{"role":"user","content":"查询甲醇的主要工业制备路线"}],"stream":false}'
```

流式：

```bash
curl -N http://127.0.0.1:18081/v1/chat/completions \
  -H "Authorization: Bearer $ADAPTER_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"chemellm_agent","messages":[{"role":"user","content":"分析该任务并展示执行过程"}],"stream":true}'
```

最后通过统一入口验证：

```bash
curl -N https://api.xuelanglm.com/v1/chat/completions \
  -H "Authorization: Bearer $SUB2API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"chemellm_agent","messages":[{"role":"user","content":"查询甲醇的主要工业制备路线"}],"stream":true}'
```

## 流式中断排查

若客户端提示 `Server error mid-response`，先更新适配器并强制重建：

```bash
cd /opt/chemellm-agent-adapter
docker compose down
docker compose build --no-cache
docker compose up -d
docker compose logs -f --tail=200
```

新版适配器会在 ChemELLM 上游异常断流或遗漏结束 choice 时补发标准 `finish_reason: stop` 和 `data: [DONE]`，避免已经输出正文后直接断开。真实上游异常仍会记录为：

```text
ChemELLM stream interrupted; emitting a synthetic terminal frame
```

同时查看 Sub2API 日志：

```bash
cd ~/sub2api-deploy
docker compose logs --tail=200 -f
```

从 Sub2API 容器内检查适配器健康状态，先用 `docker ps` 确认实际容器名：

```bash
docker ps --format 'table {{.Names}}\t{{.Image}}'
docker exec <sub2api容器名> wget -qO- http://chemellm-agent-adapter:18081/healthz
```

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `LISTEN` | `127.0.0.1:18081` | 监听地址 |
| `PUBLIC_MODEL` | `chemellm_agent` | Sub2API 和用户看到的模型名 |
| `CHEMELLM_UPSTREAM_URL` | 官方 Agent 地址 | ChemELLM Agent API |
| `CHEMELLM_AGENT_TOKEN` | 无 | 调用 Agent 接口的令牌，必填 |
| `CHEMELLM_API_KEY` | 无 | 旧变量名，仅为兼容保留 |
| `ADAPTER_API_KEY` | 空 | Sub2API 访问适配器所用密钥，生产环境必须设置 |
| `UPSTREAM_TIMEOUT_SECONDS` | `600` | 上游超时 |
| `INCLUDE_TOOL_EVENTS` | `true` | 请求 ChemELLM 返回工具事件；事件不会暴露给客户端 |
| `VERIFY_TLS` | `true` | TLS 校验，生产环境不要关闭 |
| `MAX_BODY_BYTES` | `8388608` | 最大请求体大小 |

`CHEMELLM_AGENT_TOKEN` 可以填写纯令牌或 `Bearer 令牌`，适配器会自动移除重复的 `Bearer` 前缀。经实际验证，同一个 ChemELLM `sk-...` 令牌可以同时调用常规 `/v1.0/chat/completions` 和 Agent `/v1.0/agent/chat/completions`。它不是 Sub2API Key 或 `ADAPTER_API_KEY`。
