# PostgreSQL 17 与 Redis 7 独立部署

`docker-compose.infra.yml` 只部署 PostgreSQL 17 和 Redis 7，供当前 Sub2API 主服务连接。需要 Docker 和 Docker Compose v2。

## 初始化配置

在 Linux 服务器的项目目录下执行：

```bash
cd /data/sub2api/deploy
cp -n .env.infra.example .env.infra.local
chmod 600 .env.infra.local
```

分别执行两次 `openssl rand -hex 32`，将生成结果填写到 `.env.infra.local` 的 `POSTGRES_PASSWORD` 和 `REDIS_PASSWORD`。密码文件仅保存在服务器上；重新部署时保留现有密码文件。

```bash
nano .env.infra.local
```

## 启动与验证

```bash
# 只检查配置，不输出密码。
docker compose --env-file .env.infra.local -f docker-compose.infra.yml config --quiet

# 启动两个服务。
docker compose --env-file .env.infra.local -f docker-compose.infra.yml up -d

# 等待两个服务均显示 healthy。
docker compose --env-file .env.infra.local -f docker-compose.infra.yml ps

# 查看启动日志。
docker compose --env-file .env.infra.local -f docker-compose.infra.yml logs --tail=100
```

默认连接地址：

| 服务 | 镜像 | 宿主机连接地址 | 持久化数据卷 |
| --- | --- | --- | --- |
| PostgreSQL | `postgres:17-alpine` | `127.0.0.1:5433` | `sub2api-infra_postgres17_data` |
| Redis | `redis:7-alpine` | `127.0.0.1:6380` | `sub2api-infra_redis7_data` |

端口只绑定本机回环地址，可与使用宿主机 `5432`、`6379` 端口的旧实例同时运行。需要其他端口时，修改 `.env.infra.local` 的 `SUB2API_POSTGRES_PORT`、`SUB2API_REDIS_PORT`。

PostgreSQL 在空数据卷上首次启动时自动创建 `POSTGRES_USER` 和 `POSTGRES_DB`，默认均为 `sub2api`。Sub2API 的表结构由主服务启动时自动迁移。

## 主服务连接配置

下面的配置适用于主服务直接运行在 Linux 宿主机上，或主服务容器设置了 `network_mode: host` 的情况。编辑主服务使用的 `deploy/.env`，保留其中已有的管理员配置、JWT 密钥和 TOTP 加密密钥，并填写：

```dotenv
DATABASE_HOST=127.0.0.1
DATABASE_PORT=5433
DATABASE_USER=sub2api
DATABASE_PASSWORD=与.env.infra.local中的POSTGRES_PASSWORD一致
DATABASE_DBNAME=sub2api
DATABASE_SSLMODE=disable

REDIS_HOST=127.0.0.1
REDIS_PORT=6380
REDIS_PASSWORD=与.env.infra.local中的REDIS_PASSWORD一致
REDIS_DB=0
```

若改过数据库用户名、库名或宿主机端口，同步修改以上配置。主服务如使用 Docker bridge 网络，应加入 `sub2api-infra_default` 网络，再通过 `postgres:5432` 和 `redis:6379` 连接；容器内部的 `127.0.0.1` 指向自身。

## 数据保留

数据保存在独立的 Docker 命名卷中，普通 `docker compose ... down` 会保留数据；`down -v` 会删除数据卷。不要将旧 PostgreSQL 10 的数据目录直接挂载给 PostgreSQL 17。

`POSTGRES_USER`、`POSTGRES_DB` 和 `POSTGRES_PASSWORD` 用于首次初始化。已有数据卷时，修改环境文件不会修改现有数据库账号或密码；需要使用 SQL 修改账号，并同步更新主服务配置。
