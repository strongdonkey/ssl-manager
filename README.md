# SSL Manager v2

基于 etcd 的分布式 SSL 证书集中管理系统。

## 架构

```
管理员 / CI
  │  curl / upload-cert.sh / Web UI
  ▼
ssl-server (HTTP API + Web UI)
  │  写入 etcd（cert/key 分开存储）
  ▼
etcd 集群
  /ssl-manager/certs/{domain}/meta    ← 元数据（版本号、指纹、有效期）
  /ssl-manager/certs/{domain}/cert    ← 证书 PEM
  /ssl-manager/certs/{domain}/key     ← 私钥 PEM（可单独设 RBAC）
  /ssl-manager/certs/{domain}/chain   ← 中间链 PEM（可选）
  /ssl-manager/status/{agentID}/{domain} ← Agent 心跳状态
  │
  │  定时轮询（默认5分钟）
  ▼
ssl-agent（每台 Nginx 服务器）
  1. 读取 /meta → 对比本地版本号+指纹
  2. 有差异 → 拉取完整 cert/key/chain
  3. 原子写入文件 + 自动备份
  4. nginx -t 校验 → nginx -s reload
  5. 上报状态到 etcd（带60s TTL）
```

## etcd key 分离存储的好处

| key | 内容 | 权限建议 |
|-----|------|---------|
| `/meta` | 版本、指纹、有效期（无敏感信息） | 所有人可读 |
| `/cert` | 证书 PEM（公开信息） | 所有人可读 |
| `/key` | **私钥 PEM（敏感）** | 仅 Agent 角色可读 |
| `/chain` | 中间链 PEM | 所有人可读 |

轮询时只读 `/meta`（轻量），仅在版本变化时才拉取 `/key`，减少私钥暴露次数。

## 同步机制

Agent 采用**定时轮询**方案（简单稳定）：
- 每 `poll_interval`（默认5分钟）读取 `/meta` 对比版本号
- **版本号比对**（O(1) 快速判断）+ **指纹兜底校验**（防止手动修改）
- 只有发现差异才拉取完整证书，节省 etcd IO
- Agent 重启后立即执行一次全量同步，不依赖历史状态

## 部署

```bash
# 1. 编译
make linux          # 生成 Linux amd64 二进制

# 2. 服务端（一台）
make install-server
systemctl start ssl-server
# Web UI: http://your-server:8080/ui

# 3. Agent（每台 Nginx 服务器）
scp bin/ssl-agent-linux root@web01:/usr/local/bin/ssl-agent
scp configs/agent.yaml  root@web01:/etc/ssl-manager/agent.yaml
# 编辑 agent.yaml，填写 domains 和 etcd 地址
systemctl start ssl-agent
```

## 上传证书

```bash
# 脚本上传
export SSL_MANAGER_URL=http://your-server:8080
bash scripts/upload-cert.sh example.com cert.pem privkey.pem chain.pem

# curl 直接调用
curl -X POST http://your-server:8080/api/v1/certs \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","cert_pem":"...","key_pem":"..."}'
```

## API

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/v1/certs | 所有证书元数据（无私钥） |
| GET | /api/v1/certs/:domain | 单个证书详情 |
| POST | /api/v1/certs | 创建/更新证书 |
| DELETE | /api/v1/certs/:domain | 删除证书 |
| GET | /api/v1/agents | Agent 状态列表 |
| GET | /api/v1/health | 健康检查 |
| GET | /ui | Web 管理界面 |

## 本地文件布局

```
/etc/nginx/ssl/
├── example.com/
│   ├── cert.pem          # 服务器证书
│   ├── key.pem           # 私钥（0600）
│   ├── chain.pem         # 中间链
│   ├── fullchain.pem     # cert+chain（Nginx 推荐）
│   ├── .version          # 当前版本号
│   └── backup/
│       └── 20250601_120000/
│           ├── cert.pem
│           └── key.pem
```

## Let's Encrypt 自动续签集成

```bash
# /etc/letsencrypt/renewal-hooks/deploy/ssl-manager.sh
#!/bin/bash
for domain in $RENEWED_DOMAINS; do
  bash /opt/ssl-manager/scripts/upload-cert.sh "$domain" \
    "/etc/letsencrypt/live/$domain/cert.pem" \
    "/etc/letsencrypt/live/$domain/privkey.pem" \
    "/etc/letsencrypt/live/$domain/chain.pem" \
    "Renewed $(date +%Y-%m-%d)"
done
```
