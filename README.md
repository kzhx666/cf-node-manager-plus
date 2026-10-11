# cf-node-manager-plus（CF 优选 Pro / Docker 一键部署版）

一个轻量的 Web 节点管理 / 订阅生成器：

- 面板里维护「优选 IP 库」与「订阅来源」
- 同步后缓存节点
- 通过 `/sub` 输出多种订阅格式（Base64 URI / Clash.Meta(mihomo) / sing-box）

> 已支持：Hy2 端口跳跃（mport/ports）、AnyTLS、ShadowTLS、NaiveProxy 的识别与生成（其中 NaiveProxy 更推荐用 sing-box 输出）。

---

## 目录结构

```text
.
├── app.py
├── templates/
│   └── index.html
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── data/               # 运行后自动生成（持久化数据/缓存/日志等）
```

---

## 快速开始（Docker Compose）

### 1）拉取代码（默认安装到 /opt 目录）

```bash
mkdir -p /opt && cd /opt
git clone https://github.com/kzhx666/cf-node-manager-plus.git
cd /opt/cf-node-manager-plus
```

### 2）配置环境变量

```bash
cp .env.example .env
# 编辑 .env，至少把 WEB_PASSWORD 改成你自己的强密码
```

> `WEB_PASSWORD` 是面板登录密码；也常作为 `/sub` 的默认 token（以项目实际实现为准）。

### 3）准备数据目录（推荐）

如果你启用了 `./data` 挂载（默认推荐持久化），先创建目录并确保容器可写：

```bash
mkdir -p data
# 让容器用户可写（示例里使用了 uid=10001）
chown -R 10001:10001 data
```

（如果你不想处理权限，也可以改成 root 运行或把挂载目录权限放宽，但不推荐。）

### 4）启动

```bash
docker compose up -d --build
docker compose ps
```

---

## 访问端口说明（很重要）

应用 **容器内通常监听 5000**，你对外访问的端口取决于 `docker-compose.yml` 里的端口映射。

- 如果 compose 写的是 `5000:5000` → 浏览器访问：`http://服务器IP:5000/`
- 如果你想对外用 8080 → 把映射改成 `8080:5000`，然后访问：`http://服务器IP:8080/`

随时可用下面命令确认实际映射：

```bash
docker compose ps
```

---

## 订阅输出接口 `/sub`

面板里会生成订阅链接，本质是 `/sub`：

### 基本格式

- Base64（默认）  
  `http://服务器IP:对外端口/sub?token=你的token`
- Clash.Meta / mihomo  
  `http://服务器IP:对外端口/sub?token=你的token&flag=clash`
- sing-box (支持 1.8+ / 1.11+ 完整开箱即用配置)  
  `http://服务器IP:对外端口/sub?token=你的token&flag=singbox`
  - 亦可加 `&format=outbounds` 输出纯节点数组

### 常用筛选参数

- `filter=关键词`：只保留包含关键词的节点
- `exclude=关键词`：排除包含关键词的节点
- `raw=1`：输出原始节点（不做优选 IP 替换）
- `raw=0`（默认）：输出替换后的优选结果

示例：

```text
/sub?token=xxxx&flag=clash&filter=HK&exclude=游戏&raw=0
```

---

## 支持的节点类型（简表）

> 具体能输出哪些格式，取决于目标客户端是否支持该类型。

- ✅ 通用：VLESS / VMess / Trojan / Shadowsocks / Hysteria2 …
- ✅ Hysteria2 端口跳跃：支持解析 `mport=起止端口`，并在输出端生成对应 multi-port（如 Clash 的 `ports:` / sing-box 的 `server_ports`）。
- ✅ AnyTLS：支持识别与生成（mihomo/Clash.Meta 与 sing-box 输出均可）。
- ✅ ShadowTLS：
  - `ss://... ?plugin=shadow-tls;...` 这类（SIP003 插件）可在 mihomo 输出为 SS+plugin
  - `shadowtls://...` 这类更偏 sing-box 输出（mihomo 若不支持会跳过，避免加载失败）
- ⚠️ NaiveProxy：更推荐使用 sing-box 输出（mihomo/Clash 并非所有版本支持 naive）。

---

## 环境变量

- `WEB_PASSWORD`：面板登录密码（也常用作 `/sub` 默认 token）
- `TZ`：容器时区（可选）

---

## 更新 / 升级

```bash
cd /opt/cf-node-manager-plus
git pull
docker compose up -d --build
docker compose ps
```

---

## 常见排错

### 1）访问不了网页
- 先看端口映射：`docker compose ps`
- 看日志：`docker compose logs -n 200`

### 2）权限报错（写 data 失败）
- 重新修正权限：`chown -R 10001:10001 data`
- 或调整 compose 让容器以 root 运行（不推荐）

### 3）看到 `version is obsolete`
这是 Docker Compose v2 的提示，`docker-compose.yml` 顶部的 `version:` 可以删掉，不影响运行。

---

## 安全建议

- 一定要改强密码（`WEB_PASSWORD`）
- 强烈建议加反向代理（Nginx/Caddy）并启用 HTTPS
- 面板尽量不要裸奔公网（至少加防火墙/白名单/访问控制）

---

## License

MIT
