# cf-node-manager-plus（CF 优选 Pro / Docker 一键部署版）

一个轻量的 Web 节点管理 / 订阅生成器：

- 面板里维护「优选 IP 库」与「订阅来源」
- 同步后缓存节点
- 通过 `/sub` 输出多种订阅格式（Base64 URI / Clash.Meta(mihomo) / sing-box）

> 已支持：Hy2 端口跳跃（mport/ports）、AnyTLS、ShadowTLS、NaiveProxy 的识别与生成（其中 NaiveProxy 更推荐用 sing-box 输出）。

---

## 最新版本更新说明（v43.30 企业级安全加固版）

- **🛡️ 独立现代化安全登录网关**：采用独立赛博深色玻璃拟态登录界面，支持密码显隐切换与 30 天持久免密登录；
- **🔐 HMAC-SHA256 签名鉴权**：全面升级鉴权机制，采用加密 HMAC 签名凭据替代原始明文密码 Cookie，防篡改防重放；
- **🚫 智能防暴力破解防护 (Rate Limiting)**：针对恶意爆破扫描，同一 IP 连续 5 次输错密码自动触发安全网关熔断（冷却锁定 60 秒）；
- **🕵️‍♂️ 防扫描隐蔽模式 (Stealth Mode)**：支持一键开启隐蔽模式，未授权直接访问根路径 `/` 返回无指纹的 404 Not Found，彻底让互联网公网端口嗅探工具失效；
- **🚪 自定义私密管理路径**：支持自由配置后台管理入口（如 `/my_secret_nodes`），不暴露默认管理路径；
- **🔒 修复公网敏感信息泄漏**：修复历史遗留 `/api/status` 接口免密公开导致优选 IP 与节点状态被扫描器抓取的安全隐患；
- **🔑 控制台安全改密与命令行维护**：
  - 前端顶部导航栏新增「🔒 安全改密」模态框，支持在线校验原密码并直接修改；
  - 服务器终端支持通过 `python app.py passwd` 随时免密查看当前状态或快速重置管理密码；
- **全面适配 Komari 探针 (1.5+) 与哪吒探针**：支持直接通过**节点名称**或 **UUID** 绑定 VPS，自动读取真实网卡进出流量并展示配额进度；
- **全面适配现代 Sing-box**：支持 Sing-box 1.8+ / 1.11+ 完整开箱即用 Profile 订阅配置；
- **数据安全快照备份**：支持一键导出 ZIP 完整备份与 JSON 格式数据，支持上传备份文件无缝恢复。

---

## 目录结构

```text
.
├── app.py
├── templates/
│   ├── index.html       # 核心管理控制台主界面
│   └── login.html       # 独立安全登录网关
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── data/               # 运行后自动生成（持久化数据/缓存/日志/密钥等）
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

## 节点自动推送 API `/api/push_nodes`

支持外部脚本（如 `sb-install-plus` 节点安装脚本）将生成的节点实时推送到本面板：

### 请求方式
- **方法**：`POST`
- **路径**：`/api/push_nodes`
- **鉴权方式**（支持以下任一种）：
  - Header: `Authorization: Bearer <WEB_PASSWORD 或 sub_token>`
  - Header: `X-API-Key: <WEB_PASSWORD 或 sub_token>`
  - URL Query: `?token=<WEB_PASSWORD 或 sub_token>`
  - JSON Body: `"token": "<WEB_PASSWORD 或 sub_token>"`

### 请求体 (JSON)
```json
{
  "tag": "My-VPS-HK",
  "nodes": "vless://...\nhysteria2://...\ntuic://...",
  "replace": true,
  "sync": true
}
```

### 字段说明
- `tag`（必填）：订阅源名称，面板中将以此名称展示该分组。
- `nodes`（必填）：节点链接内容，支持多行文本或链接数组。
- `replace`（可选，默认 `true`）：如果已存在同名订阅源，则全量更新替换；设为 `false` 则追加。
- `sync`（可选，默认 `true`）：推送后是否立即触发后台节点同步与地区旗帜识别。

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

## 🛡️ 安全配置与维护指南

### 1）开启隐蔽防扫描模式 (推荐)
- 在控制台底部「⚙️ 参数设置与高级模板」中，勾选 **「开启防扫描隐蔽模式」** 并保存；
- 开启后，任何未授权或探测性访问根路径 `/` 均会返回纯净的 `404 Not Found`，互联网全网扫描器（如 Shodan、Censys、ZoomEye）无法探测出后台存在；
- 管理员仅可通过设定的自定义路径（如 `http://IP:PORT/admin_login`）进入安全登录网关。

### 2）自定义私密管理路径
- 可将默认的 `admin_login` 修改为您专属的私密路径（如 `sec_panel`）；
- 修改后管理入口自动切换，彻底杜绝弱口令探测。

### 3）终端一键查改管理密码
- 如果在生产环境中遗忘面板密码，可在服务器终端直接执行：
  ```bash
  # 本地 Python 环境运行
  python app.py passwd

  # 或 Docker 容器中执行
  docker compose exec app python app.py passwd
  ```
  即可免密查看当前设定的管理密码、自定义路径及隐蔽模式状态，并支持直接键入新密码进行重设。

### 4）与 VPS Cluster Manager 协同联动
- 在 **VPS Cluster Manager** 全局设置中填入本面板的 URL 与 Token；
- VPS 部署完毕后，主节点和 Argo 优选节点将通过带 HMAC-SHA256 签名鉴权的 `/api/push_nodes` 接口极速推送到本面板，安全高效。

---

## License

MIT
