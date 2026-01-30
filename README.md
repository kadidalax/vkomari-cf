# vKomari - Cloudflare Worker Edition

Virtual Komari Agent Cluster Management - 虚拟探针节点 (Cloudflare Worker 版)

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/kadidalax/cf-vkomari)

## 项目简介

将 vKomari 移植到 Cloudflare 免费环境，利用 Cloudflare Workers 模拟节点上报，通过 Cron Triggers 实现高频数据上报。无需服务器，零成本即可拥有一个炫酷的服务器监控面板。

## 功能特性

*   **完全免费**: 基于 Cloudflare Workers 和 D1 数据库。
*   **高频上报**: 利用 Worker 的生命周期实现秒级数据模拟。
*   **真实模拟**: 模拟 CPU、内存、硬盘、流量波动，支持多种系统和架构特征。
*   **分组管理**: 支持拖拽排序、分组归类。
*   **一键解析**: 支持解析常见的探针安装脚本，快速添加节点。
*   **多地区 IP**: 内置全球主要国家和地区的 IP 段库。

## 部署教程

### 方法一：GitHub Actions 自动部署 (详细图文步骤)

这是最推荐的部署方式，后续更新只需同步代码即可自动部署。

#### 1. Fork 本仓库
点击页面右上角的 `Fork` 按钮，将本项目克隆到你自己的 GitHub 账号下。

#### 2. 创建 Cloudflare D1 数据库
1.  登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)。
2.  在左侧菜单选择 **Workers & Pages** -> **D1 SQL Database**。
3.  点击 **Create** 创建一个新数据库，命名为 `vkomari-db`。
4.  创建成功后，请复制页面上显示的 **Database ID** (例如: `xxxx-xxxx-xxxx-xxxx`)，稍后要用。

#### 3. 修改配置文件
1.  回到你 Fork 的 GitHub 仓库。
2.  找到并点击 `wrangler.toml` 文件。
3.  点击右侧的铅笔图标✏️进行编辑。
4.  找到 `[[d1_databases]]` 区域，将 `database_id` 的值修改为你刚刚复制的 ID。
    ```toml
    [[d1_databases]]
    binding = "DB"
    database_name = "vkomari-db"
    database_id = "在这里填入你的Database ID"
    ```
    > **⚠️ 安全提示**: `database_id` 仅是一个资源标识符（类似用户名），**不是密码**。
    > 即使公开了 ID，没有您的 Cloudflare API Token（密钥），任何人也都无法访问您的数据库。请放心提交。

5.  点击右上角 **Commit changes** 保存更改。

#### 4. 配置 GitHub Secrets (密钥)
为了让 GitHub 有权限帮你部署，需要配置 Cloudflare 的访问凭证。

1.  在 GitHub 仓库页面，点击 **Settings** -> **Secrets and variables** -> **Actions**。
2.  点击 **New repository secret**，添加以下两个变量：
    *   **`CLOUDFLARE_API_TOKEN`**:
        *   获取方式：访问 [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens)。
        *   点击 **Create Token** -> 使用 **Edit Cloudflare Workers** 模板。
        *   完成创建后复制 Token。
    *   **`CLOUDFLARE_ACCOUNT_ID`**:
        *   获取方式：在 Cloudflare Dashboard 的 Workers 页面右下角可以找到 **Account ID**。
        *   或者在浏览器地址栏 `dash.cloudflare.com/` 后面的那一串字符就是 Account ID。

#### 5. 触发自动部署
1.  点击仓库的 **Actions** 选项卡。
2.  如果是第一次，可能需要点击绿色按钮 **I understand my workflows, go ahead and enable them**。
3.  由于刚才修改了 `wrangler.toml`，Actions 应该已经自动开始运行并尝试部署了。
4.  等待 Workflow 显示绿色对号 ✅，即表示部署成功。

#### 6. 初始化数据库 (最后一步)
部署完成后，还需要创建数据表才能正常运行。

1.  回到 [Cloudflare Dashboard](https://dash.cloudflare.com/) -> **D1 SQL Database**。
2.  点击 `vkomari-db` -> **Console** 标签页。
3.  复制下文的 [数据库初始化 SQL](#数据库初始化-sql) 中的**所有内容**。
4.  粘贴到 Console 输入框中，点击 **Execute** 执行。
5.  访问你的 Worker 域名（GitHub Actions 日志里会有，或者在 CF 后台查看），开始使用！

---

### 方法二：Wrangler 命令行部署 (简易版)

适合开发者或熟悉命令行的用户。

1.  **环境准备**: 确保本地安装了 Node.js 和 Git。
2.  **克隆与安装**:
    ```bash
    git clone https://github.com/your-username/cf-vkomari.git
    cd cf-vkomari
    npm install
    ```
3.  **创建数据库**:
    ```bash
    npx wrangler login
    npx wrangler d1 create vkomari-db
    ```
    *记录输出的 `database_id`。*
4.  **配置**: 修改 `wrangler.toml` 中的 `database_id`。
5.  **初始化与部署**:
    ```bash
    npx wrangler d1 execute vkomari-db --file=./schema.sql
    npx wrangler deploy
    ```

---

## 数据库初始化 SQL

**请在 Cloudflare D1 Console 中执行以下 SQL 语句：**

```sql
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS nodes;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS templates;

CREATE TABLE groups (
  id INTEGER PRIMARY KEY AUTOINCREMENT, 
  name TEXT, 
  color TEXT, 
  sort_order INTEGER
);

CREATE TABLE nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT, 
  name TEXT, 
  group_id INTEGER, 
  server_address TEXT, 
  client_secret TEXT, 
  client_uuid TEXT, 
  cpu_model TEXT, 
  cpu_cores INTEGER, 
  ram_total INTEGER, 
  swap_total INTEGER, 
  disk_total INTEGER, 
  os TEXT, 
  arch TEXT, 
  virtualization TEXT, 
  region TEXT, 
  kernel_version TEXT, 
  gpu_name TEXT, 
  ipv4 TEXT, 
  ipv6 TEXT, 
  fake_ip TEXT, 
  group_name TEXT, 
  load_profile TEXT, 
  cpu_min REAL, 
  cpu_max REAL, 
  mem_min REAL, 
  mem_max REAL, 
  swap_min REAL, 
  swap_max REAL, 
  disk_min REAL, 
  disk_max REAL, 
  net_min INTEGER, 
  net_max INTEGER, 
  conn_min INTEGER, 
  conn_max INTEGER, 
  proc_min INTEGER, 
  proc_max INTEGER, 
  report_interval INTEGER DEFAULT 3, 
  enabled INTEGER DEFAULT 1, 
  boot_time INTEGER DEFAULT 0, 
  uptime_base INTEGER DEFAULT 0, 
  traffic_reset_day INTEGER DEFAULT 1, 
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  sort_order INTEGER DEFAULT 0
);

CREATE TABLE users (
  id INTEGER PRIMARY KEY, 
  username TEXT UNIQUE, 
  password TEXT, 
  salt TEXT
);

CREATE TABLE templates (
  id INTEGER PRIMARY KEY AUTOINCREMENT, 
  name TEXT, 
  config TEXT, 
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 默认管理员账号 (用户名: admin, 密码: vkomari)
INSERT INTO users (username, password, salt) VALUES ('admin', 'ce751a5323c718e60248219bb18bbe95d0143e5a5a4b3101463635339a1907e9867c6715b4e8080201b8a2792388b02e6d72a53dbb9b50198e651ea479aca728', '3374b09b526978182746180373809613');
```

## 使用手册

### 登录与安全
*   **默认账号**: `admin`
*   **默认密码**: `vkomari`
*   **安全建议**: 首次登录后，系统会弹出提示，请务必立即修改密码。

### 节点管理
*   **添加节点**: 点击右上角“+ 添加节点”。
*   **智能解析**: 复制哪吒探针或 ServerStatus 的安装脚本（如 `bash <(curl ...)`），粘贴到添加窗口的“一键解析”框中，系统会自动提取服务器地址和密钥。
*   **拖拽排序**: 在节点列表页面，长按或直接拖动节点卡片即可进行排序。支持跨分组拖放，拖入新分组后节点会自动归类到该分组。

### 开发调试

本地运行（使用 SQLite 模拟 D1）：
```bash
npm install
node server.js
```
访问 `http://localhost:25770` 进行调试。
