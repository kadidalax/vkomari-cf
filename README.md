 # vKomari-CF 🛰️

 虚拟探针节点管理器 — 同时向 **Komari** 和 **CF-VPS-Monitor** 双面板发送模拟 VPS 实时数据。

 [![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/kadidalax/vkomari-cf)

 ## 特性

 - 🎛️ 双面板并行上报：Komari（每秒） + CF-VPS-Monitor（动态 3s/120s 策略）
 - 🧬 高拟真度虚拟数据生成：多层波形叠加 CPU、真实 RAM/Disk/Network 曲线
 - 🎨 紫色玻璃态 UI：Tailwind CSS + Alpine.js + SortableJS 拖拽排序
 - 🔐 JWT 认证 + 登录限速 + 强制改密
 - 📦 一键解析安装脚本、模板系统、导入/导出
 - ⏱️ Cron 驱动循环模拟，每节点独立 PRNG 种子

 ## 一键部署

 点击上方 **Deploy to Cloudflare Workers** 按钮，然后一直点下一步：

 1. 授权 GitHub，选择仓库
 2. 设置环境变量 `JWT_SECRET`（随机字符串，至少 32 位）
 3. 创建 D1 数据库 `vkomari-db`，执行 `schema.sql` 初始化
 4. 部署完成 ✅

 > 默认登录：`admin` / `vkomari`（首次登录后请立即修改密码）

 ## 本地开发

 ```bash
 npm install
 npm run d1:init    # 初始化本地 D1
 npm run dev        # 启动 → http://localhost:8787
 ```

 ## 项目结构

 ```
 src/
   index.js          # Hono 入口 + Cron 调度
   agent.js          # 虚拟数据生成器
   auth.js           # JWT 中间件 + 登录限速
   db.js             # D1 查询封装
   reporters/
     komari.js       # Komari WS v1 上报
     cfmonitor.js    # CF-VPS-Monitor WS 上报
   routes/
     auth.js         # 登录/改密
     nodes.js        # 节点 CRUD
   utils/
     jwt.js          # JWT + 密码哈希
 public/
   index.html        # SPA 管理界面
   js/               # 前端 JS
 schema.sql          # D1 表结构
 wrangler.toml       # Worker 配置
 ```

 ## 协议兼容

 | 面板 | 上报方式 | 认证 |
 |------|---------|------|
 | Komari | WebSocket 每秒 | `?token=` URL 参数 |
 | CF-VPS-Monitor | WebSocket 动态策略 | `?token=` URL 参数 |
 
 > ⚠ CF Workers WebSocket 不支持自定义升级头，故 `Authorization: Bearer` 改为 `?token=`。如需使用 HTTP 头认证，请在目标 Worker 添加查询参数备选路径。
