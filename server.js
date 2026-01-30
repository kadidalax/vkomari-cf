const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const WebSocket = require('ws');
const nodePath = require('path');
const fs = require('fs');
const crypto = require('crypto');
const https = require('https');
const http = require('http');

// 原生轻量化 JWT 实现，减少依赖
const jwt = {
    sign: (payload, secret, options = {}) => {
        const header = { alg: 'HS256', typ: 'JWT' };
        if (options.expiresIn) {
            const match = options.expiresIn.match(/^(\d+)h$/);
            if (match) payload.exp = Math.floor(Date.now() / 1000) + (parseInt(match[1]) * 3600);
        }
        const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
        const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
        const signature = crypto.createHmac('sha256', secret)
            .update(encodedHeader + '.' + encodedPayload)
            .digest('base64url');
        return `${encodedHeader}.${encodedPayload}.${signature}`;
    },
    verify: (token, secret, callback) => {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) return callback(new Error('Invalid token'));
            const [header, payload, signature] = parts;
            const expectedSignature = crypto.createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');
            if (signature !== expectedSignature) return callback(new Error('Invalid signature'));
            const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString());
            if (decoded.exp && decoded.exp < Date.now() / 1000) return callback(new Error('Expired'));
            callback(null, decoded);
        } catch (e) { callback(e); }
    }
};





var PORT = 25770;
var DB_PATH = process.env.DB_PATH || nodePath.join(__dirname, 'data', 'database.sqlite');
var JWT_SECRET = process.env.JWT_SECRET || 'vkomari-secret-key-2026';
var LOGIN_ATTEMPTS = new Map();
var LOCKOUT_TIME = 300000;

var dbDir = nodePath.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

var app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(nodePath.join(__dirname, 'public')));

var db = new sqlite3.Database(DB_PATH);

db.serialize(function () {
    db.run('CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, color TEXT, sort_order INTEGER)');
    db.run('CREATE TABLE IF NOT EXISTS nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, group_id INTEGER, server_address TEXT, client_secret TEXT, client_uuid TEXT, cpu_model TEXT, cpu_cores INTEGER, ram_total INTEGER, swap_total INTEGER, disk_total INTEGER, os TEXT, arch TEXT, virtualization TEXT, region TEXT, kernel_version TEXT, gpu_name TEXT, ipv4 TEXT, ipv6 TEXT, fake_ip TEXT, group_name TEXT, load_profile TEXT, cpu_min REAL, cpu_max REAL, mem_min REAL, mem_max REAL, swap_min REAL, swap_max REAL, disk_min REAL, disk_max REAL, net_min INTEGER, net_max INTEGER, conn_min INTEGER, conn_max INTEGER, proc_min INTEGER, proc_max INTEGER, report_interval INTEGER DEFAULT 3, enabled INTEGER DEFAULT 1, boot_time INTEGER DEFAULT 0, uptime_base INTEGER DEFAULT 0, traffic_reset_day INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, sort_order INTEGER DEFAULT 0)');

    db.all('PRAGMA table_info(nodes)', function (err, rows) {
        if (!rows) return;
        var cols = ['gpu_name', 'ipv6', 'group_id', 'uptime_base', 'traffic_reset_day', 'sort_order'];
        cols.forEach(function (c) {
            if (!rows.some(function (r) { return r.name === c; })) db.run('ALTER TABLE nodes ADD COLUMN ' + c + ' TEXT');
        });
        if (!rows.some(function (c) { return c.name === 'group_name'; })) {
            db.run('ALTER TABLE nodes ADD COLUMN group_name TEXT');
        }
        if (!rows.some(function (c) { return c.name === 'fake_ip'; })) {
            db.run('ALTER TABLE nodes ADD COLUMN fake_ip TEXT');
        }
        if (!rows.some(function (c) { return c.name === 'sort_order'; })) {
            db.run('ALTER TABLE nodes ADD COLUMN sort_order INTEGER DEFAULT 0');
        }
    });

    db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, salt TEXT)', [], function () {
        db.get('SELECT * FROM users WHERE username=?', ['admin'], function (e, r) {
            if (!r) {
                var salt = crypto.randomBytes(16).toString('hex');
                var hash = crypto.pbkdf2Sync('vkomari', salt, 10000, 64, 'sha512').toString('hex');
                db.run('INSERT INTO users (username,password,salt) VALUES (?,?,?)', ['admin', hash, salt]);
                console.log('[vKomari] Default admin created (user: admin, pass: vkomari).');
            }
        });
    });

    db.run('CREATE TABLE IF NOT EXISTS templates (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, config TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)');
});

function hashPwd(p, s) {
    s = s || crypto.randomBytes(16).toString('hex');
    return { hash: crypto.pbkdf2Sync(p, s, 10000, 64, 'sha512').toString('hex'), salt: s };
}

function checkLoginAttempts(ip) {
    if (!LOGIN_ATTEMPTS.has(ip)) return true;
    var entry = LOGIN_ATTEMPTS.get(ip);
    if (Date.now() - entry.lastAttempt > LOCKOUT_TIME) { LOGIN_ATTEMPTS.delete(ip); return true; }
    return entry.count < 5;
}

function recordFailedLogin(ip) {
    var entry = LOGIN_ATTEMPTS.get(ip) || { count: 0, lastAttempt: 0 };
    entry.count++; entry.lastAttempt = Date.now();
    LOGIN_ATTEMPTS.set(ip, entry);
}

function auth(req, res, next) {
    var t = (req.headers['authorization'] || '').split(' ')[1];
    if (!t) return res.status(401).json({ error: 'Unauthorized' });
    jwt.verify(t, JWT_SECRET, function (e, u) {
        if (e) return res.status(403).json({ error: 'Invalid token' });
        req.user = u; next();
    });
}

var activeAgents = new Map();

function Agent(config) {
    this.config = config;
    this.connections = []; // 存储多个连接对象 {ws, timers, state, addr}
    this.state = { sendCount: 0, totalUp: 0, totalDown: 0 };
    this.simTimer = null;

    // 确保配置值有效
    var cpu_min = Number(config.cpu_min) || 0.5;
    var cpu_max = Number(config.cpu_max) || 5.0;
    var mem_min = Number(config.mem_min) || 5.0;
    var mem_max = Number(config.mem_max) || 15.0;
    var swap_min = Number(config.swap_min) || 0;
    var swap_max = Number(config.swap_max) || 1.0;
    var disk_min = Number(config.disk_min) || 10.0;
    var disk_max = Number(config.disk_max) || 10.5;

    // 真实性模拟状态 (初始化 - 增加随机偏移，防止多个节点数据雷同)
    var rawRamTotal = Number(config.ram_total) || 1024;
    var rawDiskTotal = Number(config.disk_total) || 10240;

    // 模拟硬件/内核预留: 实际显示的 Total 往往比配置的小 1%-3%
    // 例如 1024MB 实际显示 986MB, 10GB 实际显示 9.6GB
    this.ram_actual = Math.floor(rawRamTotal * (0.96 + Math.random() * 0.02));
    this.disk_actual = parseFloat((rawDiskTotal * (0.94 + Math.random() * 0.03)).toFixed(1));

    var ramTotalMB = this.ram_actual;
    // 模拟 Linux 系统基础开销: 小内存比例更高
    var systemBaseMB = ramTotalMB <= 512 ? (ramTotalMB * 0.4) : (150 + ramTotalMB * 0.1);
    var systemBasePct = (systemBaseMB / ramTotalMB) * 100;

    // 磁盘基础开销模拟 (OS 占用)
    var diskTotalMB = this.disk_actual * 1024; // 这里的 config.disk_total 是 GB
    var osDiskMB = diskTotalMB <= 2048 ? (diskTotalMB * 0.65) : (800 + diskTotalMB * 0.03);
    var osDiskPct = (osDiskMB / diskTotalMB) * 100;

    // 初始值在配置的 min 基础上增加随机偏移
    var initialCpu = cpu_min + (Math.random() * (cpu_max - cpu_min) * 0.2);
    var initialMem = Math.max(mem_min, systemBasePct) + (Math.random() * 2);
    var initialDisk = Math.max(disk_min, osDiskPct) + (Math.random() * 0.5);

    this.sim = {
        cpu: parseFloat(initialCpu.toFixed(1)),
        cpuBurstLevel: 0,
        cpuBurstDecay: 0,

        mem: parseFloat(initialMem.toFixed(1)),
        memLeakAccum: Math.random() * 0.5, // 初始缓存累积随机

        swap: parseFloat(swap_min.toFixed(1)),
        disk: parseFloat(initialDisk.toFixed(1)),

        conn: Math.round((Number(config.conn_min) || 50) + (Math.random() * 10)),
        proc: Math.round((Number(config.proc_min) || 100) + (Math.random() * 5)),

        gpu: 0,
        tickCount: Math.floor(Math.random() * 1000) // 随机初始 tick，使不同节点的正弦波周期错开
    };

    this.startTime = Date.now();
    this.uptimeBase = Number(config.uptime_base) || 0;
    this.uuid = config.client_uuid || crypto.randomUUID();

    // 流量模拟逻辑：总流量与开机时间相关联
    // 获取当月已运行天数（模拟月度流量）
    var dayOfMonth = (new Date()).getDate();
    // 假设平均每天产生的流量 (根据配置的范围取均值，并乘以 86400 转换为日总量)
    var avgNetDaily = ((Number(config.net_min) || 1024) + (Number(config.net_max) || 102400)) / 2 * 86400;
    // 实际模拟运行天数（不超过当月天数）
    var simDays = Math.min(dayOfMonth, (this.uptimeBase / 86400));

    this.state = {
        sendCount: 0,
        totalUp: Math.floor(simDays * avgNetDaily * 0.4 * (Math.random() * 0.5 + 0.75)),
        totalDown: Math.floor(simDays * avgNetDaily * 0.6 * (Math.random() * 0.5 + 0.75))
    };

    // 硬件指纹：计算真实的可用值（非整数，模拟系统预留和文件系统开销）
    this.calculateUsableHardware();

    this.shouldReconnect = false;
}

Agent.prototype.calculateUsableHardware = function () {
    var c = this.config;
    var ramTotalMB = Number(c.ram_total) || 1024;
    var diskTotalMB = Number(c.disk_total) || 10240;
    var swapTotalMB = Number(c.swap_total) || 0;

    // RAM 损耗: 94% - 98% 可用
    var ramFactor = 0.94 + (Math.random() * 0.04);
    // Disk 损耗: 91% - 95% 可用 (包含二进制转换和 FS 开销)
    var diskFactor = 0.91 + (Math.random() * 0.04);

    this.usable = {
        ram: Math.floor(ramTotalMB * ramFactor * 1048576),
        disk: Math.floor(diskTotalMB * diskFactor * 1048576),
        swap: Math.floor(swapTotalMB * 1048576) // Swap 无损耗，设置多少是多少
    };
};

Agent.prototype.rand = function (min, max) {
    min = Number(min) || 0; max = Number(max) || 0;
    if (min > max) { var t = min; min = max; max = t; }
    return Math.floor(Math.random() * (max - min + 1) + min);
};

Agent.prototype.randFloat = function (min, max) {
    min = Number(min) || 0; max = Number(max) || 0;
    if (min > max) { var t = min; min = max; max = t; }
    return Math.random() * (max - min) + min;
};

Agent.prototype.start = function () {
    if (!this.config.enabled) return;
    this.shouldReconnect = true;
    this.startSim();
    this.connect();
};

Agent.prototype.stop = function () {
    this.shouldReconnect = false;
    if (this.simTimer) clearInterval(this.simTimer);
    this.simTimer = null;
    this.connections.forEach(function (c) {
        if (c.timers.heartbeat) clearInterval(c.timers.heartbeat);
        if (c.timers.info) clearInterval(c.timers.info);
        if (c.timers.reconnect) clearTimeout(c.timers.reconnect);
        if (c.ws) { try { c.ws.close(); c.ws.terminate(); } catch (e) { } }
    });
    this.connections = [];
};

Agent.prototype.update = function (newConfig) {
    var self = this;
    var wasEnabled = !!this.config.enabled;
    var needsRestart = this.config.server_address !== newConfig.server_address || this.config.client_secret !== newConfig.client_secret;

    // 检查规格或上报配置变更
    var specFields = ['name', 'cpu_model', 'cpu_cores', 'ram_total', 'swap_total', 'disk_total', 'os', 'arch', 'virtualization', 'region', 'kernel_version', 'gpu_name', 'fake_ip', 'ipv6'];
    var specChanged = specFields.some(function (f) { return String(self.config[f]) !== String(newConfig[f]); });

    this.config = newConfig;

    // 立即生效：重置模拟状态配置 (引入随机性以区分不同节点)
    var ramTotalMB = Number(newConfig.ram_total) || 1024;
    var systemBaseMB = ramTotalMB <= 512 ? (ramTotalMB * 0.4) : (150 + ramTotalMB * 0.1);
    var systemBasePct = (systemBaseMB / ramTotalMB) * 100;

    // 磁盘基础开销
    var diskTotalMB = Number(newConfig.disk_total) || 10240;
    var osDiskMB = diskTotalMB <= 2048 ? (diskTotalMB * 0.65) : (800 + diskTotalMB * 0.03);
    var osDiskPct = (osDiskMB / diskTotalMB) * 100;

    var cMin = Number(newConfig.cpu_min) || 0;
    var cMax = Number(newConfig.cpu_max) || (cMin + 5);
    var mMin = Number(newConfig.mem_min) || 0;
    var dMin = Number(newConfig.disk_min) || 0;

    this.sim.cpu = parseFloat((cMin + (Math.random() * (cMax - cMin) * 0.2)).toFixed(1));
    this.sim.cpuBurstLevel = 0;
    this.sim.cpuBurstDecay = 0;
    this.sim.mem = parseFloat((Math.max(mMin, systemBasePct) + (Math.random() * 2)).toFixed(1));
    this.sim.memLeakAccum = Math.random() * 0.2;
    this.sim.swap = parseFloat((Number(newConfig.swap_min) || 0).toFixed(1));
    this.sim.disk = parseFloat((Math.max(dMin, osDiskPct) + (Math.random() * 0.2)).toFixed(1));
    this.sim.conn = Math.round((Number(newConfig.conn_min) || 50) + (Math.random() * 5));
    this.sim.proc = Math.round((Number(newConfig.proc_min) || 100) + (Math.random() * 3));
    this.sim.tickCount = Math.floor(Math.random() * 1000); // 重置时也随机化 tick，错开周期
    var oldUptimeBase = this.uptimeBase;
    this.uptimeBase = Number(newConfig.uptime_base) || 0;
    this.startTime = Date.now();

    // 如果当前流量为 0 或 NaN，或者 uptime_base 发生了显著变化，重新初始化流量
    if (!this.state.totalUp || isNaN(this.state.totalUp) || Math.abs(this.uptimeBase - oldUptimeBase) > 3600) {
        var dayOfMonth = (new Date()).getDate();
        var avgNetDaily = ((Number(newConfig.net_min) || 1024) + (Number(newConfig.net_max) || 102400)) / 2 * 86400;
        var simDays = Math.min(dayOfMonth, (this.uptimeBase / 86400));
        this.state.totalUp = Math.floor(simDays * avgNetDaily * 0.4 * (Math.random() * 0.5 + 0.75));
        this.state.totalDown = Math.floor(simDays * avgNetDaily * 0.6 * (Math.random() * 0.5 + 0.75));
    }

    // 重新计算硬件指纹（如果规格变了）
    this.calculateUsableHardware();

    if (!newConfig.enabled) {
        this.stop();
    } else if (!wasEnabled || needsRestart) {
        this.stop();
        this.start();
    } else {
        //核心逻辑：如果连接没断，立即强制推送所有信息
        this.connections.forEach(function (c) {
            if (c.online) {
                if (specChanged) self.uploadInfo(c); // 如果硬件规格变了，先推静态信息
                self.sendToConn(c); // 无论如何，立即推一次实时数据
            }
        });

        // 重新启动模拟计时器和连接计时器以匹配新的 interval
        this.startSim(); // 这会按照新的 interval 重新开始循环
    }
};

Agent.prototype.connect = function () {
    var self = this;
    if (!this.shouldReconnect) return;

    var addrs = (this.config.server_address || '').split(/[,，\s]+/).map(s => s.trim()).filter(Boolean);

    addrs.forEach(function (rawAddr) {
        if (self.connections.some(c => c.rawAddr === rawAddr)) return;

        var addr = rawAddr.replace(/\/+$/, '');
        if (!/^(ws|http)s?:\/\//.test(addr)) addr = 'wss://' + addr;
        var wsUrl = addr.replace(/^http/, 'ws') + '/api/clients/report?token=' + encodeURIComponent(self.config.client_secret);
        var httpUrl = addr.replace(/^ws/, 'http');

        var conn = {
            rawAddr: rawAddr,
            baseUrl: httpUrl,
            ws: null,
            timers: { heartbeat: null, info: null, reconnect: null },
            online: false,
            lastError: ''
        };
        self.connections.push(conn);
        self.establishWs(conn);
    });
};

Agent.prototype.establishWs = function (conn) {
    var self = this;
    if (!this.shouldReconnect) return;

    var addr = conn.rawAddr.replace(/\/+$/, '');
    if (!/^(ws|http)s?:\/\//.test(addr)) addr = 'wss://' + addr;
    var wsUrl = addr.replace(/^http/, 'ws') + '/api/clients/report?token=' + encodeURIComponent(this.config.client_secret);

    try {
        conn.ws = new WebSocket(wsUrl, {
            headers: { 'User-Agent': 'komari-agent/0.1.0', 'Origin': conn.baseUrl },
            handshakeTimeout: 10000, rejectUnauthorized: false
        });
        conn.ws.on('open', function () {
            console.log('[vKomari] ✓ Linked: ' + self.config.name + ' -> ' + conn.rawAddr);
            conn.online = true; conn.lastError = '';
            self.uploadInfo(conn);
            self.startLoops(conn);
        });
        conn.ws.on('error', function (e) { conn.lastError = e.message; conn.online = false; });
        conn.ws.on('close', function () {
            conn.online = false; conn.ws = null;
            if (self.shouldReconnect) conn.timers.reconnect = setTimeout(function () { self.establishWs(conn); }, 5000);
        });
    } catch (e) {
        conn.lastError = e.message;
        if (self.shouldReconnect) conn.timers.reconnect = setTimeout(function () { self.establishWs(conn); }, 5000);
    }
};

Agent.prototype.uploadInfo = function (conn) {
    var c = this.config;
    var info = {
        cpu_name: c.cpu_model || 'Intel Xeon',
        cpu_cores: parseInt(c.cpu_cores) || 2,
        arch: c.arch || 'amd64',
        os: c.os || 'Linux',
        virtualization: c.virtualization || 'kvm',
        kernel_version: c.kernel_version || '',
        gpu_name: c.gpu_name || '',
        mem_total: this.usable.ram,
        swap_total: this.usable.swap,
        disk_total: this.usable.disk,
        ipv4: c.fake_ip || 'Hidden',
        ipv6: c.ipv6 || '',
        region: (c.region || 'CN').toUpperCase(),
        version: '1.2.0'
    };

    var self = this;
    try {
        var paths = ['/api/v1/client/upload-basic-info', '/api/clients/uploadBasicInfo'];
        paths.forEach(function (path) {
            var url = new URL(conn.baseUrl + path + '?token=' + encodeURIComponent(c.client_secret));
            var postData = JSON.stringify(info);
            var req = (url.protocol === 'https:' ? https : http).request({
                hostname: url.hostname, port: url.port || (url.protocol === 'https:' ? 443 : 80),
                path: url.pathname + url.search,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Content-Length': Buffer.byteLength(postData),
                    'User-Agent': 'komari-agent/1.2.0'
                },
                rejectUnauthorized: false
            }, function (res) {
                var body = '';
                res.on('data', function (chunk) { body += chunk; });
                res.on('end', function () {
                    // Silently fail if one path doesn't work, as we support two versions
                });
            });
            req.on('error', function (err) { });
            req.write(postData);
            req.end();
        });
    } catch (e) { }
};

Agent.prototype.startLoops = function (conn) {
    var self = this;
    if (conn.timers.heartbeat) clearInterval(conn.timers.heartbeat);
    if (conn.timers.info) clearInterval(conn.timers.info);

    var iv = Math.max(1000, Math.min(10000, (this.config.report_interval || 1) * 1000));
    this.sendToConn(conn);
    conn.timers.heartbeat = setInterval(function () {
        if (conn.ws && conn.ws.readyState === WebSocket.OPEN) self.sendToConn(conn);
    }, iv);
    conn.timers.info = setInterval(function () {
        if (conn.online) self.uploadInfo(conn);
    }, 300000);
};

Agent.prototype.startSim = function () {
    var self = this;
    if (this.simTimer) clearInterval(this.simTimer);
    var iv = Math.max(1000, Math.min(10000, (this.config.report_interval || 1) * 1000));
    this.simTimer = setInterval(function () { self.updateLiveStats(); }, iv);
};

Agent.prototype.sendData = function () {
    // Legacy support or internal calls
    this.updateLiveStats();
};

Agent.prototype.updateLiveStats = function () {
    var c = this.config;
    var now = new Date();
    var hour = now.getHours();
    var minute = now.getMinutes();
    var interval = c.report_interval || 3;
    this.sim.tickCount++;

    // 1. 负载特征（基于 profile）
    var profile = (c.load_profile || 'low').toLowerCase();
    var profileMap = {
        'low': { jitter: 0.8, spikeChance: 0.01, burstScale: 0.3, inertia: 0.85, netMultiplier: 10 },
        'mid': { jitter: 2.5, spikeChance: 0.05, burstScale: 0.7, inertia: 0.70, netMultiplier: 1 },
        'high': { jitter: 5.0, spikeChance: 0.15, burstScale: 1.2, inertia: 0.50, netMultiplier: 1 }
    };
    var p = profileMap[profile] || profileMap['low'];

    // 2. CPU 核心算法 (日夜周期 + 随机游走 + 突变)
    // 增加正弦波模拟业务周期性波动
    var timeFactor = (Math.sin(((hour - 9) / 24) * 2 * Math.PI) + 1) / 2; // 0-1
    var waveFactor = Math.sin(this.sim.tickCount / 20) * 0.05; // 周期性微弱波动

    var cpuMin = Number(c.cpu_min) || 0.5;
    var cpuMax = Number(c.cpu_max) || 100;
    var range = cpuMax - cpuMin;

    // 基础波动目标值
    var target = cpuMin + (range * (0.1 + waveFactor) * timeFactor);

    // 定时任务 (Cron) 模拟: 每 30 分钟一个小高峰
    if (minute % 30 === 0 && now.getSeconds() < 15) target += range * 0.15;

    // 随机突发处理
    if (this.sim.cpuBurstDecay <= 0 && Math.random() < p.spikeChance) {
        this.sim.cpuBurstLevel = this.randFloat(range * 0.2, range * 0.6) * p.burstScale;
        this.sim.cpuBurstDecay = this.rand(4, 12);
    }

    target += this.sim.cpuBurstLevel;

    // 指数平滑算法 (惯性过渡) - 降低 inertia 使其不那么平滑
    this.sim.cpu = this.sim.cpu * p.inertia + target * (1 - p.inertia);
    this.sim.cpu += (Math.random() * 2 - 1) * p.jitter; // 增加高频抖动

    // 突发衰减
    if (this.sim.cpuBurstDecay > 0) {
        this.sim.cpuBurstDecay--;
    } else {
        this.sim.cpuBurstLevel *= 0.8;
    }
    this.sim.cpu = parseFloat(Math.max(cpuMin, Math.min(cpuMax, this.sim.cpu)).toFixed(1));

    // 3. 内存模拟 (重点：增加真实的基础开销)
    var ramTotalMB = Number(c.ram_total) || 1024;
    // 模拟 Linux 系统基础开销 (OS + 基础服务)
    var systemBaseMB = ramTotalMB <= 512 ? (ramTotalMB * 0.4) : (150 + ramTotalMB * 0.1);
    var systemBasePct = (systemBaseMB / ramTotalMB) * 100;

    var memMin = Math.max(Number(c.mem_min) || 0, systemBasePct);
    var memMax = Math.max(Number(c.mem_max) || 0, memMin + 2);

    // 内存跟随 CPU 负载有一定正相关，但有较大延迟
    var memTarget = memMin + (this.sim.cpu / 100) * (memMax - memMin) * 0.3;

    // 内存泄漏/缓存累积模拟
    if (this.sim.tickCount % 60 === 0) {
        this.sim.memLeakAccum += 0.02 * (profile === 'high' ? 2 : 1);
        if (Math.random() < 0.005) this.sim.memLeakAccum *= 0.5; // GC
    }

    this.sim.mem = this.sim.mem * 0.98 + (memTarget + this.sim.memLeakAccum) * 0.02 + (Math.random() * 0.1 - 0.05);
    this.sim.mem = parseFloat(Math.max(memMin, Math.min(memMax, this.sim.mem)).toFixed(1));

    // 4. 网络模拟 (流量跟随 CPU 负载 + 随机流量爆发)
    var netMin = Number(c.net_min) || 0;
    var netMax = Number(c.net_max) || 1048576;
    var netRange = netMax - netMin;

    var netLoadRatio = (this.sim.cpu - cpuMin) / (range || 1);
    var currentNet = netMin + (netRange * 0.1 * timeFactor) + (netRange * 0.6 * netLoadRatio);

    if (Math.random() < 0.03 * p.burstScale) currentNet += netRange * this.randFloat(0.3, 0.7);

    this.state.currentUp = (currentNet * 0.4 + (Math.random() * (netMin + 100) * 0.2)) * (p.netMultiplier || 1);
    this.state.currentDown = (currentNet * 0.6 + (Math.random() * (netMin + 100) * 0.2)) * (p.netMultiplier || 1);
    this.state.totalUp += this.state.currentUp * interval;
    this.state.totalDown += this.state.currentDown * interval;

    // 流量月度重置
    var resetDay = Number(c.traffic_reset_day) || 1;
    if (now.getDate() === resetDay && hour === 0 && minute === 0 && now.getSeconds() < interval) {
        this.state.totalUp = 0;
        this.state.totalDown = 0;
    }

    // 5. 联动数据 (连接数/进程数/Swap/Disk)
    this.sim.conn = Math.round((Number(c.conn_min) || 10) + (this.sim.cpu * 2.5 * p.burstScale) + (Math.random() * 5));
    this.sim.proc = Math.round((Number(c.proc_min) || 50) + (this.sim.cpu * 0.3) + (Math.random() * 3));
    var swapVal = (this.sim.mem > 80) ? (this.sim.mem - 80) * 1.2 : (Number(c.swap_min) || 0);
    this.sim.swap = parseFloat(swapVal.toFixed(1));

    // 磁盘：模拟操作系统占用 + 用户设置的最小占用
    var diskTotalMB = Number(c.disk_total) || 10240;
    var osUsageMB = diskTotalMB <= 2048 ? (diskTotalMB * 0.65) : (800 + diskTotalMB * 0.03);
    var osUsagePct = (osUsageMB / diskTotalMB) * 100;
    var dMin = Math.max(Number(c.disk_min) || 0, osUsagePct);

    // 模拟磁盘随时间缓慢增长
    if (this.sim.tickCount % 60 === 0) this.sim.disk += 0.001;
    var diskWave = Math.sin(this.sim.tickCount / 100) * 0.02;
    this.sim.disk = parseFloat(Math.max(dMin, Math.min(99.8, this.sim.disk + diskWave)).toFixed(1));

    // 6. GPU 模拟
    if (c.gpu_name) {
        var gpuVal = this.sim.gpu * 0.9 + (this.sim.cpu * 0.8) * 0.1 + (Math.random() * 0.5);
        this.sim.gpu = parseFloat(gpuVal.toFixed(1));
    }
};

Agent.prototype.sendToConn = function (conn) {
    var c = this.config;
    var ramTotal = Math.floor((Number(c.ram_total) || 1024) * 1048576);
    var swapTotal = Math.floor((Number(c.swap_total) || 0) * 1048576);
    var diskTotal = Math.floor((Number(c.disk_total) || 10240) * 1048576);

    var data = {
        type: 'report',
        cpu: {
            name: c.cpu_model || 'Intel Xeon',
            cores: parseInt(c.cpu_cores) || 2,
            arch: c.arch || 'amd64',
            usage: parseFloat(this.sim.cpu.toFixed(1))
        },
        ram: {
            total: this.usable.ram,
            used: Math.round(this.usable.ram * this.sim.mem / 100)
        },
        swap: {
            total: this.usable.swap,
            used: Math.round(this.usable.swap * this.sim.swap / 100)
        },
        load: {
            load1: parseFloat(((this.sim.cpu / 100) * (c.cpu_cores || 1) * 1.05).toFixed(1)),
            load5: parseFloat(((this.sim.cpu / 100) * (c.cpu_cores || 1) * 0.95).toFixed(1)),
            load15: parseFloat(((this.sim.cpu / 100) * (c.cpu_cores || 1) * 0.9).toFixed(1))
        },
        disk: {
            total: this.usable.disk,
            used: Math.round(this.usable.disk * this.sim.disk / 100)
        },
        network: {
            up: Math.floor(this.state.currentUp || 0),
            down: Math.floor(this.state.currentDown || 0),
            totalUp: Math.floor(this.state.totalUp),
            totalDown: Math.floor(this.state.totalDown)
        },
        connections: {
            tcp: this.sim.conn,
            udp: this.rand(0, 5)
        },
        gpu: {
            count: c.gpu_name ? 1 : 0,
            average_usage: c.gpu_name ? parseFloat(this.sim.gpu.toFixed(1)) : 0,
            detailed_info: c.gpu_name ? [{
                name: c.gpu_name,
                memory_total: 8589934592,
                memory_used: Math.floor(8589934592 * (this.sim.gpu / 100)),
                utilization: parseFloat(this.sim.gpu.toFixed(1)),
                temperature: 40 + Math.floor(this.sim.gpu / 2)
            }] : []
        },
        uptime: this.uptimeBase + Math.floor((Date.now() - this.startTime) / 1000),
        process: this.sim.proc,
        message: ''
    };
    try { conn.ws.send(JSON.stringify(data)); this.state.sendCount++; } catch (e) { }
};

Agent.prototype.status = function () {
    var online = this.connections.some(c => c.online);
    var errors = this.connections.map(c => c.lastError).filter(Boolean).join('; ');
    return { online: online, sendCount: this.state.sendCount, uptime: Math.floor(Date.now() / 1000) - this.bootTime, lastError: errors };
};

function loadNodes() {
    db.all('SELECT * FROM nodes', [], function (e, rows) {
        if (!e && rows) rows.forEach(function (r) {
            if (activeAgents.has(r.id)) activeAgents.get(r.id).stop();
            var a = new Agent(r); activeAgents.set(r.id, a); a.start();
        });
        console.log('[vKomari] Loaded ' + (rows ? rows.length : 0) + ' nodes');
    });
}

app.post('/api/login', function (req, res) {
    var ip = req.ip;
    if (!checkLoginAttempts(ip)) return res.status(429).json({ error: 'Too many attempts' });
    var username = req.body.username, password = req.body.password;
    db.get('SELECT * FROM users WHERE username=?', [username], function (e, u) {
        if (e || !u) { recordFailedLogin(ip); return res.status(401).json({ error: 'Invalid' }); }
        var h = hashPwd(password, u.salt);
        if (h.hash !== u.password) { recordFailedLogin(ip); return res.status(401).json({ error: 'Invalid' }); }
        var token = jwt.sign({ username: u.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token: token, isDefault: h.hash === hashPwd('vkomari', u.salt).hash });
    });
});

app.post('/api/change-password', auth, function (req, res) {
    var newPassword = req.body.newPassword;
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Too short' });
    var h = hashPwd(newPassword);
    db.run('UPDATE users SET password=?, salt=?', [h.hash, h.salt], function (e) { res.json({ success: !e }); });
});

app.get('/api/nodes', auth, function (req, res) {
    db.all('SELECT * FROM nodes ORDER BY sort_order ASC, id DESC', [], function (e, rows) {
        if (e) return res.status(500).json({ error: e.message });
        var result = rows.map(function (r) {
            var status = activeAgents.has(r.id) ? activeAgents.get(r.id).status() : { online: false };
            return Object.assign({}, r, status);
        });
        res.json(result);
    });
});

app.post('/api/toggle', auth, function (req, res) {
    var id = req.body.id, enabled = req.body.enabled ? 1 : 0;
    db.run('UPDATE nodes SET enabled=? WHERE id=?', [enabled, id], function (e) {
        if (e) return res.status(500).json({ error: e.message });
        if (activeAgents.has(id)) {
            var agent = activeAgents.get(id);
            agent.update(Object.assign({}, agent.config, { enabled: enabled }));
        }
        res.json({ status: 'ok' });
    });
});

app.post('/api/nodes', auth, function (req, res) {
    var d = req.body;
    if (!d.client_uuid) d.client_uuid = crypto.randomUUID();
    if (!d.id && !d.fake_ip) d.fake_ip = '';

    // 如果没有填开机日期（uptime_base 为 0），则随机生成一个 20-60 天的时间
    if (!d.uptime_base || d.uptime_base == 0) {
        d.uptime_base = Math.floor(Math.random() * 7 + 1) * 86400;
    }

    var fields = 'name,server_address,client_secret,client_uuid,cpu_model,cpu_cores,ram_total,swap_total,disk_total,os,arch,virtualization,region,kernel_version,load_profile,cpu_min,cpu_max,mem_min,mem_max,swap_min,swap_max,disk_min,disk_max,net_min,net_max,conn_min,conn_max,proc_min,proc_max,report_interval,enabled,boot_time,fake_ip,group_name,gpu_name,ipv6,traffic_reset_day,uptime_base,sort_order';
    var keys = fields.split(',');
    var values = keys.map(function (k) { return d[k] === undefined ? null : d[k]; });

    if (d.id) {
        var setClause = keys.map(function (k) { return k + '=?'; }).join(',');
        var sql = 'UPDATE nodes SET ' + setClause + ' WHERE id=?';
        values.push(d.id);
        db.run(sql, values, function (e) {
            if (e) { console.error(e); return res.status(500).json({ error: e.message }); }
            var cfg = Object.assign({}, d, { id: d.id });
            if (activeAgents.has(d.id)) activeAgents.get(d.id).update(cfg);
            else { var a = new Agent(cfg); activeAgents.set(d.id, a); a.start(); }
            res.json({ status: 'updated' });
        });
    } else {
        var placeholders = keys.map(function () { return '?'; }).join(',');
        var sql = 'INSERT INTO nodes (' + keys.join(',') + ') VALUES (' + placeholders + ')';
        db.run(sql, values, function (e) {
            if (e) { console.error(e); return res.status(500).json({ error: e.message }); }
            var id = this.lastID;
            var a = new Agent(Object.assign({}, d, { id: id }));
            activeAgents.set(id, a); a.start();
            res.json({ status: 'created', id: id });
        });
    }
});

app.post('/api/batch', auth, function (req, res) {
    var en = req.body.action === 'start' ? 1 : 0;
    db.run('UPDATE nodes SET enabled=?', [en], function (e) {
        if (e) return res.status(500).json({ error: e.message });
        activeAgents.forEach(function (a) { a.update(Object.assign({}, a.config, { enabled: en })); });
        res.json({ status: 'ok' });
    });
});

// Reorder Nodes
app.post('/api/reorder', auth, function (req, res) {
    var updates = req.body.updates;
    if (!Array.isArray(updates)) return res.status(400).json({ error: 'Invalid data' });

    db.serialize(function () {
        db.run('BEGIN TRANSACTION');
        var stmt = db.prepare('UPDATE nodes SET sort_order = COALESCE(?, sort_order), group_name = COALESCE(?, group_name) WHERE id = ?');
        updates.forEach(function (u) {
            if (u.id) {
                stmt.run(u.sort_order, u.group_name, u.id);
            }
        });
        stmt.finalize();
        db.run('COMMIT', function (e) {
            if (e) return res.status(500).json({ error: e.message });
            res.json({ status: 'ok', count: updates.length });
        });
    });
});

app.post('/api/groups/rename', auth, function (req, res) {
    var oldName = req.body.oldName || '';
    var newName = req.body.newName || '';
    if (oldName === newName) return res.json({ status: 'no_change' });

    db.run('UPDATE nodes SET group_name=? WHERE group_name=?', [newName, oldName], function (e) {
        if (e) return res.status(500).json({ error: e.message });

        // Update local agents' config
        activeAgents.forEach(function (a) {
            if (a.config.group_name === oldName) {
                a.config.group_name = newName;
            }
        });

        res.json({ status: 'ok', updated: this.changes });
    });
});

app.get('/api/templates', auth, function (req, res) {
    db.all('SELECT * FROM templates ORDER BY id DESC', [], function (e, rows) {
        if (e) return res.status(500).json({ error: e.message });
        res.json(rows.map(r => ({ id: r.id, name: r.name, config: JSON.parse(r.config) })));
    });
});

app.post('/api/templates', auth, function (req, res) {
    var name = req.body.name, config = JSON.stringify(req.body.config);
    db.run('INSERT INTO templates (name, config) VALUES (?, ?)', [name, config], function (e) {
        if (e) return res.status(500).json({ error: e.message });
        res.json({ status: 'ok', id: this.lastID });
    });
});

app.post('/api/templates/delete', auth, function (req, res) {
    var id = req.body.id;
    db.run('DELETE FROM templates WHERE id=?', [id], function (e) {
        res.json({ status: 'ok' });
    });
});

app.post('/api/import', auth, function (req, res) {
    var nodes = req.body.nodes;
    if (!Array.isArray(nodes)) return res.status(400).json({ error: 'Invalid data' });

    var fields = 'name,server_address,client_secret,client_uuid,cpu_model,cpu_cores,ram_total,swap_total,disk_total,os,arch,virtualization,region,kernel_version,load_profile,cpu_min,cpu_max,mem_min,mem_max,swap_min,swap_max,disk_min,disk_max,net_min,net_max,conn_min,conn_max,proc_min,proc_max,report_interval,enabled,boot_time,fake_ip,group_name,gpu_name,ipv6,traffic_reset_day,uptime_base,sort_order';
    var keys = fields.split(',');

    nodes.forEach(function (n) {
        if (!n.client_uuid) n.client_uuid = crypto.randomUUID();
        if (!n.fake_ip) n.fake_ip = '';
        if (!n.uptime_base || n.uptime_base == 0) {
            n.uptime_base = Math.floor(Math.random() * 7 + 1) * 86400;
        }
        var values = keys.map(function (k) { return n[k] === undefined ? null : n[k]; });
        var placeholders = keys.map(function () { return '?'; }).join(',');
        var sql = 'INSERT INTO nodes (' + keys.join(',') + ') VALUES (' + placeholders + ')';
        db.run(sql, values, function (e) {
            if (!e) {
                var id = this.lastID;
                var a = new Agent(Object.assign({}, n, { id: id }));
                activeAgents.set(id, a); a.start();
            }
        });
    });
    res.json({ status: 'imported' });
});

app.post('/api/delete', auth, function (req, res) {
    var id = req.body.id;
    db.run('DELETE FROM nodes WHERE id=?', [id], function (e) {
        if (e) return res.status(500).json({ error: e.message });
        if (activeAgents.has(id)) { activeAgents.get(id).stop(); activeAgents.delete(id); }
        res.json({ status: 'deleted' });
    });
});

// /api/presets 已迁移至前端 dropdown_data.js

app.listen(PORT, function () { console.log('[vKomari] v0.1.0 running on port ' + PORT); loadNodes(); });
