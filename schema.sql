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

-- Default Admin (username: admin, password: vkomari)
-- Salt: 3374b09b526978182746180373809613
-- Hash: ce751a5323c718e60248219bb18bbe95d0143e5a5a4b3101463635339a1907e9867c6715b4e8080201b8a2792388b02e6d72a53dbb9b50198e651ea479aca728
INSERT INTO users (username, password, salt) VALUES ('admin', 'ce751a5323c718e60248219bb18bbe95d0143e5a5a4b3101463635339a1907e9867c6715b4e8080201b8a2792388b02e6d72a53dbb9b50198e651ea479aca728', '3374b09b526978182746180373809613');
