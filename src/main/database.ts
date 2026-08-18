/**
 * 数据库层 - 使用 sql.js（WebAssembly SQLite）
 * 纯 JavaScript 实现，无需原生编译，跨平台可用
 */
import path from 'path';
import fs from 'fs';
import { app } from 'electron';
import initSqlJs, { Database as SqlJsDatabase } from 'sql.js';

let db: SqlJsDatabase | null = null;
let dbFilePath: string;

// 数据库备份文件保留的最大份数（超出后删除最旧的）
const DB_BACKUP_KEEP = 5;

// sql.js 的 wasm 文件路径
const wasmPath = path.join(
  __dirname,
  '../../node_modules/sql.js/dist/sql-wasm.wasm'
);

/**
 * 备份当前磁盘上的数据库文件为带时间戳的 .bak。
 * 在每次持久化写入前调用，避免因异常/空库覆盖导致数据不可恢复。
 */
function backupDatabaseFile(): void {
  if (!dbFilePath) return;
  try {
    // 仅当磁盘上确实存在旧数据库时才备份
    if (!fs.existsSync(dbFilePath)) return;
    const srcStat = fs.statSync(dbFilePath);
    if (srcStat.size === 0) return; // 空文件无需备份

    const ts = new Date()
      .toISOString()
      .replace(/[:.]/g, '-')
      .slice(0, 19); // YYYY-MM-DDTHH-MM-SS
    const bakPath = path.join(
      path.dirname(dbFilePath),
      `snmp-alert-${ts}.db.bak`
    );
    fs.copyFileSync(dbFilePath, bakPath);

    // 清理旧备份，只保留最近 DB_BACKUP_KEEP 份
    const bakDir = path.dirname(dbFilePath);
    const backups = fs
      .readdirSync(bakDir)
      .filter((f) => /^snmp-alert-.*\.db\.bak$/.test(f))
      .sort()
      .reverse();
    for (const f of backups.slice(DB_BACKUP_KEEP)) {
      try {
        fs.unlinkSync(path.join(bakDir, f));
      } catch {
        // 忽略清理失败
      }
    }
  } catch (err) {
    console.error('数据库备份失败:', err);
  }
}

/**
 * 初始化数据库
 * 由于 sql.js 是异步加载 wasm，需要异步初始化
 */
export async function getDatabase(): Promise<SqlJsDatabase> {
  if (db) return db;

  const SQL = await initSqlJs({
    locateFile: (file: string) => path.join(path.dirname(wasmPath), file),
  });

  dbFilePath = path.join(app.getPath('userData'), 'snmp-alert.db');

  // 如果数据库文件已存在，加载它
  if (fs.existsSync(dbFilePath)) {
    const fileBuffer = fs.readFileSync(dbFilePath);
    // 若文件损坏（非空但无法解析为合法 SQLite），尝试从最近备份恢复，避免空库/坏库覆盖旧数据
    if (fileBuffer.length > 0 && !isValidSqlite(fileBuffer)) {
      console.warn('检测到数据库文件异常，尝试从备份恢复...');
      const restored = tryRestoreFromBackup();
      if (restored) {
        db = new SQL.Database(fs.readFileSync(dbFilePath));
      } else {
        db = new SQL.Database();
      }
    } else {
      db = new SQL.Database(fileBuffer);
    }
  } else {
    // 主库不存在时，尝试从备份恢复（防止主库被误删后直接新建空库）
    const restored = tryRestoreFromBackup();
    db = restored ? new SQL.Database(fs.readFileSync(dbFilePath)) : new SQL.Database();
  }

  initializeTables(db);
  // 加载旧库后、首次落盘前，把磁盘上原有的数据库备份一份，防止后续异常覆盖导致数据不可恢复
  backupDatabaseFile();
  persistDatabase();
  return db;
}

/**
 * 判断 buffer 是否为合法的 SQLite 数据库文件（头部魔数 "SQLite format 3\0"）
 */
function isValidSqlite(buffer: Buffer): boolean {
  return buffer.length >= 16 && buffer.toString('utf8', 0, 16) === 'SQLite format 3\u0000';
}

/**
 * 查找最近的数据库备份文件
 */
function findLatestBackup(): string | null {
  try {
    const bakDir = path.dirname(dbFilePath);
    const backups = fs
      .readdirSync(bakDir)
      .filter((f) => /^snmp-alert-.*\.db\.bak$/.test(f))
      .sort()
      .reverse();
    return backups.length > 0 ? path.join(bakDir, backups[0]) : null;
  } catch {
    return null;
  }
}

/**
 * 从最近的备份恢复数据库（返回是否恢复成功）
 * 仅当备份文件是合法 SQLite 且非空时恢复
 */
function tryRestoreFromBackup(): boolean {
  try {
    const bakPath = findLatestBackup();
    if (!bakPath) return false;
    const buf = fs.readFileSync(bakPath);
    if (buf.length === 0 || !isValidSqlite(buf)) return false;
    fs.copyFileSync(bakPath, dbFilePath);
    console.warn(`已从备份恢复数据库: ${bakPath}`);
    return true;
  } catch (err) {
    console.error('数据库恢复失败:', err);
    return false;
  }
}

/**
 * 获取已初始化的数据库（同步版本，用于已确保初始化的场景）
 */
export function getDbSync(): SqlJsDatabase {
  if (!db) {
    throw new Error('数据库尚未初始化，请先调用 getDatabase()');
  }
  return db;
}

/**
 * 初始化表结构
 */
function initializeTables(database: SqlJsDatabase): void {
  database.run(`
    CREATE TABLE IF NOT EXISTS security_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      attack_type TEXT NOT NULL,
      attack_category TEXT DEFAULT '其他',
      source_ip TEXT NOT NULL,
      source_port INTEGER DEFAULT 0,
      target_ip TEXT NOT NULL,
      target_port INTEGER DEFAULT 0,
      severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low')),
      device_name TEXT NOT NULL,
      device_ip TEXT NOT NULL,
      description TEXT DEFAULT '',
      oid TEXT DEFAULT '',
      raw_trap TEXT DEFAULT '',
      timestamp TEXT NOT NULL,
      acknowledged INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      ip TEXT NOT NULL,
      port INTEGER DEFAULT 161,
      snmp_version TEXT DEFAULT 'v2c',
      community TEXT DEFAULT 'public',
      snmp_username TEXT DEFAULT '',
      snmp_auth_protocol TEXT DEFAULT 'sha',
      snmp_auth_key TEXT DEFAULT '',
      snmp_priv_protocol TEXT DEFAULT 'aes',
      snmp_priv_key TEXT DEFAULT '',
      device_type TEXT DEFAULT 'firewall',
      location TEXT DEFAULT '',
      description TEXT DEFAULT '',
      status TEXT DEFAULT 'unknown',
      last_checked TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS config (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS ip_location (
      ip TEXT PRIMARY KEY,
      country TEXT DEFAULT '',
      province TEXT DEFAULT '',
      city TEXT DEFAULT '',
      isp TEXT DEFAULT '',
      source TEXT DEFAULT 'unknown',
      update_time DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS device_interfaces (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id INTEGER NOT NULL,
      interfaces TEXT NOT NULL,          -- 接口列表 JSON（DeviceInterface[]）
      sample_time TEXT NOT NULL,         -- 采样时间（ISO UTC）
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_device_interfaces_device ON device_interfaces(device_id);

    CREATE TABLE IF NOT EXISTS user_classify_rules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      vendor TEXT DEFAULT '',
      feature TEXT NOT NULL,
      category TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_user_rule_unique ON user_classify_rules(vendor, feature);
    CREATE INDEX IF NOT EXISTS idx_user_rule_category ON user_classify_rules(category);

    CREATE TABLE IF NOT EXISTS custom_event_types (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      feature_keywords TEXT DEFAULT '[]',
      default_severity TEXT DEFAULT 'medium',
      is_builtin INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_custom_type_name ON custom_event_types(name);

    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);
    CREATE INDEX IF NOT EXISTS idx_events_device ON security_events(device_name);
    CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
  `);

  // 插入默认配置
  const defaultConfigs: [string, string][] = [
    ['trap_port', '162'],
    ['trap_enabled', 'true'],
    ['syslog_port', '514'],
    ['syslog_enabled', 'false'],
    ['alert_sound_enabled', 'true'],
    ['alert_flash_enabled', 'true'],
    ['alert_auto_close', 'false'],
    ['alert_auto_close_seconds', '30'],
    ['alert_popup_critical', 'true'],
    ['alert_popup_high', 'true'],
    ['alert_popup_medium', 'true'],
    ['alert_popup_low', 'true'],
    ['tray_minimize', 'true'],
    ['startup_launch', 'false'],
    ['raw_log_enabled', 'false'],
    ['raw_log_snmp', 'true'],
    ['raw_log_syslog', 'true'],
  ];

  for (const [key, value] of defaultConfigs) {
    database.run('INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)', [key, value]);
  }

  // 迁移：为已有数据库补充 source_port / target_port 字段
  migrateSecurityEvents(database);
  // 迁移：为已有数据库补充 SNMPv3 字段
  migrateDevicesV3(database);

  // 初始化内置事件类型种子数据（与 DEFAULT_TYPES 一致，is_builtin=1）
  // 用 INSERT OR IGNORE 避免重复，后续用户可在此基础上增改
  const builtinTypes = [
    '系统事件', '病毒', '木马', '僵尸网络', '间谍软件', '广告软件', 'CGI攻击', '跨站脚本攻击',
    '注入攻击', '目录遍历', '信息泄漏', '远程文件包含攻击', '溢出攻击', '代码执行',
    '拒绝服务', '扫描工具', '蠕虫', '后门', '分布式拒绝服务', 'webshell', 'Ransomware', '其他'
  ];
  for (const name of builtinTypes) {
    database.run(
      'INSERT OR IGNORE INTO custom_event_types (name, feature_keywords, default_severity, is_builtin) VALUES (?, ?, ?, 1)',
      [name, '[]', 'medium']
    );
  }
}

/**
 * 数据库迁移：为 devices 表补充 SNMPv3 认证字段
 */
function migrateDevicesV3(database: SqlJsDatabase): void {
  try {
    const columns = database.exec('PRAGMA table_info(devices)');
    const columnNames = columns.length > 0 ? columns[0].values.map(v => v[1] as string) : [];

    const v3Columns: [string, string][] = [
      ['snmp_username', "TEXT DEFAULT ''"],
      ['snmp_auth_protocol', "TEXT DEFAULT 'sha'"],
      ['snmp_auth_key', "TEXT DEFAULT ''"],
      ['snmp_priv_protocol', "TEXT DEFAULT 'aes'"],
      ['snmp_priv_key', "TEXT DEFAULT ''"],
    ];
    for (const [name, def] of v3Columns) {
      if (!columnNames.includes(name)) {
        database.run(`ALTER TABLE devices ADD COLUMN ${name} ${def}`);
      }
    }
  } catch (err) {
    console.error('devices 表 SNMPv3 迁移失败:', err);
  }
}

/**
 * 数据库迁移：为旧表补充新增字段
 */
function migrateSecurityEvents(database: SqlJsDatabase): void {
  try {
    // 检查 security_events 表是否已有 source_port 字段
    const columns = database.exec("PRAGMA table_info(security_events)");
    const columnNames = columns.length > 0 ? columns[0].values.map(v => v[1] as string) : [];

    if (!columnNames.includes('source_port')) {
      database.run('ALTER TABLE security_events ADD COLUMN source_port INTEGER DEFAULT 0');
    }
    if (!columnNames.includes('target_port')) {
      database.run('ALTER TABLE security_events ADD COLUMN target_port INTEGER DEFAULT 0');
    }
    if (!columnNames.includes('attack_category')) {
      database.run(`ALTER TABLE security_events ADD COLUMN attack_category TEXT DEFAULT '其他'`);
    }
    // 归类依据来源（user_rule/custom_keyword/builtin/default）
    if (!columnNames.includes('classify_source')) {
      database.run(`ALTER TABLE security_events ADD COLUMN classify_source TEXT DEFAULT 'builtin'`);
    }
  } catch (err) {
    console.error('数据库迁移失败:', err);
  }
}

/**
 * 将数据库持久化到磁盘
 */
export function persistDatabase(): void {
  if (!db || !dbFilePath) return;
  try {
    const data = db.export();
    fs.writeFileSync(dbFilePath, Buffer.from(data));
  } catch (err) {
    console.error('数据库持久化失败:', err);
  }
}

/**
 * 关闭数据库（持久化后关闭）
 */
export function closeDatabase(): void {
  if (db) {
    persistDatabase();
    db.close();
    db = null;
  }
}
