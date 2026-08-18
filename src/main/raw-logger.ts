/**
 * 原始报文保存模块（调试用途）
 * 将 SNMP Trap 和 Syslog 收到的原始报文原样保存为 txt 文件
 * 不做任何解析、转换或修改
 */
import fs from 'fs';
import path from 'path';
import { queryOne } from './db-helper';

// 默认保存目录（用户数据目录下 raw_logs）
const DEFAULT_BASE_DIR = path.join(process.env.APPDATA || '.', 'snmp-security-alert', 'raw_logs');

export type RawSource = 'snmp' | 'syslog';

interface RawLogConfig {
  enabled: boolean;
  baseDir: string;
  snmpEnabled: boolean;
  syslogEnabled: boolean;
}

/**
 * 读取原始报文保存配置（从数据库 config 表）
 */
function getConfig(): RawLogConfig {
  const getVal = (key: string, defaultVal: string) =>
    queryOne<{ value: string }>('SELECT value FROM config WHERE key = ?', [key])?.value || defaultVal;

  return {
    enabled: getVal('raw_log_enabled', 'false') === 'true',
    baseDir: getVal('raw_log_dir', DEFAULT_BASE_DIR),
    snmpEnabled: getVal('raw_log_snmp', 'true') === 'true',
    syslogEnabled: getVal('raw_log_syslog', 'true') === 'true',
  };
}

/**
 * 确保目录存在
 */
function ensureDir(dir: string): boolean {
  try {
    fs.mkdirSync(dir, { recursive: true });
    return true;
  } catch (err) {
    console.error('创建原始报文目录失败:', err);
    return false;
  }
}

/**
 * 生成安全的文件名（替换非法字符）
 */
function safeFileName(name: string): string {
  return name.replace(/[\\/:*?"<>|]/g, '_').replace(/\s+/g, '_');
}

/**
 * 保存原始报文
 * @param source 报文来源（snmp/syslog）
 * @param rawContent 原始报文内容
 * @param deviceIp 来源设备 IP
 * @param extraInfo 附加信息（用于文件名，如 OID/类型）
 */
export function saveRawLog(
  source: RawSource,
  rawContent: string | Buffer,
  deviceIp: string,
  extraInfo?: string
): string | null {
  try {
    const config = getConfig();
    if (!config.enabled) return null;
    if (source === 'snmp' && !config.snmpEnabled) return null;
    if (source === 'syslog' && !config.syslogEnabled) return null;

    // 按协议分目录
    const sourceDir = path.join(config.baseDir, source);
    if (!ensureDir(sourceDir)) return null;

    // 按天分目录（便于排查，使用本地时区日期）
    const now = new Date();
    const dayDir = path.join(
      sourceDir,
      `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`
    );
    if (!ensureDir(dayDir)) return null;

    // 文件名：时间戳 + 设备IP + 序号，避免重名
    const ts = now.toISOString().replace(/[:.]/g, '-').slice(0, 23);
    const dev = safeFileName(deviceIp || 'unknown');
    const seq = Math.floor(Math.random() * 100000);
    const extra = extraInfo ? `_${safeFileName(extraInfo)}` : '';
    const filename = `${ts}_${dev}${extra}_${seq}.txt`;
    const filePath = path.join(dayDir, filename);

    // 原始内容（不做修改）
    const content = Buffer.isBuffer(rawContent) ? rawContent : Buffer.from(String(rawContent), 'utf-8');

    // 附加元信息头（仅用于调试定位，不修改报文本体）
    const header = [
      `# 原始报文调试文件`,
      `# 时间: ${now.toLocaleString('zh-CN')}`,
      `# 来源协议: ${source === 'snmp' ? 'SNMP Trap' : 'Syslog'}`,
      `# 设备IP: ${deviceIp || '未知'}`,
      `# 以下为原始报文内容（未做任何修改）:`,
      `# -------------------------------------------------`,
      ``,
    ].join('\n');

    fs.writeFileSync(filePath, header + content.toString('utf-8') + '\n');
    return filePath;
  } catch (err) {
    console.error('保存原始报文失败:', err);
    return null;
  }
}

/**
 * 获取原始报文保存配置
 */
export function getRawLogConfig(): RawLogConfig {
  return getConfig();
}

/**
 * 更新原始报文保存配置
 */
export function updateRawLogConfig(config: Partial<RawLogConfig>): void {
  const { execute } = require('./db-helper');
  const save = (key: string, value: string) => {
    execute('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', [key, value]);
  };

  if (config.enabled !== undefined) save('raw_log_enabled', config.enabled ? 'true' : 'false');
  if (config.baseDir) save('raw_log_dir', config.baseDir);
  if (config.snmpEnabled !== undefined) save('raw_log_snmp', config.snmpEnabled ? 'true' : 'false');
  if (config.syslogEnabled !== undefined) save('raw_log_syslog', config.syslogEnabled ? 'true' : 'false');
}
