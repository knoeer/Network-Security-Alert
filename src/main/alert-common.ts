/**
 * 告警处理公共模块
 * 供 SNMP Trap 和 Syslog 两个接收器共用的告警入库、通知、弹窗逻辑
 */
import { BrowserWindow } from 'electron';
import { executeInsert, queryOne, queryScalar } from './db-helper';
import { showAlert, isAlertPaused } from './alert-manager';
import { playAlertSound } from './alert-sound';
import { classifyMessageDetailed } from './event-classifier';

export interface AlertData {
  attackType: string;
  sourceIp: string;
  sourcePort: number;
  targetIp: string;
  targetPort: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  deviceName: string;
  deviceIp: string;
  description: string;
  oid: string;
  timestamp: string;
  // 原始报文（真正收到的原始数据，不做任何解析）
  rawMessage?: string;
  // 扩展字段（华为 IPS 等结构化日志）
  application?: string;    // 应用
  threatName?: string;     // 威胁名称（如 Web Scanner: Censys）
  action?: string;         // 动作（Block/Detect 等）
  category?: string;       // 威胁类别（Scanner 等）
  protocol?: string;       // 协议
  policy?: string;         // 命中策略
  signId?: number;         // 签名 ID
  // 源地址攻击次数（该 sourceIp 在数据库中的累计攻击次数 + 近24小时次数）
  sourceAttackCount?: number;
  sourceAttackCountToday?: number;
  // 标准攻击类型（跨厂商统一分类：病毒/木马/僵尸网络/扫描工具等，见 event-type-map.json）
  attackCategory?: string;
}

/**
 * 根据设备 IP 查找设备名称
 */
export function findDeviceName(deviceIp: string): string {
  try {
    const device = queryOne<{ name: string }>(
      'SELECT name FROM devices WHERE ip = ?',
      [deviceIp]
    );
    return device?.name || '未知设备';
  } catch {
    return '未知设备';
  }
}

/**
 * 将告警事件写入数据库
 */
export function saveAlertToDatabase(alert: AlertData): number {
  try {
    // 原始报文：优先用真正收到的原始数据（rawMessage），否则回退到构造的结构化 JSON
    let rawData: string;
    if (alert.rawMessage) {
      rawData = alert.rawMessage;
    } else {
      rawData = JSON.stringify({
        attackType: alert.attackType,
        sourceIp: alert.sourceIp,
        sourcePort: alert.sourcePort,
        targetIp: alert.targetIp,
        targetPort: alert.targetPort,
        severity: alert.severity,
        deviceName: alert.deviceName,
        deviceIp: alert.deviceIp,
        description: alert.description || '',
        timestamp: alert.timestamp,
      }, null, 2);
    }

    // 标准攻击类型：若未指定，则按原始报文/描述推断（跨厂商统一分类）
    // 同时记录归类依据来源（user_rule/custom_keyword/builtin/default）
    let classifySource = 'builtin';
    if (!alert.attackCategory) {
      try {
        const raw = alert.rawMessage || alert.description || alert.attackType;
        const detail = classifyMessageDetailed(raw, detectVendorOfAlert(alert));
        alert.attackCategory = detail.category;
        classifySource = detail.source;
      } catch {
        alert.attackCategory = '其他';
      }
    }

    const id = executeInsert(
      `INSERT INTO security_events
        (attack_type, attack_category, source_ip, source_port, target_ip, target_port, severity, device_name, device_ip, description, oid, raw_trap, timestamp, classify_source)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        alert.attackType,
        alert.attackCategory || '其他',
        alert.sourceIp,
        alert.sourcePort,
        alert.targetIp,
        alert.targetPort,
        alert.severity,
        alert.deviceName,
        alert.deviceIp,
        alert.description,
        alert.oid,
        rawData,
        alert.timestamp,
        classifySource,
      ]
    );
    return id;
  } catch (err) {
    console.error('保存告警事件失败:', err);
    return -1;
  }
}

/**
 * 根据告警数据判断厂商（用于标准攻击类型分类）
 */
function detectVendorOfAlert(alert: AlertData): string {
  const raw = alert.rawMessage || alert.description || '';
  if (/%%01/.test(raw)) return 'huawei';
  if (/\bWAF:\s/.test(raw) || /\bdevicename=/.test(raw)) return 'cssos';
  if (/^%(ASA|PIX|FTD)/.test(raw) || /106023|733100/.test(raw)) return 'cisco';
  return '';
}

/**
 * 通知所有窗口（渲染进程）收到新的告警
 */
export function notifyWindows(alert: AlertData): void {
  BrowserWindow.getAllWindows().forEach((win) => {
    if (!win.isDestroyed()) {
      win.webContents.send('alert:received', alert);
    }
  });
}

/**
 * 根据威胁等级判断是否允许弹窗
 * 读取系统设置中该等级的弹窗开关，默认开启
 */
function isPopupEnabledForSeverity(severity: AlertData['severity']): boolean {
  try {
    const keyMap: Record<AlertData['severity'], string> = {
      critical: 'alert_popup_critical',
      high: 'alert_popup_high',
      medium: 'alert_popup_medium',
      low: 'alert_popup_low',
    };
    const key = keyMap[severity];
    if (!key) return true;
    const row = queryOne<{ value: string }>('SELECT value FROM config WHERE key = ?', [key]);
    return row?.value !== 'false'; // 默认开启
  } catch {
    return true;
  }
}

/**
 * 触发告警弹窗和声音提示（按威胁等级控制）
 * 若该等级被设置为不弹窗，则跳过弹窗和声音（仍会入库和横幅通知）
 */
export function triggerAlertPopup(alert: AlertData): void {
  // 暂停弹窗时跳过弹窗与声音（仍会入库和横幅通知）
  if (isAlertPaused()) {
    console.log(`[告警] 弹窗已暂停，跳过弹窗: ${alert.attackType} ${alert.sourceIp} -> ${alert.targetIp}`);
    return;
  }
  if (!isPopupEnabledForSeverity(alert.severity)) {
    console.log(`[告警] 等级 ${alert.severity} 已设置为不弹窗，跳过弹窗`);
    return;
  }
  showAlert(alert);
  playAlertSound(alert.severity);
}

/**
 * 告警聚合去重：相同来源 + 相同攻击类型，在冷却窗口内只弹窗一次（仍入库）。
 * 用于缓解攻击刷屏导致的告警疲劳，例如暴力破解在 1 秒内产生数十条。
 */
const dedupWindow = new Map<string, number>();
// 冷却窗口（毫秒）：同源同类型告警在此时间内不再重复弹窗
const DEDUP_WINDOW_MS = 30 * 1000;
// 每 5 分钟清理一次过期去重记录，防止 Map 无限增长
const DEDUP_CLEAN_INTERVAL_MS = 5 * 60 * 1000;
let lastDedupClean = 0;

function isDuplicateAlert(alert: AlertData): boolean {
  const now = Date.now();
  // 定期清理过期记录
  if (now - lastDedupClean > DEDUP_CLEAN_INTERVAL_MS) {
    for (const [key, ts] of dedupWindow) {
      if (now - ts > DEDUP_WINDOW_MS) dedupWindow.delete(key);
    }
    lastDedupClean = now;
  }

  const key = `${alert.deviceIp}|${alert.attackType}|${alert.sourceIp}|${alert.targetIp}`;
  const last = dedupWindow.get(key);
  if (last && now - last < DEDUP_WINDOW_MS) {
    return true;
  }
  dedupWindow.set(key, now);
  return false;
}

/**
 * 完整的告警处理流程（入库 + 通知 + 弹窗）
 * 入库和横幅通知始终执行；弹窗/声音在去重窗口内被抑制，避免刷屏。
 */
export function processAlert(alert: AlertData): void {
  // 统计该源地址的攻击次数（用于弹窗标识）
  if (alert.sourceIp) {
    try {
      const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      alert.sourceAttackCount = queryScalar<number>(
        'SELECT COUNT(*) FROM security_events WHERE source_ip = ?',
        [alert.sourceIp]
      ) || 0;
      alert.sourceAttackCountToday = queryScalar<number>(
        'SELECT COUNT(*) FROM security_events WHERE source_ip = ? AND timestamp >= ?',
        [alert.sourceIp, last24h]
      ) || 0;
    } catch (err) {
      console.error('统计源地址攻击次数失败:', err);
    }
  }

  saveAlertToDatabase(alert);
  notifyWindows(alert);

  const dup = isDuplicateAlert(alert);
  if (!dup) {
    triggerAlertPopup(alert);
  } else {
    console.log(`[告警去重] 冷却窗口内重复告警已抑制弹窗: ${alert.attackType} ${alert.sourceIp} -> ${alert.targetIp}`);
  }

  console.log(
    `告警处理完成: [${alert.severity}] ${alert.attackType} ${alert.sourceIp}:${alert.sourcePort} -> ${alert.targetIp}:${alert.targetPort}`
  );
}
