/**
 * 设备离线监测模块
 * 定时轮询所有设备的在线状态，连续多次探测失败判定离线并触发告警，
 * 设备恢复在线后触发恢复通知。
 */
import { BrowserWindow } from 'electron';
import { queryAll, queryOne, execute } from './db-helper';
import { probeDevice } from './device-probe';
import { processAlert, AlertData } from './alert-common';

// 监测配置项 key（存 config 表）
const CFG_KEYS = {
  enabled: 'monitor_enabled',
  interval: 'monitor_interval', // 秒
  failThreshold: 'monitor_fail_threshold', // 连续失败次数
  severity: 'monitor_severity', // 离线告警等级
  recoverNotify: 'monitor_recover_notify', // 恢复在线是否通知
} as const;

export interface MonitorConfig {
  enabled: boolean;
  interval: number; // 轮询间隔（秒）
  failThreshold: number; // 连续失败多少次判定离线
  severity: AlertData['severity']; // 离线告警等级
  recoverNotify: boolean; // 恢复在线是否发送通知
}

export interface MonitorStatus {
  running: boolean;
  lastRunAt: string | null;
  nextRunAt: string | null;
  lastError: string | null;
  devices: Array<{
    id: number;
    name: string;
    ip: string;
    status: string;
    failCount: number;
    lastChecked: string | null;
    monitorEnabled: boolean;
  }>;
}

// 每台设备的内存监测状态
interface DeviceState {
  consecutiveFailures: number; // 当前连续失败次数
  lastStatus: string; // 上次判定状态：online / offline / unknown
  alertSent: boolean; // 是否已发送离线告警（防止重复弹窗）
}

let monitorTimer: NodeJS.Timeout | null = null;
let running = false;
let lastRunAt: string | null = null;
let lastError: string | null = null;
let nextRunAt: string | null = null;

// 设备 id -> 内存监测状态
const deviceStates = new Map<number, DeviceState>();

/** 从 config 表读取监测配置（缺省用默认值） */
export function getMonitorConfig(): MonitorConfig {
  const get = (key: string, def: string): string =>
    queryOne<{ value: string }>('SELECT value FROM config WHERE key = ?', [key])?.value ?? def;
  return {
    enabled: get(CFG_KEYS.enabled, 'true') !== 'false',
    interval: Math.max(10, Number(get(CFG_KEYS.interval, '60')) || 60),
    failThreshold: Math.max(1, Number(get(CFG_KEYS.failThreshold, '3')) || 3),
    severity: (get(CFG_KEYS.severity, 'high') as AlertData['severity']),
    recoverNotify: get(CFG_KEYS.recoverNotify, 'true') !== 'false',
  };
}

/** 保存监测配置并重启定时器 */
export function saveMonitorConfig(config: Partial<MonitorConfig>): { success: boolean } {
  const set = (key: string, value: string) =>
    execute('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', [key, value]);
  if (config.enabled !== undefined) set(CFG_KEYS.enabled, config.enabled ? 'true' : 'false');
  if (config.interval !== undefined) set(CFG_KEYS.interval, String(config.interval));
  if (config.failThreshold !== undefined) set(CFG_KEYS.failThreshold, String(config.failThreshold));
  if (config.severity !== undefined) set(CFG_KEYS.severity, config.severity);
  if (config.recoverNotify !== undefined) set(CFG_KEYS.recoverNotify, config.recoverNotify ? 'true' : 'false');
  restartMonitor();
  return { success: true };
}

/** 通知所有窗口：设备状态变化（用于前端自动刷新） */
function notifyDeviceStatusChanged(device: { id: number; name: string; status: string }): void {
  BrowserWindow.getAllWindows().forEach((win) => {
    if (!win.isDestroyed()) {
      win.webContents.send('monitor:deviceStatusChanged', {
        id: device.id,
        name: device.name,
        status: device.status,
      });
    }
  });
}

/** 发送离线告警事件（入库 + 弹窗 + 声音 + 横幅通知） */
function sendOfflineAlert(device: any, failCount: number, severity: AlertData['severity']): void {
  const alert: AlertData = {
    attackType: '设备离线',
    sourceIp: device.ip,
    sourcePort: 0,
    targetIp: '',
    targetPort: 0,
    severity,
    deviceName: device.name,
    deviceIp: device.ip,
    description: `设备 ${device.name}（${device.ip}）连续 ${failCount} 次探测失败，已判定离线`,
    oid: '',
    timestamp: new Date().toISOString(),
  };
  processAlert(alert);
}

/** 发送恢复在线事件 */
function sendRecoverAlert(device: any): void {
  const alert: AlertData = {
    attackType: '设备恢复',
    sourceIp: device.ip,
    sourcePort: 0,
    targetIp: '',
    targetPort: 0,
    severity: 'low',
    deviceName: device.name,
    deviceIp: device.ip,
    description: `设备 ${device.name}（${device.ip}）已恢复在线`,
    oid: '',
    timestamp: new Date().toISOString(),
  };
  processAlert(alert);
}

/**
 * 执行一轮监测
 * 对所有设备并行探测，统计连续失败次数，状态变化时触发告警/恢复通知
 */
export async function runMonitorOnce(): Promise<{ total: number; online: number; offline: number; failed: number }> {
  if (running) {
    return { total: 0, online: 0, offline: 0, failed: 0 };
  }
  running = true;
  const config = getMonitorConfig();
  const devices = queryAll<any>('SELECT * FROM devices');
  let online = 0;
  let offline = 0;
  let failed = 0;

  try {
    await Promise.all(devices.map(async (device) => {
      // 每台设备独立 try/catch，单台失败不影响其他设备
      try {
        const state = deviceStates.get(device.id) || {
          consecutiveFailures: 0,
          lastStatus: device.status || 'unknown',
          alertSent: false,
        };

        const result = await probeDevice(device);
        const now = new Date().toISOString();
        const isOnline = result.online;

        if (isOnline) {
          // 在线：重置失败计数
          const wasOffline = state.lastStatus === 'offline';
          state.consecutiveFailures = 0;
          state.lastStatus = 'online';
          if (wasOffline && config.recoverNotify) {
            sendRecoverAlert(device);
          }
          online++;
          execute('UPDATE devices SET status = ?, last_checked = ? WHERE id = ?', ['online', now, device.id]);
          notifyDeviceStatusChanged({ id: device.id, name: device.name, status: 'online' });
        } else {
          // 离线：累加失败次数
          state.consecutiveFailures++;
          if (state.consecutiveFailures >= config.failThreshold) {
            state.lastStatus = 'offline';
            if (!state.alertSent) {
              state.alertSent = true;
              sendOfflineAlert(device, state.consecutiveFailures, config.severity);
            }
            offline++;
          } else {
            // 未达阈值，暂不判定离线
            failed++;
          }
          execute('UPDATE devices SET status = ?, last_checked = ? WHERE id = ?', ['offline', now, device.id]);
          notifyDeviceStatusChanged({ id: device.id, name: device.name, status: 'offline' });
        }

        deviceStates.set(device.id, state);
      } catch (err: any) {
        failed++;
        console.error(`[设备监测] 探测 ${device.name} 失败:`, err?.message || err);
      }
    }));

    lastRunAt = new Date().toISOString();
    lastError = null;
  } catch (err: any) {
    lastError = err?.message || '监测执行出错';
    console.error('[设备监测] 执行出错:', err);
  } finally {
    running = false;
    nextRunAt = new Date(Date.now() + config.interval * 1000).toISOString();
  }

  return { total: devices.length, online, offline, failed };
}

/** 启动定时监测 */
export function startDeviceMonitor(): void {
  stopDeviceMonitor();
  const config = getMonitorConfig();
  if (!config.enabled) {
    console.log('[设备监测] 未启用，跳过启动');
    return;
  }
  console.log(`[设备监测] 启动，每 ${config.interval} 秒轮询一次`);
  nextRunAt = new Date(Date.now() + config.interval * 1000).toISOString();
  monitorTimer = setInterval(() => {
    runMonitorOnce();
  }, config.interval * 1000);
  // 启动后立即执行一轮
  runMonitorOnce();
}

/** 停止定时监测 */
export function stopDeviceMonitor(): void {
  if (monitorTimer) {
    clearInterval(monitorTimer);
    monitorTimer = null;
  }
}

/** 配置变化后重启定时器 */
function restartMonitor(): void {
  const config = getMonitorConfig();
  if (config.enabled) {
    startDeviceMonitor();
  } else {
    stopDeviceMonitor();
  }
}

/** 获取当前监测状态（供前端展示） */
export function getMonitorStatus(): MonitorStatus {
  const config = getMonitorConfig();
  const devices = queryAll<any>('SELECT id, name, ip, status, last_checked FROM devices');
  return {
    running: !!monitorTimer,
    lastRunAt,
    nextRunAt,
    lastError,
    devices: devices.map((d) => {
      const state = deviceStates.get(d.id);
      return {
        id: d.id,
        name: d.name,
        ip: d.ip,
        status: d.status,
        failCount: state?.consecutiveFailures ?? 0,
        lastChecked: d.last_checked,
        monitorEnabled: config.enabled,
      };
    }),
  };
}
