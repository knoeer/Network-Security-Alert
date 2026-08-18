/**
 * 接口流量历史监控模块
 * 定时采样设备所有接口的收发字节计数器（ifTable inOctets/outOctets），
 * 与上次采样值做差计算平均速率，入库保存用于绘制流量趋势图。
 *
 * 与 performance-monitor（CPU/内存）共用类似的定时器结构，但独立存储，
 * 避免接口流量采样（需读取完整 ifTable）影响 CPU/内存的轻量采样节奏。
 */
import * as snmp from 'net-snmp';
import { queryAll, queryOne, execute, executeInsert } from './db-helper';
import { createSnmpSession } from './device-probe';

// 配置项 key（存 config 表）
const CFG_KEYS = {
  enabled: 'traffic_enabled',
  interval: 'traffic_interval', // 秒
} as const;

// ifTable 相关 OID（MIB-II）
const IF_TABLE_OID = '1.3.6.1.2.1.2.2';
const IF_COLS = {
  inOctets: 10,
  outOctets: 16,
};

export interface TrafficConfig {
  enabled: boolean;
  interval: number; // 秒
}

export interface TrafficSample {
  id: number;
  device_id: number;
  in_rate: number; // bytes/s
  out_rate: number; // bytes/s
  timestamp: string;
}

let trafficTimer: NodeJS.Timeout | null = null;
let running = false;

// 上次采样的计数器值（deviceId -> { inOctets, outOctets, timestamp }）
const lastCounters = new Map<number, { inOctets: number; outOctets: number; timestamp: number }>();

/** 读取流量监控配置 */
export function getTrafficConfig(): TrafficConfig {
  const get = (key: string, def: string): string =>
    queryOne<{ value: string }>('SELECT value FROM config WHERE key = ?', [key])?.value ?? def;
  return {
    enabled: get(CFG_KEYS.enabled, 'false') !== 'false',
    interval: Math.max(60, Number(get(CFG_KEYS.interval, '300')) || 300),
  };
}

/** 保存流量监控配置并重启定时器 */
export function saveTrafficConfig(config: Partial<TrafficConfig>): { success: boolean } {
  const set = (key: string, value: string) =>
    execute('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', [key, value]);
  if (config.enabled !== undefined) set(CFG_KEYS.enabled, config.enabled ? 'true' : 'false');
  if (config.interval !== undefined) set(CFG_KEYS.interval, String(config.interval));
  restartMonitor();
  return { success: true };
}

/** 初始化流量采样表 */
export function ensureTrafficTable(): void {
  execute(`
    CREATE TABLE IF NOT EXISTS device_traffic (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id INTEGER NOT NULL,
      in_rate REAL DEFAULT 0,
      out_rate REAL DEFAULT 0,
      timestamp TEXT NOT NULL,
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    )
  `);
  execute('CREATE INDEX IF NOT EXISTS idx_traffic_device_time ON device_traffic(device_id, timestamp DESC)');
}

/** 将 varbind 计数类值转为 number（兼容 number/bigint/Buffer） */
function counterToNumber(value: any): number {
  if (value === null || value === undefined) return 0;
  if (typeof value === 'number') return value;
  if (typeof value === 'bigint') {
    const n = Number(value);
    return isNaN(n) ? 0 : n;
  }
  if (Buffer.isBuffer(value)) {
    try {
      if (value.length === 8) return Number(value.readBigUInt64BE(0));
      if (value.length > 0 && value.length <= 8) {
        const padded = Buffer.alloc(8);
        value.copy(padded, 8 - value.length);
        return Number(padded.readBigUInt64BE(0));
      }
    } catch {
      return 0;
    }
  }
  const n = Number(value);
  return isNaN(n) ? 0 : n;
}

/** 读取 ifTable 的收发计数器列，返回 { rowIndex: {col: value} } */
function readIfCounters(session: snmp.Session): Promise<Record<string, Record<string, any>>> {
  return new Promise((resolve) => {
    try {
      session.tableColumns(IF_TABLE_OID, Object.values(IF_COLS), 100, (error: any, table: any) => {
        if (error) {
          resolve({});
          return;
        }
        resolve(table || {});
      });
    } catch {
      resolve({});
    }
  });
}

/**
 * 采集单台设备的总收发速率
 * 通过两次读取计数器（间隔约 1 秒）计算差值速率，或复用上次采样值
 */
function sampleTraffic(device: any): Promise<{ inRate: number; outRate: number } | null> {
  return new Promise((resolve) => {
    let session: snmp.Session | null = null;
    try {
      session = createSnmpSession(device);

      readIfCounters(session).then((table) => {
        // 汇总所有接口的收发计数器
        let inOctets = 0;
        let outOctets = 0;
        for (const row of Object.values(table) as any[]) {
          inOctets += counterToNumber(row[IF_COLS.inOctets]);
          outOctets += counterToNumber(row[IF_COLS.outOctets]);
        }
        session?.close();

        if (Object.keys(table).length === 0) {
          resolve(null);
          return;
        }

        // 与上次采样值做差计算速率
        const now = Date.now();
        const last = lastCounters.get(device.id);
        let inRate = 0;
        let outRate = 0;
        if (last) {
          const dt = (now - last.timestamp) / 1000; // 秒
          if (dt > 0) {
            // 处理计数器回绕
            const wrap32 = 2 ** 32;
            const diffIn = inOctets >= last.inOctets ? inOctets - last.inOctets : inOctets + wrap32 - last.inOctets;
            const diffOut = outOctets >= last.outOctets ? outOctets - last.outOctets : outOctets + wrap32 - last.outOctets;
            inRate = Math.round(diffIn / dt);
            outRate = Math.round(diffOut / dt);
          }
        }
        lastCounters.set(device.id, { inOctets, outOctets, timestamp: now });

        resolve({ inRate, outRate });
      }).catch(() => {
        session?.close();
        resolve(null);
      });
    } catch (err) {
      session?.close();
      resolve(null);
    }
  });
}

/**
 * 执行一轮流量采样（所有在线设备）
 * 首次采样仅记录计数器基准（速率为 0），后续采样计算真实速率
 */
export async function runTrafficSampleOnce(): Promise<{ total: number; sampled: number }> {
  if (running) return { total: 0, sampled: 0 };
  running = true;
  const devices = queryAll<any>('SELECT * FROM devices WHERE status = ?', ['online']);
  let sampled = 0;

  try {
    await Promise.all(devices.map(async (device) => {
      try {
        const result = await sampleTraffic(device);
        if (!result) return;

        const timestamp = new Date().toISOString();
        executeInsert(
          'INSERT INTO device_traffic (device_id, in_rate, out_rate, timestamp) VALUES (?, ?, ?, ?)',
          [device.id, result.inRate, result.outRate, timestamp]
        );
        sampled++;
      } catch (err: any) {
        console.error(`[流量监控] 采样 ${device.name} 失败:`, err?.message || err);
      }
    }));
  } finally {
    running = false;
  }

  return { total: devices.length, sampled };
}

/**
 * 立即对单台设备执行一次流量采样并入库（供设备详情页"刷新"按钮调用）
 * 为避免首次采样速率为 0（只记录基准），内部做两次读取（间隔 1 秒）计算真实速率。
 * @param deviceId 设备 ID
 * @returns { success: boolean; inRate: number; outRate: number }
 */
export async function sampleTrafficNow(deviceId: number): Promise<{ success: boolean; inRate: number; outRate: number }> {
  const device = queryOne<any>('SELECT * FROM devices WHERE id = ?', [deviceId]);
  if (!device) return { success: false, inRate: 0, outRate: 0 };

  // 读取一次计数器基准
  const readOnce = (): Promise<{ inOctets: number; outOctets: number } | null> => {
    return new Promise((resolve) => {
      let session: snmp.Session | null = null;
      try {
        session = createSnmpSession(device);
        readIfCounters(session).then((table) => {
          session?.close();
          if (!table || Object.keys(table).length === 0) { resolve(null); return; }
          let inOctets = 0;
          let outOctets = 0;
          for (const row of Object.values(table) as any[]) {
            inOctets += counterToNumber(row[IF_COLS.inOctets]);
            outOctets += counterToNumber(row[IF_COLS.outOctets]);
          }
          resolve({ inOctets, outOctets });
        }).catch(() => { session?.close(); resolve(null); });
      } catch {
        session?.close();
        resolve(null);
      }
    });
  };

  try {
    const first = await readOnce();
    if (!first) return { success: false, inRate: 0, outRate: 0 };

    // 间隔 1 秒再读一次，计算速率
    await new Promise((r) => setTimeout(r, 1000));
    const second = await readOnce();
    if (!second) return { success: false, inRate: 0, outRate: 0 };

    const wrap32 = 2 ** 32;
    const diffIn = second.inOctets >= first.inOctets ? second.inOctets - first.inOctets : second.inOctets + wrap32 - first.inOctets;
    const diffOut = second.outOctets >= first.outOctets ? second.outOctets - first.outOctets : second.outOctets + wrap32 - first.outOctets;
    const inRate = Math.round(diffIn / 1);
    const outRate = Math.round(diffOut / 1);

    const timestamp = new Date().toISOString();
    executeInsert(
      'INSERT INTO device_traffic (device_id, in_rate, out_rate, timestamp) VALUES (?, ?, ?, ?)',
      [device.id, inRate, outRate, timestamp]
    );
    // 更新内存基准，保持与定时采样一致
    lastCounters.set(device.id, { inOctets: second.inOctets, outOctets: second.outOctets, timestamp: Date.now() });

    return { success: true, inRate, outRate };
  } catch (err: any) {
    console.error(`[流量监控] 手动采样 ${device.name} 失败:`, err?.message || err);
    return { success: false, inRate: 0, outRate: 0 };
  }
}

/** 启动流量监控定时器 */
export function startTrafficMonitor(): void {
  stopTrafficMonitor();
  ensureTrafficTable();
  const config = getTrafficConfig();
  if (!config.enabled) {
    console.log('[流量监控] 未启用，跳过启动');
    return;
  }
  console.log(`[流量监控] 启动，每 ${config.interval} 秒采样一次`);
  trafficTimer = setInterval(() => {
    runTrafficSampleOnce();
  }, config.interval * 1000);
  // 启动后立即采样一轮（记录基准）
  runTrafficSampleOnce();
}

/** 停止流量监控定时器 */
export function stopTrafficMonitor(): void {
  if (trafficTimer) {
    clearInterval(trafficTimer);
    trafficTimer = null;
  }
}

/** 配置变化后重启定时器 */
function restartMonitor(): void {
  const config = getTrafficConfig();
  if (config.enabled) {
    startTrafficMonitor();
  } else {
    stopTrafficMonitor();
  }
}

/** 获取某设备最近 N 条流量采样记录 */
export function getTrafficHistory(deviceId: number, limit = 50): TrafficSample[] {
  return queryAll<TrafficSample>(
    `SELECT id, device_id, in_rate, out_rate, timestamp
     FROM device_traffic
     WHERE device_id = ?
     ORDER BY timestamp DESC
     LIMIT ?`,
    [deviceId, limit]
  ).reverse(); // 升序返回
}

/** 清理过旧的流量采样数据（保留最近 7 天） */
export function cleanupTrafficHistory(): void {
  const cutoff = new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString();
  execute('DELETE FROM device_traffic WHERE timestamp < ?', [cutoff]);
}
