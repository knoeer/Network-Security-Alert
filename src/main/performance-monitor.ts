/**
 * 设备性能监控模块
 * 通过 SNMP 主动轮询读取设备 CPU / 内存使用率（HOST-RESOURCES-MIB），
 * 采样入库，并支持超阈值告警。
 *
 * CPU 使用率：hrProcessorLoad（1.3.6.1.2.1.25.3.3.1.2），多核需取平均。
 * 内存使用率：hrStorage（1.3.6.1.2.1.25.2.3），通过 hrStorageType 定位物理内存/虚拟内存，
 *             用 hrStorageUsed / hrStorageSize 计算百分比。
 */
import * as snmp from 'net-snmp';
import { queryAll, queryOne, execute, executeInsert } from './db-helper';
import { processAlert, AlertData } from './alert-common';
import { createSnmpSession } from './device-probe';

// 配置项 key（存 config 表）
const CFG_KEYS = {
  enabled: 'perf_enabled',
  interval: 'perf_interval', // 秒
  cpuThreshold: 'perf_cpu_threshold', // CPU 告警阈值（%）
  memThreshold: 'perf_mem_threshold', // 内存告警阈值（%）
} as const;

// HOST-RESOURCES-MIB OID
const OID = {
  hrProcessorLoad: '1.3.6.1.2.1.25.3.3.1.2', // CPU 负载（多行，每核一个）
  hrStorageTable: '1.3.6.1.2.1.25.2.3', // 存储表
} as const;

// hrStorageTable 列索引
const STORAGE_COLS = {
  type: 1, // hrStorageType
  descr: 3, // hrStorageDescr
  allocationUnits: 4, // hrStorageAllocationUnits
  size: 5, // hrStorageSize
  used: 6, // hrStorageUsed
} as const;

// hrStorageType 物理内存 OID（RAM = 1.3.6.1.2.1.25.2.1.2）
const RAM_TYPE_OID = '1.3.6.1.2.1.25.2.1.2';

// 华为 USG / VRP 私有设备性能 MIB（HUAWEI-DEVICE-STATISTICS-MIB）
// 表：hwDevicePerformanceTable = 1.3.6.1.4.1.2011.5.25.31.1.1.1
//   行结构：1.3.6.1.4.1.2011.5.25.31.1.1.1.1.<列>.<frame>.<slot>.<cpu>
//   列 1  = hwDeviceCpuUsage   （CPU 使用率，%）
//   列 12 = hwDeviceMemUsage   （内存使用率，% —— 实测与设备 Web 界面一致）
//   列 20 = hwDeviceBoardType  （板卡类型，1=主控/引擎板，2=业务板）
// 重要：华为 USG6000F 的内存使用率在"列 12"，不是列 2（列 2 返回值远小于真实值）。
//       且真实数据所在的主引擎板索引是 ...16777217（frame1 slot0 cpu1），
//       而同板 cpu0 索引 16777216 的内存列值为 0，需过滤掉。
// 整机 CPU/内存取"板卡类型=1（主引擎）且该行内存列>0"的板卡的平均值。
const HW_DEVICE_PERF_TABLE = '1.3.6.1.4.1.2011.5.25.31.1.1.1';
const HW_COL_CPU = 1;
const HW_COL_MEM = 12;
const HW_COL_BOARD_TYPE = 20;
const HW_BOARD_MAIN = 1; // 主控/引擎板

export interface PerformanceConfig {
  enabled: boolean;
  interval: number; // 秒
  cpuThreshold: number; // %
  memThreshold: number; // %
}

export interface PerformanceSample {
  id: number;
  device_id: number;
  cpu_percent: number;
  mem_percent: number;
  disk_percent: number;
  disks?: DiskPartition[]; // 全部分区列表（JSON）
  timestamp: string;
}

/** 磁盘分区信息（用于在界面展示所有分区） */
export interface DiskPartition {
  name: string;   // 分区标识，如 "/"、"/usr/local/las"
  percent: number; // 使用率 %（0-100），-1 表示不可用
  size: number;   // 总大小（字节）
  used: number;   // 已用（字节）
}

/** 采样内部结果：disk 为根分区使用率（-1 无），disks 为全部分区列表 */
interface DiskResult {
  root: number;         // 根分区 "/" 使用率（-1 表示无）
  disks: DiskPartition[];
}

/** 采样内部结果类型 */
interface SampleResult {
  cpu: number;
  mem: number;
  rootDisk: number;
  disks: DiskPartition[];
}

let perfTimer: NodeJS.Timeout | null = null;
let running = false;

/** 读取性能监控配置 */
export function getPerformanceConfig(): PerformanceConfig {
  const get = (key: string, def: string): string =>
    queryOne<{ value: string }>('SELECT value FROM config WHERE key = ?', [key])?.value ?? def;
  return {
    enabled: get(CFG_KEYS.enabled, 'false') !== 'false',
    interval: Math.max(30, Number(get(CFG_KEYS.interval, '300')) || 300),
    cpuThreshold: Math.min(100, Math.max(1, Number(get(CFG_KEYS.cpuThreshold, '90')) || 90)),
    memThreshold: Math.min(100, Math.max(1, Number(get(CFG_KEYS.memThreshold, '90')) || 90)),
  };
}

/** 保存性能监控配置并重启定时器 */
export function savePerformanceConfig(config: Partial<PerformanceConfig>): { success: boolean } {
  const set = (key: string, value: string) =>
    execute('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', [key, value]);
  if (config.enabled !== undefined) set(CFG_KEYS.enabled, config.enabled ? 'true' : 'false');
  if (config.interval !== undefined) set(CFG_KEYS.interval, String(config.interval));
  if (config.cpuThreshold !== undefined) set(CFG_KEYS.cpuThreshold, String(config.cpuThreshold));
  if (config.memThreshold !== undefined) set(CFG_KEYS.memThreshold, String(config.memThreshold));
  restartMonitor();
  return { success: true };
}

/** 初始化性能采样表（含磁盘使用率字段） */
export function ensurePerformanceTable(): void {
  execute(`
    CREATE TABLE IF NOT EXISTS device_performance (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id INTEGER NOT NULL,
      cpu_percent REAL DEFAULT 0,
      mem_percent REAL DEFAULT 0,
      disk_percent REAL DEFAULT -1,
      disks TEXT DEFAULT '[]',
      timestamp TEXT NOT NULL,
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    )
  `);
  // 兼容旧库：若缺少 disk_percent / disks 列则补充
  try {
    execute('ALTER TABLE device_performance ADD COLUMN disk_percent REAL DEFAULT -1');
  } catch {
    // 列已存在，忽略
  }
  try {
    execute('ALTER TABLE device_performance ADD COLUMN disks TEXT DEFAULT \'[]\'');
  } catch {
    // 列已存在，忽略
  }
  execute('CREATE INDEX IF NOT EXISTS idx_perf_device_time ON device_performance(device_id, timestamp DESC)');
}

/**
 * 将 varbind 数值转为 number（兼容 number/bigint/Buffer）
 */
function toNumber(value: any): number {
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

/**
 * 读取一列 OID（返回数值数组），用于 hrProcessorLoad 等多行列
 * net-snmp 的 subtree 是流式回调：feedCb 每批调用一次，doneCb 结束时调用一次
 */
function readColumn(session: snmp.Session, oid: string): Promise<number[]> {
  return new Promise((resolve) => {
    const values: number[] = [];
    try {
      session.subtree(
        oid,
        100,
        (varbinds: any[]) => {
          if (varbinds) {
            for (const vb of varbinds) {
              values.push(toNumber(vb.value));
            }
          }
        },
        (_error: any) => {
          resolve(values);
        }
      );
    } catch {
      resolve(values);
    }
  });
}

/**
 * 读取 hrStorageTable 表格，返回 { rowIndex: {col: value} }
 */
function readStorageTable(session: snmp.Session): Promise<Record<string, Record<string, any>>> {
  return new Promise((resolve) => {
    try {
      session.tableColumns(OID.hrStorageTable, Object.values(STORAGE_COLS), 100, (error: any, table: any) => {
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

/** 将 hrStorageType 的 ObjectID/Buffer 转为字符串 OID，用于匹配 */
function storageTypeToString(value: any): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'object' && typeof value.toStr === 'function') {
    const s = value.toStr();
    // 去除前导点（net-snmp ObjectID.toStr 可能返回 ".1.3.6..."）
    return s.replace(/^\.+/, '');
  }
  const s = String(value);
  return s.replace(/^\.+/, '');
}

/**
 * 判断 hrStorage 表的某一行是否为物理内存（RAM），排除虚拟内存/缓存/磁盘等
 * @param typeStr hrStorageType 转字符串后的值（可能为 OID 字符串，如 "1.3.6.1.2.1.25.2.1.2"）
 * @param descr   hrStorageDescr（如 "Physical memory"、"Virtual memory"、"Memory buffers"）
 */
function isPhysicalMemoryRow(typeStr: string, descr: string): boolean {
  // 1. 按 hrStorageType OID 精确匹配 hrStorageRam（1.3.6.1.2.1.25.2.1.2）
  //    兼容带/不带前导点
  const normalizedType = typeStr.replace(/^\.+/, '');
  if (normalizedType === RAM_TYPE_OID || normalizedType.endsWith('.25.2.1.2')) {
    return true;
  }

  // 2. 按 descr 精确匹配标准物理内存名（严格区分，避免误匹配虚拟内存/缓存）
  //    物理内存标准名：Physical memory / Physical Memory / Memory / RAM / 内存
  const descrLower = descr.toLowerCase();
  const isPhyMemoryName =
    descrLower === 'physical memory' ||
    descrLower === 'physical memory (ram)' ||
    descrLower === 'memory' ||
    descrLower === 'ram' ||
    descrLower === '内存' ||
    descrLower === '物理内存';

  if (!isPhyMemoryName) return false;

  // 3. 排除明显不是物理内存的 descr（双保险）
  const exclude =
    /virtual|swap|buffer|cached|shared|缓存|交换|缓冲/.test(descrLower);
  return !exclude;
}

/**
 * 判断 hrStorage 表的某一行是否为页缓存（Cached memory），用于从物理内存 used 中扣除
 * @param descr hrStorageDescr（如 "Cached memory" / "Cached Memory" / "缓存"）
 */
function isCachedMemoryRow(descr: string): boolean {
  const d = descr.toLowerCase();
  // 精确匹配缓存行，避免误匹配其他
  return (
    d === 'cached memory' ||
    d === 'cached' ||
    d === 'cache' ||
    d === '缓存' ||
    d === '页缓存'
  );
}

/**
 * 采集单台设备的 CPU / 内存使用率
 *
 * 采集流程：
 * 1. 先尝试标准 HOST-RESOURCES-MIB（hrProcessorLoad + hrStorage）—— 对 Linux/通用设备有效。
 * 2. 若标准 MIB 采不到 CPU 或内存（华为 USG / VRP 等防火墙不提供 HOST-RESOURCES-MIB），
 *    回退到华为私有设备性能 MIB（1.3.6.1.4.1.2011.5.25.31.1.1.1）。
 *
 * 修复点：
 * - 标准 MIB 与私有 MIB 各自使用独立的 session，串行执行，避免共享 session 并发丢包。
 * - 内存计算从物理内存 used 中扣除页缓存，接近设备管理界面口径。
 */
function sampleDevice(device: any): Promise<SampleResult | null> {
  return new Promise((resolve) => {
    let session: snmp.Session | null = null;
    try {
      session = createSnmpSession(device);

      // 串行执行：先读 CPU（subtree），再读 hrStorage（tableColumns）
      readColumn(session, OID.hrProcessorLoad)
        .then((cpuLoads) => readStorageTable(session!).then((storageTable) => ({ cpuLoads, storageTable })))
        .then(({ cpuLoads, storageTable }) => {
          session?.close();

          // CPU：多核取平均负载
          let cpu = -1;
          if (cpuLoads.length > 0) {
            const sum = cpuLoads.reduce((a, b) => a + b, 0);
            cpu = Math.round((sum / cpuLoads.length) * 10) / 10;
          }

          // 内存：从 hrStorage 表精确匹配物理内存（RAM），并从 used 中减去页缓存（Cached memory）
          let mem = calcHrMemory(storageTable);

          // 磁盘：从 hrStorage 表取根分区 "/" 使用率 + 全部分区列表
          const diskResult = calcHrDisk(storageTable);
          let rootDisk = diskResult.root;
          let disks = diskResult.disks;

          // 标准 MIB 采不到时，回退到华为私有 MIB
          if (cpu < 0 || mem < 0 || rootDisk < 0) {
            sampleHuaweiUsg(device)
              .then((hw) => {
                if (hw) {
                  if (cpu < 0) cpu = hw.cpu;
                  if (mem < 0) mem = hw.mem;
                  if (rootDisk < 0 && hw.disks && hw.disks.length > 0) {
                    // 华为私有 MIB 一般无磁盘，但若有则使用
                    rootDisk = hw.disks.find((d) => d.name === '/')?.percent ?? -1;
                    disks = hw.disks;
                  }
                }
                resolve({ cpu, mem, rootDisk, disks });
              })
              .catch(() => resolve({ cpu, mem, rootDisk, disks }));
          } else {
            resolve({ cpu, mem, rootDisk, disks });
          }
        })
        .catch((err) => {
          session?.close();
          console.error(`[性能监控] ${device.name} 采样异常:`, err?.message || err);
          resolve(null);
        });
    } catch (err) {
      session?.close();
      resolve(null);
    }
  });
}

/**
 * 从 hrStorage 表计算所有磁盘分区使用率。
 * 排除内存类（Physical/Virtual/Buffers/Cached/Shared/Swap）和零容量行，
 * 返回根分区 "/" 的使用率（root）与全部分区列表（disks）。
 */
function calcHrDisk(storageTable: Record<string, Record<string, any>>): DiskResult {
  const disks: DiskPartition[] = [];
  let root = -1;
  for (const row of Object.values(storageTable) as any[]) {
    const descr = row[STORAGE_COLS.descr] ? String(row[STORAGE_COLS.descr]).trim() : '';
    const size = toNumber(row[STORAGE_COLS.size]);
    const units = toNumber(row[STORAGE_COLS.allocationUnits]);
    if (size <= 0) continue;
    // 排除内存类分区（名称或类型匹配内存相关关键字）
    const d = descr.toLowerCase();
    if (/physical memory|virtual memory|memory buffers|cached memory|cached|shared memory|swap space|内存|虚拟内存|缓存|交换|缓冲|共享/.test(d)) continue;
    const used = toNumber(row[STORAGE_COLS.used]);
    const percent = Math.round((used / size) * 1000) / 10;
    const totalBytes = units * size;
    disks.push({
      name: descr || '(未命名)',
      percent,
      size: totalBytes,
      used: units * used,
    });
    // 根分区 "/"（descr 恰好等于 "/"）
    if (descr === '/') {
      root = percent;
    }
  }
  // 磁盘按使用率降序排序（最紧张的排前面）
  disks.sort((a, b) => b.percent - a.percent);
  return { root, disks };
}

/** 从 hrStorage 表计算内存使用率（已扣除页缓存），返回 -1 表示无物理内存数据 */
function calcHrMemory(storageTable: Record<string, Record<string, any>>): number {
  let physSize = -1;
  let physUsed = -1;
  let cachedUsed = 0;
  for (const row of Object.values(storageTable) as any[]) {
    const typeStr = storageTypeToString(row[STORAGE_COLS.type]);
    const descr = row[STORAGE_COLS.descr] ? String(row[STORAGE_COLS.descr]).trim() : '';

    if (isPhysicalMemoryRow(typeStr, descr)) {
      if (physSize < 0) {
        physSize = toNumber(row[STORAGE_COLS.size]);
        physUsed = toNumber(row[STORAGE_COLS.used]);
      }
    } else if (isCachedMemoryRow(descr)) {
      const cUsed = toNumber(row[STORAGE_COLS.used]);
      if (cUsed > 0) cachedUsed += cUsed;
    }
  }

  if (physSize <= 0) return -1;
  const realUsed = Math.max(0, physUsed - cachedUsed);
  return Math.round((realUsed / physSize) * 1000) / 10;
}

/**
 * 华为 USG / VRP 设备性能采样（私有 MIB）
 * 读取 hwDevicePerformanceTable，取主引擎板（板卡类型=1）的 CPU/内存使用率平均值。
 * 华为 USG 防火墙不提供 HOST-RESOURCES-MIB，需用此私有 MIB。
 * @returns 百分比（0-100），不可用则为 -1（华为私有 MIB 无磁盘表时 disks 为空数组）
 */
function sampleHuaweiUsg(device: any): Promise<SampleResult | null> {
  return new Promise((resolve) => {
    let session: snmp.Session | null = null;
    try {
      session = createSnmpSession(device);
      const table = HW_DEVICE_PERF_TABLE;

      // 读取完整性能表（含 CPU/内存/板卡类型列），一次 tableColumns 拿全所有列
      session.tableColumns(
        table,
        [HW_COL_CPU, HW_COL_MEM, HW_COL_BOARD_TYPE],
        100,
        (error: any, rows: any) => {
          session?.close();
          if (error || !rows || Object.keys(rows).length === 0) {
            resolve(null);
            return;
          }

          // 解析行索引（如 "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.<列>.<frame>.<slot>.<cpu>"）
          // 收集主引擎板（板卡类型=1）的 CPU/内存值。
          // 关键：只统计"内存列>0 且 <=100"的行（索引 ...16777217 才有真实内存数据，
          //      同板 cpu0 索引 16777216 的内存列为 0，应排除），避免把 0 误算拉低均值。
          const cpuVals: number[] = [];
          const memVals: number[] = [];
          const validMemIdx: string[] = [];
          for (const idx of Object.keys(rows)) {
            const row = rows[idx];
            const boardType = toNumber(row[HW_COL_BOARD_TYPE]);
            if (boardType !== HW_BOARD_MAIN) continue; // 只统计主引擎板

            const memV = row[HW_COL_MEM];
            // 内存列有效值：>0 且 <=100（真实使用率）
            if (typeof memV === 'number' && !isNaN(memV) && memV > 0 && memV <= 100) {
              memVals.push(memV);
              validMemIdx.push(idx);
            }
          }

          // CPU 只统计"有真实内存数据"的主引擎板行，与内存口径一致
          for (const idx of validMemIdx) {
            const cpuV = rows[idx][HW_COL_CPU];
            if (typeof cpuV === 'number' && !isNaN(cpuV) && cpuV >= 0 && cpuV <= 100) {
              cpuVals.push(cpuV);
            }
          }

          let cpu = -1;
          let mem = -1;
          if (cpuVals.length > 0) {
            cpu = Math.round((cpuVals.reduce((a, b) => a + b, 0) / cpuVals.length) * 10) / 10;
          }
          if (memVals.length > 0) {
            mem = Math.round((memVals.reduce((a, b) => a + b, 0) / memVals.length) * 10) / 10;
          }

          // 华为 USG 私有性能 MIB 无磁盘使用率字段
          resolve({ cpu, mem, rootDisk: -1, disks: [] });
        }
      );
    } catch (err) {
      session?.close();
      resolve(null);
    }
  });
}

/**
 * 执行一轮性能采样（所有在线设备）
 */
export async function runPerformanceSampleOnce(): Promise<{ total: number; sampled: number }> {
  if (running) return { total: 0, sampled: 0 };
  running = true;
  const config = getPerformanceConfig();
  const devices = queryAll<any>('SELECT * FROM devices WHERE status = ?', ['online']);
  let sampled = 0;

  try {
    await Promise.all(devices.map(async (device) => {
      try {
        const result = await sampleDevice(device);
        if (!result) return;

        const timestamp = new Date().toISOString();
        executeInsert(
          'INSERT INTO device_performance (device_id, cpu_percent, mem_percent, disk_percent, disks, timestamp) VALUES (?, ?, ?, ?, ?, ?)',
          [device.id, result.cpu, result.mem, result.rootDisk, JSON.stringify(result.disks || []), timestamp]
        );
        sampled++;

        // 阈值告警
        checkThreshold(device, result.cpu, result.mem, config);
      } catch (err: any) {
        console.error(`[性能监控] 采样 ${device.name} 失败:`, err?.message || err);
      }
    }));
  } finally {
    running = false;
  }

  return { total: devices.length, sampled };
}

/**
 * 立即对单台设备执行一次性能采样并入库（供设备详情页"刷新"按钮调用）
 * @param deviceId 设备 ID
 * @returns { success: boolean; cpu: number; mem: number }
 */
export async function sampleDeviceNow(deviceId: number): Promise<{ success: boolean; cpu: number; mem: number }> {
  const device = queryOne<any>('SELECT * FROM devices WHERE id = ?', [deviceId]);
  if (!device) return { success: false, cpu: -1, mem: -1 };

  try {
    const result = await sampleDevice(device);
    if (!result) return { success: false, cpu: -1, mem: -1 };

    const timestamp = new Date().toISOString();
    executeInsert(
      'INSERT INTO device_performance (device_id, cpu_percent, mem_percent, disk_percent, disks, timestamp) VALUES (?, ?, ?, ?, ?, ?)',
      [device.id, result.cpu, result.mem, result.rootDisk, JSON.stringify(result.disks || []), timestamp]
    );

    // 阈值告警
    checkThreshold(device, result.cpu, result.mem, getPerformanceConfig());
    return { success: true, cpu: result.cpu, mem: result.mem };
  } catch (err: any) {
    console.error(`[性能监控] 手动采样 ${device.name} 失败:`, err?.message || err);
    return { success: false, cpu: -1, mem: -1 };
  }
}

/**
 * 阈值检查：CPU / 内存超过阈值时触发告警（去重：短时间内不重复告警）
 */
const lastThresholdAlert = new Map<string, number>(); // key: deviceId:type -> timestamp
const THRESHOLD_ALERT_COOLDOWN = 10 * 60 * 1000; // 10 分钟冷却

function checkThreshold(device: any, cpu: number, mem: number, config: PerformanceConfig): void {
  const now = Date.now();

  const maybeAlert = (type: string, value: number, threshold: number) => {
    if (value < 0 || value < threshold) return;
    const key = `${device.id}:${type}`;
    const last = lastThresholdAlert.get(key) || 0;
    if (now - last < THRESHOLD_ALERT_COOLDOWN) return;
    lastThresholdAlert.set(key, now);

    const severity: AlertData['severity'] = value >= threshold + 10 ? 'critical' : 'high';
    const alert: AlertData = {
      attackType: type === 'cpu' ? 'CPU 使用率过高' : '内存使用率过高',
      sourceIp: device.ip,
      sourcePort: 0,
      targetIp: '',
      targetPort: 0,
      severity,
      deviceName: device.name,
      deviceIp: device.ip,
      description: `设备 ${device.name}（${device.ip}）${type === 'cpu' ? 'CPU' : '内存'}使用率 ${value}%，超过阈值 ${threshold}%`,
      oid: '',
      timestamp: new Date().toISOString(),
    };
    processAlert(alert);
  };

  maybeAlert('cpu', cpu, config.cpuThreshold);
  maybeAlert('mem', mem, config.memThreshold);
}

/** 启动性能监控定时器 */
export function startPerformanceMonitor(): void {
  stopPerformanceMonitor();
  ensurePerformanceTable();
  const config = getPerformanceConfig();
  if (!config.enabled) {
    console.log('[性能监控] 未启用，跳过启动');
    return;
  }
  console.log(`[性能监控] 启动，每 ${config.interval} 秒采样一次`);
  perfTimer = setInterval(() => {
    runPerformanceSampleOnce();
  }, config.interval * 1000);
  // 启动后立即采样一轮
  runPerformanceSampleOnce();
}

/** 停止性能监控定时器 */
export function stopPerformanceMonitor(): void {
  if (perfTimer) {
    clearInterval(perfTimer);
    perfTimer = null;
  }
}

/** 配置变化后重启定时器 */
function restartMonitor(): void {
  const config = getPerformanceConfig();
  if (config.enabled) {
    startPerformanceMonitor();
  } else {
    stopPerformanceMonitor();
  }
}

/** 获取某设备最近 N 条性能采样记录 */
export function getPerformanceHistory(deviceId: number, limit = 50): PerformanceSample[] {
  const rows = queryAll<any>(
    `SELECT id, device_id, cpu_percent, mem_percent, disk_percent, disks, timestamp
     FROM device_performance
     WHERE device_id = ?
     ORDER BY timestamp DESC
     LIMIT ?`,
    [deviceId, limit]
  );
  // 解析 disks JSON，升序返回（便于前端画趋势）
  return rows.map((r) => ({
    id: r.id,
    device_id: r.device_id,
    cpu_percent: r.cpu_percent,
    mem_percent: r.mem_percent,
    disk_percent: r.disk_percent,
    disks: parseDisks(r.disks),
    timestamp: r.timestamp,
  })).reverse();
}

/** 安全解析磁盘分区 JSON，失败返回空数组 */
function parseDisks(raw: any): DiskPartition[] {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  try {
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

/** 清理过旧的历史采样数据（保留最近 7 天） */
export function cleanupPerformanceHistory(): void {
  const cutoff = new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString();
  execute('DELETE FROM device_performance WHERE timestamp < ?', [cutoff]);
}
