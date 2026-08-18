/**
 * IP 地址属地查询模块
 * 策略：离线库为主 + 在线兜底 + 双层缓存（内存 LRU + SQLite 持久化）
 *
 * 数据源：
 *   1. 离线库 ip2region（data/ip2region.db，约 8.7MB，本地解析，断网可用）
 *   2. 在线 API ipinfo.io（兜底，仅离线库未命中时查询，结果写缓存）
 *   3. SQLite ip_location 表（持久化缓存，避免重复查询）
 *
 * 返回结构：
 *   { country, province, city, isp, source }  // source: offline/online
 *
 * 内网/保留 IP（RFC1918 等）直接标"内网"，不查库不联网。
 */
import path from 'path';
import fs from 'fs';
import { app } from 'electron';
import { queryOne, execute } from './db-helper';
import IP2Region from 'ip2region';

export interface IpLocationResult {
  country: string;
  province: string;
  city: string;
  isp: string;
  source: 'offline' | 'online' | 'private' | 'unknown';
}

// 内存缓存（避免同一 IP 重复查库），最大条数
const memCache = new Map<string, IpLocationResult>();
const MEM_CACHE_MAX = 10000;

// 离线库实例（懒加载）
let ip2region: InstanceType<typeof IP2Region> | null = null;
let offlineInitError: string | null = null;

/** 内网/保留 IP 段判断（RFC1918、本地、保留地址等） */
const PRIVATE_PATTERN =
  /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.|255\.|224\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|198\.18\.|198\.19\.)/;

/**
 * 判断是否为内网/保留 IP（无需查询归属地）
 */
export function isPrivateIp(ip: string): boolean {
  if (!ip) return true;
  return PRIVATE_PATTERN.test(ip);
}

/**
 * 获取离线库文件路径（兼容开发与打包环境）
 * 开发：{app}/data/ip2region.db
 * 打包：{app}/resources/data/ip2region.db（extraResources）
 */
function getDbFilePath(): string {
  const appPath = app.getAppPath();
  const candidates = [
    path.join(appPath, 'data', 'ip2region.db'),
    path.join(appPath, 'resources', 'data', 'ip2region.db'),
    path.join(process.resourcesPath || '', 'data', 'ip2region.db'),
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  return candidates[0];
}

/**
 * 初始化离线库（懒加载）
 */
function getOfflineQuery(): InstanceType<typeof IP2Region> | null {
  if (ip2region) return ip2region;
  if (offlineInitError) return null;
  try {
    const dbPath = getDbFilePath();
    if (!fs.existsSync(dbPath)) {
      offlineInitError = `离线库文件不存在: ${dbPath}`;
      console.error(`[IP属地] ${offlineInitError}`);
      return null;
    }
    ip2region = new IP2Region({ ipv4db: dbPath, disableIpv6: true });
    return ip2region;
  } catch (err: any) {
    offlineInitError = err?.message || '初始化失败';
    console.error('[IP属地] 离线库初始化失败:', offlineInitError);
    return null;
  }
}

/**
 * 写入内存缓存
 */
function setCache(ip: string, result: IpLocationResult): void {
  if (memCache.size >= MEM_CACHE_MAX) {
    const oldest = memCache.keys().next().value;
    if (oldest !== undefined) memCache.delete(oldest);
  }
  memCache.set(ip, result);
}

/**
 * 从离线库查询
 */
function queryOffline(ip: string): IpLocationResult | null {
  const q = getOfflineQuery();
  if (!q) return null;
  try {
    const res = q.search(ip);
    if (!res) return null;
    return {
      country: res.country || '',
      province: res.province || '',
      city: res.city || '',
      isp: res.isp || '',
      source: 'offline',
    };
  } catch {
    return null;
  }
}

/**
 * 从在线 API 查询（ipinfo.io，仅作兜底）
 */
function queryOnline(ip: string): Promise<IpLocationResult | null> {
  return new Promise((resolve) => {
    try {
      const https = require('https');
      const url = `https://ipinfo.io/${ip}/json`;
      const req = https.get(url, { timeout: 6000 }, (res: any) => {
        if (res.statusCode !== 200) {
          res.resume();
          return resolve(null);
        }
        let data = '';
        res.on('data', (c: Buffer) => (data += c.toString()));
        res.on('end', () => {
          try {
            const j = JSON.parse(data);
            const org = (j.org || '').replace(/^AS\d+\s*/, '');
            resolve({
              country: j.country || '',
              province: j.region || '',
              city: j.city || '',
              isp: org || '',
              source: 'online',
            });
          } catch {
            resolve(null);
          }
        });
      });
      req.on('error', () => resolve(null));
      req.on('timeout', () => {
        req.destroy();
        resolve(null);
      });
    } catch {
      resolve(null);
    }
  });
}

/**
 * 从数据库缓存查询
 */
function queryDbCache(ip: string): IpLocationResult | null {
  try {
    const row = queryOne<{ country: string; province: string; city: string; isp: string; source: string }>(
      'SELECT country, province, city, isp, source FROM ip_location WHERE ip = ?',
      [ip]
    );
    if (row) {
      return {
        country: row.country || '',
        province: row.province || '',
        city: row.city || '',
        isp: row.isp || '',
        source: (row.source as IpLocationResult['source']) || 'unknown',
      };
    }
  } catch {
    // 表可能不存在，忽略
  }
  return null;
}

/**
 * 写入数据库缓存
 */
function saveDbCache(ip: string, result: IpLocationResult): void {
  try {
    execute(
      `INSERT OR REPLACE INTO ip_location (ip, country, province, city, isp, source, update_time)
       VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`,
      [ip, result.country, result.province, result.city, result.isp, result.source]
    );
  } catch (err) {
    console.error('[IP属地] 写缓存失败:', err);
  }
}

/**
 * 查询 IP 属地（对外主入口）
 * 查询顺序：内存缓存 → 数据库缓存 → 离线库 → 在线 API → 未知
 */
export async function queryLocation(ip: string): Promise<IpLocationResult> {
  const trimmed = (ip || '').trim();
  // 无效或空 IP
  if (!trimmed) {
    return { country: '', province: '', city: '', isp: '', source: 'unknown' };
  }

  // 内网/保留 IP：直接标内网，不查库不联网
  if (isPrivateIp(trimmed)) {
    const privateResult: IpLocationResult = { country: '', province: '', city: '内网', isp: '', source: 'private' };
    setCache(trimmed, privateResult);
    return privateResult;
  }

  // 1. 内存缓存
  const mem = memCache.get(trimmed);
  if (mem) return mem;

  // 2. 数据库缓存
  const dbCache = queryDbCache(trimmed);
  if (dbCache) {
    setCache(trimmed, dbCache);
    return dbCache;
  }

  // 3. 离线库
  const offline = queryOffline(trimmed);
  if (offline && (offline.country || offline.province || offline.city || offline.isp)) {
    setCache(trimmed, offline);
    saveDbCache(trimmed, offline);
    return offline;
  }

  // 4. 在线 API（兜底）
  try {
    const online = await queryOnline(trimmed);
    if (online && (online.country || online.province || online.city || online.isp)) {
      setCache(trimmed, online);
      saveDbCache(trimmed, online);
      return online;
    }
  } catch {
    // 忽略在线查询错误
  }

  // 5. 全部失败 → 未知
  const unknown: IpLocationResult = { country: '', province: '', city: '', isp: '', source: 'unknown' };
  setCache(trimmed, unknown);
  return unknown;
}

/**
 * 格式化为展示文本，如 "广东省 深圳市 阿里云"、"美国"、"内网"
 */
export function formatLocation(loc: IpLocationResult): string {
  if (loc.source === 'private') return '内网';
  const parts: string[] = [];
  if (loc.country) parts.push(loc.country);
  if (loc.province && loc.province !== loc.country) parts.push(loc.province);
  if (loc.city && loc.city !== loc.province) parts.push(loc.city);
  if (loc.isp) parts.push(loc.isp);
  return parts.length > 0 ? parts.join(' ') : '未知';
}

/**
 * 批量查询（减少 IPC 调用，用于列表页）
 */
export async function queryLocations(ips: string[]): Promise<Record<string, string>> {
  const result: Record<string, string> = {};
  const uniq = Array.from(new Set(ips.filter((ip) => ip)));
  // 限制单次批量数量，避免阻塞
  const batch = uniq.slice(0, 50);
  await Promise.all(
    batch.map(async (ip) => {
      const loc = await queryLocation(ip);
      result[ip] = formatLocation(loc);
    })
  );
  return result;
}
