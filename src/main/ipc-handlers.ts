import { ipcMain, dialog, BrowserWindow, app } from 'electron';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { getDatabase, getDbSync } from './database';
import { queryAll, queryOne, execute, executeInsert, queryScalar } from './db-helper';
import { startTrapReceiver, stopTrapReceiver, getTrapStatus, sendTestAlert } from './snmp-receiver';
import { startSyslogReceiver, stopSyslogReceiver, getSyslogStatus, getRecentLogs, clearRecentLogs } from './syslog-receiver';
import { probeDevice, probeAndUpdateDevice, checkAllDevices, probeInterfaces, probeTopology, SnmpDevice } from './device-probe';
import { getRawLogConfig, updateRawLogConfig } from './raw-logger';
import { getMonitorConfig, saveMonitorConfig, getMonitorStatus, runMonitorOnce } from './device-monitor';
import { getPerformanceConfig, savePerformanceConfig, getPerformanceHistory, runPerformanceSampleOnce } from './performance-monitor';
import { getTrafficConfig, saveTrafficConfig, getTrafficHistory, runTrafficSampleOnce, sampleTrafficNow } from './traffic-monitor';
import { saveInterfaceSnapshot, getInterfaceSnapshot } from './interface-snapshot';
import { sampleDeviceNow } from './performance-monitor';
import { queryLocation, queryLocations, formatLocation } from './ip-location';
import { DEFAULT_TYPES, reloadConfig, getConfigFilePath, backfillAttackCategories, saveUserClassifyRule, deleteUserClassifyRule, getUserClassifyRules, extractThreatFeature, classifyMessage, detectVendorFromMessage, listEventTypes, createEventType, updateEventType, deleteEventType } from './event-classifier';

interface EventFilter {
  severity?: string;
  deviceName?: string;
  startTime?: string;
  endTime?: string;
  attackType?: string;
  attackCategory?: string; // 标准攻击类型筛选
  keyword?: string;
  limit?: number;
  offset?: number;
}

/** 设备表单数据（新增/编辑，含 SNMPv3 字段） */
interface DeviceForm extends SnmpDevice {
  id?: number;
  name: string;
  device_type?: string;
  location?: string;
  description?: string;
}

/**
 * 将前端筛选的"本地时间字符串"转换为 UTC ISO 边界字符串（用于与数据库 timestamp 比较）。
 *
 * 数据库 timestamp 存的是 UTC ISO 字符串（如 "2026-08-14T18:44:12.127Z"），
 * 而前端筛选输入的是本地时间（如 "2026-08-17" 或 "2026-08-17T15:30"）。
 * 若不先转换，直接拿本地字符串与 UTC 时间戳比较会产生时区错位，导致日期筛选不准确。
 *
 * 支持两种输入：
 *   - "YYYY-MM-DD"（日期，代表本地当天）
 *   - "YYYY-MM-DDTHH:mm"（datetime-local，代表本地某时刻，精确到分）
 *
 * @param input 本地时间字符串
 * @param isEnd  true 表示作为结束边界（取当天/该分钟末尾 23:59:59.999 或 mm:59.999，含边界）；
 *               false 表示作为起始边界（取当天 00:00:00.000 或该分钟 00.000 整）
 * @returns 对应的 UTC ISO 字符串；输入为空返回 undefined
 */
function localFilterToUTC(input: string, isEnd: boolean): string | undefined {
  if (!input) return undefined;
  let date: Date;
  if (input.includes('T')) {
    // "YYYY-MM-DDTHH:mm" 本地时刻
    const [d, t] = input.split('T');
    const [y, mo, day] = d.split('-').map(Number);
    const [h, mi] = t.split(':').map(Number);
    date = new Date(y, mo - 1, day, h, mi, isEnd ? 59 : 0, isEnd ? 999 : 0);
  } else {
    // "YYYY-MM-DD" 本地日期
    const [y, mo, day] = input.split('-').map(Number);
    date = new Date(y, mo - 1, day, isEnd ? 23 : 0, isEnd ? 59 : 0, isEnd ? 59 : 0, isEnd ? 999 : 0);
  }
  return date.toISOString();
}

/**
 * 返回某个"本地日期"当天 00:00:00 对应的 UTC ISO 字符串（用于 timestamp >= 比较）。
 * 数据库 timestamp 存的是 UTC ISO 字符串（如 "2026-08-14T18:44:12.127Z"），
 * 而"按天统计"需要按用户本地时区划分。
 * 例如本地 2026-08-15 00:00 即 UTC 2026-08-14T16:00:00Z。
 */
function localDayStartUTC(d: Date): string {
  const y = d.getFullYear();
  const m = d.getMonth();
  const day = d.getDate();
  return new Date(y, m, day, 0, 0, 0, 0).toISOString();
}

/**
 * 返回某个"本地日期"次日 00:00:00 对应的 UTC ISO 字符串（用于 timestamp < 比较）。
 */
function localDayEndUTC(d: Date): string {
  const y = d.getFullYear();
  const m = d.getMonth();
  const day = d.getDate();
  return new Date(y, m, day + 1, 0, 0, 0, 0).toISOString();
}

/**
 * 返回某个"本地日期"的展示标签 "YYYY-MM-DD"（仅用于前端展示）。
 */
function toLocalDateStr(d: Date): string {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

/**
 * 广播未确认事件数变化（通知侧边栏徽标实时刷新）
 */
function notifyUnacknowledgedChanged(): void {
  BrowserWindow.getAllWindows().forEach((win) => {
    if (!win.isDestroyed()) {
      win.webContents.send('unacknowledged:changed');
    }
  });
}

export function registerIpcHandlers(): void {
  // ====== 安全事件相关 ======
  // 获取未确认事件数量（侧边栏红色徽标）
  ipcMain.handle('db:getUnacknowledgedCount', () => {
    return queryScalar<number>(
      'SELECT COUNT(*) as count FROM security_events WHERE acknowledged = 0'
    ) || 0;
  });

  ipcMain.handle('db:getEvents', (_event, filter: EventFilter = {}) => {
    let sql = 'SELECT * FROM security_events WHERE 1=1';
    const params: any[] = [];

    if (filter.severity) {
      sql += ' AND severity = ?';
      params.push(filter.severity);
    }
    if (filter.deviceName) {
      sql += ' AND device_name LIKE ?';
      params.push(`%${filter.deviceName}%`);
    }
    if (filter.attackType) {
      sql += ' AND attack_type LIKE ?';
      params.push(`%${filter.attackType}%`);
    }
    if (filter.attackCategory) {
      sql += ' AND attack_category = ?';
      params.push(filter.attackCategory);
    }
    if (filter.keyword) {
      const kw = `%${filter.keyword}%`;
      sql += ' AND (attack_type LIKE ? OR attack_category LIKE ? OR device_name LIKE ? OR source_ip LIKE ? OR target_ip LIKE ? OR device_ip LIKE ?'
        + ' OR CAST(source_port AS TEXT) LIKE ? OR CAST(target_port AS TEXT) LIKE ?'
        + ' OR timestamp LIKE ? OR description LIKE ? OR oid LIKE ?)';
      params.push(kw, kw, kw, kw, kw, kw, kw, kw, kw, kw, kw);
    }
    if (filter.startTime) {
      sql += ' AND timestamp >= ?';
      params.push(localFilterToUTC(filter.startTime, false));
    }
    if (filter.endTime) {
      sql += ' AND timestamp <= ?';
      params.push(localFilterToUTC(filter.endTime, true));
    }

    sql += ' ORDER BY timestamp DESC';

    const countSql = sql.replace('SELECT *', 'SELECT COUNT(*) as total');
    const total = queryScalar<number>(countSql, params) || 0;

    if (filter.limit !== undefined) {
      sql += ' LIMIT ?';
      params.push(filter.limit);
    }
    if (filter.offset !== undefined) {
      sql += ' OFFSET ?';
      params.push(filter.offset);
    }

    const events = queryAll(sql, params);
    return { events, total };
  });

  ipcMain.handle('db:getEventById', (_event, id: number) => {
    return queryOne('SELECT * FROM security_events WHERE id = ?', [id]);
  });

  // 确认/取消确认事件
  ipcMain.handle('db:acknowledgeEvent', (_event, id: number, acknowledged: boolean) => {
    execute('UPDATE security_events SET acknowledged = ? WHERE id = ?', [
      acknowledged ? 1 : 0,
      id,
    ]);
    notifyUnacknowledgedChanged();
    return { success: true, id, acknowledged };
  });

  // 批量确认事件
  ipcMain.handle('db:acknowledgeEvents', (_event, ids: number[], acknowledged: boolean) => {
    if (!ids || ids.length === 0) return { success: false, message: '未选择事件' };
    const placeholders = ids.map(() => '?').join(',');
    execute(`UPDATE security_events SET acknowledged = ? WHERE id IN (${placeholders})`, [
      acknowledged ? 1 : 0,
      ...ids,
    ]);
    notifyUnacknowledgedChanged();
    return { success: true, count: ids.length };
  });

  // 一键确认所有未确认事件
  ipcMain.handle('db:acknowledgeAllEvents', () => {
    const count = execute('UPDATE security_events SET acknowledged = 1 WHERE acknowledged = 0');
    notifyUnacknowledgedChanged();
    return { success: true, count };
  });

  // 删除单个事件
  ipcMain.handle('db:deleteEvent', (_event, id: number) => {
    execute('DELETE FROM security_events WHERE id = ?', [id]);
    notifyUnacknowledgedChanged();
    return { success: true };
  });

  // 批量删除事件
  ipcMain.handle('db:deleteEvents', (_event, ids: number[]) => {
    if (!ids || ids.length === 0) return { success: false, message: '未选择事件' };
    const placeholders = ids.map(() => '?').join(',');
    execute(`DELETE FROM security_events WHERE id IN (${placeholders})`, ids);
    notifyUnacknowledgedChanged();
    return { success: true, count: ids.length };
  });

  // 清空所有事件
  ipcMain.handle('db:clearEvents', () => {
    execute('DELETE FROM security_events');
    notifyUnacknowledgedChanged();
    return { success: true };
  });

  // ====== 数据备份与恢复（导入/导出） ======
  // 导出：将数据库主要表数据导出为 JSON 备份文件（用户选择保存位置）
  ipcMain.handle('db:exportData', async () => {
    try {
      const db = getDbSync();
      // 导出主要业务表（排除 ip_location 庞大的离线缓存，避免备份文件过大）
      // 含事件、设备、配置、接口快照、自定义事件类型、用户归类规则
      const exportTables = ['security_events', 'devices', 'config', 'device_interfaces', 'custom_event_types', 'user_classify_rules'];
      const data: Record<string, any[]> = {};
      for (const table of exportTables) {
        data[table] = queryAll(`SELECT * FROM ${table}`);
      }
      const payload = {
        app: 'snmp-security-alert',
        type: 'backup',
        exportedAt: new Date().toISOString(),
        version: require('../../package.json').version || '1.0.0',
        stats: {
          events: data.security_events?.length || 0,
          devices: data.devices?.length || 0,
        },
        data,
      };

      const now = new Date();
      const defaultName = `SNMP数据备份_${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}_${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}.json`;

      const result = await dialog.showSaveDialog({
        title: '导出应用数据',
        defaultPath: path.join(app.getPath('downloads') || os.homedir(), defaultName),
        filters: [{ name: '备份文件', extensions: ['json'] }],
      });
      if (result.canceled || !result.filePath) {
        return { success: false, canceled: true, message: '已取消导出' };
      }
      fs.writeFileSync(result.filePath, JSON.stringify(payload, null, 2), 'utf-8');
      return {
        success: true,
        filePath: result.filePath,
        stats: payload.stats,
      };
    } catch (err: any) {
      console.error('导出数据失败:', err);
      return { success: false, message: err?.message || '导出失败' };
    }
  });

  // 导入：从 JSON 备份文件恢复数据（合并方式，保留现有数据，冲突以备份为准）
  ipcMain.handle('db:importData', async () => {
    try {
      const result = await dialog.showOpenDialog({
        title: '导入应用数据',
        properties: ['openFile'],
        filters: [{ name: '备份文件', extensions: ['json'] }],
      });
      if (result.canceled || result.filePaths.length === 0) {
        return { success: false, canceled: true, message: '已取消导入' };
      }

      const filePath = result.filePaths[0];
      const raw = fs.readFileSync(filePath, 'utf-8');
      const parsed = JSON.parse(raw);

      // 校验备份文件格式
      if (!parsed || parsed.app !== 'snmp-security-alert' || !parsed.data || typeof parsed.data !== 'object') {
        return { success: false, message: '备份文件格式无效，无法导入' };
      }

      const db = getDbSync();
      db.run('BEGIN TRANSACTION');
      try {
        // 设备表（name 唯一，冲突时更新）
        if (Array.isArray(parsed.data.devices)) {
          for (const dev of parsed.data.devices) {
            db.run(
              `INSERT INTO devices (id, name, ip, port, snmp_version, community, snmp_username, snmp_auth_protocol, snmp_auth_key, snmp_priv_protocol, snmp_priv_key, device_type, location, description, status, last_checked, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(name) DO UPDATE SET
                 ip=excluded.ip, port=excluded.port, snmp_version=excluded.snmp_version, community=excluded.community,
                 snmp_username=excluded.snmp_username, snmp_auth_protocol=excluded.snmp_auth_protocol, snmp_auth_key=excluded.snmp_auth_key,
                 snmp_priv_protocol=excluded.snmp_priv_protocol, snmp_priv_key=excluded.snmp_priv_key, device_type=excluded.device_type,
                 location=excluded.location, description=excluded.description, status=excluded.status,
                 last_checked=excluded.last_checked, updated_at=CURRENT_TIMESTAMP`,
              [dev.id, dev.name, dev.ip, dev.port || 161, dev.snmp_version || 'v2c', dev.community || 'public',
               dev.snmp_username || '', dev.snmp_auth_protocol || 'sha', dev.snmp_auth_key || '',
               dev.snmp_priv_protocol || 'aes', dev.snmp_priv_key || '', dev.device_type || 'firewall',
               dev.location || '', dev.description || '', dev.status || 'unknown', dev.last_checked || null,
               dev.created_at || null, dev.updated_at || null]
            );
          }
        }

        // 安全事件表（按 id 冲突时覆盖，避免重复）
        if (Array.isArray(parsed.data.security_events)) {
          for (const ev of parsed.data.security_events) {
            db.run(
              `INSERT INTO security_events (id, attack_type, attack_category, source_ip, source_port, target_ip, target_port, severity, device_name, device_ip, description, oid, raw_trap, timestamp, acknowledged, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                 attack_type=excluded.attack_type, attack_category=excluded.attack_category, source_ip=excluded.source_ip,
                 source_port=excluded.source_port, target_ip=excluded.target_ip, target_port=excluded.target_port,
                 severity=excluded.severity, device_name=excluded.device_name, device_ip=excluded.device_ip,
                 description=excluded.description, oid=excluded.oid, raw_trap=excluded.raw_trap,
                 timestamp=excluded.timestamp, acknowledged=excluded.acknowledged`,
              [ev.id, ev.attack_type, ev.attack_category || '其他', ev.source_ip || '', ev.source_port || 0,
               ev.target_ip || '', ev.target_port || 0, ev.severity, ev.device_name || '', ev.device_ip || '',
               ev.description || '', ev.oid || '', ev.raw_trap || '', ev.timestamp, ev.acknowledged || 0,
               ev.created_at || null]
            );
          }
        }

        // 配置表（key 唯一，冲突时覆盖）
        if (Array.isArray(parsed.data.config)) {
          for (const c of parsed.data.config) {
            db.run('INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?,?,?)', [
              c.key, c.value, c.updated_at || null,
            ]);
          }
        }

        // 接口快照表
        if (Array.isArray(parsed.data.device_interfaces)) {
          for (const itf of parsed.data.device_interfaces) {
            db.run(
              `INSERT OR REPLACE INTO device_interfaces (id, device_id, interfaces, sample_time) VALUES (?,?,?,?)`,
              [itf.id, itf.device_id, itf.interfaces, itf.sample_time]
            );
          }
        }

        // 自定义事件类型表（name 唯一，冲突时覆盖）
        if (Array.isArray(parsed.data.custom_event_types)) {
          for (const t of parsed.data.custom_event_types) {
            db.run(
              `INSERT INTO custom_event_types (id, name, feature_keywords, default_severity, is_builtin, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(name) DO UPDATE SET
                 feature_keywords=excluded.feature_keywords, default_severity=excluded.default_severity, updated_at=CURRENT_TIMESTAMP`,
              [t.id, t.name, t.feature_keywords || '[]', t.default_severity || 'medium', t.is_builtin || 0, t.created_at || null, t.updated_at || null]
            );
          }
        }

        // 用户归类规则表（vendor+feature 唯一，冲突时覆盖）
        if (Array.isArray(parsed.data.user_classify_rules)) {
          for (const r of parsed.data.user_classify_rules) {
            db.run(
              `INSERT INTO user_classify_rules (id, vendor, feature, category, created_at, updated_at)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(vendor, feature) DO UPDATE SET category=excluded.category, updated_at=CURRENT_TIMESTAMP`,
              [r.id, r.vendor || '', r.feature, r.category, r.created_at || null, r.updated_at || null]
            );
          }
        }

        db.run('COMMIT');
      } catch (e) {
        db.run('ROLLBACK');
        throw e;
      }

      // 落盘
      const { persistDatabase } = require('./database');
      persistDatabase();
      notifyUnacknowledgedChanged();

      return {
        success: true,
        stats: {
          events: parsed.data.security_events?.length || 0,
          devices: parsed.data.devices?.length || 0,
        },
      };
    } catch (err: any) {
      console.error('导入数据失败:', err);
      return { success: false, message: err?.message || '导入失败' };
    }
  });

  // 导出事件（返回全部符合条件的事件数据）
  ipcMain.handle('db:exportEvents', (_event, filter: EventFilter = {}) => {
    let sql = 'SELECT * FROM security_events WHERE 1=1';
    const params: any[] = [];

    if (filter.severity) {
      sql += ' AND severity = ?';
      params.push(filter.severity);
    }
    if (filter.deviceName) {
      sql += ' AND device_name LIKE ?';
      params.push(`%${filter.deviceName}%`);
    }
    if (filter.attackType) {
      sql += ' AND attack_type LIKE ?';
      params.push(`%${filter.attackType}%`);
    }
    if (filter.attackCategory) {
      sql += ' AND attack_category = ?';
      params.push(filter.attackCategory);
    }
    if (filter.keyword) {
      const kw = `%${filter.keyword}%`;
      sql += ' AND (attack_type LIKE ? OR attack_category LIKE ? OR device_name LIKE ? OR source_ip LIKE ? OR target_ip LIKE ? OR device_ip LIKE ?'
        + ' OR CAST(source_port AS TEXT) LIKE ? OR CAST(target_port AS TEXT) LIKE ?'
        + ' OR timestamp LIKE ? OR description LIKE ? OR oid LIKE ?)';
      params.push(kw, kw, kw, kw, kw, kw, kw, kw, kw, kw, kw);
    }
    if (filter.startTime) {
      sql += ' AND timestamp >= ?';
      params.push(localFilterToUTC(filter.startTime, false));
    }
    if (filter.endTime) {
      sql += ' AND timestamp <= ?';
      params.push(localFilterToUTC(filter.endTime, true));
    }

    sql += ' ORDER BY timestamp DESC';
    const events = queryAll(sql, params);
    return { events, total: events.length };
  });

  ipcMain.handle('db:getEventStats', () => {
    const total = queryScalar<number>('SELECT COUNT(*) as count FROM security_events') || 0;
    const now = new Date();
    const todayCount = queryScalar<number>(
      'SELECT COUNT(*) as count FROM security_events WHERE timestamp >= ? AND timestamp < ?',
      [localDayStartUTC(now), localDayEndUTC(now)]
    ) || 0;

    const bySeverity = queryAll<{ severity: string; count: number }>(`
      SELECT severity, COUNT(*) as count
      FROM security_events
      GROUP BY severity
      ORDER BY CASE severity
        WHEN 'critical' THEN 1 WHEN 'high' THEN 2
        WHEN 'medium' THEN 3 WHEN 'low' THEN 4
      END
    `);

    const recentEvents = queryAll(
      'SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 10'
    );

    return { total, todayCount, bySeverity, recentEvents };
  });

  // ====== 仪表盘统计相关 ======
  // 攻击类型 TOP 榜
  ipcMain.handle('db:getAttackTop', (_event, limit: number = 10) => {
    return queryAll(`
      SELECT attack_category as attack_type, COUNT(*) as count
      FROM security_events
      GROUP BY attack_category
      ORDER BY count DESC
      LIMIT ?
    `, [limit]);
  });

  // 近 N 天趋势（按天统计）
  ipcMain.handle('db:getTrend', (_event, days: number = 7) => {
    const result: { date: string; count: number; critical: number; high: number; medium: number; low: number }[] = [];
    const now = new Date();

    for (let i = days - 1; i >= 0; i--) {
      const date = new Date(now);
      date.setDate(now.getDate() - i);
      const dateStr = toLocalDateStr(date); // 展示标签（本地日期）
      const start = localDayStartUTC(date); // 本地当天 00:00 的 UTC
      const end = localDayEndUTC(date);     // 本地次日 00:00 的 UTC

      const count = queryScalar<number>(
        'SELECT COUNT(*) FROM security_events WHERE timestamp >= ? AND timestamp < ?',
        [start, end]
      ) || 0;
      const critical = queryScalar<number>(
        "SELECT COUNT(*) FROM security_events WHERE severity = 'critical' AND timestamp >= ? AND timestamp < ?",
        [start, end]
      ) || 0;
      const high = queryScalar<number>(
        "SELECT COUNT(*) FROM security_events WHERE severity = 'high' AND timestamp >= ? AND timestamp < ?",
        [start, end]
      ) || 0;
      const medium = queryScalar<number>(
        "SELECT COUNT(*) FROM security_events WHERE severity = 'medium' AND timestamp >= ? AND timestamp < ?",
        [start, end]
      ) || 0;
      const low = queryScalar<number>(
        "SELECT COUNT(*) FROM security_events WHERE severity = 'low' AND timestamp >= ? AND timestamp < ?",
        [start, end]
      ) || 0;

      result.push({ date: dateStr, count, critical, high, medium, low });
    }

    return result;
  });

  // 近 24 小时趋势（按小时统计）
  ipcMain.handle('db:getHourlyTrend', () => {
    const result: { hour: string; count: number }[] = [];
    const now = new Date();

    for (let i = 23; i >= 0; i--) {
      const hourDate = new Date(now);
      hourDate.setHours(now.getHours() - i, 0, 0, 0);
      const nextHourDate = new Date(hourDate);
      nextHourDate.setHours(hourDate.getHours() + 1, 0, 0, 0);

      const count = queryScalar<number>(
        'SELECT COUNT(*) FROM security_events WHERE timestamp >= ? AND timestamp < ?',
        [hourDate.toISOString(), nextHourDate.toISOString()]
      ) || 0;

      const hourLabel = `${String(hourDate.getHours()).padStart(2, '0')}:00`;
      result.push({ hour: hourLabel, count });
    }

    return result;
  });

  // 来源 IP 分布 TOP
  ipcMain.handle('db:getSourceIpTop', (_event, limit: number = 10) => {
    return queryAll(`
      SELECT source_ip, COUNT(*) as count
      FROM security_events
      WHERE source_ip != ''
      GROUP BY source_ip
      ORDER BY count DESC
      LIMIT ?
    `, [limit]);
  });

  // 源地址攻击次数统计（弹窗、事件详情页使用）
  // 返回该源 IP 的累计攻击次数、近24小时攻击次数、攻击类型分布
  ipcMain.handle('db:getSourceAttackCount', (_event, sourceIp: string) => {
    if (!sourceIp) return { count: 0, todayCount: 0, byAttackType: [] };

    // 累计攻击次数
    const count = queryScalar<number>(
      'SELECT COUNT(*) FROM security_events WHERE source_ip = ?',
      [sourceIp]
    ) || 0;

    // 近24小时攻击次数
    const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const todayCount = queryScalar<number>(
      'SELECT COUNT(*) FROM security_events WHERE source_ip = ? AND timestamp >= ?',
      [sourceIp, last24h]
    ) || 0;

    // 该源 IP 的攻击类型分布
    const byAttackType = queryAll<{ attack_type: string; count: number }>(`
      SELECT attack_type, COUNT(*) as count
      FROM security_events
      WHERE source_ip = ?
      GROUP BY attack_type
      ORDER BY count DESC
      LIMIT 10
    `, [sourceIp]);

    return { count, todayCount, byAttackType };
  });

  // 目标 IP 分布 TOP
  ipcMain.handle('db:getTargetIpTop', (_event, limit: number = 10) => {
    return queryAll(`
      SELECT target_ip, COUNT(*) as count
      FROM security_events
      WHERE target_ip != ''
      GROUP BY target_ip
      ORDER BY count DESC
      LIMIT ?
    `, [limit]);
  });

  // 设备告警分布
  ipcMain.handle('db:getDeviceAlertStats', () => {
    return queryAll(`
      SELECT device_name, COUNT(*) as count
      FROM security_events
      GROUP BY device_name
      ORDER BY count DESC
    `);
  });

  // ====== 设备管理相关 ======
  ipcMain.handle('db:getDevices', () => {
    return queryAll('SELECT * FROM devices ORDER BY created_at DESC');
  });

  // 按 ID 获取单台设备（设备详情页使用）
  ipcMain.handle('db:getDeviceById', (_event, id: number) => {
    return queryOne('SELECT * FROM devices WHERE id = ?', [id]);
  });

  ipcMain.handle('db:addDevice', (_event, device: DeviceForm) => {
    const id = executeInsert(
      `INSERT INTO devices (name, ip, port, snmp_version, community, snmp_username, snmp_auth_protocol, snmp_auth_key, snmp_priv_protocol, snmp_priv_key, device_type, location, description)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        device.name, device.ip, device.port || 161,
        device.snmp_version || 'v2c', device.community || 'public',
        device.snmp_username || '', device.snmp_auth_protocol || 'sha', device.snmp_auth_key || '',
        device.snmp_priv_protocol || 'aes', device.snmp_priv_key || '',
        device.device_type || 'firewall', device.location || '', device.description || '',
      ]
    );
    return { id, ...device };
  });

  ipcMain.handle('db:updateDevice', (_event, device: DeviceForm) => {
    execute(
      `UPDATE devices SET name=?, ip=?, port=?, snmp_version=?, community=?, snmp_username=?, snmp_auth_protocol=?, snmp_auth_key=?, snmp_priv_protocol=?, snmp_priv_key=?,
       device_type=?, location=?, description=?, updated_at=CURRENT_TIMESTAMP
       WHERE id=?`,
      [
        device.name, device.ip, device.port || 161,
        device.snmp_version || 'v2c', device.community || 'public',
        device.snmp_username || '', device.snmp_auth_protocol || 'sha', device.snmp_auth_key || '',
        device.snmp_priv_protocol || 'aes', device.snmp_priv_key || '',
        device.device_type || 'firewall', device.location || '', device.description || '',
        device.id,
      ]
    );
    return device;
  });

  ipcMain.handle('db:deleteDevice', (_event, id: number) => {
    execute('DELETE FROM devices WHERE id = ?', [id]);
    return { success: true };
  });

  ipcMain.handle('db:testDeviceConnection', async (_event, device: SnmpDevice) => {
    // 使用真实 SNMP 探测
    const result = await probeDevice(device);
    return {
      success: result.online,
      message: result.message,
      info: result.info,
      online: result.online,
    };
  });

  // 探测单个设备并更新状态
  ipcMain.handle('db:probeDevice', async (_event, id: number) => {
    const result = await probeAndUpdateDevice(id);
    return {
      success: result.online,
      message: result.message,
      info: result.info,
      online: result.online,
    };
  });

  // 探测设备接口列表与实时流量（P1），成功后保存最后一次采样结果
  ipcMain.handle('db:probeInterfaces', async (_event, id: number) => {
    const device = queryOne('SELECT * FROM devices WHERE id = ?', [id]);
    if (!device) {
      return { success: false, online: false, message: '设备不存在', interfaces: [], sampleTime: null };
    }
    const result = await probeInterfaces(device);
    // 采样成功则持久化最后一次结果
    if (result.success && result.interfaces && result.interfaces.length > 0) {
      const sampleTime = new Date().toISOString();
      saveInterfaceSnapshot(id, result.interfaces, sampleTime);
      return { ...result, sampleTime };
    }
    return { ...result, sampleTime: null };
  });

  // 获取设备最后一次接口采样结果（不触发重新采样）
  ipcMain.handle('db:getSavedInterfaces', (_event, id: number) => {
    return getInterfaceSnapshot(id);
  });

  // 批量检查所有设备状态
  ipcMain.handle('db:checkAllDevices', async () => {
    const result = await checkAllDevices();
    return result;
  });

  // 探测设备路由表与 ARP 表（网络拓扑）
  ipcMain.handle('db:probeTopology', async (_event, id: number) => {
    const device = queryOne<any>('SELECT * FROM devices WHERE id = ?', [id]);
    if (!device) {
      return {
        success: false,
        online: false,
        message: '设备不存在',
        deviceIp: '',
        deviceName: '',
        routes: [],
        arp: [],
      };
    }
    const result = await probeTopology(device);
    return result;
  });

  // ====== 性能监控相关 ======
  // 获取性能监控配置
  ipcMain.handle('perf:getConfig', () => {
    return getPerformanceConfig();
  });

  // 保存性能监控配置
  ipcMain.handle('perf:saveConfig', (_event, config: Partial<import('./performance-monitor').PerformanceConfig>) => {
    return savePerformanceConfig(config);
  });

  // 获取某设备的性能采样历史
  ipcMain.handle('perf:getHistory', (_event, deviceId: number, limit?: number) => {
    return getPerformanceHistory(deviceId, limit);
  });

  // 立即执行性能采样：传 deviceId 则只采单台设备，否则采样所有在线设备
  ipcMain.handle('perf:sampleNow', async (_event, deviceId?: number) => {
    if (deviceId) {
      return await sampleDeviceNow(Number(deviceId));
    }
    const result = await runPerformanceSampleOnce();
    return result;
  });

  // ====== 接口流量监控相关 ======
  // 获取流量监控配置
  ipcMain.handle('traffic:getConfig', () => {
    return getTrafficConfig();
  });

  // 保存流量监控配置
  ipcMain.handle('traffic:saveConfig', (_event, config: Partial<import('./traffic-monitor').TrafficConfig>) => {
    return saveTrafficConfig(config);
  });

  // 获取某设备的流量采样历史
  ipcMain.handle('traffic:getHistory', (_event, deviceId: number, limit?: number) => {
    return getTrafficHistory(deviceId, limit);
  });

  // 立即执行流量采样：传 deviceId 则只采单台设备，否则采样所有在线设备
  ipcMain.handle('traffic:sampleNow', async (_event, deviceId?: number) => {
    if (deviceId) {
      return await sampleTrafficNow(Number(deviceId));
    }
    const result = await runTrafficSampleOnce();
    return result;
  });

  // 获取单台设备的告警统计（设备详情页使用）
  ipcMain.handle('db:getDeviceAlertSummary', (_event, device: { ip: string; name: string }) => {
    const ip = device?.ip || '';
    const name = device?.name || '';
    if (!ip && !name) {
      return { total: 0, todayCount: 0, bySeverity: [], lastAlert: null };
    }

    const total = queryScalar<number>(
      'SELECT COUNT(*) FROM security_events WHERE device_ip = ? OR device_name = ?',
      [ip, name]
    ) || 0;

    const now = new Date();
    const todayCount = queryScalar<number>(
      'SELECT COUNT(*) FROM security_events WHERE (device_ip = ? OR device_name = ?) AND timestamp >= ? AND timestamp < ?',
      [ip, name, localDayStartUTC(now), localDayEndUTC(now)]
    ) || 0;

    const bySeverity = queryAll<{ severity: string; count: number }>(`
      SELECT severity, COUNT(*) as count
      FROM security_events
      WHERE device_ip = ? OR device_name = ?
      GROUP BY severity
      ORDER BY CASE severity
        WHEN 'critical' THEN 1 WHEN 'high' THEN 2
        WHEN 'medium' THEN 3 WHEN 'low' THEN 4
      END
    `, [ip, name]);

    const lastAlert = queryOne(`
      SELECT attack_type, severity, source_ip, target_ip, timestamp, description, acknowledged
      FROM security_events
      WHERE device_ip = ? OR device_name = ?
      ORDER BY timestamp DESC
      LIMIT 1
    `, [ip, name]);

    // 最近告警列表（设备详情页展示）
    const recentAlerts = queryAll(`
      SELECT id, attack_type, severity, source_ip, source_port, target_ip, target_port,
             device_name, device_ip, description, timestamp, acknowledged
      FROM security_events
      WHERE device_ip = ? OR device_name = ?
      ORDER BY timestamp DESC
      LIMIT 10
    `, [ip, name]);

    return { total, todayCount, bySeverity, lastAlert: lastAlert || null, recentAlerts };
  });

  // ====== IP 地址属地查询 ======
  // 查询单个 IP 属地（离线库为主 + 在线兜底）
  ipcMain.handle('ip:queryLocation', async (_event, ip: string) => {
    const loc = await queryLocation(ip || '');
    return { ...loc, display: formatLocation(loc) };
  });

  // 批量查询 IP 属地（列表页使用，返回 ip -> 展示文本 映射）
  ipcMain.handle('ip:queryLocations', async (_event, ips: string[]) => {
    return await queryLocations(Array.isArray(ips) ? ips : []);
  });

  // ====== 标准攻击类型分类 ======
  // 获取标准攻击类型列表（供筛选/报表使用）
  ipcMain.handle('event:getAttackCategories', () => {
    return DEFAULT_TYPES;
  });

  // 按标准攻击类型统计（报表/图表使用）
  ipcMain.handle('event:getCategoryTop', (_event, limit: number = 15) => {
    return queryAll(`
      SELECT attack_category, COUNT(*) as count
      FROM security_events
      WHERE attack_category IS NOT NULL AND attack_category != ''
      GROUP BY attack_category
      ORDER BY count DESC
      LIMIT ?
    `, [limit]);
  });

  // 获取分类配置文件路径
  ipcMain.handle('event:getConfigPath', () => {
    return getConfigFilePath();
  });

  // 重新加载分类配置（用户编辑配置文件后调用）
  ipcMain.handle('event:reloadConfig', () => {
    reloadConfig();
    return { success: true };
  });

  // 手动归类威胁事件：保存用户规则 + 更新当前事件类型，此后同类威胁自动归入
  ipcMain.handle('event:manualClassify', (_event, payload: { id: number; category: string; raw_trap?: string; vendor?: string }) => {
    try {
      if (!payload || !payload.id || !payload.category) {
        return { success: false, message: '参数不完整' };
      }
      const row = queryOne<{ raw_trap: string; attack_type: string; device_name: string }>(
        'SELECT raw_trap, attack_type, device_name FROM security_events WHERE id = ?',
        [payload.id]
      );
      if (!row) return { success: false, message: '事件不存在' };

      const raw = payload.raw_trap || row.raw_trap || row.attack_type || '';
      const vendor = (payload.vendor || detectVendorFromMessage(raw) || '').toLowerCase();
      const feature = extractThreatFeature(raw, vendor);
      if (!feature) {
        return { success: false, message: '该事件无法提取稳定特征，无法学习归类规则' };
      }

      // 保存/更新用户规则
      const ok = saveUserClassifyRule(vendor, feature, payload.category);
      if (!ok) return { success: false, message: '保存归类规则失败' };

      // 更新当前事件的攻击类型
      execute('UPDATE security_events SET attack_category = ? WHERE id = ?', [payload.category, payload.id]);

      return { success: true, feature, vendor, category: payload.category };
    } catch (err: any) {
      console.error('[手动归类] 失败:', err);
      return { success: false, message: err?.message || '归类失败' };
    }
  });

  // 获取全部用户手动归类规则
  ipcMain.handle('event:getUserRules', () => {
    return { success: true, rules: getUserClassifyRules() };
  });

  // 删除用户手动归类规则
  ipcMain.handle('event:deleteUserRule', (_event, id: number) => {
    const ok = deleteUserClassifyRule(id);
    return { success: ok };
  });

  // 获取全部事件类型（内置 + 自定义）
  ipcMain.handle('eventType:list', () => {
    return { success: true, types: listEventTypes() };
  });

  // 新增自定义事件类型
  ipcMain.handle('eventType:create', (_event, payload: { name: string; feature_keywords: string[]; default_severity: string }) => {
    const res = createEventType(payload?.name, payload?.feature_keywords || [], payload?.default_severity || 'medium');
    return res;
  });

  // 修改事件类型
  ipcMain.handle('eventType:update', (_event, payload: { id: number; name: string; feature_keywords: string[]; default_severity: string }) => {
    if (!payload || !payload.id) return { success: false, message: '参数不完整' };
    const res = updateEventType(payload.id, payload.name, payload.feature_keywords || [], payload.default_severity || 'medium');
    return res;
  });

  // 删除事件类型（内置类型禁止删除）
  ipcMain.handle('eventType:delete', (_event, id: number) => {
    return deleteEventType(id);
  });

  // 重新回填历史事件的标准攻击类型
  ipcMain.handle('event:backfill', () => {
    const updated = backfillAttackCategories();
    return { updated };
  });

  // ====== SNMP Trap 控制 ======
  ipcMain.handle('snmp:startTrap', async (_event, port: number = 162) => {
    const result = await startTrapReceiver(port);
    return { ...result, port, status: result.success ? 'running' : 'stopped' };
  });

  ipcMain.handle('snmp:stopTrap', () => {
    const result = stopTrapReceiver();
    return { ...result, status: 'stopped' };
  });

  ipcMain.handle('snmp:getStatus', () => {
    return getTrapStatus();
  });

  // 发送测试告警（开发调试用）
  ipcMain.handle('snmp:sendTestAlert', () => {
    sendTestAlert();
    return { success: true };
  });

  // ====== Syslog 控制 ======
  ipcMain.handle('syslog:start', async (_event, port: number = 514) => {
    const result = await startSyslogReceiver(port);
    return { ...result, port, status: result.success ? 'running' : 'stopped' };
  });

  ipcMain.handle('syslog:stop', () => {
    const result = stopSyslogReceiver();
    return { ...result, status: 'stopped' };
  });

  ipcMain.handle('syslog:getStatus', () => {
    return getSyslogStatus();
  });

  // Syslog 调试接口
  ipcMain.handle('syslog:getRecentLogs', () => {
    return getRecentLogs();
  });

  ipcMain.handle('syslog:clearLogs', () => {
    clearRecentLogs();
    return { success: true };
  });

  // ====== 告警配置 ======
  ipcMain.handle('config:getAlertConfig', () => {
    const getConfig = (key: string, defaultVal: string) =>
      queryOne<{ value: string }>('SELECT value FROM config WHERE key = ?', [key])?.value || defaultVal;
    return {
      autoClose: getConfig('alert_auto_close', 'false') === 'true',
      seconds: Number(getConfig('alert_auto_close_seconds', '30')) || 30,
      // 各威胁等级是否弹窗（默认全部开启）
      popupCritical: getConfig('alert_popup_critical', 'true') !== 'false',
      popupHigh: getConfig('alert_popup_high', 'true') !== 'false',
      popupMedium: getConfig('alert_popup_medium', 'true') !== 'false',
      popupLow: getConfig('alert_popup_low', 'true') !== 'false',
    };
  });

  ipcMain.handle('config:saveAlertConfig', (_event, config: { autoClose: boolean; seconds: number; popupCritical?: boolean; popupHigh?: boolean; popupMedium?: boolean; popupLow?: boolean }) => {
    execute('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', ['alert_auto_close', config.autoClose ? 'true' : 'false']);
    execute('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', ['alert_auto_close_seconds', String(config.seconds)]);
    if (config.popupCritical !== undefined) execute('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', ['alert_popup_critical', config.popupCritical ? 'true' : 'false']);
    if (config.popupHigh !== undefined) execute('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', ['alert_popup_high', config.popupHigh ? 'true' : 'false']);
    if (config.popupMedium !== undefined) execute('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', ['alert_popup_medium', config.popupMedium ? 'true' : 'false']);
    if (config.popupLow !== undefined) execute('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', ['alert_popup_low', config.popupLow ? 'true' : 'false']);
    return { success: true };
  });

  // ====== 设备离线监测 ======
  ipcMain.handle('monitor:getConfig', () => {
    return getMonitorConfig();
  });

  ipcMain.handle('monitor:saveConfig', (_event, config: Parameters<typeof saveMonitorConfig>[0]) => {
    return saveMonitorConfig(config);
  });

  ipcMain.handle('monitor:getStatus', () => {
    return getMonitorStatus();
  });

  ipcMain.handle('monitor:runNow', async () => {
    return await runMonitorOnce();
  });

  // ====== 原始报文调试配置 ======
  ipcMain.handle('rawlog:getConfig', () => {
    return getRawLogConfig();
  });

  ipcMain.handle('rawlog:updateConfig', (_event, config: {
    enabled: boolean;
    baseDir: string;
    snmpEnabled: boolean;
    syslogEnabled: boolean;
  }) => {
    updateRawLogConfig(config);
    return { success: true };
  });

  // 选择文件夹（用于原始报文保存目录）
  ipcMain.handle('dialog:selectDirectory', async () => {
    const result = await dialog.showOpenDialog({
      title: '选择原始报文保存目录',
      properties: ['openDirectory', 'createDirectory'],
    });
    if (result.canceled || result.filePaths.length === 0) {
      return null;
    }
    return result.filePaths[0];
  });

  // ====== 应用信息 ======
  ipcMain.handle('app:getVersion', () => {
    return require('../../package.json').version;
  });
}
