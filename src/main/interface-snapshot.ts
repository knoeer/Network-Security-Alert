/**
 * 接口采样快照持久化模块
 * 保存每台设备"最后一次网络接口与流量采样结果"到数据库，
 * 支持前端进入页面时直接读取上次结果（不触发重新采样）。
 */
import { execute, queryOne } from './db-helper';

interface InterfaceSnapshotRow {
  interfaces: string;
  sample_time: string;
}

/** 确保接口快照表存在（幂等） */
export function ensureInterfaceSnapshotTable(): void {
  execute(`
    CREATE TABLE IF NOT EXISTS device_interfaces (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id INTEGER NOT NULL,
      interfaces TEXT NOT NULL,
      sample_time TEXT NOT NULL,
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    )
  `);
  execute('CREATE INDEX IF NOT EXISTS idx_device_interfaces_device ON device_interfaces(device_id)');
}

/**
 * 保存某设备最后一次接口采样结果（同一设备只保留一条最新记录）
 * @param deviceId 设备 ID
 * @param interfaces 接口列表（DeviceInterface[]）
 * @param sampleTime 采样时间（ISO UTC）
 */
export function saveInterfaceSnapshot(
  deviceId: number,
  interfaces: unknown[],
  sampleTime: string
): void {
  ensureInterfaceSnapshotTable();
  // 先删除该设备旧记录，再插入最新一条（保证只保存最后一次）
  execute('DELETE FROM device_interfaces WHERE device_id = ?', [deviceId]);
  execute(
    'INSERT INTO device_interfaces (device_id, interfaces, sample_time) VALUES (?, ?, ?)',
    [deviceId, JSON.stringify(interfaces), sampleTime]
  );
}

/**
 * 获取设备最后一次接口采样结果
 * @returns { interfaces: DeviceInterface[], sampleTime: string | null }
 *          没有保存过采样结果时返回 { interfaces: null, sampleTime: null }
 */
export function getInterfaceSnapshot(deviceId: number): {
  interfaces: unknown[] | null;
  sampleTime: string | null;
} {
  ensureInterfaceSnapshotTable();
  const row = queryOne<InterfaceSnapshotRow>(
    'SELECT interfaces, sample_time FROM device_interfaces WHERE device_id = ? ORDER BY id DESC LIMIT 1',
    [deviceId]
  );
  if (!row) {
    return { interfaces: null, sampleTime: null };
  }
  try {
    const interfaces = JSON.parse(row.interfaces);
    return { interfaces, sampleTime: row.sample_time };
  } catch {
    return { interfaces: null, sampleTime: null };
  }
}
