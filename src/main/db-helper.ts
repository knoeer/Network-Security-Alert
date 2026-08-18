/**
 * sql.js 查询辅助函数
 * 提供类似 better-sqlite3 的便捷查询接口
 */
import { getDbSync, persistDatabase } from './database';

/**
 * 查询所有记录
 */
export function queryAll<T = any>(sql: string, params: any[] = []): T[] {
  const db = getDbSync();
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const results: T[] = [];
  while (stmt.step()) {
    results.push(stmt.getAsObject() as T);
  }
  stmt.free();
  return results;
}

/**
 * 查询单条记录
 */
export function queryOne<T = any>(sql: string, params: any[] = []): T | undefined {
  const results = queryAll<T>(sql, params);
  return results[0];
}

/**
 * 执行写操作（INSERT/UPDATE/DELETE）
 * 返回影响的行数
 */
export function execute(sql: string, params: any[] = []): number {
  const db = getDbSync();
  db.run(sql, params);
  persistDatabase();
  return db.getRowsModified();
}

/**
 * 执行写操作并返回最后插入的行 ID
 */
export function executeInsert(sql: string, params: any[] = []): number {
  const db = getDbSync();
  db.run(sql, params);
  const lastId = getLastInsertId();
  persistDatabase();
  return lastId;
}

/**
 * 获取最后插入的行 ID
 */
export function getLastInsertId(): number {
  const db = getDbSync();
  const result = db.exec('SELECT last_insert_rowid() as id');
  if (result.length > 0 && result[0].values.length > 0) {
    return Number(result[0].values[0][0]);
  }
  return 0;
}

/**
 * 查询标量值
 */
export function queryScalar<T = number | string>(sql: string, params: any[] = []): T {
  const db = getDbSync();
  const result = db.exec(sql, params);
  if (result.length > 0 && result[0].values.length > 0) {
    return result[0].values[0][0] as T;
  }
  return undefined as T;
}
