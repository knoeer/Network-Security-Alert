/**
 * 跨厂商安全事件攻击类型分类器
 *
 * 功能：将各厂商安全设备的报警报文，归一化分类到统一的标准攻击类型
 * （病毒/木马/僵尸网络/间谍软件/广告软件/CGI攻击/跨站脚本攻击/注入攻击/目录遍历/
 *  信息泄漏/远程文件包含攻击/溢出攻击/代码执行/拒绝服务/扫描工具/蠕虫/后门/
 *  分布式拒绝服务/webshell/Ransomware/其他）
 *
 * 分类依据：event-type-map.json 配置文件（可编辑，无需改代码）
 *  - 开发环境：{项目根}/config/event-type-map.json
 *  - 打包环境：{resources}/config/event-type-map.json
 *
 * 分类逻辑：
 *   1. 从报文提取攻击特征文本（SignName / signature / type / threat-name 等）
 *   2. 按配置文件 classifier 顺序匹配关键字（正则，不区分大小写）
 *   3. 命中即返回该类型；无命中返回 defaultType（其他）
 *
 * 设计说明：
 *   - classifier 数组顺序 = 匹配优先级，同时命中时靠前者优先
 *   - 无攻击特征词的报文（如仅 action=deny）归类为"其他"
 */
import fs from 'fs';
import path from 'path';
import { app } from 'electron';
import { queryAll, queryOne, execute, executeInsert } from './db-helper';

export const DEFAULT_TYPES = [
  '系统事件', '病毒', '木马', '僵尸网络', '间谍软件', '广告软件', 'CGI攻击', '跨站脚本攻击',
  '注入攻击', '目录遍历', '信息泄漏', '远程文件包含攻击', '溢出攻击', '代码执行',
  '拒绝服务', '扫描工具', '蠕虫', '后门', '分布式拒绝服务', 'webshell', 'Ransomware', '其他'
];

interface ClassifierRule {
  type: string;
  keywords: string[];
}

interface EventTypeMap {
  types: string[];
  classifier: ClassifierRule[];
  defaultType: string;
}

// 配置缓存（避免重复读取文件）
let config: EventTypeMap | null = null;
let configPath: string | null = null;

/**
 * 获取配置文件路径（兼容开发与打包）
 */
function getConfigPath(): string {
  const appPath = app.getAppPath();
  const candidates = [
    path.join(appPath, 'config', 'event-type-map.json'),
    path.join(process.resourcesPath || '', 'config', 'event-type-map.json'),
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  return candidates[0];
}

/**
 * 加载配置（懒加载 + 缓存）
 */
export function loadConfig(): EventTypeMap {
  if (config) return config;
  const p = getConfigPath();
  configPath = p;
  try {
    if (fs.existsSync(p)) {
      config = JSON.parse(fs.readFileSync(p, 'utf8'));
    }
  } catch (err) {
    console.error('[事件分类] 配置文件读取失败，使用默认分类:', err);
  }
  if (!config || !Array.isArray(config.classifier)) {
    config = { types: DEFAULT_TYPES, classifier: [], defaultType: '其他' };
  }
  return config;
}

/**
 * 重新加载配置（用户编辑配置文件后调用）
 */
export function reloadConfig(): void {
  config = null;
  loadConfig();
}

/**
 * 获取配置文件路径（供外部展示）
 */
export function getConfigFilePath(): string | null {
  return configPath || getConfigPath();
}

/**
 * 编译关键字为正则（缓存编译结果）
 */
const regexCache = new Map<string, RegExp>();
function compileRegex(keyword: string): RegExp {
  if (regexCache.has(keyword)) return regexCache.get(keyword)!;
  const re = new RegExp(keyword, 'i');
  regexCache.set(keyword, re);
  return re;
}

/**
 * 核心分类函数：根据攻击特征文本，返回标准攻击类型
 * @param featureText 攻击特征文本（SignName、signature、type 等，越全越准）
 * @returns 标准攻击类型名称
 */
export function classifyEvent(featureText: string | undefined | null): string {
  const text = (featureText || '').trim();
  if (!text) return DEFAULT_TYPES[DEFAULT_TYPES.length - 1]; // 其他

  const cfg = loadConfig();
  for (const rule of cfg.classifier || []) {
    if (!rule.keywords || rule.keywords.length === 0) continue;
    for (const kw of rule.keywords) {
      try {
        if (compileRegex(kw).test(text)) {
          return rule.type;
        }
      } catch {
        // 忽略无效正则
      }
    }
  }
  return cfg.defaultType || DEFAULT_TYPES[DEFAULT_TYPES.length - 1];
}

/**
 * 从华为 IPS 报文提取 SignName
 */
export function extractHuaweiSignName(message: string): string {
  const m = message.match(/SignName="([^"]*)"/);
  return m ? m[1].trim() : '';
}

/**
 * 从 CSSOS WAF 报文提取 type
 */
export function extractCssosType(message: string): string {
  const m = message.match(/rule_id=\d+\s+type=([^\s|]+)/);
  return m ? m[1].trim() : '';
}

/**
 * 从思科/其他厂商报文提取 signature / attack-name / threat-name
 */
export function extractVendorFeature(message: string): string {
  const m = message.match(/(?:signature|attack[_-]?name|threat[_-]?name)\s*[=:]\s*"?([^",\s]+)/i);
  return m ? m[1].trim() : '';
}

/**
 * 通用入口：给定一条原始报文和厂商，返回标准攻击类型
 * @param message 原始报文
 * @param vendor 厂商名（huawei/cssos/cisco 等）
 */
export function classifyMessage(message: string, vendor?: string): string {
  return classifyMessageDetailed(message, vendor).category;
}

/**
 * 分类来源类型：
 * - 'user_rule'     用户手动归类学习的签名规则
 * - 'custom_keyword' 自定义事件类型的特征关键字
 * - 'builtin'        内置配置（event-type-map.json）关键字
 * - 'default'        未命中任何规则，回退到默认类型
 */
export type ClassifySource = 'user_rule' | 'custom_keyword' | 'builtin' | 'default';

/**
 * 分类并返回来源（用于事件详情页标注归类依据）
 * @param message 原始报文
 * @param vendor 厂商名
 * @returns { category, source }
 */
export function classifyMessageDetailed(message: string, vendor?: string): { category: string; source: ClassifySource } {
  if (!message) {
    return { category: DEFAULT_TYPES[DEFAULT_TYPES.length - 1], source: 'default' };
  }
  const v = (vendor || '').toLowerCase();

  // 1. 用户手动归类规则（优先级最高，签名级精确匹配）
  const userCategory = classifyByUserRule(message, v);
  if (userCategory) return { category: userCategory, source: 'user_rule' };

  // 2. 自定义事件类型的特征关键字自动匹配
  let feature = '';
  if (v === 'huawei') {
    feature = extractHuaweiSignName(message);
  } else if (v === 'cssos') {
    feature = extractCssosType(message);
    if (!feature) {
      feature = message;
    }
  } else {
    feature = extractVendorFeature(message) || message;
  }

  const customCategory = classifyByCustomKeywords(message, feature);
  if (customCategory) return { category: customCategory, source: 'custom_keyword' };

  // 3. 内置关键字分类
  const builtinCategory = classifyEvent(feature || message);
  if (builtinCategory) return { category: builtinCategory, source: 'builtin' };

  // 4. 默认兜底
  return { category: DEFAULT_TYPES[DEFAULT_TYPES.length - 1], source: 'default' };
}

/**
 * 按自定义事件类型（custom_event_types）的 feature_keywords 自动匹配。
 * 用户新增/编辑事件类型时填写的特征关键字会在此参与自动分类，
 * 命中即返回对应类型名称，未命中返回空字符串。
 * 匹配对象同时包含原始报文与提取的特征文本，提高命中率。
 */
export function classifyByCustomKeywords(message: string, featureText: string): string {
  try {
    const searchText = `${message}\n${featureText || ''}`.toLowerCase();
    if (!searchText.trim()) return '';
    const types = queryAll<{ name: string; feature_keywords: string }>(
      'SELECT name, feature_keywords FROM custom_event_types WHERE feature_keywords IS NOT NULL AND feature_keywords != \'[]\' AND feature_keywords != \'\''
    );
    for (const t of types) {
      let keywords: string[] = [];
      try {
        keywords = JSON.parse(t.feature_keywords || '[]');
      } catch {
        continue;
      }
      if (!Array.isArray(keywords) || keywords.length === 0) continue;
      for (const kw of keywords) {
        const k = (kw || '').trim().toLowerCase();
        if (!k) continue;
        // 关键字直接作为子串匹配（不视为正则，避免用户输入特殊字符报错）
        if (searchText.includes(k)) {
          return t.name;
        }
      }
    }
    return '';
  } catch (err) {
    console.error('[事件分类] 自定义类型关键字匹配失败:', err);
    return '';
  }
}

/**
 * 提取一条事件的"同类威胁"特征键（用于用户规则匹配）
 * 返回规范化的小写特征文本；无特征时返回空字符串。
 * 华为优先取 SignName（签名名稳定唯一），缺失则取 SignID；其他厂商取 signature/threat-name。
 */
export function extractThreatFeature(message: string, vendor?: string): string {
  if (!message) return '';
  const v = (vendor || '').toLowerCase();

  let feature = '';
  if (v === 'huawei') {
    feature = extractHuaweiSignName(message);
    if (!feature) {
      const id = message.match(/Sign(?:ID|Id|ID|atureID)\s*=\s*"?(\d+)"?/i);
      if (id) feature = id[1].trim();
    }
  } else if (v === 'cssos') {
    feature = extractCssosType(message);
  } else {
    feature = extractVendorFeature(message);
  }
  return feature.trim();
}

/**
 * 按用户手动归类规则分类（用户规则优先于内置配置）
 */
export function classifyByUserRule(message: string, vendor: string): string {
  try {
    const feature = extractThreatFeature(message, vendor);
    if (!feature) return '';
    const v = vendor.toLowerCase();
    const row = queryAll<{ category: string }>(
      'SELECT category FROM user_classify_rules WHERE vendor = ? AND feature = ?',
      [v, feature]
    );
    return row && row.length > 0 ? row[0].category : '';
  } catch (err) {
    console.error('[事件分类] 查询用户规则失败:', err);
    return '';
  }
}

/**
 * 保存（或更新）一条用户手动归类规则
 * 同一 (vendor, feature) 只保留一条规则，重复归类时更新目标类型。
 * @returns 是否成功
 */
export function saveUserClassifyRule(vendor: string, feature: string, category: string): boolean {
  try {
    const v = (vendor || '').toLowerCase();
    if (!feature || !category) return false;
    execute(
      `INSERT INTO user_classify_rules (vendor, feature, category, updated_at)
       VALUES (?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(vendor, feature) DO UPDATE SET category = excluded.category, updated_at = CURRENT_TIMESTAMP`,
      [v, feature, category]
    );
    return true;
  } catch (err) {
    console.error('[事件分类] 保存用户规则失败:', err);
    return false;
  }
}

/**
 * 删除用户手动归类规则
 */
export function deleteUserClassifyRule(id: number): boolean {
  try {
    execute('DELETE FROM user_classify_rules WHERE id = ?', [id]);
    return true;
  } catch (err) {
    console.error('[事件分类] 删除用户规则失败:', err);
    return false;
  }
}

/**
 * 获取全部用户手动归类规则
 */
export function getUserClassifyRules(): Array<{ id: number; vendor: string; feature: string; category: string; created_at: string; updated_at: string }> {
  try {
    return queryAll(
      'SELECT id, vendor, feature, category, created_at, updated_at FROM user_classify_rules ORDER BY updated_at DESC'
    );
  } catch (err) {
    console.error('[事件分类] 获取用户规则失败:', err);
    return [];
  }
}

// 合法威胁程度（固定 4 档）
const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low'];

/**
 * 校验威胁程度是否合法
 */
export function isValidSeverity(severity: string): boolean {
  return SEVERITY_LEVELS.includes(severity);
}

/**
 * 获取全部事件类型（内置 + 自定义）
 */
export function listEventTypes(): Array<{ id: number; name: string; feature_keywords: string; default_severity: string; is_builtin: number }> {
  try {
    return queryAll(
      'SELECT id, name, feature_keywords, default_severity, is_builtin FROM custom_event_types ORDER BY is_builtin DESC, name ASC'
    );
  } catch (err) {
    console.error('[事件类型] 获取列表失败:', err);
    return [];
  }
}

/**
 * 新增自定义事件类型
 * @param name 类型名称（唯一）
 * @param featureKeywords 特征关键字数组
 * @param defaultSeverity 默认威胁程度
 */
export function createEventType(name: string, featureKeywords: string[], defaultSeverity: string): { success: boolean; message?: string; id?: number } {
  const n = (name || '').trim();
  if (!n) return { success: false, message: '类型名称不能为空' };
  if (!isValidSeverity(defaultSeverity)) return { success: false, message: '威胁程度不合法' };
  try {
    const existing = queryAll<{ id: number }>('SELECT id FROM custom_event_types WHERE name = ?', [n]);
    if (existing.length > 0) return { success: false, message: '该事件类型已存在' };
    const id = executeInsert(
      'INSERT INTO custom_event_types (name, feature_keywords, default_severity) VALUES (?, ?, ?)',
      [n, JSON.stringify(featureKeywords || []), defaultSeverity]
    );
    return { success: true, id };
  } catch (err) {
    console.error('[事件类型] 新增失败:', err);
    return { success: false, message: '新增事件类型失败' };
  }
}

/**
 * 修改事件类型（改名/改特征关键字/改默认威胁程度）
 * @param id 类型 id
 * @param name 新名称
 * @param featureKeywords 特征关键字数组
 * @param defaultSeverity 默认威胁程度
 */
export function updateEventType(id: number, name: string, featureKeywords: string[], defaultSeverity: string): { success: boolean; message?: string } {
  const n = (name || '').trim();
  if (!n) return { success: false, message: '类型名称不能为空' };
  if (!isValidSeverity(defaultSeverity)) return { success: false, message: '威胁程度不合法' };
  try {
    const dup = queryAll<{ id: number }>('SELECT id FROM custom_event_types WHERE name = ? AND id != ?', [n, id]);
    if (dup.length > 0) return { success: false, message: '该事件类型已存在' };
    const row = queryOne<{ name: string }>('SELECT name FROM custom_event_types WHERE id = ?', [id]);
    if (!row) return { success: false, message: '事件类型不存在' };

    execute(
      'UPDATE custom_event_types SET name = ?, feature_keywords = ?, default_severity = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [n, JSON.stringify(featureKeywords || []), defaultSeverity, id]
    );

    // 若名称变化，同步更新用户归类规则中指向该类型的 category，避免归类失联
    if (row.name !== n) {
      execute('UPDATE user_classify_rules SET category = ? WHERE category = ?', [n, row.name]);
    }
    return { success: true };
  } catch (err) {
    console.error('[事件类型] 修改失败:', err);
    return { success: false, message: '修改事件类型失败' };
  }
}

/**
 * 删除事件类型（内置类型禁止删除）
 * @param id 类型 id
 */
export function deleteEventType(id: number): { success: boolean; message?: string } {
  try {
    const row = queryOne<{ is_builtin: number }>('SELECT is_builtin FROM custom_event_types WHERE id = ?', [id]);
    if (!row) return { success: false, message: '事件类型不存在' };
    if (row.is_builtin === 1) return { success: false, message: '内置类型不可删除' };
    execute('DELETE FROM custom_event_types WHERE id = ?', [id]);
    return { success: true };
  } catch (err) {
    console.error('[事件类型] 删除失败:', err);
    return { success: false, message: '删除事件类型失败' };
  }
}

/**
 * 判断厂商（用于历史记录回填）
 */
export function detectVendorFromMessage(message: string): string {
  if (!message) return '';
  if (/%%01/.test(message)) return 'huawei';
  if (/\bWAF:\s/.test(message) || /\bdevicename=/.test(message)) return 'cssos';
  if (/^%(ASA|PIX|FTD)/.test(message) || /106023|733100/.test(message)) return 'cisco';
  return '';
}

/**
 * 对历史事件回填标准攻击类型
 * 对 attack_category 仍为默认值且 raw_trap 含威胁特征的记录，重新分类回填。
 * 在应用启动时调用一次。
 */
export function backfillAttackCategories(): number {
  try {
    const rows = queryAll<{ id: number; raw_trap: string; attack_type: string }>(
      `SELECT id, raw_trap, attack_type FROM security_events
       WHERE attack_category IS NULL OR attack_category = '' OR attack_category = '其他'
       ORDER BY id`
    );
    let updated = 0;
    for (const row of rows) {
      const raw = row.raw_trap || row.attack_type || '';
      if (!raw) continue;
      const vendor = detectVendorFromMessage(raw);
      const category = classifyMessage(raw, vendor);
      if (category && category !== '其他') {
        execute('UPDATE security_events SET attack_category = ? WHERE id = ?', [category, row.id]);
        updated++;
      }
    }
    if (updated > 0) {
      console.log(`[事件分类] 已回填 ${updated} 条历史事件的标准攻击类型`);
    }
    return updated;
  } catch (err) {
    console.error('[事件分类] 历史回填失败:', err);
    return 0;
  }
}
