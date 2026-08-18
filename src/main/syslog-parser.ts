/**
 * Syslog 日志解析器
 * 解析华为 USG 防火墙的威胁日志，提取攻击类型、源/目标 IP、端口、严重级别
 * 华为日志格式：%%01MODULE/SEVERITY/EVENTNAME(l):key1=value1,key2=value2,...
 * 
 * 日志分类：
 *   - 威胁类（IPS/AV/ATK/DDOS/SEC等）→ 作为安全告警入库+弹窗
 *   - 系统类（CPUDEFEND/SYSTEM/IPSEC等）→ 非威胁，仅记录，不弹窗
 */
import { AlertData } from './alert-common';
import { detectVendor, isVendorThreat, parseVendorSyslog } from './vendor-parser';

// 华为防火墙事件名到攻击类型的映射
const EVENT_PATTERNS: Array<{ regex: RegExp; attackType: string; severity: AlertData['severity'] }> = [
  { regex: /POLICYDENY|POLICY DENY|策略拒绝/i, attackType: '策略拒绝', severity: 'medium' },
  { regex: /POLICYPERMIT/i, attackType: '策略放行', severity: 'low' },
  { regex: /PORT.?SCAN|端口扫描/i, attackType: '端口扫描', severity: 'medium' },
  { regex: /DDOS|DOS ATTACK|拒绝服务/i, attackType: 'DDoS攻击', severity: 'critical' },
  { regex: /BRUTE.?FORCE|暴力破解|PASSWORD GUESS/i, attackType: '暴力破解', severity: 'high' },
  { regex: /SQL.?INJECT|SQL注入/i, attackType: 'SQL注入攻击', severity: 'critical' },
  { regex: /VIRUS|WORM|TROJAN|MALWARE|病毒|木马|蠕虫|恶意/i, attackType: '恶意软件', severity: 'high' },
  { regex: /BUFFER.?OVERFLOW|缓冲区溢出/i, attackType: '缓冲区溢出', severity: 'critical' },
  { regex: /PHISHING|钓鱼/i, attackType: '网络钓鱼', severity: 'high' },
  { regex: /LOGIN.?FAIL|AUTHENTICATION|认证失败|登录失败|UNAUTHORIZED|未授权/i, attackType: '未授权访问', severity: 'high' },
  { regex: /INTRUSION|入侵|ATTACK|攻击/i, attackType: '入侵攻击', severity: 'critical' },
  { regex: /ARP.?SPOOF|ARP欺骗/i, attackType: 'ARP欺骗', severity: 'high' },
  { regex: /SCAN|扫描/i, attackType: '网络扫描', severity: 'medium' },
  { regex: /WEBSHELL|CND|木马/i, attackType: 'Web攻击', severity: 'high' },
  ];

  /**
  * WAF 攻击类型映射表（根据 type= 字段及关键字识别）
  * 覆盖常见 WAF 检测到的攻击类型
  */
  const WAF_TYPE_PATTERNS: Array<{ regex: RegExp; attackType: string; severity: AlertData['severity'] }> = [
  { regex: /HTTP CONFORMITY|HTTP合规|HTTP合规性/i, attackType: 'HTTP合规性攻击', severity: 'medium' },
  { regex: /SQL INJECT|SQL注入/i, attackType: 'SQL注入攻击', severity: 'critical' },
  { regex: /XSS|CROSS.?SITE/i, attackType: 'XSS跨站脚本攻击', severity: 'high' },
  { regex: /WEBSHELL|木马|TROJAN/i, attackType: 'Webshell木马攻击', severity: 'critical' },
  { regex: /CC ATTACK|CC攻击|FLOOD/i, attackType: 'CC攻击', severity: 'high' },
  { regex: /CSRF/i, attackType: 'CSRF跨站请求伪造', severity: 'high' },
  { regex: /FILE INCLUSION|文件包含/i, attackType: '文件包含攻击', severity: 'high' },
  { regex: /COMMAND INJECT|命令注入/i, attackType: '命令注入攻击', severity: 'critical' },
  { regex: /DIRECTORY TRAVERSAL|目录遍历|\.\.\//i, attackType: '目录遍历攻击', severity: 'high' },
  { regex: /SENSITIVE|敏感信息|INFORMATION LEAK/i, attackType: '敏感信息泄露', severity: 'medium' },
  { regex: /SCANNER|SCAN|扫描/i, attackType: 'Web扫描探测', severity: 'medium' },
  { regex: /BRUTE|暴力|LOGIN FAIL/i, attackType: '暴力破解', severity: 'high' },
  { regex: /UPLOAD|上传/i, attackType: '文件上传攻击', severity: 'critical' },
  ];

/**
 * 华为威胁类模块前缀（这些模块产生的日志是安全威胁）
 */
const THREAT_MODULES = /%%01(IPS|AV|ATK|DDOS|SEC|THREAT|ATTACK|APT|CND|BLS|URLF|IDP|NGE_IPS|NGE_AV|NGE_ATK|NGE_DDOS)/i;

/**
 * 华为系统类模块前缀（这些是系统状态日志，非威胁）
 */
const SYSTEM_MODULES = /%%01(CPUDEFEND|SYSTEM|INFO|ENTEXT|IPSEC|SNMP|FM|CLI|CFG|LOG|HTTPD|HRP|BGP|OSPF|NTP|DEV|DEVM|IFNET|VTY)/i;

/**
 * 华为系统事件中文描述表
 */
const SYSTEM_EVENT_DESC: Array<{ regex: RegExp; attackType: string; description: string; severity: AlertData['severity'] }> = [
  { regex: /CPUDEFEND.*cpcar.*alarm_clear/i, attackType: 'CPU负载恢复', description: 'CPU 报文限速告警已解除，服务恢复正常', severity: 'low' },
  { regex: /CPUDEFEND.*cpcar.*drop/i, attackType: 'CPU过载丢包', description: 'CPU 接收速率超过限制，报文被丢弃（可能为流量洪峰）', severity: 'medium' },
  { regex: /CPUDEFEND/i, attackType: 'CPU防御告警', description: 'CPU 防御机制触发', severity: 'medium' },
  { regex: /CPUUsage|CpuUsage/i, attackType: 'CPU使用率告警', description: '设备 CPU 使用率异常', severity: 'medium' },
  { regex: /SYSTEM\/.*TM_TIME|时间变更/i, attackType: '系统时间变更', description: '设备系统时间被修改', severity: 'low' },
  { regex: /WARMSTART|COLDSTART/i, attackType: '设备重启', description: '设备重启（SNMP 系统事件）', severity: 'medium' },
  { regex: /LINK.?UP|LINK.?DOWN/i, attackType: '链路状态变更', description: '网络链路状态变化', severity: 'low' },
  { regex: /AUTHFAIL|authentication.*fail/i, attackType: 'SNMP认证失败', description: 'SNMP 访问认证失败，可能存在未授权访问尝试', severity: 'high' },
  { regex: /CFG.?CHANGE|CONFIG/i, attackType: '配置变更', description: '设备配置被修改', severity: 'low' },
  { regex: /IKE.*ESTABLISH|IPSEC/i, attackType: 'VPN隧道事件', description: 'IPSec VPN 隧道建立或状态变化', severity: 'low' },
];

/**
 * 安全解析端口号（校验有效性，无效返回 0）
 */
function parsePort(value: string | undefined | null): number {
  if (value === undefined || value === null || value === '') return 0;
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0 || num > 65535 || !Number.isInteger(num)) return 0;
  return num;
}

/**
 * 去除字段值两侧的引号（华为 key=value 中 SignName/Policy 等带双引号）
 */
function stripQuotes(value: string | undefined | null): string {
  if (!value) return value || '';
  return value.replace(/^"+|"+$/g, '');
}

/**
 * 从华为/WAF key=value 格式日志中提取字段
 * 值支持包含空格（如 WAF 的 type=HTTP Conformity Rule 可完整提取），
 * 遇到下一个 key= 或 , ; 或行尾时停止；空值字段（如 http_type=）不会被吞并后续内容
 */
function extractFields(message: string): Record<string, string> {
  const fields: Record<string, string> = {};
  // 值首字符必须非空白（避免空值字段吞并后续 key），且允许中间空格直到下一个 key=
  const kvRegex = /([a-zA-Z][\w-]*)=((?:[^\s][^,;]*?)?)(?=\s+[a-zA-Z][\w-]*=|\s*$|,|;)/g;
  let match;
  while ((match = kvRegex.exec(message)) !== null) {
    fields[match[1].toLowerCase()] = match[2].trim();
  }
  return fields;
}

/**
 * 提取华为日志头信息 %%01MODULE/SEVERITY/EVENTNAME
 */
function extractHuaweiHeader(message: string): { module: string; severity: number; eventName: string } {
  const m = message.match(/%%01([A-Za-z0-9_]+)\/(\d+)\/([A-Za-z0-9_]+)/);
  return {
    module: m ? m[1] : '',
    severity: m ? Number(m[2]) : 0,
    eventName: m ? m[3] : '',
  };
}

/**
 * 解析攻击类型和严重级别（基于事件名 EVENTNAME）
 */
function parseThreatType(message: string): { attackType: string; severity: AlertData['severity'] } {
  for (const pattern of EVENT_PATTERNS) {
    if (pattern.regex.test(message)) {
      return { attackType: pattern.attackType, severity: pattern.severity };
    }
  }
  // 默认：带 IP 的安全日志视为网络活动
  if (/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(message)) {
    return { attackType: '网络活动告警', severity: 'low' };
  }
  return { attackType: '安全日志', severity: 'low' };
}

/**
 * 判断是否为 WAF 设备的攻击日志
 * WAF 报文特征：
 *   - 含 "WAF:" 设备类型标记
 *   - 含 devicename= 字段，且报文结构为 源IP:端口->目标 方向格式
 *   - 含 type=/action=/attack_field 等 WAF 专用字段
 */
function isWafLog(message: string): boolean {
  return (
    /\bWAF:/i.test(message) ||
    /devicename=[^\s,;]+/.test(message) && /\d+\.\d+\.\d+\.\d+:\d+\s*->/.test(message)
  );
}

/**
 * 从 WAF 报文的方向段提取源 IP 和源端口
 * 格式：39.144.142.111:44892->psxzyy-ybydzf.lszyktwx.com
 */
function extractWafSource(message: string): { ip: string; port: number } {
  const m = message.match(/(\d+\.\d+\.\d+\.\d+):(\d+)\s*->/);
  if (m) {
    return { ip: m[1], port: parsePort(m[2]) };
  }
  return { ip: '', port: 0 };
}

/**
 * 从 WAF 报文的方向段提取目标（域名或 IP）
 * 格式：->psxzyy-ybydzf.lszyktwx.com
 */
function extractWafTargetHost(message: string): string {
  const m = message.match(/->\s*([^\s,;]+)/);
  return m ? m[1].trim() : '';
}

/**
 * 解析 WAF 攻击类型和严重级别（基于 type= 字段及关键字）
 */
function parseWafThreatType(message: string, fields: Record<string, string>): { attackType: string; severity: AlertData['severity'] } {
  // 优先用 type= 字段（含空格需提取完整值）
  const typeField = fields['type'] || '';
  const searchText = `${typeField} ${message}`;
  for (const pattern of WAF_TYPE_PATTERNS) {
    if (pattern.regex.test(searchText)) {
      return { attackType: pattern.attackType, severity: pattern.severity };
    }
  }
  // 默认 Web 攻击
  return { attackType: 'Web攻击', severity: 'medium' };
}

/**
 * WAF 报文严重级别映射
 * 优先遵循设备明确的 severity 数字字段（越大越严重，0=低危），
 * 仅在缺少 severity 字段时才用 action 与攻击类型兜底推断。
 * 说明：主流 WAF 惯例，severity 0-7，越大越严重，0 为低危。
 */
function mapWafSeverity(message: string, fields: Record<string, string>): AlertData['severity'] {
  const sev = fields['severity'] || '';
  const numSev = Number(sev);

  // 1. 设备明确给出 severity 数字 → 完全遵循（0=低危，越大越严重）
  if (sev !== '' && !Number.isNaN(numSev)) {
    if (numSev >= 5) return 'critical';
    if (numSev >= 3) return 'high';
    if (numSev >= 1) return 'medium';
    return 'low'; // 0 = 低危
  }

  // 2. 无 severity 字段时，按攻击类型危害 + action 兜底推断
  const { severity: typeSev } = parseWafThreatType(message, fields);
  const action = (fields['action'] || '').toUpperCase();
  // REJECT/BLOCK/DROP 主动拦截，在类型基础上适当加权
  if (action === 'REJECT' || action === 'BLOCK' || action === 'DROP') {
    if (typeSev === 'low') return 'medium';
    return typeSev;
  }
  return typeSev;
}

/**
 * 生成 WAF 攻击的中文描述
 */
function generateWafDescription(message: string, fields: Record<string, string>): string {
  const { attackType } = parseWafThreatType(message, fields);
  const method = fields['method'] || '';
  const url = fields['url'] || '';
  const ruleId = fields['rule_id'] || '';
  const profileId = fields['profile_id'] || '';
  const host = extractWafTargetHost(message);
  const action = (fields['action'] || '').toUpperCase();

  const parts: string[] = [];
  parts.push(`WAF拦截「${attackType}」`);
  if (method) parts.push(`请求方式 ${method}`);
  if (url) parts.push(`URL ${url}`);
  if (host) parts.push(`目标 ${host}`);
  if (ruleId) parts.push(`命中规则 #${ruleId}`);
  if (profileId) parts.push(`策略组 #${profileId}`);
  if (action) parts.push(`动作 ${action}`);
  return parts.join('，');
}

/**
 * 判断是否为威胁日志（返回 true=威胁，false=系统/非威胁）
 * 比旧版更精确：只认威胁模块前缀，避免系统日志误判
 */
export function isThreatLog(message: string): boolean {
  // 多厂商识别：非华为厂商走专用威胁识别逻辑
  const vendor = detectVendor(message);
  if (vendor !== 'huawei') {
    return isVendorThreat(message, vendor);
  }

  // WAF 攻击日志：含 WAF 结构，且带攻击特征（拦截/告警动作或明确的攻击 type 字段）
  if (isWafLog(message)) {
    const fields = extractFields(message);
    const action = (fields['action'] || '').toUpperCase();
    const typeField = fields['type'] || '';
    // 主动拦截/告警，或 type 字段能匹配到攻击类型 → 视为威胁
    if (/^(REJECT|BLOCK|DROP|DENY|ALERT)$/.test(action) || WAF_TYPE_PATTERNS.some(p => p.regex.test(`${typeField} ${message}`))) {
      return true;
    }
    // 无攻击特征（如纯放行/正常记录）→ 非威胁
    return false;
  }
  // 威胁模块前缀（如 IPS、AV、ATK、DDOS、SEC）
  if (THREAT_MODULES.test(message)) {
    return true;
  }
  // 攻击/威胁关键字
  const hasAttackKeyword = EVENT_PATTERNS.some(p => p.regex.test(message));
  // 策略命中（deny/permit）作为低威胁
  const isPolicyLog = /%%01POLICY\/.*(DENY|PERMIT)|策略命中|policy (deny|hit)/i.test(message);

  return hasAttackKeyword || isPolicyLog;
}

/**
 * 生成中文描述（根据华为事件名+字段）
 * 优先级：威胁名称 > 攻击类型 > 事件名
 */
function generateDescription(message: string, fields: Record<string, string>): string {
  const { module, eventName } = extractHuaweiHeader(message);
  let desc = '';

  // 1. 优先用威胁名称（SignName），如 "Web Scanner: Censys"（去除引号）
  if (fields['signname']) {
    desc = `检测到威胁「${stripQuotes(fields['signname'])}」`;
  }
  // 2. 策略拒绝描述
  else if (/POLICYDENY/i.test(message)) {
    desc = '检测到策略拒绝';
  }
  // 3. 系统事件 → 中文描述
  else {
    for (const item of SYSTEM_EVENT_DESC) {
      if (item.regex.test(message)) {
        desc = item.description;
        break;
      }
    }
  }

  // 补充动作信息（Block=阻断，Detect=检测）
  const actionMap: Record<string, string> = { block: '阻断', detect: '检测', alert: '告警', permit: '放行', deny: '拒绝' };
  if (fields['action']) {
    const action = actionMap[fields['action'].toLowerCase()] || fields['action'];
    desc += desc ? `，动作: ${action}` : `动作: ${action}`;
  }
  // 补充类别（Category）
  if (fields['category']) {
    desc += `，类别: ${fields['category']}`;
  }
  // 补充协议
  if (fields['protocol']) {
    desc += `，协议: ${fields['protocol']}`;
  }
  // 补充策略
  if (fields['policy']) {
    desc += `，策略: ${fields['policy']}`;
  }
  // 补充应用
  if (fields['application']) {
    desc += `，应用: ${fields['application']}`;
  }

  // 若无生成描述，回退到模块+事件名
  if (!desc && module && eventName) {
    desc = `华为 ${module} 模块事件 ${eventName}`;
  }

  // 最后回退原文
  if (!desc) {
    desc = message.length > 300 ? message.slice(0, 300) : message;
  }

  return desc;
}

/**
 * 根据华为 Severity 字段映射到软件严重级别
 * 华为级别：emergency=0 ... debug=7；事件字段 Severity 为 low/medium/high/critical
 */
function mapSeverity(message: string, fields: Record<string, string>): AlertData['severity'] {
  // 优先用 Severity 字段（华为 IPS 事件里是 low/medium/high/critical）
  const sev = (fields['severity'] || '').toLowerCase();
  if (sev === 'critical') return 'critical';
  if (sev === 'high') return 'high';
  if (sev === 'medium' || sev === 'medium-high') return 'medium';
  if (sev === 'low' || sev === 'info' || sev === 'informational') return 'low';
  if (sev === 'emergency' || sev === 'alert') return 'critical';

  // 其次用 %%01MODULE/N 中的数字级别（0=emergency ... 7=debug）
  const m = message.match(/%%01[A-Z0-9_]+\/(\d+)\//);
  if (m) {
    const level = Number(m[1]);
    if (level <= 1) return 'critical';
    if (level <= 3) return 'high';
    if (level <= 5) return 'medium';
    return 'low';
  }

  return 'medium';
}

/**
 * 解析华为 Syslog 日志为告警数据
 * @param rawMessage 原始 Syslog 消息
 * @param sourceAddress 发送日志的设备 IP
 */
export function parseSyslog(rawMessage: string, sourceAddress: string): AlertData {
  const now = new Date().toISOString();
  const message = rawMessage.trim();

  // 多厂商识别：非华为厂商走专用解析逻辑
  const vendor = detectVendor(message);
  if (vendor !== 'huawei') {
    return parseVendorSyslog(message, sourceAddress, vendor);
  }

  // 提取结构化字段（华为/WAF key=value 格式）
  const fields = extractFields(message);

  // WAF 报文走专用解析逻辑
  if (isWafLog(message)) {
    return parseWafSyslog(message, sourceAddress, fields, now);
  }

  // 提取源/目标 IP 和端口（覆盖华为、思科、通用命名风格）
  const sourceIp = fields['source-ip'] || fields['srcip'] || fields['src-ip'] || fields['attacker-ip'] || fields['attackip'] || '';
  const targetIp = fields['destination-ip'] || fields['dstip'] || fields['dst-ip'] || fields['target-ip'] || fields['victim-ip'] || fields['dest-ip'] || '';
  const sourcePort = parsePort(fields['source-port'] || fields['srcport'] || fields['src-port'] || fields['sport'] || fields['attackerport'] || fields['attackport']);
  const targetPort = parsePort(fields['destination-port'] || fields['dstport'] || fields['dst-port'] || fields['dport'] || fields['target-port'] || fields['victimport'] || fields['dest-port']);

  // 解析攻击类型（基于事件名）
  const { attackType } = parseThreatType(message);

  // 严重级别：与华为 Severity 字段保持一致
  const severity = mapSeverity(message, fields);

  // 生成中文描述
  const description = generateDescription(message, fields);

  // 提取扩展字段（去除华为字段值两侧引号）
  const application = stripQuotes(fields['application'] || fields['application-name'] || '');
  const threatName = stripQuotes(fields['signname'] || fields['signaturename'] || '');
  const action = stripQuotes(fields['action'] || '');
  const category = stripQuotes(fields['category'] || '');
  const protocol = stripQuotes(fields['protocol'] || '');
  const policy = stripQuotes(fields['policy'] || fields['rule-name'] || '');
  const signId = parsePort(fields['signid']);

  return {
    attackType,
    sourceIp,
    sourcePort,
    targetIp,
    targetPort,
    severity,
    deviceName: '未知设备', // 由接收器填充
    deviceIp: sourceAddress,
    description,
    oid: 'syslog',
    timestamp: now,
    application,
    threatName,
    action,
    category,
    protocol,
    policy,
    signId,
  };
}

/**
 * 解析 WAF 设备 Syslog 报文为告警数据
 * WAF 格式：<PRI>MMM dd HH:mm:ss HOST yyyy-MM-dd HH:mm:ss WAF: 源IP:端口->目标 dip=xxx devicename=xxx type=xxx action=xxx ...
 */
function parseWafSyslog(
  message: string,
  sourceAddress: string,
  fields: Record<string, string>,
  timestamp: string
): AlertData {
  // 源 IP/端口：从方向段提取
  const source = extractWafSource(message);

  // 目标 IP：优先 dip= 字段；目标端口：方向段域名后可能有 :端口
  const targetIp = fields['dip'] || fields['dstip'] || fields['destination-ip'] || '';
  const host = extractWafTargetHost(message);
  // 目标端口：若方向段目标为 ip:port 则提取端口
  const hostPortMatch = host.match(/:(\d+)$/);
  const targetPort = hostPortMatch ? parsePort(hostPortMatch[1]) : 0;

  // 攻击类型与严重级别
  const { attackType } = parseWafThreatType(message, fields);
  const severity = mapWafSeverity(message, fields);

  // 中文描述
  const description = generateWafDescription(message, fields);

  // 扩展字段
  const application = fields['application'] || fields['app'] || '';
  const threatName = fields['type'] || '';
  const action = fields['action'] || '';
  const category = fields['category'] || '';
  const protocol = fields['http_type'] || (fields['method'] ? 'HTTP' : '') || fields['protocol'] || '';
  const policy = fields['profile_id'] ? `策略组 #${fields['profile_id']}` : (fields['policy'] || '');
  const signId = parsePort(fields['rule_id']);

  return {
    attackType,
    sourceIp: source.ip,
    sourcePort: source.port,
    targetIp,
    targetPort,
    severity,
    deviceName: fields['devicename'] || 'WAF设备',
    deviceIp: sourceAddress,
    description,
    oid: 'syslog',
    timestamp,
    application,
    threatName,
    action,
    category,
    protocol,
    policy,
    signId,
  };
}
