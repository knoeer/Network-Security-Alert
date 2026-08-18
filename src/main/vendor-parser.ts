/**
 * 多厂商 Syslog 日志解析器
 * 支持 H3C、思科（Cisco）、中兴（ZTE）、锐捷（Ruijie）、CSSOS WAF、华为 FusionCompute 虚拟化平台
 * 的日志识别与解析。
 *
 * 华为 USG（%%01...）格式在 syslog-parser.ts 中单独处理，本模块负责其余厂商。
 *
 * 各厂商日志格式特征：
 *   - H3C   ：%May 16 10:00:00:123 2026 Device MODULE/SEVERITY/EVENTNAME: description
 *             （与华为类似的 MODULE/SEVERITY/EVENTNAME 结构，但以 % 开头并带时间戳头）
 *   - 思科  ：%ASA-4-106023: Deny tcp src ... 或 %LINK-3-UPDOWN: ...
 *             （% + FACILITY-SEVERITY-MNEMONIC: 消息体）
 *   - 中兴  ：%SSH-6-SSH2_LOGIN_SUCCESS: ... 或带 logid 结构
 *   - 锐捷  ：%STP-3-... 或 timestamp %MODULE-SEVERITY-MNEMONIC: ...
 *   - CSSOS：WAF: 源IP:端口->目标 dip=... devicename=CSSOS ... type=... action=...
 *             （山石/启明星辰等 WAF 设备，含 WAF: 标记 + devicename= 字段）
 *   - 华为 FC：<104> 时间 severity IP 101*|序号*|用户*|认证*|来源IP*|FC_Manage*|操作时间*|操作*|结果*|详情*|
 *             （华为 FusionCompute 虚拟化平台管理日志，按 *| 分隔）
 */
import { AlertData } from './alert-common';

export type VendorName = 'huawei' | 'h3c' | 'cisco' | 'zte' | 'ruijie' | 'cssos' | 'huawei-fc' | 'generic';

/**
 * 识别日志厂商
 * 华为格式由 syslog-parser.ts 处理，这里返回 huawei 供上游判断；
 * 无法识别时返回 generic（通用兜底）
 */
export function detectVendor(message: string): VendorName {
  // 华为 USG：%%01 开头（含 WAF 设备的 devicename= 结构由华为解析器处理）
  if (/%%01/.test(message)) return 'huawei';

  // CSSOS WAF：含 WAF: 标记 + devicename= 字段（山石/启明星辰等 WAF 设备）
  // 特征：报文主体含 "WAF:" 且 devicename= 字段（如 devicename=CSSOS）
  if (/\bWAF:\s+[\d.]+\:\d+\s*->/.test(message) && /\bdevicename=/.test(message)) return 'cssos';
  // CSSOS STC 统计流量日志：STC:devicename=CSSOS ... （连接/流量统计，非攻击）
  if (/^.*\bSTC:\s*devicename=CSSOS\b/.test(message)) return 'cssos';

  // 华为 FusionCompute 虚拟化平台：含 FC_Manage 模块，*| 分隔符
  // 特征：报文含 *|FC_Manage*| 或 *|FC_Man*，操作日志用 *| 分隔
  if (/\*\|FC_?Man?age\*\|/.test(message) || /FusionCompute/i.test(message)) return 'huawei-fc';

  // H3C：% 开头 + 时间戳（如 %May 16 10:00:00:123）+ MODULE/SEVERITY/EVENTNAME
  // H3C 日志带完整时间戳头，特征明显
  if (/^%[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/.test(message)) return 'h3c';

  // 思科：%FACILITY-SEVERITY-MNEMONIC 格式，FACILITY 典型为 ASA/IOS 特有
  // 思科特征：ASA 专用事件号（106023、405001 等），或 FACILITY 为 ASA/PIX
  if (/^%(ASA|PIX|FTD)-\d-[A-Z0-9_]+/.test(message)) return 'cisco';
  if (/\b(106023|106100|106101|733100|419001|419002|710003|710005|405001)\b/.test(message)) return 'cisco';

  // 中兴：特征关键字 zte/zxs/logid 或典型模块（SSH/AAA/DHCP 等中兴设备常见）
  if (/zte|zxs|zxr10|logid/i.test(message)) return 'zte';

  // 锐捷：特征关键字 ruijie/rg- 或典型模块（STP/OSPF/BFD/VRRP 等锐捷设备常见）
  if (/ruijie|rg-|rg\d|red.?giant|锐捷/i.test(message)) return 'ruijie';

  // 其余 %MODULE-SEVERITY-MNEMONIC 通用格式（无法细分厂商时归为 generic）
  if (/^%[A-Z]{2,8}-\d-[A-Z0-9_]+/.test(message)) return 'generic';

  return 'generic';
}

/**
 * 通用攻击类型识别（基于关键字，适用于各厂商）
 * 思科 ASA 的攻击关键字、H3C/中兴/锐捷的中英文关键字
 */
const VENDOR_THREAT_PATTERNS: Array<{ regex: RegExp; attackType: string; severity: AlertData['severity'] }> = [
  { regex: /port.?scan|端口扫描/i, attackType: '端口扫描', severity: 'medium' },
  { regex: /ddos|dos.?attack|syn.?flood|icmp.?flood|udp.?flood|拒绝服务/i, attackType: 'DDoS攻击', severity: 'critical' },
  { regex: /brute.?force|暴力破解|password.?guess|login.?attempt|认证失败|auth.?fail/i, attackType: '暴力破解', severity: 'high' },
  { regex: /sql.?inject|sql注入/i, attackType: 'SQL注入攻击', severity: 'critical' },
  { regex: /virus|worm|trojan|malware|病毒|木马|蠕虫|恶意/i, attackType: '恶意软件', severity: 'high' },
  { regex: /buffer.?overflow|缓冲区溢出/i, attackType: '缓冲区溢出', severity: 'critical' },
  { regex: /phishing|钓鱼/i, attackType: '网络钓鱼', severity: 'high' },
  { regex: /unauthorized|未授权|access.?denied|deny|denied/i, attackType: '未授权访问', severity: 'high' },
  { regex: /intrusion|入侵|attack|攻击/i, attackType: '入侵攻击', severity: 'critical' },
  { regex: /arp.?spoof|arp欺骗/i, attackType: 'ARP欺骗', severity: 'high' },
  { regex: /scan|扫描|probe|探测/i, attackType: '网络扫描', severity: 'medium' },
  { regex: /webshell|xss|cross.?site|csrf|文件包含|命令注入|目录遍历/i, attackType: 'Web攻击', severity: 'high' },
];

/**
 * 思科 ASA 特定事件：%ASA-4-106023（拒绝连接）等
 */
const CISCO_EVENT_PATTERNS: Array<{ regex: RegExp; attackType: string; severity: AlertData['severity'] }> = [
  { regex: /106023|deny.*(tcp|udp|icmp|ip)/i, attackType: '连接拒绝', severity: 'medium' },
  { regex: /106100|106101|permit|access.?list/i, attackType: '访问控制', severity: 'low' },
  { regex: /733100|object.?drop|threat.?detect/i, attackType: '威胁检测', severity: 'high' },
  { regex: /419001|419002|teardown|connection/i, attackType: '连接事件', severity: 'low' },
  { regex: /710003|710005|tcp.?connection/i, attackType: '连接限制', severity: 'medium' },
  { regex: /405001|arp.*(spoof|mismatch)|ip.?conflict/i, attackType: 'ARP欺骗', severity: 'high' },
];

/**
 * CSSOS WAF 攻击类型映射（根据 type= 字段）
 * CSSOS WAF 报文：... rule_id=... type=HTTP Conformity Rule severity=0 action=REJECT ...
 */
const CSSOS_TYPE_PATTERNS: Array<{ regex: RegExp; attackType: string; severity: AlertData['severity'] }> = [
  { regex: /HTTP Conformity Rule/i, attackType: 'HTTP合规拦截', severity: 'medium' },
  { regex: /Signature Rule/i, attackType: '签名规则拦截', severity: 'high' },
  { regex: /ASCN Rule/i, attackType: '主动安全防护拦截', severity: 'medium' },
  { regex: /CC Attack|CC攻击|Flood/i, attackType: 'CC攻击', severity: 'high' },
  { regex: /SQL Inject/i, attackType: 'SQL注入攻击', severity: 'critical' },
  { regex: /XSS/i, attackType: 'XSS跨站脚本攻击', severity: 'high' },
  { regex: /WebShell/i, attackType: 'Webshell木马攻击', severity: 'critical' },
  { regex: /Command Inject/i, attackType: '命令注入攻击', severity: 'critical' },
  { regex: /Directory Traversal/i, attackType: '目录遍历攻击', severity: 'high' },
  { regex: /Scanner|Scan/i, attackType: 'Web扫描探测', severity: 'medium' },
];

/**
 * 华为 FusionCompute 虚拟化平台管理操作的中文描述
 * 报文结构：101*|序号*|用户名*|认证类型*|来源IP*|模块*|操作时间*|操作名称*|结果*|详情*|0*|
 */
const FUSIONCOMPUTE_OP_DESC: Array<{ regex: RegExp; attackType: string; description: string; severity: AlertData['severity'] }> = [
  { regex: /User login/i, attackType: '平台登录', description: 'FusionCompute 平台用户登录', severity: 'low' },
  { regex: /User logout/i, attackType: '平台登出', description: 'FusionCompute 平台用户登出', severity: 'low' },
  { regex: /Login.*fail|登录.*失败/i, attackType: '登录失败', description: 'FusionCompute 平台登录失败，可能存在未授权访问尝试', severity: 'high' },
  { regex: /Modify remote SNMP/i, attackType: 'SNMP配置变更', description: 'FusionCompute 平台远程 SNMP 管理配置被修改', severity: 'medium' },
  { regex: /Delete remote SNMP/i, attackType: 'SNMP配置变更', description: 'FusionCompute 平台远程 SNMP 管理配置被删除', severity: 'medium' },
  { regex: /Add host/i, attackType: '主机管理', description: 'FusionCompute 平台添加主机', severity: 'low' },
  { regex: /Delete host/i, attackType: '主机管理', description: 'FusionCompute 平台删除主机', severity: 'medium' },
  { regex: /Add VM|创建虚拟机/i, attackType: '虚拟机管理', description: 'FusionCompute 平台创建虚拟机', severity: 'low' },
  { regex: /Delete VM|删除虚拟机/i, attackType: '虚拟机管理', description: 'FusionCompute 平台删除虚拟机', severity: 'medium' },
  { regex: /password|密码/i, attackType: '密码修改', description: 'FusionCompute 平台用户密码相关操作', severity: 'high' },
];

/** 校验端口有效性 */
function parsePort(value: string | undefined | null): number {
  if (value === undefined || value === null || value === '') return 0;
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0 || num > 65535 || !Number.isInteger(num)) return 0;
  return num;
}

/**
 * 提取消息中的 IP 地址（第一个出现的 IPv4）
 */
function extractFirstIp(message: string): string {
  const m = message.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
  return m ? m[1] : '';
}

/**
 * 提取消息中的全部 IPv4 地址
 */
function extractAllIps(message: string): string[] {
  const ips: string[] = [];
  const re = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
  let m;
  while ((m = re.exec(message)) !== null) {
    ips.push(m[1]);
  }
  return ips;
}

/**
 * 提取消息中的源/目标端口
 * 优先从明确的端口上下文提取（ip:port、port=N、src/dst 后的端口），
 * 避免误把时间戳、接口索引等数字当作端口。
 */
function extractPorts(message: string): { sourcePort: number; targetPort: number } {
  let sourcePort = 0;
  let targetPort = 0;

  // 思科格式：src outside:1.2.3.4/1234 dst inside:10.0.0.1/80
  const ciscoSrc = message.match(/src[^:]*:[\d.]+\/(\d+)/i);
  const ciscoDst = message.match(/dst[^:]*:[\d.]+\/(\d+)/i);
  if (ciscoSrc) sourcePort = parsePort(ciscoSrc[1]);
  if (ciscoDst) targetPort = parsePort(ciscoDst[1]);

  // 通用 ip:port 格式（如 192.168.1.100:8080）
  if (sourcePort === 0 || targetPort === 0) {
    const ipPortMatches = message.matchAll(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})/g);
    const pairs = Array.from(ipPortMatches);
    if (pairs.length >= 1 && sourcePort === 0) sourcePort = parsePort(pairs[0][2]);
    if (pairs.length >= 2 && targetPort === 0) targetPort = parsePort(pairs[1][2]);
  }

  // key=value 端口字段（srcport/dstport/sport/dport 等）
  const srcPortField = message.match(/(?:srcport|source-port|sport)\s*[=:]\s*(\d+)/i);
  const dstPortField = message.match(/(?:dstport|destination-port|dport|dest-port)\s*[=:]\s*(\d+)/i);
  if (srcPortField && sourcePort === 0) sourcePort = parsePort(srcPortField[1]);
  if (dstPortField && targetPort === 0) targetPort = parsePort(dstPortField[1]);

  // port 关键字（通用）
  const portField = message.match(/\bport\s*[=:]\s*(\d+)/i);
  if (portField && targetPort === 0) targetPort = parsePort(portField[1]);

  return { sourcePort, targetPort };
}

/**
 * 判断非华为厂商的日志是否为威胁
 */
export function isVendorThreat(message: string, vendor: VendorName): boolean {
  // 各厂商威胁识别
  switch (vendor) {
    case 'cisco':
      return CISCO_EVENT_PATTERNS.some((p) => p.regex.test(message)) ||
        VENDOR_THREAT_PATTERNS.some((p) => p.regex.test(message));
    case 'h3c':
    case 'zte':
    case 'ruijie':
      return VENDOR_THREAT_PATTERNS.some((p) => p.regex.test(message));
    case 'cssos':
      // CSSOS WAF：STC: 统计流量日志非威胁；其余带 type= 且动作为 BLOCK/REJECT 视为威胁
      if (/STC:/i.test(message)) return false;
      // 提取 type= 字段（rule_id 之后）
      const cssosType = (message.match(/rule_id=\d+\s+type=([^\s]+)/) || [])[1] || '';
      if (cssosType && CSSOS_TYPE_PATTERNS.some((p) => p.regex.test(cssosType))) {
        return true;
      }
      // 兜底：action 为主动拦截且含攻击特征
      if (/\baction=(BLOCK|REJECT|DROP)\b/i.test(message)) {
        return VENDOR_THREAT_PATTERNS.some((p) => p.regex.test(message));
      }
      return false;
    case 'huawei-fc':
      // 华为 FusionCompute：管理操作日志，非威胁（仅记录）
      return false;
    case 'generic':
      // 通用：带攻击关键字或带 IP 的 deny/block 记录
      return VENDOR_THREAT_PATTERNS.some((p) => p.regex.test(message));
    default:
      return false;
  }
}

/**
 * 解析非华为厂商的 Syslog 为告警数据
 */
export function parseVendorSyslog(rawMessage: string, sourceAddress: string, vendor: VendorName): AlertData {
  const message = rawMessage.trim();
  const now = new Date().toISOString();

  // CSSOS WAF：走专用解析逻辑
  if (vendor === 'cssos') {
    return parseCssosSyslog(message, sourceAddress, now);
  }

  // 华为 FusionCompute：走专用解析逻辑（管理操作日志）
  if (vendor === 'huawei-fc') {
    return parseFusionComputeSyslog(message, sourceAddress, now);
  }

  // 提取 IP 和端口
  const ips = extractAllIps(message);
  const sourceIp = ips.length > 0 ? ips[0] : '';
  const targetIp = ips.length > 1 ? ips[1] : '';

  // 提取端口（基于上下文关键词，避免误提取时间戳等数字）
  const { sourcePort, targetPort } = extractPorts(message);

  // 识别攻击类型
  let attackType = '安全日志';
  let severity: AlertData['severity'] = 'low';

  if (vendor === 'cisco') {
    for (const p of CISCO_EVENT_PATTERNS) {
      if (p.regex.test(message)) {
        attackType = p.attackType;
        severity = p.severity;
        break;
      }
    }
  }
  // 兜底：通用攻击关键字
  if (attackType === '安全日志') {
    for (const p of VENDOR_THREAT_PATTERNS) {
      if (p.regex.test(message)) {
        attackType = p.attackType;
        severity = p.severity;
        break;
      }
    }
  }

  // 生成描述
  const description = generateVendorDescription(message, vendor, attackType);

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
    application: '',
    threatName: '',
    action: '',
    category: '',
    protocol: '',
    policy: '',
    signId: 0,
  };
}

/** 校验端口有效性 */
function safePort(value: string | undefined | null): number {
  if (value === undefined || value === null || value === '') return 0;
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0 || num > 65535 || !Number.isInteger(num)) return 0;
  return num;
}

/**
 * 解析 CSSOS WAF Syslog 为告警数据
 * CSSOS WAF 报文结构：
 *   <188>MMM dd HH:mm:ss CSSOS YYYY-MM-DD HH:mm:ss WAF: 源IP:源端口->目标[:目标端口] dip=内网目标IP
 *   devicename=CSSOS url=... method=... args=... flag_field=... block_time=... http_type=... attack_field=...
 *   profile_id=... rule_id=... type=... severity=N action=BLOCK/REJECT referer=... useragent=... post=...
 *   equipment=... os=... browser=... |
 * 说明：
 *   - 源 IP/端口从 "WAF: ip:port->" 段提取
 *   - 目标：优先 dip= 字段（内网真实目标 IP）；方向段目标为域名或公网 IP
 *   - 目标端口：方向段目标带 :port 时提取；否则 0
 */
function parseCssosSyslog(message: string, sourceAddress: string, timestamp: string): AlertData {
  // 源 IP/端口：WAF: 源IP:源端口->
  let sourceIp = '';
  let sourcePort = 0;
  const srcMatch = message.match(/WAF:\s*([\d.]+):(\d+)\s*->/);
  if (srcMatch) {
    sourceIp = srcMatch[1];
    sourcePort = safePort(srcMatch[2]);
  }

  // 目标：dip= 字段（内网真实目标 IP）优先；否则方向段目标
  const dipMatch = message.match(/\bdip=([^\s]+)/);
  let targetIp = dipMatch ? dipMatch[1].trim() : '';

  // 目标端口：方向段目标 "host:port" 提取；否则 0
  let targetPort = 0;
  const hostMatch = message.match(/->\s*([^\s]+)/);
  const hostPort = hostMatch ? hostMatch[1].match(/([\d.]+):(\d+)\s*$/) : null;
  if (hostPort) {
    if (!targetIp && hostPort[1]) targetIp = hostPort[1];
    targetPort = safePort(hostPort[2]);
  }

  // 提取结构化字段
  const fields: Record<string, string> = {};
  const kvRegex = /([a-zA-Z][\w-]*)=((?:[^\s][^,;|]*?)?)(?=\s+[a-zA-Z][\w-]*=|\s*$|,|;|\|)/g;
  let m;
  while ((m = kvRegex.exec(message)) !== null) {
    fields[m[1].toLowerCase()] = m[2].trim();
  }

  // 攻击类型（基于 type= 字段）
  const cssosType = fields['type'] || '';
  let attackType = 'Web攻击';
  let baseSeverity: AlertData['severity'] = 'medium';
  for (const p of CSSOS_TYPE_PATTERNS) {
    if (p.regex.test(cssosType)) {
      attackType = p.attackType;
      baseSeverity = p.severity;
      break;
    }
  }

  // 严重级别：优先设备 severity 字段（CSSOS: 0-3，越大越严重）
  let severity: AlertData['severity'] = baseSeverity;
  if (fields['severity'] !== '') {
    const numSev = Number(fields['severity']);
    if (!Number.isNaN(numSev)) {
      if (numSev >= 3) severity = 'critical';
      else if (numSev >= 2) severity = 'high';
      else if (numSev >= 1) severity = 'medium';
      else severity = 'low'; // 0 = 低危
    }
  }

  // 动作（BLOCK/REJECT）
  const action = fields['action'] || '';

  // 中文描述
  const url = fields['url'] || '';
  const method = fields['method'] || '';
  const parts: string[] = [`CSSOS WAF拦截「${attackType}」`];
  if (method) parts.push(`请求方式 ${method}`);
  if (url) parts.push(`URL ${url}`);
  if (action) parts.push(`动作 ${action}`);
  if (fields['rule_id']) parts.push(`规则 #${fields['rule_id']}`);
  if (fields['profile_id']) parts.push(`策略组 #${fields['profile_id']}`);
  const description = parts.join('，');

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
    timestamp,
    application: '',
    threatName: cssosType,
    action,
    category: '',
    protocol: '',
    policy: fields['profile_id'] ? `策略组 #${fields['profile_id']}` : '',
    signId: safePort(fields['rule_id']),
  };
}

/**
 * 解析华为 FusionCompute 虚拟化平台 Syslog 为告警数据（管理操作日志，非威胁）
 * 报文结构：
 *   <104> 时间 severity IP 101*|序号*|用户名*|认证类型*|来源IP*|模块*|操作时间*|操作名称*|结果*|详情*|0*|
 */
function parseFusionComputeSyslog(message: string, sourceAddress: string, timestamp: string): AlertData {
  // 定位内容主体（去掉 <PRI> 时间 severity IP 前缀）
  const bodyMatch = message.match(/\d+\*\|(.*)/s);
  const body = bodyMatch ? bodyMatch[1] : message;
  const parts = body.split('*|').map((p) => p.replace(/\*$/, '').trim());

  // 字段索引：0=序号 1=用户名 2=认证类型 3=来源IP 4=模块 5=操作时间 6=操作名称 7=结果 8=详情
  const operator = parts[1] || '';
  const sourceIp = parts[3] || '';
  const module = parts[4] || '';
  const opName = parts[6] || '';
  const result = parts[7] || '';
  const detail = parts[8] || '';

  // 匹配操作类型
  let attackType = '平台管理操作';
  let severity: AlertData['severity'] = 'low';
  let description = `FusionCompute 平台管理操作: ${opName || '未知操作'}`;
  for (const item of FUSIONCOMPUTE_OP_DESC) {
    if (item.regex.test(`${opName} ${detail}`)) {
      attackType = item.attackType;
      severity = item.severity;
      description = `${item.description}: ${opName}`;
      break;
    }
  }

  if (operator) description += `，操作人 ${operator}`;
  if (sourceIp) description += `，来源 ${sourceIp}`;
  if (result) description += `，结果 ${result}`;
  if (module) description += `，模块 ${module}`;

  return {
    attackType,
    sourceIp,
    sourcePort: 0,
    targetIp: sourceAddress,
    targetPort: 0,
    severity,
    deviceName: '未知设备', // 由接收器填充
    deviceIp: sourceAddress,
    description,
    oid: 'syslog',
    timestamp,
    application: module,
    threatName: opName,
    action: result,
    category: '管理操作',
    protocol: '',
    policy: '',
    signId: 0,
  };
}

/**
 * 生成厂商日志的中文描述
 */
function generateVendorDescription(message: string, vendor: VendorName, attackType: string): string {
  const vendorName: Record<VendorName, string> = {
    huawei: '华为',
    h3c: 'H3C',
    cisco: '思科',
    zte: '中兴',
    ruijie: '锐捷',
    cssos: 'CSSOS WAF',
    'huawei-fc': '华为FusionCompute',
    generic: '网络设备',
  };
  // 截取原始消息（去掉时间戳头等噪声，保留关键信息）
  const brief = message.slice(0, 200).replace(/\s+/g, ' ').trim();
  return `[${vendorName[vendor]}] 检测到${attackType}：${brief}`;
}
