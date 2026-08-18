/**
 * SNMP Trap 报文解析器
 * 解析 net-snmp 库收到的 Trap 报文，提取关键告警信息
 */

export interface ParsedTrap {
  attackType: string;
  sourceIp: string;
  sourcePort: number;
  targetIp: string;
  targetPort: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  deviceName: string;
  deviceIp: string;
  description: string;
  oid: string;
  rawTrap: string;
  timestamp: string;
}

// 常见 IP 地址相关的 varbind OID 后缀
const SOURCE_IP_OIDS = [
  '.1.3.6.1.4.1.12356.101.3.1.1', // 源IP
  '.1.3.6.1.4.1.9.9.147.1.2.1.1', // 源IP (Cisco)
  '.1.3.6.1.2.1.4.20.1.1', // ipAdEntAddr 相关
];

const TARGET_IP_OIDS = [
  '.1.3.6.1.4.1.12356.101.3.1.2', // 目标IP
  '.1.3.6.1.4.1.9.9.147.1.2.1.2', // 目标IP (Cisco)
  '.1.3.6.1.2.1.4.20.1.2',
];

/**
 * 判断一个值是否是合法的 IPv4 地址
 */
function isIPv4(value: string): boolean {
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  return parts.every(p => {
    const num = Number(p);
    return !isNaN(num) && num >= 0 && num <= 255 && String(num) === p;
  });
}

/**
 * 从 net-snmp 库收到的 varbind 中提取 IP 地址和端口
 * 策略：优先按 OID 关键字匹配（更准确），否则按值类型兜底
 */
function extractIpAndPort(varbinds: any[]): { sourceIp: string; sourcePort: number; targetIp: string; targetPort: number } {
  let sourceIp = '';
  let targetIp = '';
  let sourcePort = 0;
  let targetPort = 0;
  const fallbackIps: string[] = [];
  const fallbackPorts: number[] = [];

  for (const vb of varbinds || []) {
    const oid = (vb.oid || '').toLowerCase();
    const value = vb.value;
    const valueStr = String(value);

    // 按 OID 关键字识别（更准确）
    if (/source.?ip|srcip|attacker.?ip|src.?addr/.test(oid) && typeof value === 'string' && isIPv4(value)) {
      sourceIp = value;
    } else if (/dest(ination)?.?ip|dstip|target.?ip|victim.?ip/.test(oid) && typeof value === 'string' && isIPv4(value)) {
      targetIp = value;
    } else if (/source.?port|sport|srcport|attacker.?port/.test(oid) && isValidPort(value)) {
      sourcePort = Number(value);
    } else if (/dest(ination)?.?port|dport|dstport|target.?port|victim.?port/.test(oid) && isValidPort(value)) {
      targetPort = Number(value);
    } else {
      // 兜底收集（仅字符串类型，避免端口字段混入 IP）
      if (typeof value === 'string' && isIPv4(value) && !isLikelyFakeIp(value)) {
        fallbackIps.push(value);
      }
      if (isValidPort(value)) {
        fallbackPorts.push(Number(value));
      }
    }
  }

  // 兜底：按位置取
  if (!sourceIp && fallbackIps.length >= 1) sourceIp = fallbackIps[0];
  if (!targetIp && fallbackIps.length >= 2) targetIp = fallbackIps[1];
  if (!sourcePort && fallbackPorts.length >= 1) sourcePort = fallbackPorts[0];
  if (!targetPort && fallbackPorts.length >= 2) targetPort = fallbackPorts[1];

  return { sourceIp, sourcePort, targetIp, targetPort };
}

/**
 * 校验端口号有效性（接受 string 或 number，范围 1-65535）
 */
function isValidPort(value: unknown): boolean {
  if (typeof value === 'number') {
    return Number.isInteger(value) && value > 0 && value <= 65535;
  }
  if (typeof value === 'string') {
    const n = Number(value);
    return Number.isFinite(n) && Number.isInteger(n) && n > 0 && n <= 65535;
  }
  return false;
}

/**
 * 过滤明显非真实 IP 的值（如 sysUptime 字段串接、计数器、序号等）
 * 真实 IPv4 各段范围都在 0-255，但小段号（1-10 出现多次）通常是其他计数器
 */
function isLikelyFakeIp(value: string): boolean {
  const parts = value.split('.');
  if (parts.length !== 4) return true;
  // 全是 0 或很小的数字（如 1.2.3.4 → 像端口而非 IP）
  // 启发式：如果任何段是 4 位数字（如 1923），不是 IP
  for (const p of parts) {
    if (p.length === 0 || p.length > 3) return true;
  }
  return false;
}

/**
 * 解析 net-snmp 库收到的原始 Trap 数据
 * @param trap net-snmp createReceiver 回调中的 trap 对象
 * @returns 解析后的 Trap 信息
 */
export function parseTrap(trap: any): ParsedTrap {
  const now = new Date().toISOString();
  const varbinds = trap.pdu?.varbinds || trap.varbinds || [];

  // 提取 OID（企业特定 OID 或标准 Trap OID）
  let oid = '';
  if (trap.pdu?.type === 4 || trap.pdu?.type === 7) {
    // 企业特定 Trap (v1)
    oid = trap.pdu?.enterprise || '';
  } else {
    // 从 varbind 中提取第一个 OID
    if (varbinds.length > 0 && varbinds[0].oid) {
      oid = varbinds[0].oid;
    }
  }

  // 提取 IP 地址和端口
  const { sourceIp, sourcePort, targetIp, targetPort } = extractIpAndPort(varbinds);

  // 设备 IP（Trap 来源地址）
  const deviceIp = trap.rinfo?.address || '';

  // 提取描述信息（varbind 中的字符串值）
  let description = '';
  for (const vb of varbinds) {
    if (typeof vb.value === 'string' && vb.value.length > description.length) {
      description = vb.value;
    }
  }

  // 构造原始 Trap 数据（用于详情页展示）
  const rawTrap = JSON.stringify(
    {
      version: trap.pdu?.version,
      type: trap.pdu?.type,
      enterprise: trap.pdu?.enterprise,
      agentAddress: trap.pdu?.agentAddr,
      varbinds: varbinds.map((vb: any) => ({ oid: vb.oid, value: vb.value })),
    },
    null,
    2
  );

  return {
    attackType: '', // 由 oid-mapping 模块填充
    sourceIp,
    sourcePort,
    targetIp,
    targetPort,
    severity: 'medium', // 由 oid-mapping 模块填充
    deviceName: '', // 由接收服务填充（根据设备IP查设备表）
    deviceIp,
    description,
    oid,
    rawTrap,
    timestamp: now,
  };
}

/**
 * 判断 Trap 的 PDU 类型名称（用于日志）
 */
export function getTrapTypeName(type: number): string {
  const types: Record<number, string> = {
    0: 'Cold Start',
    1: 'Warm Start',
    2: 'Link Down',
    3: 'Link Up',
    4: 'Authentication Failure',
    5: 'EGP Neighbor Loss',
    6: 'Enterprise Specific',
  };
  return types[type] || `Unknown (${type})`;
}
