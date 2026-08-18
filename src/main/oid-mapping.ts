/**
 * SNMP OID 到攻击类型的映射表
 * 将 SNMP Trap 中携带的 OID 转换为可读的攻击类型描述
 */

export interface OidMapping {
  /** 攻击类型中文名 */
  attackType: string;
  /** 严重级别 */
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** 描述 */
  description: string;
}

// 常见安全设备（防火墙/IDS/IPS）告警 OID
// 这些 OID 遵循标准 SNMP 企业 OID 规范
const OID_MAPPINGS: Record<string, OidMapping> = {
  // 端口扫描
  '1.3.6.1.4.1.9.9.147.1.2.2.1': { attackType: '端口扫描', severity: 'medium', description: '检测到端口扫描活动，可能为攻击前的侦查行为' },
  '1.3.6.1.4.1.12356.101.3.2.1': { attackType: '端口扫描', severity: 'medium', description: '检测到主机端口扫描' },

  // DDoS 攻击
  '1.3.6.1.4.1.9.9.147.1.2.2.2': { attackType: 'DDoS攻击', severity: 'critical', description: '检测到分布式拒绝服务攻击' },
  '1.3.6.1.4.1.12356.101.3.2.2': { attackType: 'DDoS攻击', severity: 'critical', description: '检测到大规模流量攻击' },

  // 暴力破解
  '1.3.6.1.4.1.12356.101.3.2.3': { attackType: '暴力破解', severity: 'high', description: '检测到暴力密码破解尝试' },
  '1.3.6.1.4.1.9.9.147.1.2.2.3': { attackType: '暴力破解', severity: 'high', description: '检测到多次登录失败尝试' },

  // SQL 注入
  '1.3.6.1.4.1.12356.101.3.2.4': { attackType: 'SQL注入攻击', severity: 'critical', description: '检测到SQL注入攻击尝试' },

  // 恶意软件
  '1.3.6.1.4.1.12356.101.3.2.5': { attackType: '恶意软件', severity: 'high', description: '检测到恶意软件活动' },

  // 缓冲区溢出
  '1.3.6.1.4.1.12356.101.3.2.6': { attackType: '缓冲区溢出', severity: 'critical', description: '检测到缓冲区溢出攻击' },

  // 网络钓鱼
  '1.3.6.1.4.1.12356.101.3.2.7': { attackType: '网络钓鱼', severity: 'high', description: '检测到网络钓鱼攻击' },

  // 病毒/蠕虫
  '1.3.6.1.4.1.12356.101.3.2.8': { attackType: '病毒/蠕虫', severity: 'critical', description: '检测到病毒或蠕虫传播' },

  // 未授权访问
  '1.3.6.1.4.1.12356.101.3.2.9': { attackType: '未授权访问', severity: 'high', description: '检测到未授权访问尝试' },
  '1.3.6.1.4.1.9.9.147.1.2.2.4': { attackType: '未授权访问', severity: 'high', description: '检测到非法登录尝试' },

  // 系统入侵
  '1.3.6.1.4.1.12356.101.3.2.10': { attackType: '系统入侵', severity: 'critical', description: '检测到系统入侵行为' },

  // 网络嗅探
  '1.3.6.1.4.1.12356.101.3.2.11': { attackType: '网络嗅探', severity: 'medium', description: '检测到网络嗅探活动' },

  // 防火墙策略违规
  '1.3.6.1.4.1.12356.101.3.2.12': { attackType: '策略违规', severity: 'low', description: '检测到防火墙策略违规访问' },

  // ARP 欺骗
  '1.3.6.1.4.1.12356.101.3.2.13': { attackType: 'ARP欺骗', severity: 'high', description: '检测到ARP欺骗攻击' },

  // ============= 华为 USG 防火墙企业 OID（企业号 2011）=============
  // IPS/IDS 攻击检测
  '1.3.6.1.4.1.2011.6.122.51.2.2.10': { attackType: '入侵攻击', severity: 'critical', description: '华为 IPS 检测到入侵攻击' },
  '1.3.6.1.4.1.2011.6.122.51.2.2': { attackType: '入侵攻击', severity: 'critical', description: '华为 IPS 检测到入侵行为' },
  // 攻击日志
  '1.3.6.1.4.1.2011.5.25.165.2.2.7.1': { attackType: '攻击告警', severity: 'high', description: '华为防火墙攻击日志' },
  '1.3.6.1.4.1.2011.5.25.165.2.2': { attackType: '攻击告警', severity: 'high', description: '华为防火墙安全告警' },
  // 配置变更
  '1.3.6.1.4.1.2011.6.10.2.1': { attackType: '配置变更', severity: 'low', description: '防火墙配置变更日志' },
  '1.3.6.1.4.1.2011.6.10.2.17': { attackType: '配置变更', severity: 'low', description: '防火墙配置变更（详细）' },
  // 系统资源
  '1.3.6.1.4.1.2011.5.25.212.2.2': { attackType: '系统资源告警', severity: 'medium', description: '防火墙系统资源状态告警' },
};

// 标准 SNMP Trap 企业特定 OID 前缀
const STANDARD_TRAP_OIDS = {
  coldStart: '1.3.6.1.6.3.1.1.5.1',
  warmStart: '1.3.6.1.6.3.1.1.5.2',
  linkDown: '1.3.6.1.6.3.1.1.5.3',
  linkUp: '1.3.6.1.6.3.1.1.5.4',
  authenticationFailure: '1.3.6.1.6.3.1.1.5.5',
};

/**
 * 根据 OID 获取攻击类型映射
 * @param oid SNMP Trap 携带的 OID
 * @returns 攻击类型映射，未匹配时返回默认值
 */
export function getOidMapping(oid: string): OidMapping {
  // 精确匹配
  if (OID_MAPPINGS[oid]) {
    return OID_MAPPINGS[oid];
  }

  // 前缀匹配（部分设备的 OID 带后缀子节点）
  for (const key of Object.keys(OID_MAPPINGS)) {
    if (oid.startsWith(key + '.')) {
      return OID_MAPPINGS[key];
    }
  }

  // 标准 Trap OID 处理
  if (oid === STANDARD_TRAP_OIDS.authenticationFailure) {
    return { attackType: '认证失败', severity: 'high', description: 'SNMP认证失败，可能存在非法访问' };
  }
  if (oid === STANDARD_TRAP_OIDS.linkDown) {
    return { attackType: '链路中断', severity: 'medium', description: '网络链路中断' };
  }

  // 默认
  return {
    attackType: '未知攻击',
    severity: 'medium',
    description: `未识别的告警类型 (OID: ${oid})`,
  };
}

/**
 * 获取所有已知的攻击类型列表（用于前端筛选）
 */
export function getKnownAttackTypes(): string[] {
  const types = new Set<string>();
  Object.values(OID_MAPPINGS).forEach(m => types.add(m.attackType));
  return Array.from(types);
}
