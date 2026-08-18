/**
 * SNMP 设备探测模块
 * 使用 net-snmp 库对设备进行真实的 SNMP get 请求，获取设备系统信息和在线状态
 */
import * as snmp from 'net-snmp';
import { queryOne, queryAll, execute } from './db-helper';

/** 创建 SNMP Session 所需的最小设备信息 */
export interface SnmpDevice {
  ip: string;
  port?: number;
  community?: string;
  snmp_version?: string;
  snmp_username?: string;
  snmp_auth_protocol?: string;
  snmp_auth_key?: string;
  snmp_priv_protocol?: string;
  snmp_priv_key?: string;
}

/**
 * 根据设备配置创建 SNMP Session（统一入口）
 * 支持 v1 / v2c / v3 三种版本，供各监控模块复用
 */
export function createSnmpSession(device: SnmpDevice): snmp.Session {
  if (device.snmp_version === 'v3') {
    const authProtocolMap: Record<string, number> = {
      md5: snmp.AuthProtocols.md5,
      sha: snmp.AuthProtocols.sha,
      sha224: snmp.AuthProtocols.sha224,
      sha256: snmp.AuthProtocols.sha256,
      sha384: snmp.AuthProtocols.sha384,
      sha512: snmp.AuthProtocols.sha512,
    };
    const privProtocolMap: Record<string, number> = {
      des: snmp.PrivProtocols.des,
      aes: snmp.PrivProtocols.aes,
      aes256b: snmp.PrivProtocols.aes256b,
      aes256r: snmp.PrivProtocols.aes256r,
    };
    const authProtocol = authProtocolMap[device.snmp_auth_protocol || 'sha'] ?? snmp.AuthProtocols.sha;
    const privProtocol = privProtocolMap[device.snmp_priv_protocol || 'aes'] ?? snmp.PrivProtocols.aes;
    const hasPriv = !!(device.snmp_priv_key && device.snmp_priv_protocol && device.snmp_priv_protocol !== 'none');
    const hasAuth = !!(device.snmp_auth_key && device.snmp_auth_protocol && device.snmp_auth_protocol !== 'none');

    return snmp.createV3Session(device.ip, {
      name: device.snmp_username || '',
      level: hasPriv ? snmp.SecurityLevel.authPriv : hasAuth ? snmp.SecurityLevel.authNoPriv : snmp.SecurityLevel.noAuthNoPriv,
      authProtocol: hasAuth ? authProtocol : snmp.AuthProtocols.none,
      authKey: device.snmp_auth_key || '',
      privProtocol: hasPriv ? privProtocol : snmp.PrivProtocols.none,
      privKey: device.snmp_priv_key || '',
    }, {
      port: device.port || 161,
      timeouts: [3000],
      retries: 1,
    });
  }

  const version = device.snmp_version === 'v1' ? snmp.Version1 : snmp.Version2c;
  return snmp.createSession(device.ip, device.community || 'public', {
    port: device.port || 161,
    version,
    timeout: 3000,
    retries: 1,
  });
}

// 标准 SNMP MIB OID（用于获取设备系统信息）
const SNMP_OIDS = {
  sysDescr: '1.3.6.1.2.1.1.1.0', // 系统描述
  sysObjectID: '1.3.6.1.2.1.1.2.0', // 系统对象ID
  sysUpTime: '1.3.6.1.2.1.1.3.0', // 系统运行时间
  sysContact: '1.3.6.1.2.1.1.4.0', // 系统联系人
  sysName: '1.3.6.1.2.1.1.5.0', // 系统名称
  sysLocation: '1.3.6.1.2.1.1.6.0', // 系统位置
  sysServices: '1.3.6.1.2.1.1.7.0', // 系统服务
  // HOST-RESOURCES-MIB 的系统运行时间。
  // 部分华为设备（如 WAF/USG YunShan OS）的标准 sysUpTime 返回值并非真实开机时长
  // （实测 WAF 的 sysUpTime=2.4天，而 hrSystemUptime=125天，与设备界面一致），
  // 因此优先使用 hrSystemUptime 计算开机时间/运行时间。
  sysUpTimeHr: '1.3.6.1.2.1.25.1.1.0',
};

export interface DeviceInfo {
  sysDescr: string;
  sysName: string;
  sysUpTime: string;
  sysLocation: string;
  sysContact: string;
  sysObjectID: string;
  sysServices: number;
  bootTime: string;
}

export interface ProbeResult {
  success: boolean;
  online: boolean;
  message: string;
  info?: DeviceInfo;
}

/**
 * 探测单个设备（SNMP get 请求）
 * @param device 设备信息
 * @returns 探测结果
 */
export function probeDevice(device: SnmpDevice): Promise<ProbeResult> {
  return new Promise((resolve) => {
    try {
      const session = createSnmpSession(device);

      const oids = Object.values(SNMP_OIDS);

      session.get(oids, (error, varbinds) => {
        session.close();

        if (error) {
          resolve({
            success: false,
            online: false,
            message: `SNMP 请求失败: ${error.message || '无法获取设备信息'}`,
          });
          return;
        }

        // 解析返回的 varbinds
        const info: DeviceInfo = {
          sysDescr: '',
          sysName: '',
          sysUpTime: '',
          sysLocation: '',
          sysContact: '',
          sysObjectID: '',
          sysServices: 0,
          bootTime: '',
        };

        // 按 OID 匹配字段（比 index 更稳健，不受返回顺序影响）
        let sysUpTimeTicks: number | null = null;   // 标准 sysUpTime
        let hrSysUpTimeTicks: number | null = null; // HOST-RESOURCES 系统运行时间
        if (varbinds && varbinds.length > 0) {
          varbinds.forEach((vb: any) => {
            const oid = (vb.oid || '').toLowerCase();
            const value = vb.value;
            if (oid.startsWith('1.3.6.1.2.1.1.1')) {
              info.sysDescr = stringifyVarbindValue(value);
            } else if (oid.startsWith('1.3.6.1.2.1.1.2')) {
              info.sysObjectID = stringifyVarbindValue(value);
            } else if (oid.startsWith('1.3.6.1.2.1.1.3')) {
              sysUpTimeTicks = Number(value);
            } else if (oid.startsWith('1.3.6.1.2.1.25.1.1')) {
              hrSysUpTimeTicks = Number(value);
            } else if (oid.startsWith('1.3.6.1.2.1.1.4')) {
              info.sysContact = stringifyVarbindValue(value);
            } else if (oid.startsWith('1.3.6.1.2.1.1.5')) {
              info.sysName = stringifyVarbindValue(value);
            } else if (oid.startsWith('1.3.6.1.2.1.1.6')) {
              info.sysLocation = stringifyVarbindValue(value);
            } else if (oid.startsWith('1.3.6.1.2.1.1.7')) {
              info.sysServices = Number(value);
            }
          });
        }

        // 优先使用 hrSystemUptime（更接近设备真实开机时长），否则回退到标准 sysUpTime。
        // 华为 WAF/USG（YunShan OS）的标准 sysUpTime 返回值并非真实开机时长，需用 hrSystemUptime。
        const effectiveTicks =
          hrSysUpTimeTicks !== null && !isNaN(hrSysUpTimeTicks) && hrSysUpTimeTicks > 0
            ? hrSysUpTimeTicks
            : sysUpTimeTicks;
        if (effectiveTicks !== null && !isNaN(effectiveTicks)) {
          info.sysUpTime = formatUptime(effectiveTicks);
          info.bootTime = formatBootTime(effectiveTicks);
        }

        resolve({
          success: true,
          online: true,
          message: '设备在线',
          info,
        });
      });
    } catch (err: any) {
      resolve({
        success: false,
        online: false,
        message: `探测失败: ${err?.message || '未知错误'}`,
      });
    }
  });
}

/**
 * 格式化系统运行时间（ticks 转可读格式）
 * SNMP sysUpTime 单位是 1/100 秒
 */
function formatUptime(ticks: number): string {
  if (!ticks || isNaN(ticks)) return '未知';
  const seconds = Math.floor(ticks / 100);
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;

  const parts: string[] = [];
  if (days > 0) parts.push(`${days}天`);
  if (hours > 0) parts.push(`${hours}小时`);
  if (minutes > 0) parts.push(`${minutes}分钟`);
  parts.push(`${secs}秒`);
  return parts.join(' ');
}

/**
 * 将 varbind 的值转为字符串
 * 处理 OBJECT IDENTIFIER 类型（net-snmp 返回 ObjectID 实例而非字符串）
 */
function stringifyVarbindValue(value: any): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number') return String(value);
  if (typeof value === 'object') {
    if (typeof value.toStr === 'function') return value.toStr();
    if (typeof value.toString === 'function') {
      const s = value.toString();
      if (s !== '[object Object]') return s;
    }
    try {
      return JSON.stringify(value);
    } catch {
      return '';
    }
  }
  return String(value);
}

/**
 * 根据 sysUpTime（ticks，单位 1/100 秒）反推设备实际开机时刻
 */
function formatBootTime(ticks: number): string {
  if (!ticks || isNaN(ticks)) return '';
  const bootDate = new Date(Date.now() - ticks * 10);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${bootDate.getFullYear()}-${pad(bootDate.getMonth() + 1)}-${pad(bootDate.getDate())} ${pad(bootDate.getHours())}:${pad(bootDate.getMinutes())}:${pad(bootDate.getSeconds())}`;
}

/**
 * 批量检查所有设备状态
 * @returns 检查结果
 */
export async function checkAllDevices(): Promise<{ total: number; online: number; offline: number }> {
  const devices = queryAll<any>('SELECT * FROM devices');
  let online = 0;
  let offline = 0;

  for (const device of devices) {
    const result = await probeDevice(device);
    const status = result.online ? 'online' : 'offline';
    const now = new Date().toISOString();

    execute('UPDATE devices SET status = ?, last_checked = ? WHERE id = ?', [
      status,
      now,
      device.id,
    ]);

    if (result.online) {
      online++;
    } else {
      offline++;
    }
  }

  return { total: devices.length, online, offline };
}

/**
 * 探测单个设备并更新其状态
 */
export async function probeAndUpdateDevice(deviceId: number): Promise<ProbeResult> {
  const device = queryOne<any>('SELECT * FROM devices WHERE id = ?', [deviceId]);
  if (!device) {
    return { success: false, online: false, message: '设备不存在' };
  }

  const result = await probeDevice(device);

  execute('UPDATE devices SET status = ?, last_checked = ? WHERE id = ?', [
    result.online ? 'online' : 'offline',
    new Date().toISOString(),
    deviceId,
  ]);

  return result;
}

// ====== 接口列表与流量探测（P1） ======

// ifTable / ifXTable 前缀（注意：tableColumns 第一个参数必须是 table 节点 OID，
// 不能是 table entry OID，因为内部会拼接 oid + ".1." 作为行前缀）
const IF_TABLE_OID = '1.3.6.1.2.1.2.2'; // ifTable（MIB-II）
const IFX_TABLE_OID = '1.3.6.1.2.1.31.1.1'; // ifXTable
const IP_ADDR_TABLE_OID = '1.3.6.1.2.1.4.20'; // ipAddrTable（接口 IP 地址）

// ifTable 列索引（MIB-II）
const IF_COLS = {
  index: 1,
  descr: 2,
  type: 3,
  mtu: 4,
  speed: 5,
  physAddress: 6,
  adminStatus: 7,
  operStatus: 8,
  inOctets: 10,
  inErrors: 14,
  outOctets: 16,
  outErrors: 20,
};

// ifXTable 列索引（64 位计数器 / 高速速率）
const IFX_COLS = {
  name: 1,
  hcInOctets: 6,
  hcOutOctets: 10,
  highSpeed: 18, // ifHighSpeed，单位 Mbps，用于 ifSpeed 溢出时回退
};

// ipAddrTable 列索引（接口 IP 地址）
const IP_ADDR_COLS = {
  addr: 1, // ipAdEntAddr（IP 地址，表索引本身）
  ifIndex: 2, // ipAdEntIfIndex（关联接口索引）
  netMask: 3, // ipAdEntNetMask（子网掩码）
};

export interface DeviceInterface {
  index: number;
  name: string; // ifName 优先，否则 ifDescr
  descr: string;
  type: string; // ifType 文本
  mtu: number;
  speed: number; // 物理速率 bit/s
  mac: string;
  adminStatus: string; // up / down / testing
  operStatus: string; // up / down / testing
  inOctets: number; // 64 位计数值
  outOctets: number;
  inRate: number; // bytes/s
  outRate: number; // bytes/s
  inErrors: number;
  outErrors: number;
  ips: string[]; // 接口绑定的 IP 地址列表（来自 ipAddrTable）
}

export interface ProbeInterfacesResult {
  success: boolean;
  online: boolean;
  message: string;
  interfaces: DeviceInterface[];
}

// ifType 文本映射（IANAifType 常见值）
const IF_TYPE_NAMES: Record<number, string> = {
  1: '其他',
  6: '以太网',
  18: '令牌环',
  23: 'PPP',
  24: '软件环回',
  37: 'ATM',
  49: '帧中继',
  53: '虚拟接口',
  71: '点到点串行',
  117: '千兆以太网',
  131: '隧道',
  135: 'VLAN',
  136: 'VLAN子接口',
  150: 'MPLS隧道',
  161: '链路聚合',
  143: 'GRE隧道',
};

/**
 * 将 varbind 计数类值转为 number
 * Counter64 在 net-snmp 中可能返回 Buffer(8字节)/number/bigint
 */
function counterToNumber(value: any): number {
  if (value === null || value === undefined) return 0;
  if (typeof value === 'number') return value;
  if (typeof value === 'bigint') {
    const n = Number(value);
    return isNaN(n) ? 0 : n;
  }
  if (Buffer.isBuffer(value)) {
    // Counter64 为变长 BER 编码（华为设备省略前导零），统一左对齐补零到 8 字节
    if (value.length === 0) return 0;
    if (value.length > 8) return 0;
    try {
      if (value.length === 8) {
        return Number(value.readBigUInt64BE(0));
      }
      const padded = Buffer.alloc(8);
      value.copy(padded, 8 - value.length);
      return Number(padded.readBigUInt64BE(0));
    } catch {
      return 0;
    }
  }
  if (typeof value === 'object' && typeof value.toString === 'function') {
    const n = Number(value.toString());
    return isNaN(n) ? 0 : n;
  }
  return 0;
}

/** 将 OCTET STRING 转为字符串（接口名/描述等） */
function octetToString(value: any): string {
  if (value === null || value === undefined) return '';
  if (Buffer.isBuffer(value)) return value.toString('utf8').replace(/\u0000/g, '').trim();
  return stringifyVarbindValue(value);
}

/**
 * 将 ipAddrTable 中的 IP 地址值转为可读字符串
 * net-snmp 中 IpAddress 类型返回 Buffer(4字节)，也可能返回 ObjectID 或字符串
 */
function formatIpAddress(value: any): string {
  if (value === null || value === undefined) return '';
  if (Buffer.isBuffer(value)) {
    if (value.length === 4) {
      return `${value[0]}.${value[1]}.${value[2]}.${value[3]}`;
    }
    // 16 字节 IPv6，简单十六进制展示
    return value.toString('hex').replace(/(.{4})/g, '$1:').slice(0, -1);
  }
  const s = stringifyVarbindValue(value);
  return s;
}

/** 格式化 MAC 地址 */
function formatMac(value: any): string {
  if (!Buffer.isBuffer(value) || value.length === 0) return '';
  const hex = value.toString('hex').toUpperCase();
  if (hex.length !== 12) return hex;
  return hex.match(/.{2}/g)!.join(':');
}

/** ifAdminStatus / ifOperStatus 状态文本 */
function statusText(value: any): string {
  const n = counterToNumber(value);
  if (n === 1) return 'up';
  if (n === 2) return 'down';
  if (n === 3) return 'testing';
  return 'unknown';
}

/**
 * 读取表的一列或多列，返回 { [rowIndex]: { [col]: value } }
 *
 * maxRepetitions 必须明显大于接口数（取 100）：
 * 华为防火墙（USG6500F/6525F 等）在 getBulk 需要分批续传时存在缓存缺陷——
 * 当某批返回的 varbind 数量恰好等于 maxRepetitions（说明还有更多数据）时，
 * 后续第二次采样会直接返回第一批的旧值，导致两次采样计数相同、流量算出来为 0。
 * maxRepetitions >= 接口数后单次 getBulk 即可取完整列，不会触发续传。
 */
const SNMP_MAX_REPETITIONS = 100;

/** 读取表的一列或多列，返回 { [rowIndex]: { [col]: value } } */
function readSnmpColumns(
  session: snmp.Session,
  oid: string,
  columns: number[]
): Promise<Record<string, Record<string, any>>> {
  return new Promise((resolve) => {
    try {
      session.tableColumns(oid, columns, SNMP_MAX_REPETITIONS, (error: any, table: any) => {
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

/** 等待指定毫秒 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * 探测设备接口列表与实时流量（P1）
 * 通过 ifTable + ifXTable 读取接口信息，两次采样（间隔 2 秒）计算收发速率
 */
export function probeInterfaces(device: SnmpDevice): Promise<ProbeInterfacesResult> {
  return new Promise(async (resolve) => {
    let session: snmp.Session | null = null;
    try {
      session = createSnmpSession(device);

      // 第一次采样：静态信息 + 计数器
      const ifTable = await readSnmpColumns(session, IF_TABLE_OID, Object.values(IF_COLS));
      const ifxTable = await readSnmpColumns(session, IFX_TABLE_OID, Object.values(IFX_COLS));
      // 接口 IP 地址表（独立表，失败不影响主流程）
      const ipAddrTable = await readSnmpColumns(session, IP_ADDR_TABLE_OID, Object.values(IP_ADDR_COLS));

      if (!ifTable || Object.keys(ifTable).length === 0) {
        session.close();
        resolve({
          success: false,
          online: false,
          message: '设备不支持 ifTable 或 SNMP 读取失败',
          interfaces: [],
        });
        return;
      }

      // 等待 2 秒后第二次采样计数器
      await sleep(2000);
      const ifTable2 = await readSnmpColumns(session, IF_TABLE_OID, [IF_COLS.inOctets, IF_COLS.outOctets]);
      const ifxTable2 = await readSnmpColumns(session, IFX_TABLE_OID, [IFX_COLS.hcInOctets, IFX_COLS.hcOutOctets]);
      session.close();
      session = null;

      // 建立接口索引 -> IP 地址列表 的映射（ipAdEntIfIndex 关联）
      const ipByIfIndex = new Map<number, string[]>();
      for (const row of Object.values(ipAddrTable) as any[]) {
        const addr = formatIpAddress(row[IP_ADDR_COLS.addr]);
        if (!addr) continue;
        const ifIndex = counterToNumber(row[IP_ADDR_COLS.ifIndex]);
        if (!ifIndex) continue;
        if (!ipByIfIndex.has(ifIndex)) {
          ipByIfIndex.set(ifIndex, []);
        }
        ipByIfIndex.get(ifIndex)!.push(addr);
      }

      const hasIfx = Object.keys(ifxTable).length > 0;
      const interfaces: DeviceInterface[] = [];

      for (const rowIdx of Object.keys(ifTable)) {
        const row = ifTable[rowIdx];
        const row2 = ifTable2[rowIdx] || {};
        const xrow = ifxTable[rowIdx] || {};
        const xrow2 = ifxTable2[rowIdx] || {};

        // 64 位计数器优先（ifXTable），否则回退 32 位
        const in1 = hasIfx && xrow[IFX_COLS.hcInOctets] !== undefined
          ? counterToNumber(xrow[IFX_COLS.hcInOctets])
          : counterToNumber(row[IF_COLS.inOctets]);
        const out1 = hasIfx && xrow[IFX_COLS.hcOutOctets] !== undefined
          ? counterToNumber(xrow[IFX_COLS.hcOutOctets])
          : counterToNumber(row[IF_COLS.outOctets]);
        const in2 = hasIfx && xrow2[IFX_COLS.hcInOctets] !== undefined
          ? counterToNumber(xrow2[IFX_COLS.hcInOctets])
          : counterToNumber(row2[IF_COLS.inOctets]);
        const out2 = hasIfx && xrow2[IFX_COLS.hcOutOctets] !== undefined
          ? counterToNumber(xrow2[IFX_COLS.hcOutOctets])
          : counterToNumber(row2[IF_COLS.outOctets]);

        // 计数器回绕处理（32 位计数器可能在高速下回绕）
        const wrap32 = 2 ** 32;
        const wrap64 = 2 ** 64;
        const diffIn = in2 >= in1 ? in2 - in1 : in2 + (hasIfx ? wrap64 : wrap32) - in1;
        const diffOut = out2 >= out1 ? out2 - out1 : out2 + (hasIfx ? wrap64 : wrap32) - out1;

        // 忽略计数值缺失导致的异常速率
        const inRate = in2 >= 0 && in1 >= 0 ? diffIn / 2 : 0; // bytes/s（间隔 2 秒）
        const outRate = out2 >= 0 && out1 >= 0 ? diffOut / 2 : 0;

        const descr = octetToString(row[IF_COLS.descr]);
        const ifxName = octetToString(xrow[IFX_COLS.name]);
        const ifTypeNum = counterToNumber(row[IF_COLS.type]);

        // ifSpeed 为 32 位，10G+ 接口会溢出为 4294967295，回退 ifXTable.ifHighSpeed（Mbps）
        let speed = counterToNumber(row[IF_COLS.speed]);
        if (speed === 4294967295) {
          const highSpeed = counterToNumber(xrow[IFX_COLS.highSpeed]);
          speed = highSpeed > 0 ? highSpeed * 1000000 : 0;
        }

        const ifIndex = counterToNumber(row[IF_COLS.index]);

        interfaces.push({
          index: ifIndex,
          name: ifxName || descr || `接口 ${rowIdx}`,
          descr,
          type: IF_TYPE_NAMES[ifTypeNum] || `类型${ifTypeNum}`,
          mtu: counterToNumber(row[IF_COLS.mtu]),
          speed,
          mac: formatMac(row[IF_COLS.physAddress]),
          adminStatus: statusText(row[IF_COLS.adminStatus]),
          operStatus: statusText(row[IF_COLS.operStatus]),
          inOctets: in2,
          outOctets: out2,
          inRate,
          outRate,
          inErrors: counterToNumber(row[IF_COLS.inErrors]),
          outErrors: counterToNumber(row[IF_COLS.outErrors]),
          ips: ipByIfIndex.get(ifIndex) || [],
        });
      }

      // 按接口索引排序
      interfaces.sort((a, b) => a.index - b.index);

      resolve({
        success: true,
        online: true,
        message: `获取到 ${interfaces.length} 个接口`,
        interfaces,
      });
    } catch (err: any) {
      if (session) {
        try {
          session.close();
        } catch {
          // ignore
        }
      }
      resolve({
        success: false,
        online: false,
        message: `接口探测失败: ${err?.message || '未知错误'}`,
        interfaces: [],
      });
    }
  });
}

// ====== 路由表 / ARP 表读取（网络拓扑） ======

// ipRouteTable（1.3.6.1.2.1.4.21，MIB-II 路由表）
const IP_ROUTE_TABLE_OID = '1.3.6.1.2.1.4.21';
// ipNetToMediaTable（1.3.6.1.2.1.4.22，ARP 表 / 邻居表）
const IP_NET_TO_MEDIA_OID = '1.3.6.1.2.1.4.22';

// ipRouteTable 列索引
const ROUTE_COLS = {
  dest: 1, // ipRouteDest
  ifIndex: 2, // ipRouteIfIndex
  metric: 3, // ipRouteMetric1
  nextHop: 7, // ipRouteNextHop
  type: 8, // ipRouteType
  mask: 11, // ipRouteMask
};

// ipNetToMediaTable 列索引
const ARP_COLS = {
  ifIndex: 2, // ipNetToMediaIfIndex
  physAddress: 3, // ipNetToMediaPhysAddress（MAC）
  netAddress: 4, // ipNetToMediaNetAddress（IP）
  type: 5, // ipNetToMediaType
};

export interface TopologyRoute {
  destination: string; // 目的网络（含掩码，如 192.168.1.0/24）
  nextHop: string; // 下一跳 IP
  ifIndex: number;
  metric: number;
  type: string; // 路由类型文本
}

export interface TopologyArpEntry {
  ip: string;
  mac: string;
  ifIndex: number;
  type: string; // 静态/动态
}

export interface TopologyResult {
  success: boolean;
  online: boolean;
  message: string;
  deviceIp: string;
  deviceName: string;
  routes: TopologyRoute[];
  arp: TopologyArpEntry[];
}

// 路由类型映射（MIB-II ipRouteType）
const ROUTE_TYPE_NAMES: Record<number, string> = {
  1: '其他',
  2: '无效',
  3: '直连',
  4: '间接',
};

// ARP 类型映射（ipNetToMediaType）
const ARP_TYPE_NAMES: Record<number, string> = {
  1: '其他',
  2: '无效',
  3: '动态',
  4: '静态',
};

/** 将 IP 地址 + 掩码转换为 CIDR 表示（如 192.168.1.0/255.255.255.0 → 192.168.1.0/24） */
function toCidr(ip: string, mask: string): string {
  if (!ip || !mask) return ip || '';
  const maskParts = mask.split('.').map(Number);
  if (maskParts.length !== 4) return ip;
  // 计算掩码中连续的 1 位
  let bits = 0;
  let allOnes = true;
  for (const octet of maskParts) {
    if (octet === 255) {
      bits += 8;
    } else if (allOnes) {
      // 找到第一个非 255 的段，计算其高位连续 1 的个数
      let v = octet;
      let b = 0;
      while (v & 0x80) {
        b++;
        v = (v << 1) & 0xff;
      }
      bits += b;
      allOnes = false;
    }
  }
  return bits > 0 ? `${ip}/${bits}` : ip;
}

/**
 * 探测设备的路由表和 ARP 表（用于网络拓扑可视化）
 */
export function probeTopology(device: SnmpDevice & { name?: string }): Promise<TopologyResult> {
  return new Promise(async (resolve) => {
    let session: snmp.Session | null = null;
    try {
      session = createSnmpSession(device);

      // 读取路由表
      const routeTable = await readSnmpColumns(session, IP_ROUTE_TABLE_OID, Object.values(ROUTE_COLS));
      // 读取 ARP 表
      const arpTable = await readSnmpColumns(session, IP_NET_TO_MEDIA_OID, Object.values(ARP_COLS));
      session.close();
      session = null;

      const routes: TopologyRoute[] = [];
      for (const row of Object.values(routeTable) as any[]) {
        const dest = formatIpAddress(row[ROUTE_COLS.dest]);
        const mask = formatIpAddress(row[ROUTE_COLS.mask]);
        const nextHop = formatIpAddress(row[ROUTE_COLS.nextHop]);
        const typeNum = counterToNumber(row[ROUTE_COLS.type]);
        // 跳过无效路由和默认路由（0.0.0.0）的展示，但保留默认路由作为网关信息
        if (!dest || typeNum === 2) continue;
        routes.push({
          destination: toCidr(dest, mask),
          nextHop,
          ifIndex: counterToNumber(row[ROUTE_COLS.ifIndex]),
          metric: counterToNumber(row[ROUTE_COLS.metric]),
          type: ROUTE_TYPE_NAMES[typeNum] || `类型${typeNum}`,
        });
      }

      const arp: TopologyArpEntry[] = [];
      for (const row of Object.values(arpTable) as any[]) {
        const ip = formatIpAddress(row[ARP_COLS.netAddress]);
        const mac = formatMac(row[ARP_COLS.physAddress]);
        if (!ip || !mac) continue;
        const typeNum = counterToNumber(row[ARP_COLS.type]);
        arp.push({
          ip,
          mac,
          ifIndex: counterToNumber(row[ARP_COLS.ifIndex]),
          type: ARP_TYPE_NAMES[typeNum] || '动态',
        });
      }

      resolve({
        success: true,
        online: true,
        message: `获取到 ${routes.length} 条路由、${arp.length} 条 ARP 记录`,
        deviceIp: device.ip,
        deviceName: device.name || device.ip,
        routes,
        arp,
      });
    } catch (err: any) {
      if (session) {
        try {
          session.close();
        } catch {
          // ignore
        }
      }
      resolve({
        success: false,
        online: false,
        message: `拓扑探测失败: ${err?.message || '未知错误'}`,
        deviceIp: device.ip,
        deviceName: device.name || device.ip,
        routes: [],
        arp: [],
      });
    }
  });
}
