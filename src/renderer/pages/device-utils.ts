// 设备类型显示标签
export const deviceTypeLabels: Record<string, string> = {
  firewall: '防火墙',
  router: '路由器',
  switch: '交换机',
  ids: '入侵检测系统(IDS)',
  ips: '入侵防御系统(IPS)',
  other: '其他',
};

// 厂商识别（根据 sysObjectID 的企业号）
const vendorMap: Array<{ prefix: string; name: string }> = [
  { prefix: '1.3.6.1.4.1.2011', name: '华为 Huawei' },
  { prefix: '1.3.6.1.4.1.9', name: '思科 Cisco' },
  { prefix: '1.3.6.1.4.1.12356', name: '飞塔 Fortinet' },
  { prefix: '1.3.6.1.4.1.24514', name: '山石 Hillstone' },
  { prefix: '1.3.6.1.4.1.8072', name: 'Net-SNMP（本机/开源）' },
];

export const getVendorName = (oid: string): string => {
  if (!oid) return '';
  const normalized = oid.endsWith('.') ? oid : oid + '.';
  for (const v of vendorMap) {
    if (normalized.startsWith(v.prefix + '.')) return v.name;
  }
  return '';
};

// 根据 sysServices 判断设备层级（OSI bit：1=物理层 2=数据链路层 4=网络层 8=传输层 16=会话层 32=表示层 64=应用层）
export const getServiceLayerDesc = (services: number): string => {
  if (!services || isNaN(services)) return '';
  const hasL2 = (services & 2) !== 0;
  const hasL3 = (services & 4) !== 0;
  const hasL4 = (services & 8) !== 0;
  const hasL7 = (services & 64) !== 0;
  if (hasL7 && hasL4 && hasL3) return '三层及以上（应用/安全网关设备）';
  if (hasL3 && hasL2) return '三层设备（路由器/三层交换机）';
  if (hasL2) return '二层设备（交换机）';
  if (hasL3) return '网络层设备（L3）';
  return '其他';
};

// 告警级别显示
export const severityLabels: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
};

export const severityConfig: Record<string, { label: string; color: string }> = {
  critical: { label: '严重', color: '#b31412' },
  high: { label: '高危', color: '#d93025' },
  medium: { label: '中危', color: '#e37400' },
  low: { label: '低危', color: '#137333' },
};

// 设备状态配置
export const statusConfig: Record<string, { label: string; dotClass: string; color: string }> = {
  online: { label: '在线', dotClass: 'status-dot-online', color: '#137333' },
  offline: { label: '离线', dotClass: 'status-dot-offline', color: '#b31412' },
  unknown: { label: '未知', dotClass: 'status-dot-offline', color: '#9aa0a6' },
};

export const formatTime = (ts: string | null): string => {
  if (!ts) return '-';
  return new Date(ts).toLocaleString('zh-CN');
};

// ====== 接口信息格式化（P1） ======

// 接口操作状态显示
export const ifOperStatusConfig: Record<string, { label: string; dotClass: string; color: string }> = {
  up: { label: '运行', dotClass: 'status-dot-online', color: '#137333' },
  down: { label: '关闭', dotClass: 'status-dot-offline', color: '#b31412' },
  testing: { label: '测试', dotClass: 'status-dot-offline', color: '#e37400' },
  unknown: { label: '未知', dotClass: 'status-dot-offline', color: '#9aa0a6' },
};

// 接口管理状态显示
export const ifAdminStatusConfig: Record<string, { label: string; color: string }> = {
  up: { label: '开启', color: '#137333' },
  down: { label: '关闭', color: '#9aa0a6' },
  testing: { label: '测试', color: '#e37400' },
  unknown: { label: '未知', color: '#9aa0a6' },
};

// 物理速率格式化（bit/s -> "1 Gbps"）
export const formatIfSpeed = (speed: number): string => {
  if (!speed || speed <= 0) return '-';
  if (speed >= 1e9) return `${(speed / 1e9).toFixed(speed % 1e9 === 0 ? 0 : 1)} Gbps`;
  if (speed >= 1e6) return `${(speed / 1e6).toFixed(speed % 1e6 === 0 ? 0 : 1)} Mbps`;
  if (speed >= 1e3) return `${(speed / 1e3).toFixed(0)} Kbps`;
  return `${speed} bps`;
};

// 实时速率格式化（bytes/s -> "1.2 MB/s"）
export const formatRate = (bytesPerSec: number): string => {
  if (!bytesPerSec || bytesPerSec <= 0) return '0 B/s';
  if (bytesPerSec >= 1024 * 1024) return `${(bytesPerSec / 1024 / 1024).toFixed(2)} MB/s`;
  if (bytesPerSec >= 1024) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  return `${Math.round(bytesPerSec)} B/s`;
};

// 累计字节数格式化
export const formatBytes = (bytes: number): string => {
  if (!bytes || bytes <= 0) return '0 B';
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${Math.round(bytes)} B`;
};
