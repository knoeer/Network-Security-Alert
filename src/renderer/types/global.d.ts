export interface SecurityEvent {
  id: number;
  attack_type: string;
  attack_category?: string; // 标准攻击类型（跨厂商统一分类）
  source_ip: string;
  source_port: number;
  target_ip: string;
  target_port: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  device_name: string;
  device_ip: string;
  description: string;
  oid: string;
  raw_trap: string;
  timestamp: string;
  acknowledged: number;
  created_at: string;
  classify_source?: string; // 归类依据来源：user_rule/custom_keyword/builtin/default
}

export interface Device {
  id: number;
  name: string;
  ip: string;
  port: number;
  snmp_version: 'v1' | 'v2c' | 'v3';
  community: string;
  snmp_username: string;
  snmp_auth_protocol: 'none' | 'md5' | 'sha' | 'sha224' | 'sha256' | 'sha384' | 'sha512';
  snmp_auth_key: string;
  snmp_priv_protocol: 'none' | 'des' | 'aes' | 'aes256b' | 'aes256r';
  snmp_priv_key: string;
  device_type: string;
  location: string;
  description: string;
  status: 'online' | 'offline' | 'unknown';
  last_checked: string | null;
  created_at: string;
  updated_at: string;
}

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

export interface DeviceAlertSummary {
  total: number;
  todayCount: number;
  bySeverity: Array<{ severity: string; count: number }>;
  lastAlert: {
    attack_type: string;
    severity: string;
    source_ip: string;
    target_ip: string;
    timestamp: string;
    description: string;
    acknowledged: number;
  } | null;
  recentAlerts: SecurityEvent[];
}

export interface DeviceInterface {
  index: number;
  name: string;
  descr: string;
  type: string;
  mtu: number;
  speed: number;
  mac: string;
  adminStatus: string;
  operStatus: string;
  inOctets: number;
  outOctets: number;
  inRate: number;
  outRate: number;
  inErrors: number;
  outErrors: number;
  ips: string[];
}

export interface ProbeInterfacesResult {
  success: boolean;
  online: boolean;
  message: string;
  interfaces: DeviceInterface[];
  sampleTime?: string | null;
}

export interface InterfaceSnapshotResult {
  interfaces: DeviceInterface[] | null;
  sampleTime: string | null;
}

export interface TopologyRoute {
  destination: string;
  nextHop: string;
  ifIndex: number;
  metric: number;
  type: string;
}

export interface TopologyArpEntry {
  ip: string;
  mac: string;
  ifIndex: number;
  type: string;
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

export interface EventFilter {
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

export interface SourceAttackStats {
  count: number;           // 该源 IP 累计攻击次数
  todayCount: number;      // 近24小时攻击次数
  byAttackType: Array<{ attack_type: string; count: number }>; // 攻击类型分布
}

export interface IpLocation {
  country: string;         // 国家
  province: string;        // 省份
  city: string;            // 城市
  isp: string;             // 运营商
  source: 'offline' | 'online' | 'private' | 'unknown'; // 数据来源
  display?: string;        // 格式化后的展示文本
}

export interface EventStats {
  total: number;
  todayCount: number;
  bySeverity: Array<{ severity: string; count: number }>;
  recentEvents: SecurityEvent[];
}

export interface AlertData {
  attackType: string;
  sourceIp: string;
  sourcePort: number;
  targetIp: string;
  targetPort: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  deviceName: string;
  deviceIp: string;
  description: string;
  timestamp: string;
  oid: string;
  // 源地址攻击次数（弹窗标识）
  sourceAttackCount?: number;
  sourceAttackCountToday?: number;
  // 标准攻击类型（跨厂商统一分类）
  attackCategory?: string;
}

export interface MonitorConfig {
  enabled: boolean;
  interval: number;
  failThreshold: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  recoverNotify: boolean;
}

export interface MonitorDeviceStatus {
  id: number;
  name: string;
  ip: string;
  status: string;
  failCount: number;
  lastChecked: string | null;
  monitorEnabled: boolean;
}

export interface MonitorStatus {
  running: boolean;
  lastRunAt: string | null;
  nextRunAt: string | null;
  lastError: string | null;
  devices: MonitorDeviceStatus[];
}

export interface PerformanceConfig {
  enabled: boolean;
  interval: number;
  cpuThreshold: number;
  memThreshold: number;
}

export interface DiskPartition {
  name: string;   // 分区标识，如 "/"、"/usr/local/las"
  percent: number; // 使用率 %（0-100）
  size: number;   // 总大小（字节）
  used: number;   // 已用（字节）
}

export interface PerformanceSample {
  id: number;
  device_id: number;
  cpu_percent: number;
  mem_percent: number;
  disk_percent: number;
  disks?: DiskPartition[]; // 全部分区列表
  timestamp: string;
}

export interface TrafficConfig {
  enabled: boolean;
  interval: number;
}

export interface TrafficSample {
  id: number;
  device_id: number;
  in_rate: number;
  out_rate: number;
  timestamp: string;
}

declare global {
  interface Window {
    electronAPI: {
      showAlert: (data: AlertData) => Promise<void>;
      closeAlert: () => Promise<void>;
      closeAlertSingle: () => Promise<void>;
      minimizeToTray: () => Promise<void>;
      getEvents: (filter: EventFilter) => Promise<{ events: SecurityEvent[]; total: number }>;
      getEventById: (id: number) => Promise<SecurityEvent>;
      getEventStats: () => Promise<EventStats>;
      getUnacknowledgedCount: () => Promise<number>;
      onUnacknowledgedChanged: (callback: () => void) => void;
      acknowledgeEvent: (id: number, acknowledged: boolean) => Promise<{ success: boolean; id: number; acknowledged: boolean }>;
      acknowledgeEvents: (ids: number[], acknowledged: boolean) => Promise<{ success: boolean; count: number }>;
      acknowledgeAllEvents: () => Promise<{ success: boolean; count: number }>;
      deleteEvent: (id: number) => Promise<{ success: boolean }>;
      deleteEvents: (ids: number[]) => Promise<{ success: boolean; count: number }>;
      clearEvents: () => Promise<{ success: boolean }>;
      exportEvents: (filter: EventFilter) => Promise<{ events: SecurityEvent[]; total: number }>;
      exportData: () => Promise<{ success: boolean; canceled?: boolean; filePath?: string; stats?: { events: number; devices: number }; message?: string }>;
      importData: () => Promise<{ success: boolean; canceled?: boolean; stats?: { events: number; devices: number }; message?: string }>;
      getAttackTop: (limit?: number) => Promise<Array<{ attack_type: string; count: number }>>;
      getTrend: (days?: number) => Promise<Array<{ date: string; count: number; critical: number; high: number; medium: number; low: number }>>;
      getHourlyTrend: () => Promise<Array<{ hour: string; count: number }>>;
      getSourceIpTop: (limit?: number) => Promise<Array<{ source_ip: string; count: number }>>;
      getTargetIpTop: (limit?: number) => Promise<Array<{ target_ip: string; count: number }>>;
      getSourceAttackCount: (sourceIp: string) => Promise<SourceAttackStats>;
      queryLocation: (ip: string) => Promise<IpLocation>;
      queryLocations: (ips: string[]) => Promise<Record<string, string>>;
      // 标准攻击类型分类
      getAttackCategories: () => Promise<string[]>;
      getEventCategoryTop: (limit?: number) => Promise<Array<{ attack_category: string; count: number }>>;
      getEventConfigPath: () => Promise<string | null>;
      reloadEventConfig: () => Promise<{ success: boolean }>;
      backfillEventCategories: () => Promise<{ updated: number }>;
      manualClassify: (payload: { id: number; category: string; raw_trap?: string; vendor?: string }) => Promise<{ success: boolean; message?: string; feature?: string; vendor?: string; category?: string }>;
      getUserClassifyRules: () => Promise<{ success: boolean; rules: Array<{ id: number; vendor: string; feature: string; category: string; created_at: string; updated_at: string }> }>;
      deleteUserClassifyRule: (id: number) => Promise<{ success: boolean }>;
      listEventTypes: () => Promise<{ success: boolean; types: Array<{ id: number; name: string; feature_keywords: string; default_severity: string; is_builtin: number }> }>;
      createEventType: (payload: { name: string; feature_keywords: string[]; default_severity: string }) => Promise<{ success: boolean; message?: string; id?: number }>;
      updateEventType: (payload: { id: number; name: string; feature_keywords: string[]; default_severity: string }) => Promise<{ success: boolean; message?: string }>;
      deleteEventType: (id: number) => Promise<{ success: boolean; message?: string }>;
      getDeviceAlertStats: () => Promise<Array<{ device_name: string; count: number }>>;
      getDevices: () => Promise<Device[]>;
      getDeviceById: (id: number) => Promise<Device>;
      addDevice: (device: Partial<Device>) => Promise<Device>;
      updateDevice: (device: Partial<Device>) => Promise<Device>;
      deleteDevice: (id: number) => Promise<{ success: boolean }>;
      testDeviceConnection: (device: Partial<Device>) => Promise<{
        success: boolean;
        message: string;
        online: boolean;
        info?: DeviceInfo;
      }>;
      probeDevice: (id: number) => Promise<{
        success: boolean;
        message: string;
        online: boolean;
        info?: DeviceInfo;
      }>;
      probeInterfaces: (id: number) => Promise<ProbeInterfacesResult>;
      getSavedInterfaces: (id: number) => Promise<InterfaceSnapshotResult>;
      probeTopology: (id: number) => Promise<TopologyResult>;
      checkAllDevices: () => Promise<{ total: number; online: number; offline: number }>;
      getDeviceAlertSummary: (device: { ip: string; name: string }) => Promise<DeviceAlertSummary>;
      startTrapListener: (port?: number) => Promise<{ success: boolean; port: number; status: string; message: string }>;
      stopTrapListener: () => Promise<{ success: boolean; status: string; message: string }>;
      getTrapStatus: () => Promise<{ status: string; port: number }>;
      sendTestAlert: () => Promise<{ success: boolean }>;
      startSyslog: (port?: number) => Promise<{ success: boolean; port: number; status: string; message: string }>;
      stopSyslog: () => Promise<{ success: boolean; status: string; message: string }>;
      getSyslogStatus: () => Promise<{ status: string; port: number }>;
      getSyslogLogs: () => Promise<Array<{ time: string; source: string; content: string; isThreat: boolean }>>;
      clearSyslogLogs: () => Promise<{ success: boolean }>;
      getAppVersion: () => Promise<string>;
      onAlertReceived: (callback: (data: AlertData) => void) => void;
      onTrapStatusChanged: (callback: (status: unknown) => void) => void;
      onListenerStatusChanged: (callback: (status: { trap: { status: string; port: number }; syslog: { status: string; port: number } }) => void) => void;
      getAlertConfig: () => Promise<{ autoClose: boolean; seconds: number; popupCritical: boolean; popupHigh: boolean; popupMedium: boolean; popupLow: boolean }>;
      saveAlertConfig: (config: { autoClose: boolean; seconds: number; popupCritical?: boolean; popupHigh?: boolean; popupMedium?: boolean; popupLow?: boolean }) => Promise<{ success: boolean }>;
      getRawLogConfig: () => Promise<{ enabled: boolean; baseDir: string; snmpEnabled: boolean; syslogEnabled: boolean }>;
      updateRawLogConfig: (config: { enabled: boolean; baseDir: string; snmpEnabled: boolean; syslogEnabled: boolean }) => Promise<{ success: boolean }>;
      selectDirectory: () => Promise<string | null>;
      getMonitorConfig: () => Promise<MonitorConfig>;
      saveMonitorConfig: (config: Partial<MonitorConfig>) => Promise<{ success: boolean }>;
      getMonitorStatus: () => Promise<MonitorStatus>;
      runMonitorNow: () => Promise<{ total: number; online: number; offline: number; failed: number }>;
      onDeviceStatusChanged: (callback: (data: { id: number; name: string; status: string }) => void) => () => void;
      getPerformanceConfig: () => Promise<PerformanceConfig>;
      savePerformanceConfig: (config: Partial<PerformanceConfig>) => Promise<{ success: boolean }>;
      getPerformanceHistory: (deviceId: number, limit?: number) => Promise<PerformanceSample[]>;
      samplePerformanceNow: (deviceId?: number) => Promise<{ total?: number; sampled?: number; success?: boolean; cpu?: number; mem?: number }>;
      getTrafficConfig: () => Promise<TrafficConfig>;
      saveTrafficConfig: (config: Partial<TrafficConfig>) => Promise<{ success: boolean }>;
      getTrafficHistory: (deviceId: number, limit?: number) => Promise<TrafficSample[]>;
      sampleTrafficNow: (deviceId?: number) => Promise<{ total?: number; sampled?: number; success?: boolean; inRate?: number; outRate?: number }>;
    };
  }
}

export {};
