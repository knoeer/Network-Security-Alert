import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('electronAPI', {
  showAlert: (data: unknown) => ipcRenderer.invoke('show-alert', data),
  closeAlert: () => ipcRenderer.invoke('close-alert'),
  closeAlertSingle: () => ipcRenderer.invoke('close-alert-single'),
  minimizeToTray: () => ipcRenderer.invoke('minimize-to-tray'),
  // 数据库操作 - 事件管理
  getEvents: (filter: unknown) => ipcRenderer.invoke('db:getEvents', filter),
  getEventById: (id: number) => ipcRenderer.invoke('db:getEventById', id),
  getEventStats: () => ipcRenderer.invoke('db:getEventStats'),
  getUnacknowledgedCount: () => ipcRenderer.invoke('db:getUnacknowledgedCount'),
  onUnacknowledgedChanged: (callback: () => void) => {
    ipcRenderer.on('unacknowledged:changed', () => callback());
  },
  acknowledgeEvent: (id: number, acknowledged: boolean) => ipcRenderer.invoke('db:acknowledgeEvent', id, acknowledged),
  acknowledgeEvents: (ids: number[], acknowledged: boolean) => ipcRenderer.invoke('db:acknowledgeEvents', ids, acknowledged),
  acknowledgeAllEvents: () => ipcRenderer.invoke('db:acknowledgeAllEvents'),
  deleteEvent: (id: number) => ipcRenderer.invoke('db:deleteEvent', id),
  deleteEvents: (ids: number[]) => ipcRenderer.invoke('db:deleteEvents', ids),
  clearEvents: () => ipcRenderer.invoke('db:clearEvents'),
  exportEvents: (filter: unknown) => ipcRenderer.invoke('db:exportEvents', filter),
  exportData: () => ipcRenderer.invoke('db:exportData'),
  importData: () => ipcRenderer.invoke('db:importData'),
  // 仪表盘统计
  getAttackTop: (limit?: number) => ipcRenderer.invoke('db:getAttackTop', limit),
  getTrend: (days?: number) => ipcRenderer.invoke('db:getTrend', days),
  getHourlyTrend: () => ipcRenderer.invoke('db:getHourlyTrend'),
  getSourceIpTop: (limit?: number) => ipcRenderer.invoke('db:getSourceIpTop', limit),
  getTargetIpTop: (limit?: number) => ipcRenderer.invoke('db:getTargetIpTop', limit),
  getSourceAttackCount: (sourceIp: string) => ipcRenderer.invoke('db:getSourceAttackCount', sourceIp),
  // IP 属地查询
  queryLocation: (ip: string) => ipcRenderer.invoke('ip:queryLocation', ip),
  queryLocations: (ips: string[]) => ipcRenderer.invoke('ip:queryLocations', ips),
  // 标准攻击类型分类
  getAttackCategories: () => ipcRenderer.invoke('event:getAttackCategories'),
  getEventCategoryTop: (limit?: number) => ipcRenderer.invoke('event:getCategoryTop', limit),
  getEventConfigPath: () => ipcRenderer.invoke('event:getConfigPath'),
  reloadEventConfig: () => ipcRenderer.invoke('event:reloadConfig'),
  backfillEventCategories: () => ipcRenderer.invoke('event:backfill'),
  manualClassify: (payload: { id: number; category: string; raw_trap?: string; vendor?: string }) => ipcRenderer.invoke('event:manualClassify', payload),
  getUserClassifyRules: () => ipcRenderer.invoke('event:getUserRules'),
  deleteUserClassifyRule: (id: number) => ipcRenderer.invoke('event:deleteUserRule', id),
  listEventTypes: () => ipcRenderer.invoke('eventType:list'),
  createEventType: (payload: { name: string; feature_keywords: string[]; default_severity: string }) => ipcRenderer.invoke('eventType:create', payload),
  updateEventType: (payload: { id: number; name: string; feature_keywords: string[]; default_severity: string }) => ipcRenderer.invoke('eventType:update', payload),
  deleteEventType: (id: number) => ipcRenderer.invoke('eventType:delete', id),
  getDeviceAlertStats: () => ipcRenderer.invoke('db:getDeviceAlertStats'),
  // 数据库操作 - 设备管理
  getDevices: () => ipcRenderer.invoke('db:getDevices'),
  getDeviceById: (id: number) => ipcRenderer.invoke('db:getDeviceById', id),
  addDevice: (device: unknown) => ipcRenderer.invoke('db:addDevice', device),
  updateDevice: (device: unknown) => ipcRenderer.invoke('db:updateDevice', device),
  deleteDevice: (id: number) => ipcRenderer.invoke('db:deleteDevice', id),
  testDeviceConnection: (device: unknown) => ipcRenderer.invoke('db:testDeviceConnection', device),
  probeDevice: (id: number) => ipcRenderer.invoke('db:probeDevice', id),
  probeInterfaces: (id: number) => ipcRenderer.invoke('db:probeInterfaces', id),
  getSavedInterfaces: (id: number) => ipcRenderer.invoke('db:getSavedInterfaces', id),
  probeTopology: (id: number) => ipcRenderer.invoke('db:probeTopology', id),
  checkAllDevices: () => ipcRenderer.invoke('db:checkAllDevices'),
  getDeviceAlertSummary: (device: unknown) => ipcRenderer.invoke('db:getDeviceAlertSummary', device),
  // SNMP Trap 控制
  startTrapListener: (port?: number) => ipcRenderer.invoke('snmp:startTrap', port),
  stopTrapListener: () => ipcRenderer.invoke('snmp:stopTrap'),
  getTrapStatus: () => ipcRenderer.invoke('snmp:getStatus'),
  sendTestAlert: () => ipcRenderer.invoke('snmp:sendTestAlert'),
  // Syslog 控制
  startSyslog: (port?: number) => ipcRenderer.invoke('syslog:start', port),
  stopSyslog: () => ipcRenderer.invoke('syslog:stop'),
  getSyslogStatus: () => ipcRenderer.invoke('syslog:getStatus'),
  getSyslogLogs: () => ipcRenderer.invoke('syslog:getRecentLogs'),
  clearSyslogLogs: () => ipcRenderer.invoke('syslog:clearLogs'),
  // 应用控制
  getAppVersion: () => ipcRenderer.invoke('app:getVersion'),
  onAlertReceived: (callback: (data: unknown) => void) => {
    ipcRenderer.on('alert:received', (_event, data) => callback(data));
  },
  onTrapStatusChanged: (callback: (status: unknown) => void) => {
    ipcRenderer.on('snmp:statusChanged', (_event, status) => callback(status));
  },
  onListenerStatusChanged: (callback: (status: unknown) => void) => {
    ipcRenderer.on('listener:statusChanged', (_event, status) => callback(status));
  },
  // 告警配置
  getAlertConfig: () => ipcRenderer.invoke('config:getAlertConfig'),
  saveAlertConfig: (config: unknown) => ipcRenderer.invoke('config:saveAlertConfig', config),
  // 设备离线监测
  getMonitorConfig: () => ipcRenderer.invoke('monitor:getConfig'),
  saveMonitorConfig: (config: unknown) => ipcRenderer.invoke('monitor:saveConfig', config),
  getMonitorStatus: () => ipcRenderer.invoke('monitor:getStatus'),
  runMonitorNow: () => ipcRenderer.invoke('monitor:runNow'),
  onDeviceStatusChanged: (callback: (data: unknown) => void) => {
    const listener = (_event: unknown, data: unknown) => callback(data);
    ipcRenderer.on('monitor:deviceStatusChanged', listener);
    return () => ipcRenderer.removeListener('monitor:deviceStatusChanged', listener);
  },
  // 原始报文调试配置
  getRawLogConfig: () => ipcRenderer.invoke('rawlog:getConfig'),
  updateRawLogConfig: (config: unknown) => ipcRenderer.invoke('rawlog:updateConfig', config),
  selectDirectory: () => ipcRenderer.invoke('dialog:selectDirectory'),
  // 设备性能监控
  getPerformanceConfig: () => ipcRenderer.invoke('perf:getConfig'),
  savePerformanceConfig: (config: unknown) => ipcRenderer.invoke('perf:saveConfig', config),
  getPerformanceHistory: (deviceId: number, limit?: number) => ipcRenderer.invoke('perf:getHistory', deviceId, limit),
  samplePerformanceNow: (deviceId?: number) => ipcRenderer.invoke('perf:sampleNow', deviceId),
  // 接口流量监控
  getTrafficConfig: () => ipcRenderer.invoke('traffic:getConfig'),
  saveTrafficConfig: (config: unknown) => ipcRenderer.invoke('traffic:saveConfig', config),
  getTrafficHistory: (deviceId: number, limit?: number) => ipcRenderer.invoke('traffic:getHistory', deviceId, limit),
  sampleTrafficNow: (deviceId?: number) => ipcRenderer.invoke('traffic:sampleNow', deviceId),
});
