import React, { useState, useEffect } from 'react';
import type { MonitorConfig, MonitorStatus, PerformanceConfig, TrafficConfig } from '../types/global';
import './Settings.css';

type TabKey = 'service' | 'alert' | 'monitor' | 'app' | 'eventtype' | 'debug';

const TABS: { key: TabKey; label: string }[] = [
  { key: 'service', label: '服务监听' },
  { key: 'alert', label: '告警通知' },
  { key: 'monitor', label: '设备监测' },
  { key: 'eventtype', label: '事件类型' },
  { key: 'debug', label: '调试工具' },
  { key: 'app', label: '应用设置' },
];

const Settings: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabKey>('service');

  const [trapPort, setTrapPort] = useState('162');
  const [trapRunning, setTrapRunning] = useState(false);
  const [syslogPort, setSyslogPort] = useState('514');
  const [syslogRunning, setSyslogRunning] = useState(false);
  const [alertSound, setAlertSound] = useState(true);
  const [alertFlash, setAlertFlash] = useState(true);
  const [autoClose, setAutoClose] = useState(false);
  const [autoCloseSeconds, setAutoCloseSeconds] = useState('30');
  // 各威胁等级是否弹窗（低/中/高/严重）
  const [popupLow, setPopupLow] = useState(true);
  const [popupMedium, setPopupMedium] = useState(true);
  const [popupHigh, setPopupHigh] = useState(true);
  const [popupCritical, setPopupCritical] = useState(true);
  const [trayMinimize, setTrayMinimize] = useState(true);
  const [version, setVersion] = useState('1.0.0');
  const [syslogLogs, setSyslogLogs] = useState<Array<{ time: string; source: string; content: string; isThreat: boolean }>>([]);
  const [rawLogEnabled, setRawLogEnabled] = useState(false);
  const [rawLogSnmp, setRawLogSnmp] = useState(true);
  const [rawLogSyslog, setRawLogSyslog] = useState(true);
  const [rawLogDir, setRawLogDir] = useState('');
  // 设备离线监测
  const [monitorEnabled, setMonitorEnabled] = useState(true);
  const [monitorInterval, setMonitorInterval] = useState('60');
  const [monitorFailThreshold, setMonitorFailThreshold] = useState('3');
  const [monitorSeverity, setMonitorSeverity] = useState('high');
  const [monitorRecoverNotify, setMonitorRecoverNotify] = useState(true);
  const [monitorStatus, setMonitorStatus] = useState<MonitorStatus | null>(null);
  const [monitorLoading, setMonitorLoading] = useState(false);
  // 设备性能监控（CPU/内存）
  const [perfEnabled, setPerfEnabled] = useState(true);
  const [perfInterval, setPerfInterval] = useState('300');
  const [perfCpuThreshold, setPerfCpuThreshold] = useState('90');
  const [perfMemThreshold, setPerfMemThreshold] = useState('90');
  // 接口流量监控
  const [trafficEnabled, setTrafficEnabled] = useState(true);
  const [trafficInterval, setTrafficInterval] = useState('300');
  // 设备状态列表：默认折叠，只显示摘要
  const [showDeviceList, setShowDeviceList] = useState(false);
  const [deviceFilter, setDeviceFilter] = useState<'all' | 'online' | 'offline'>('all');
  // 数据备份与恢复
  const [dataOpLoading, setDataOpLoading] = useState(false);
  const [dataOpMsg, setDataOpMsg] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);

  // 导出数据为备份文件
  const handleExportData = async () => {
    try {
      setDataOpLoading(true);
      setDataOpMsg(null);
      const result = await window.electronAPI.exportData();
      if (!result || result.canceled) {
        setDataOpMsg({ type: 'info', text: '已取消导出' });
      } else if (result.success) {
        setDataOpMsg({
          type: 'success',
          text: `导出成功：${result.filePath}（安全事件 ${result.stats?.events ?? 0} 条，设备 ${result.stats?.devices ?? 0} 台）`,
        });
      } else {
        setDataOpMsg({ type: 'error', text: result.message || '导出失败' });
      }
    } catch (err: any) {
      console.error('导出数据失败:', err);
      setDataOpMsg({ type: 'error', text: '导出失败：' + (err?.message || '未知错误') });
    } finally {
      setDataOpLoading(false);
    }
  };

  // 从备份文件导入数据（合并方式，保留现有数据）
  const handleImportData = async () => {
    if (!window.confirm('导入将合并备份文件中的数据。已有数据将保留，相同 ID 的记录会被备份数据覆盖。\n\n确定继续吗？')) {
      return;
    }
    try {
      setDataOpLoading(true);
      setDataOpMsg(null);
      const result = await window.electronAPI.importData();
      if (!result || result.canceled) {
        setDataOpMsg({ type: 'info', text: '已取消导入' });
      } else if (result.success) {
        setDataOpMsg({
          type: 'success',
          text: `导入成功：合并安全事件 ${result.stats?.events ?? 0} 条，设备 ${result.stats?.devices ?? 0} 台`,
        });
      } else {
        setDataOpMsg({ type: 'error', text: result.message || '导入失败' });
      }
    } catch (err: any) {
      console.error('导入数据失败:', err);
      setDataOpMsg({ type: 'error', text: '导入失败：' + (err?.message || '未知错误') });
    } finally {
      setDataOpLoading(false);
    }
  };

  // 用户归类规则管理
  const [userRules, setUserRules] = useState<Array<{ id: number; vendor: string; feature: string; category: string; updated_at: string }>>([]);
  const [rulesMsg, setRulesMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const loadUserRules = async () => {
    try {
      const res = await window.electronAPI.getUserClassifyRules();
      if (res.success) setUserRules(res.rules);
    } catch (err) {
      console.error('加载归类规则失败:', err);
    }
  };

  const handleDeleteUserRule = async (ruleId: number, feature: string) => {
    if (!window.confirm(`确定删除规则"${feature}"吗？删除后同类威胁将不再自动归入该类型。`)) return;
    try {
      const res = await window.electronAPI.deleteUserClassifyRule(ruleId);
      if (res.success) {
        setRulesMsg({ type: 'success', text: '已删除规则' });
        loadUserRules();
      } else {
        setRulesMsg({ type: 'error', text: '删除失败' });
      }
    } catch (err) {
      console.error('删除规则失败:', err);
      setRulesMsg({ type: 'error', text: '删除失败：' + (err as Error)?.message });
    }
  };

  // 自定义事件类型管理
  const [eventTypes, setEventTypes] = useState<Array<{ id: number; name: string; feature_keywords: string; default_severity: string; is_builtin: number }>>([]);
  const [typeMsg, setTypeMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  // 行内编辑状态
  const [editingTypeId, setEditingTypeId] = useState<number | null>(null); // null=不在编辑
  const [addingNew, setAddingNew] = useState(false); // 是否在新增行
  const [typeFormName, setTypeFormName] = useState('');
  const [typeFormKeywords, setTypeFormKeywords] = useState('');
  const [typeFormSeverity, setTypeFormSeverity] = useState('medium');

  const loadEventTypes = async () => {
    try {
      const res = await window.electronAPI.listEventTypes();
      if (res.success) setEventTypes(res.types);
    } catch (err) {
      console.error('加载事件类型失败:', err);
    }
  };

  // 开始新增（顶部显示可编辑行）
  const startCreateType = () => {
    setAddingNew(true);
    setEditingTypeId(null);
    setTypeFormName('');
    setTypeFormKeywords('');
    setTypeFormSeverity('medium');
    setTypeMsg(null);
  };

  // 开始行内编辑某条类型
  const startInlineEdit = (t: { id: number; name: string; feature_keywords: string; default_severity: string }) => {
    let keywords: string[] = [];
    try {
      keywords = JSON.parse(t.feature_keywords || '[]');
    } catch { /* 忽略解析错误 */ }
    setAddingNew(false);
    setEditingTypeId(t.id);
    setTypeFormName(t.name);
    setTypeFormKeywords(keywords.join('，'));
    setTypeFormSeverity(t.default_severity || 'medium');
    setTypeMsg(null);
  };

  // 取消行内编辑
  const cancelInlineEdit = () => {
    setEditingTypeId(null);
    setAddingNew(false);
    setTypeFormName('');
    setTypeFormKeywords('');
    setTypeFormSeverity('medium');
  };

  // 提交行内新增/编辑
  const handleSaveType = async () => {
    const name = typeFormName.trim();
    if (!name) {
      setTypeMsg({ type: 'error', text: '请输入事件类型名称' });
      return;
    }
    const keywords = typeFormKeywords
      .split(/[,，;；\s]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    try {
      const payload = { name, feature_keywords: keywords, default_severity: typeFormSeverity };
      const res = editingTypeId
        ? await window.electronAPI.updateEventType({ id: editingTypeId, ...payload })
        : await window.electronAPI.createEventType(payload);
      if (res.success) {
        setTypeMsg({ type: 'success', text: editingTypeId ? '已保存修改' : '已新增事件类型' });
        cancelInlineEdit();
        loadEventTypes();
      } else {
        setTypeMsg({ type: 'error', text: res.message || '保存失败' });
      }
    } catch (err) {
      console.error('保存事件类型失败:', err);
      setTypeMsg({ type: 'error', text: '保存失败：' + (err as Error)?.message });
    }
  };

  // 删除事件类型
  const handleDeleteType = async (t: { id: number; name: string; is_builtin: number }) => {
    if (t.is_builtin === 1) {
      setTypeMsg({ type: 'error', text: '内置类型不可删除' });
      return;
    }
    if (!window.confirm(`确定删除事件类型"${t.name}"吗？`)) return;
    try {
      const res = await window.electronAPI.deleteEventType(t.id);
      if (res.success) {
        setTypeMsg({ type: 'success', text: '已删除事件类型' });
        if (editingTypeId === t.id) {
          cancelInlineEdit();
        }
        loadEventTypes();
      } else {
        setTypeMsg({ type: 'error', text: res.message || '删除失败' });
      }
    } catch (err) {
      console.error('删除事件类型失败:', err);
      setTypeMsg({ type: 'error', text: '删除失败：' + (err as Error)?.message });
    }
  };

  // 打开设置时加载用户归类规则与事件类型
  useEffect(() => {
    loadUserRules();
    loadEventTypes();
  }, []);

  const saveMonitorConfig = (patch: Partial<MonitorConfig>) => {
    window.electronAPI?.saveMonitorConfig({
      enabled: patch.enabled ?? monitorEnabled,
      interval: patch.interval ?? Math.max(10, Number(monitorInterval) || 60),
      failThreshold: patch.failThreshold ?? Math.max(1, Number(monitorFailThreshold) || 3),
      severity: (patch.severity ?? monitorSeverity) as MonitorConfig['severity'],
      recoverNotify: patch.recoverNotify ?? monitorRecoverNotify,
    });
  };

  const savePerfConfig = (patch: Partial<PerformanceConfig>) => {
    window.electronAPI?.savePerformanceConfig({
      enabled: patch.enabled ?? perfEnabled,
      interval: patch.interval ?? Math.max(30, Number(perfInterval) || 300),
      cpuThreshold: patch.cpuThreshold ?? Math.min(100, Math.max(1, Number(perfCpuThreshold) || 90)),
      memThreshold: patch.memThreshold ?? Math.min(100, Math.max(1, Number(perfMemThreshold) || 90)),
    });
  };

  const saveTrafficConfig = (patch: Partial<TrafficConfig>) => {
    window.electronAPI?.saveTrafficConfig({
      enabled: patch.enabled ?? trafficEnabled,
      interval: patch.interval ?? Math.max(60, Number(trafficInterval) || 300),
    });
  };

  const saveRawLogConfig = (patch: Partial<{ enabled: boolean; snmpEnabled: boolean; syslogEnabled: boolean; baseDir: string }>) => {
    window.electronAPI?.updateRawLogConfig({
      enabled: patch.enabled ?? rawLogEnabled,
      snmpEnabled: patch.snmpEnabled ?? rawLogSnmp,
      syslogEnabled: patch.syslogEnabled ?? rawLogSyslog,
      baseDir: patch.baseDir ?? rawLogDir,
    });
  };

  const loadSyslogLogs = async () => {
    try {
      const logs = await window.electronAPI.getSyslogLogs();
      setSyslogLogs(logs);
    } catch (err) {
      console.error(err);
    }
  };

  React.useEffect(() => {
    window.electronAPI?.getAppVersion().then(v => setVersion(v));
    window.electronAPI?.getTrapStatus().then(s => {
      setTrapRunning(s.status === 'running');
      setTrapPort(String(s.port));
    });
    window.electronAPI?.getSyslogStatus().then(s => {
      setSyslogRunning(s.status === 'running');
      setSyslogPort(String(s.port));
    });
    window.electronAPI?.getAlertConfig().then(c => {
      setAutoClose(c.autoClose);
      setAutoCloseSeconds(String(c.seconds));
      setPopupLow(c.popupLow);
      setPopupMedium(c.popupMedium);
      setPopupHigh(c.popupHigh);
      setPopupCritical(c.popupCritical);
    });
    window.electronAPI?.getRawLogConfig().then(c => {
      setRawLogEnabled(c.enabled);
      setRawLogSnmp(c.snmpEnabled);
      setRawLogSyslog(c.syslogEnabled);
      setRawLogDir(c.baseDir);
    });
    window.electronAPI?.getMonitorConfig().then(c => {
      setMonitorEnabled(c.enabled);
      setMonitorInterval(String(c.interval));
      setMonitorFailThreshold(String(c.failThreshold));
      setMonitorSeverity(c.severity);
      setMonitorRecoverNotify(c.recoverNotify);
    });
    window.electronAPI?.getPerformanceConfig().then(c => {
      setPerfEnabled(c.enabled);
      setPerfInterval(String(c.interval));
      setPerfCpuThreshold(String(c.cpuThreshold));
      setPerfMemThreshold(String(c.memThreshold));
    });
    window.electronAPI?.getTrafficConfig().then(c => {
      setTrafficEnabled(c.enabled);
      setTrafficInterval(String(c.interval));
    });
    const loadMonitorStatus = () => window.electronAPI?.getMonitorStatus().then(s => setMonitorStatus(s));
    loadMonitorStatus();
    const monitorTimer = setInterval(loadMonitorStatus, 5000);
    return () => {
      clearInterval(monitorTimer);
    };
  }, []);

  // 切换到调试标签时才加载 syslog 日志，避免后台频繁轮询
  React.useEffect(() => {
    if (activeTab === 'debug') {
      loadSyslogLogs();
      const timer = setInterval(loadSyslogLogs, 2000);
      return () => clearInterval(timer);
    }
  }, [activeTab]);

  const handleToggleTrap = async () => {
    try {
      if (trapRunning) {
        await window.electronAPI.stopTrapListener();
        setTrapRunning(false);
      } else {
        await window.electronAPI.startTrapListener(Number(trapPort));
        setTrapRunning(true);
      }
    } catch (err) {
      console.error('Failed to toggle trap:', err);
    }
  };

  const handleToggleSyslog = async () => {
    try {
      if (syslogRunning) {
        await window.electronAPI.stopSyslog();
        setSyslogRunning(false);
      } else {
        await window.electronAPI.startSyslog(Number(syslogPort));
        setSyslogRunning(true);
      }
    } catch (err) {
      console.error('Failed to toggle syslog:', err);
    }
  };

  const onlineCount = monitorStatus?.devices.filter(d => d.status === 'online').length ?? 0;
  const offlineCount = monitorStatus?.devices.filter(d => d.status === 'offline').length ?? 0;
  const totalDevices = monitorStatus?.devices.length ?? 0;

  const filteredDevices = monitorStatus?.devices.filter(d =>
    deviceFilter === 'all' ? true : d.status === deviceFilter
  ) ?? [];

  return (
    <div className="settings-page">
      <div className="page-header">
        <h1>系统设置</h1>
      </div>

      {/* 标签页导航 */}
      <div className="settings-tabs">
        {TABS.map(tab => (
          <button
            key={tab.key}
            className={`settings-tab ${activeTab === tab.key ? 'settings-tab-active' : ''}`}
            onClick={() => setActiveTab(tab.key)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="settings-tab-content">
        {/* ==================== 服务监听 ==================== */}
        {activeTab === 'service' && (
          <>
            <div className="card" style={{ marginBottom: 20 }}>
              <div className="card-header">SNMP Trap 接收设置</div>
              <div className="card-body">
                <div className="setting-row">
                  <div className="setting-info">
                    <div className="setting-label">监听端口</div>
                    <div className="setting-desc">SNMP Trap 默认使用 UDP 162 端口</div>
                  </div>
                  <div className="setting-control">
                    <input className="input" type="number" value={trapPort}
                      onChange={e => setTrapPort(e.target.value)}
                      style={{ width: 120 }} disabled={trapRunning} />
                  </div>
                </div>
                <div className="setting-row">
                  <div className="setting-info">
                    <div className="setting-label">Trap 接收服务</div>
                    <div className="setting-desc">
                      状态：{trapRunning ? '运行中' : '已停止'}
                    </div>
                  </div>
                  <div className="setting-control">
                    <button
                      className={`btn ${trapRunning ? 'btn-danger' : 'btn-primary'}`}
                      onClick={handleToggleTrap}
                    >
                      {trapRunning ? '停止监听' : '启动监听'}
                    </button>
                  </div>
                </div>
                <div className="setting-row">
                  <div className="setting-info">
                    <div className="setting-label">发送测试告警</div>
                    <div className="setting-desc">
                      模拟一条安全告警，用于验证告警弹窗和事件记录
                    </div>
                  </div>
                  <div className="setting-control">
                    <button
                      className="btn btn-secondary"
                      onClick={async () => { await window.electronAPI.sendTestAlert(); }}
                    >
                      发送测试告警
                    </button>
                  </div>
                </div>
              </div>
            </div>

            <div className="card" style={{ marginBottom: 20 }}>
              <div className="card-header">Syslog 日志接收设置</div>
              <div className="card-body">
                <div className="setting-row">
                  <div className="setting-info">
                    <div className="setting-label">监听端口</div>
                    <div className="setting-desc">Syslog 默认使用 UDP 514 端口（华为防火墙威胁日志）</div>
                  </div>
                  <div className="setting-control">
                    <input className="input" type="number" value={syslogPort}
                      onChange={e => setSyslogPort(e.target.value)}
                      style={{ width: 120 }} disabled={syslogRunning} />
                  </div>
                </div>
                <div className="setting-row">
                  <div className="setting-info">
                    <div className="setting-label">Syslog 接收服务</div>
                    <div className="setting-desc">
                      状态：{syslogRunning ? '运行中' : '已停止'}
                    </div>
                  </div>
                  <div className="setting-control">
                    <button
                      className={`btn ${syslogRunning ? 'btn-danger' : 'btn-primary'}`}
                      onClick={handleToggleSyslog}
                    >
                      {syslogRunning ? '停止监听' : '启动监听'}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </>
        )}

        {/* ==================== 告警通知 ==================== */}
        {activeTab === 'alert' && (
          <div className="card" style={{ marginBottom: 20 }}>
            <div className="card-header">告警通知设置</div>
            <div className="card-body">
              <div className="setting-row">
                <div className="setting-info">
                  <div className="setting-label">声音提示</div>
                  <div className="setting-desc">收到告警时播放提示音</div>
                </div>
                <div className="setting-control">
                  <label className="toggle">
                    <input type="checkbox" checked={alertSound}
                      onChange={e => setAlertSound(e.target.checked)} />
                    <span className="toggle-slider"></span>
                  </label>
                </div>
              </div>
              <div className="setting-row">
                <div className="setting-info">
                  <div className="setting-label">闪烁效果</div>
                  <div className="setting-desc">告警弹窗边框闪烁提醒</div>
                </div>
                <div className="setting-control">
                  <label className="toggle">
                    <input type="checkbox" checked={alertFlash}
                      onChange={e => setAlertFlash(e.target.checked)} />
                    <span className="toggle-slider"></span>
                  </label>
                </div>
              </div>
              <div className="setting-row">
                <div className="setting-info">
                  <div className="setting-label">自动关闭弹窗</div>
                  <div className="setting-desc">告警弹窗在指定秒数后自动关闭</div>
                </div>
                <div className="setting-control">
                  <label className="toggle">
                    <input type="checkbox" checked={autoClose}
                      onChange={e => {
                        setAutoClose(e.target.checked);
                        window.electronAPI?.saveAlertConfig({
                          autoClose: e.target.checked,
                          seconds: Math.max(1, Number(autoCloseSeconds) || 30),
                        });
                      }} />
                    <span className="toggle-slider"></span>
                  </label>
                </div>
              </div>
              {autoClose && (
                <div className="setting-row">
                  <div className="setting-info">
                    <div className="setting-label">自动关闭时间</div>
                    <div className="setting-desc">弹窗显示多少秒后自动关闭（1-600秒）</div>
                  </div>
                  <div className="setting-control">
                    <input className="input" type="number" value={autoCloseSeconds}
                      onChange={e => {
                        const val = e.target.value;
                        setAutoCloseSeconds(val);
                        const secs = Math.max(1, Number(val) || 30);
                        window.electronAPI?.saveAlertConfig({ autoClose: true, seconds: secs });
                      }}
                      style={{ width: 100 }} min="1" max="600" />
                    <span style={{ marginLeft: 8, color: 'var(--color-text-secondary)', fontSize: 13 }}>秒</span>
                  </div>
                </div>
              )}

              <div className="setting-section-title">按威胁程度控制弹窗</div>
              <div className="setting-desc" style={{ marginBottom: 8 }}>
                可单独控制各威胁等级是否弹窗提醒，关闭后该等级的告警仅记录，不弹窗、不播放提示音
              </div>
              {[
                { key: 'critical', label: '严重告警', desc: 'Critical 级别', val: popupCritical, set: setPopupCritical },
                { key: 'high', label: '高危告警', desc: 'High 级别', val: popupHigh, set: setPopupHigh },
                { key: 'medium', label: '中等告警', desc: 'Medium 级别', val: popupMedium, set: setPopupMedium },
                { key: 'low', label: '低危告警', desc: 'Low 级别', val: popupLow, set: setPopupLow },
              ].map(item => (
                <div key={item.key} className="severity-popup-row">
                  <div className="setting-info">
                    <div className="setting-label"><span className={`sev-dot sev-${item.key}`}></span>{item.label}</div>
                    <div className="setting-desc">{item.desc}</div>
                  </div>
                  <div className="setting-control">
                    <label className="toggle">
                      <input type="checkbox" checked={item.val}
                        onChange={e => {
                          item.set(e.target.checked);
                          window.electronAPI?.saveAlertConfig({
                            autoClose, seconds: Math.max(1, Number(autoCloseSeconds) || 30),
                            [`popup${item.key.charAt(0).toUpperCase()}${item.key.slice(1)}`]: e.target.checked,
                          });
                        }} />
                      <span className="toggle-slider"></span>
                    </label>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ==================== 设备监测 ==================== */}
        {activeTab === 'monitor' && (
          <>
          <div className="card" style={{ marginBottom: 20 }}>
            <div className="card-header">设备离线监测</div>
            <div className="card-body">
              <div className="setting-row">
                <div className="setting-info">
                  <div className="setting-label">启用离线监测</div>
                  <div className="setting-desc">定时探测设备在线状态，离线时触发告警弹窗</div>
                </div>
                <div className="setting-control">
                  <label className="toggle">
                    <input type="checkbox" checked={monitorEnabled}
                      onChange={e => {
                        setMonitorEnabled(e.target.checked);
                        saveMonitorConfig({ enabled: e.target.checked });
                      }} />
                    <span className="toggle-slider"></span>
                  </label>
                </div>
              </div>
              <div className="setting-row">
                <div className="setting-info">
                  <div className="setting-label">轮询间隔</div>
                  <div className="setting-desc">每隔多少秒探测一次设备（10-3600 秒）</div>
                </div>
                <div className="setting-control">
                  <input className="input" type="number" value={monitorInterval}
                    onChange={e => {
                      setMonitorInterval(e.target.value);
                      saveMonitorConfig({ interval: Math.max(10, Number(e.target.value) || 60) });
                    }}
                    style={{ width: 100 }} min="10" max="3600" />
                  <span style={{ marginLeft: 8, color: 'var(--color-text-secondary)', fontSize: 13 }}>秒</span>
                </div>
              </div>
              <div className="setting-row">
                <div className="setting-info">
                  <div className="setting-label">离线判定阈值</div>
                  <div className="setting-desc">连续探测失败多少次判定设备离线（防止偶发超时误报）</div>
                </div>
                <div className="setting-control">
                  <input className="input" type="number" value={monitorFailThreshold}
                    onChange={e => {
                      setMonitorFailThreshold(e.target.value);
                      saveMonitorConfig({ failThreshold: Math.max(1, Number(e.target.value) || 3) });
                    }}
                    style={{ width: 100 }} min="1" max="20" />
                  <span style={{ marginLeft: 8, color: 'var(--color-text-secondary)', fontSize: 13 }}>次</span>
                </div>
              </div>
              <div className="setting-row">
                <div className="setting-info">
                  <div className="setting-label">离线告警等级</div>
                  <div className="setting-desc">设备离线时使用的威胁等级</div>
                </div>
                <div className="setting-control">
                  <select
                    className="input"
                    value={monitorSeverity}
                    onChange={e => {
                      setMonitorSeverity(e.target.value);
                      saveMonitorConfig({ severity: e.target.value as MonitorConfig['severity'] });
                    }}
                    style={{ width: 120 }}
                  >
                    <option value="critical">严重</option>
                    <option value="high">高危</option>
                    <option value="medium">中等</option>
                    <option value="low">低危</option>
                  </select>
                </div>
              </div>
              <div className="setting-row">
                <div className="setting-info">
                  <div className="setting-label">恢复在线通知</div>
                  <div className="setting-desc">设备从离线恢复在线时发送一条低危通知</div>
                </div>
                <div className="setting-control">
                  <label className="toggle">
                    <input type="checkbox" checked={monitorRecoverNotify}
                      onChange={e => {
                        setMonitorRecoverNotify(e.target.checked);
                        saveMonitorConfig({ recoverNotify: e.target.checked });
                      }} />
                    <span className="toggle-slider"></span>
                  </label>
                </div>
              </div>
              <div className="setting-row">
                <div className="setting-info">
                  <div className="setting-label">立即执行一轮</div>
                  <div className="setting-desc">
                    手动触发一次探测，立即检查所有设备在线状态
                    {monitorStatus?.lastRunAt && (
                      <span style={{ display: 'block', marginTop: 4, fontSize: 12, color: 'var(--color-text-secondary)' }}>
                        上次执行：{new Date(monitorStatus.lastRunAt).toLocaleTimeString('zh-CN')}
                      </span>
                    )}
                  </div>
                </div>
                <div className="setting-control">
                  <button className="btn btn-secondary" disabled={monitorLoading}
                    onClick={async () => {
                      setMonitorLoading(true);
                      try {
                        await window.electronAPI?.runMonitorNow();
                        const s = await window.electronAPI?.getMonitorStatus();
                        setMonitorStatus(s);
                      } catch (err) {
                        console.error('执行监测失败:', err);
                      } finally {
                        setMonitorLoading(false);
                      }
                    }}>
                    {monitorLoading ? '探测中…' : '立即执行'}
                  </button>
                </div>
              </div>

              {/* 设备状态摘要 + 可折叠列表 */}
              <div className="monitor-summary">
                <div className="monitor-summary-stats">
                  <span className="monitor-summary-stat">
                    设备总数 <strong>{totalDevices}</strong>
                  </span>
                  <span className="monitor-summary-stat stat-online">
                    在线 <strong>{onlineCount}</strong>
                  </span>
                  <span className="monitor-summary-stat stat-offline">
                    离线 <strong>{offlineCount}</strong>
                  </span>
                </div>
                <button
                  className="btn btn-secondary btn-sm"
                  onClick={() => setShowDeviceList(v => !v)}
                >
                  {showDeviceList ? '收起设备列表' : '展开设备列表'}
                </button>
              </div>

              {showDeviceList && (
                <div className="monitor-status-list">
                  <div className="monitor-filter-bar">
                    {(['all', 'online', 'offline'] as const).map(f => (
                      <button
                        key={f}
                        className={`monitor-filter-btn ${deviceFilter === f ? 'monitor-filter-active' : ''}`}
                        onClick={() => setDeviceFilter(f)}
                      >
                        {f === 'all' ? '全部' : f === 'online' ? '在线' : '离线'}
                      </button>
                    ))}
                  </div>
                  <div className="monitor-status-scroll">
                    {filteredDevices.length === 0 ? (
                      <div className="monitor-status-empty">暂无设备</div>
                    ) : (
                      filteredDevices.map(d => (
                        <div key={d.id} className="monitor-status-item">
                          <span className={`sev-dot ${d.status === 'online' ? 'sev-online' : d.status === 'offline' ? 'sev-offline' : 'sev-unknown'}`}></span>
                          <span className="monitor-status-name">{d.name}</span>
                          <span className="monitor-status-ip">{d.ip}</span>
                          <span className={`monitor-status-badge ${d.status === 'online' ? 'badge-online' : d.status === 'offline' ? 'badge-offline' : 'badge-unknown'}`}>
                            {d.status === 'online' ? '在线' : d.status === 'offline' ? '离线' : '未知'}
                          </span>
                          {d.failCount > 0 && d.status !== 'online' && (
                            <span className="monitor-status-fail">连续失败 {d.failCount} 次</span>
                          )}
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="card" style={{ marginTop: 20 }}>
            <div className="card-header">性能监控（CPU / 内存）</div>
            <div className="card-body">
              <div className="setting-row">
                <div className="setting-info">
                  <div className="setting-label">启用性能监控</div>
                  <div className="setting-desc">通过 SNMP 定时采集设备 CPU 和内存使用率</div>
                </div>
                <div className="setting-control">
                  <label className="toggle">
                    <input type="checkbox" checked={perfEnabled}
                      onChange={e => {
                        setPerfEnabled(e.target.checked);
                        savePerfConfig({ enabled: e.target.checked });
                      }} />
                    <span className="toggle-slider"></span>
                  </label>
                </div>
              </div>

              <div className="setting-row">
                <div className="setting-info">
                  <div className="setting-label">采样间隔</div>
                  <div className="setting-desc">每隔多少秒采集一次性能数据（30-3600 秒）</div>
                </div>
                <div className="setting-control">
                  <input className="input" type="number" value={perfInterval}
                    onChange={e => {
                      setPerfInterval(e.target.value);
                      savePerfConfig({ interval: Math.max(30, Number(e.target.value) || 300) });
                    }}
                    style={{ width: 100 }} min="30" max="3600" />
                  <span style={{ marginLeft: 8, color: 'var(--color-text-secondary)', fontSize: 13 }}>秒</span>
                </div>
              </div>

              <div className="setting-row">
                <div className="setting-info">
                  <div className="setting-label">CPU 告警阈值</div>
                  <div className="setting-desc">CPU 使用率超过该值时触发告警</div>
                </div>
                <div className="setting-control">
                  <input className="input" type="number" value={perfCpuThreshold}
                    onChange={e => {
                      setPerfCpuThreshold(e.target.value);
                      savePerfConfig({ cpuThreshold: Math.min(100, Math.max(1, Number(e.target.value) || 90)) });
                    }}
                    style={{ width: 100 }} min="1" max="100" />
                  <span style={{ marginLeft: 8, color: 'var(--color-text-secondary)', fontSize: 13 }}>%</span>
                </div>
              </div>

              <div className="setting-row">
                <div className="setting-info">
                  <div className="setting-label">内存告警阈值</div>
                  <div className="setting-desc">内存使用率超过该值时触发告警</div>
                </div>
                <div className="setting-control">
                  <input className="input" type="number" value={perfMemThreshold}
                    onChange={e => {
                      setPerfMemThreshold(e.target.value);
                      savePerfConfig({ memThreshold: Math.min(100, Math.max(1, Number(e.target.value) || 90)) });
                    }}
                    style={{ width: 100 }} min="1" max="100" />
                  <span style={{ marginLeft: 8, color: 'var(--color-text-secondary)', fontSize: 13 }}>%</span>
                </div>
              </div>
            </div>
          </div>

          <div className="card" style={{ marginTop: 20 }}>
            <div className="card-header">流量监控（接口收发速率）</div>
            <div className="card-body">
              <div className="setting-row">
                <div className="setting-info">
                  <div className="setting-label">启用流量监控</div>
                  <div className="setting-desc">通过 SNMP 定时采集设备接口收发速率，绘制流量趋势</div>
                </div>
                <div className="setting-control">
                  <label className="toggle">
                    <input type="checkbox" checked={trafficEnabled}
                      onChange={e => {
                        setTrafficEnabled(e.target.checked);
                        saveTrafficConfig({ enabled: e.target.checked });
                      }} />
                    <span className="toggle-slider"></span>
                  </label>
                </div>
              </div>

              <div className="setting-row">
                <div className="setting-info">
                  <div className="setting-label">采样间隔</div>
                  <div className="setting-desc">每隔多少秒采集一次流量数据（60-3600 秒）</div>
                </div>
                <div className="setting-control">
                  <input className="input" type="number" value={trafficInterval}
                    onChange={e => {
                      setTrafficInterval(e.target.value);
                      saveTrafficConfig({ interval: Math.max(60, Number(e.target.value) || 300) });
                    }}
                    style={{ width: 100 }} min="60" max="3600" />
                  <span style={{ marginLeft: 8, color: 'var(--color-text-secondary)', fontSize: 13 }}>秒</span>
                </div>
              </div>
            </div>
          </div>
          </>
        )}

        {/* ==================== 应用设置 ==================== */}
        {activeTab === 'app' && (
          <>
            <div className="card" style={{ marginBottom: 20 }}>
              <div className="card-header">应用设置</div>
              <div className="card-body">
                <div className="setting-row">
                  <div className="setting-info">
                    <div className="setting-label">最小化到托盘</div>
                    <div className="setting-desc">关闭窗口时最小化到系统托盘</div>
                  </div>
                  <div className="setting-control">
                    <label className="toggle">
                      <input type="checkbox" checked={trayMinimize}
                        onChange={e => setTrayMinimize(e.target.checked)} />
                      <span className="toggle-slider"></span>
                    </label>
                  </div>
                </div>
              </div>
            </div>

            <div className="card" style={{ marginBottom: 20 }}>
              <div className="card-header">数据备份与恢复</div>
              <div className="card-body">
                <div className="setting-row">
                  <div className="setting-info">
                    <div className="setting-label">导出应用数据</div>
                    <div className="setting-desc">将安全事件、设备、配置等数据导出为 JSON 备份文件，可随时保存到任意位置</div>
                  </div>
                  <div className="setting-control">
                    <button
                      className="btn btn-primary btn-sm"
                      onClick={handleExportData}
                      disabled={dataOpLoading}
                    >
                      {dataOpLoading ? '处理中...' : '导出数据'}
                    </button>
                  </div>
                </div>

                <div className="setting-row">
                  <div className="setting-info">
                    <div className="setting-label">导入应用数据</div>
                    <div className="setting-desc">从备份文件恢复数据（合并导入，保留现有数据，相同 ID 以备份为准）</div>
                  </div>
                  <div className="setting-control">
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={handleImportData}
                      disabled={dataOpLoading}
                    >
                      {dataOpLoading ? '处理中...' : '导入数据'}
                    </button>
                  </div>
                </div>

                {dataOpMsg && (
                  <div
                    className={`data-op-msg ${
                      dataOpMsg.type === 'success' ? 'data-op-success' :
                      dataOpMsg.type === 'error' ? 'data-op-error' : 'data-op-info'
                    }`}
                    style={{ marginTop: 10, fontSize: 12 }}
                  >
                    {dataOpMsg.text}
                  </div>
                )}
              </div>
            </div>
          </>
        )}

        {/* ==================== 事件类型 ==================== */}
        {activeTab === 'eventtype' && (
          <>
            <div className="card" style={{ marginBottom: 20 }}>
              <div className="card-header">自定义事件类型</div>
              <div className="card-body">
                <div className="setting-row">
                  <div className="setting-info">
                    <div className="setting-label">事件类型管理</div>
                    <div className="setting-desc">
                      可新增、改名、删除事件类型，并为每种类型配置特征关键字（feature_keywords）与默认威胁程度。<br />
                      填写特征关键字后，<b>新收到的威胁报文若包含该关键字，将自动归入此类型</b>（关键词级匹配，不区分大小写），无需再手动归类。
                    </div>
                  </div>
                  <div className="setting-control">
                    <button className="btn btn-primary btn-sm" onClick={startCreateType}>
                      + 新增类型
                    </button>
                  </div>
                </div>

                {/* 新增行（行内编辑） */}
                {addingNew && (
                  <div
                    style={{
                      marginTop: 12,
                      display: 'grid',
                      gridTemplateColumns: '1fr 1fr 110px 80px',
                      gap: 8,
                      alignItems: 'center',
                      padding: 8,
                      border: '1px solid #dbeafe',
                      borderRadius: 6,
                      background: '#f0f7ff',
                      fontSize: 12,
                    }}
                  >
                    <input
                      className="input"
                      type="text"
                      placeholder="类型名称（如：挖矿）"
                      value={typeFormName}
                      onChange={(e) => setTypeFormName(e.target.value)}
                      autoFocus
                    />
                    <input
                      className="input"
                      type="text"
                      placeholder="特征关键字（逗号分隔）"
                      value={typeFormKeywords}
                      onChange={(e) => setTypeFormKeywords(e.target.value)}
                    />
                    <select
                      value={typeFormSeverity}
                      onChange={(e) => setTypeFormSeverity(e.target.value)}
                      style={{ fontSize: 12, padding: '4px 6px', borderRadius: 4, border: '1px solid #ccc' }}
                    >
                      <option value="critical">严重</option>
                      <option value="high">高危</option>
                      <option value="medium">中</option>
                      <option value="low">低</option>
                    </select>
                    <div style={{ display: 'flex', gap: 4 }}>
                      <button className="btn btn-primary btn-sm" onClick={handleSaveType}>
                        保存
                      </button>
                      <button className="btn btn-secondary btn-sm" onClick={cancelInlineEdit}>
                        取消
                      </button>
                    </div>
                  </div>
                )}

                {/* 类型列表 */}
                {eventTypes.length === 0 ? (
                  <div style={{ fontSize: 12, color: '#888', padding: '8px 0' }}>
                    暂无事件类型
                  </div>
                ) : (
                  <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse', marginTop: 12 }}>
                    <thead>
                      <tr style={{ textAlign: 'left', borderBottom: '1px solid #eee' }}>
                        <th style={{ padding: '6px 8px' }}>类型名称</th>
                        <th style={{ padding: '6px 8px' }}>特征关键字</th>
                        <th style={{ padding: '6px 8px' }}>默认威胁程度</th>
                        <th style={{ padding: '6px 8px' }}>类型</th>
                        <th style={{ padding: '6px 8px' }}>操作</th>
                      </tr>
                    </thead>
                    <tbody>
                      {eventTypes.map((t) => {
                        let keywords = '';
                        try {
                          keywords = JSON.parse(t.feature_keywords || '[]').join('，');
                        } catch { /* 忽略 */ }
                        const severityLabel = { critical: '严重', high: '高危', medium: '中', low: '低' }[t.default_severity] || '中';
                        const isEditing = editingTypeId === t.id;
                        // 行内编辑模式
                        if (isEditing) {
                          return (
                            <tr key={t.id} style={{ borderBottom: '1px solid #f5f5f5', background: '#f0f7ff' }}>
                              <td colSpan={5} style={{ padding: '6px 8px' }}>
                                <div
                                  style={{
                                    display: 'grid',
                                    gridTemplateColumns: '1fr 1fr 110px 100px',
                                    gap: 8,
                                    alignItems: 'center',
                                    fontSize: 12,
                                  }}
                                >
                                  <input
                                    className="input"
                                    type="text"
                                    value={typeFormName}
                                    onChange={(e) => setTypeFormName(e.target.value)}
                                    autoFocus
                                  />
                                  <input
                                    className="input"
                                    type="text"
                                    placeholder="特征关键字（逗号分隔）"
                                    value={typeFormKeywords}
                                    onChange={(e) => setTypeFormKeywords(e.target.value)}
                                  />
                                  <select
                                    value={typeFormSeverity}
                                    onChange={(e) => setTypeFormSeverity(e.target.value)}
                                    style={{ fontSize: 12, padding: '4px 6px', borderRadius: 4, border: '1px solid #ccc' }}
                                  >
                                    <option value="critical">严重</option>
                                    <option value="high">高危</option>
                                    <option value="medium">中</option>
                                    <option value="low">低</option>
                                  </select>
                                  <div style={{ display: 'flex', gap: 4 }}>
                                    <button className="btn btn-primary btn-sm" onClick={handleSaveType}>
                                      保存
                                    </button>
                                    <button className="btn btn-secondary btn-sm" onClick={cancelInlineEdit}>
                                      取消
                                    </button>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          );
                        }
                        // 普通显示模式：点击类型名称或编辑按钮进入行内编辑
                        return (
                          <tr
                            key={t.id}
                            style={{ borderBottom: '1px solid #f5f5f5', cursor: t.is_builtin === 1 ? 'pointer' : 'pointer' }}
                            onDoubleClick={() => startInlineEdit(t)}
                          >
                            <td
                              style={{ padding: '6px 8px' }}
                              onClick={() => startInlineEdit(t)}
                              title="点击编辑"
                            >
                              {t.name}
                            </td>
                            <td style={{ padding: '6px 8px', color: '#888' }}>{keywords || '-'}</td>
                            <td style={{ padding: '6px 8px' }}>{severityLabel}</td>
                            <td style={{ padding: '6px 8px' }}>{t.is_builtin === 1 ? '内置' : '自定义'}</td>
                            <td style={{ padding: '6px 8px', display: 'flex', gap: 6 }}>
                              <button className="btn btn-secondary btn-sm" onClick={() => startInlineEdit(t)}>
                                编辑
                              </button>
                              {t.is_builtin !== 1 && (
                                <button
                                  className="btn btn-danger btn-sm"
                                  onClick={() => handleDeleteType(t)}
                                >
                                  删除
                                </button>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                )}

                {typeMsg && (
                  <div
                    style={{
                      marginTop: 8,
                      fontSize: 12,
                      color: typeMsg.type === 'success' ? '#16a34a' : '#dc2626',
                    }}
                  >
                    {typeMsg.text}
                  </div>
                )}
              </div>
            </div>

            <div className="card" style={{ marginBottom: 20 }}>
              <div className="card-header">用户归类规则</div>
              <div className="card-body">
                <div className="setting-row">
                  <div className="setting-info">
                    <div className="setting-label">手动归类学习到的规则</div>
                    <div className="setting-desc">
                      这是你在<b>事件详情页手动归类</b>时学习的<b>签名级精确匹配</b>规则（记录厂商 + 签名特征，如同签名攻击自动归入所选类型）。<br />
                      优先级最高（&gt; 自定义类型特征关键字 &gt; 内置配置）。可在此查看或删除。
                    </div>
                  </div>
                  <div className="setting-control">
                    <button className="btn btn-secondary btn-sm" onClick={loadUserRules}>
                      刷新
                    </button>
                  </div>
                </div>

                {userRules.length === 0 ? (
                  <div style={{ fontSize: 12, color: '#888', padding: '8px 0' }}>
                    暂无用户归类规则
                  </div>
                ) : (
                  <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse', marginTop: 8 }}>
                    <thead>
                      <tr style={{ textAlign: 'left', borderBottom: '1px solid #eee' }}>
                        <th style={{ padding: '6px 8px' }}>威胁特征</th>
                        <th style={{ padding: '6px 8px' }}>厂商</th>
                        <th style={{ padding: '6px 8px' }}>归类类型</th>
                        <th style={{ padding: '6px 8px' }}>操作</th>
                      </tr>
                    </thead>
                    <tbody>
                      {userRules.map((rule) => (
                        <tr key={rule.id} style={{ borderBottom: '1px solid #f5f5f5' }}>
                          <td style={{ padding: '6px 8px' }}>{rule.feature}</td>
                          <td style={{ padding: '6px 8px' }}>{rule.vendor || '-'}</td>
                          <td style={{ padding: '6px 8px' }}>{rule.category}</td>
                          <td style={{ padding: '6px 8px' }}>
                            <button
                              className="btn btn-danger btn-sm"
                              onClick={() => handleDeleteUserRule(rule.id, rule.feature)}
                            >
                              删除
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}

                {rulesMsg && (
                  <div
                    style={{
                      marginTop: 8,
                      fontSize: 12,
                      color: rulesMsg.type === 'success' ? '#16a34a' : '#dc2626',
                    }}
                  >
                    {rulesMsg.text}
                  </div>
                )}
              </div>
            </div>
          </>
        )}

        {/* ==================== 应用设置（续：关于） ==================== */}
        {activeTab === 'app' && (
          <>
            <div className="card">
              <div className="card-header">关于</div>
              <div className="card-body">
                <div className="about-info">
                  <div className="about-row">
                    <span>软件名称</span>
                    <span>SNMP安全告警系统</span>
                  </div>
                  <div className="about-row">
                    <span>版本号</span>
                    <span>v{version}</span>
                  </div>
                  <div className="about-row">
                    <span>开发团队</span>
                    <span>屏山县中医医院信息科&他们的小伙伴们</span>
                  </div>
                </div>
              </div>
            </div>
          </>
        )}

        {/* ==================== 调试工具 ==================== */}
        {activeTab === 'debug' && (
          <>
            <div className="card" style={{ marginBottom: 20 }}>
              <div className="card-header">原始报文调试</div>
              <div className="card-body">
                <div className="setting-row">
                  <div className="setting-info">
                    <div className="setting-label">保存原始报文</div>
                    <div className="setting-desc">将收到的 SNMP/Syslog 原始报文原样保存为 txt 文件（调试用途）</div>
                  </div>
                  <div className="setting-control">
                    <label className="toggle">
                      <input type="checkbox" checked={rawLogEnabled}
                        onChange={e => {
                          setRawLogEnabled(e.target.checked);
                          saveRawLogConfig({ enabled: e.target.checked });
                        }} />
                      <span className="toggle-slider"></span>
                    </label>
                  </div>
                </div>
                {rawLogEnabled && (
                  <>
                    <div className="setting-row">
                      <div className="setting-info">
                        <div className="setting-label">保存 SNMP Trap</div>
                        <div className="setting-desc">保存 SNMP 协议收到的原始报文</div>
                      </div>
                      <div className="setting-control">
                        <label className="toggle">
                          <input type="checkbox" checked={rawLogSnmp}
                            onChange={e => {
                              setRawLogSnmp(e.target.checked);
                              saveRawLogConfig({ snmpEnabled: e.target.checked });
                            }} />
                          <span className="toggle-slider"></span>
                        </label>
                      </div>
                    </div>
                    <div className="setting-row">
                      <div className="setting-info">
                        <div className="setting-label">保存 Syslog</div>
                        <div className="setting-desc">保存 Syslog 协议收到的原始报文</div>
                      </div>
                      <div className="setting-control">
                        <label className="toggle">
                          <input type="checkbox" checked={rawLogSyslog}
                            onChange={e => {
                              setRawLogSyslog(e.target.checked);
                              saveRawLogConfig({ syslogEnabled: e.target.checked });
                            }} />
                          <span className="toggle-slider"></span>
                        </label>
                      </div>
                    </div>
                    <div className="setting-row">
                      <div className="setting-info">
                        <div className="setting-label">保存目录</div>
                        <div className="setting-desc">原始报文保存的文件夹路径</div>
                      </div>
                      <div className="setting-control">
                        <input className="input" type="text" value={rawLogDir}
                          onChange={e => {
                            setRawLogDir(e.target.value);
                            saveRawLogConfig({ baseDir: e.target.value });
                          }}
                          style={{ width: 280 }} placeholder="默认: %APPDATA%/snmp-security-alert/raw_logs" />
                        <button className="btn btn-secondary btn-sm" style={{ marginLeft: 8, whiteSpace: 'nowrap' }}
                          onClick={async () => {
                            const dir = await window.electronAPI?.selectDirectory();
                            if (dir) {
                              setRawLogDir(dir);
                              saveRawLogConfig({ baseDir: dir });
                            }
                          }}>
                          选择文件夹
                        </button>
                      </div>
                    </div>
                  </>
                )}
              </div>
            </div>

            <div className="card">
              <div className="card-header">
                Syslog 接收日志（调试用）
                <div style={{ display: 'flex', gap: 8 }}>
                  <button className="btn btn-secondary btn-sm" onClick={loadSyslogLogs}>刷新</button>
                  <button className="btn btn-secondary btn-sm" onClick={async () => { await window.electronAPI.clearSyslogLogs(); loadSyslogLogs(); }}>清空</button>
                </div>
              </div>
              <div className="card-body" style={{ padding: 12 }}>
                <div className="syslog-debug-info">
                  共收到 <strong>{syslogLogs.length}</strong> 条日志，其中{' '}
                  <strong style={{ color: '#b31412' }}>{syslogLogs.filter(l => l.isThreat).length}</strong> 条识别为威胁日志
                </div>
                <div className="syslog-log-list">
                  {syslogLogs.length === 0 ? (
                    <div className="syslog-empty">
                      暂无日志。请确认：
                      <ol>
                        <li>软件 Syslog 监听已启动（端口 {syslogPort}）</li>
                        <li>防火墙 Syslog 日志主机指向 {`192.168.100.250`}</li>
                        <li>防火墙侧触发一条威胁日志或策略命中</li>
                      </ol>
                    </div>
                  ) : (
                    syslogLogs.map((log, index) => (
                      <div key={index} className={`syslog-log-item ${log.isThreat ? 'syslog-log-threat' : ''}`}>
                        <div className="syslog-log-header">
                          <span className="syslog-log-time">{new Date(log.time).toLocaleTimeString('zh-CN')}</span>
                          <span className="syslog-log-source">来自 {log.source}</span>
                          {log.isThreat && <span className="syslog-log-badge">威胁</span>}
                        </div>
                        <div className="syslog-log-content">{log.content}</div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default Settings;
