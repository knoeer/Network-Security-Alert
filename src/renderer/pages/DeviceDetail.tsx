import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import type { Device, DeviceInfo, DeviceAlertSummary, DeviceInterface, PerformanceSample, TrafficSample, InterfaceSnapshotResult } from '../types/global';
import {
  deviceTypeLabels,
  getVendorName,
  getServiceLayerDesc,
  severityLabels,
  statusConfig,
  formatTime,
  ifOperStatusConfig,
  ifAdminStatusConfig,
  formatIfSpeed,
  formatRate,
  formatBytes,
} from './device-utils';
import './DeviceDetail.css';

// 根据采样值计算柱状图高度（归一化到 0-100%）
function calcBarHeight(value: number, history: TrafficSample[]): number {
  if (value <= 0) return 0;
  const max = Math.max(1, ...history.map((s) => Math.max(s.in_rate, s.out_rate)));
  return Math.min(100, (value / max) * 100);
}

/**
 * 将 ISO 时间戳格式化为本地时区显示
 * 数据库存的是 UTC 时间（toISOString），直接 slice 会显示 UTC 时刻（比本地慢 8 小时），
 * 需先转为本地时间再格式化。
 * @param iso ISO 时间字符串（如 "2026-08-17T00:44:54.612Z"）
 * @param withDate 是否包含日期（true: "2026-08-17 00:44"，false: "00:44"）
 */
function formatSampleTime(iso: string, withDate = false): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return withDate ? iso.replace('T', ' ').slice(0, 16) : iso.slice(11, 16);
  const pad = (n: number) => String(n).padStart(2, '0');
  const hm = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  if (!withDate) return hm;
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${hm}`;
}

const DeviceDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [device, setDevice] = useState<Device | null>(null);
  const [detailInfo, setDetailInfo] = useState<DeviceInfo | null>(null);
  const [alertSummary, setAlertSummary] = useState<DeviceAlertSummary | null>(null);
  const [interfaces, setInterfaces] = useState<DeviceInterface[] | null>(null);
  const [interfacesLoading, setInterfacesLoading] = useState(false);
  const [interfacesError, setInterfacesError] = useState('');
  const [interfaceSampleTime, setInterfaceSampleTime] = useState<string | null>(null);
  const [perfHistory, setPerfHistory] = useState<PerformanceSample[]>([]);
  const [perfLoading, setPerfLoading] = useState(false);
  const [trafficHistory, setTrafficHistory] = useState<TrafficSample[]>([]);
  const [trafficLoading, setTrafficLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [probing, setProbing] = useState(false);
  const [notFound, setNotFound] = useState(false);

  const loadData = useCallback(async (refreshInfo = true) => {
    const deviceId = Number(id);
    if (!deviceId || isNaN(deviceId)) {
      setNotFound(true);
      setLoading(false);
      return;
    }

    try {
      const dev = await window.electronAPI.getDeviceById(deviceId);
      if (!dev) {
        setNotFound(true);
        setLoading(false);
        return;
      }
      setDevice(dev);
      setNotFound(false);

      // 加载告警统计
      try {
        const summary = await window.electronAPI.getDeviceAlertSummary({
          ip: dev.ip,
          name: dev.name,
        });
        setAlertSummary(summary);
      } catch (err) {
        console.error('获取告警统计失败:', err);
      }

      // 探测系统信息
      if (refreshInfo) {
        setProbing(true);
        setDetailInfo(null);
        try {
          const result = await window.electronAPI.probeDevice(deviceId);
          if (result.info) {
            setDetailInfo(result.info);
          }
        } catch (err) {
          console.error('获取设备系统信息失败:', err);
        } finally {
          setProbing(false);
        }
      }
    } catch (err) {
      console.error('加载设备失败:', err);
      setNotFound(true);
    } finally {
      setLoading(false);
    }
  }, [id]);

  // 手动重新采样接口列表与实时流量（点"重新采样"触发）
  const loadInterfaces = useCallback(async () => {
    const deviceId = Number(id);
    if (!deviceId || isNaN(deviceId)) return;
    setInterfacesLoading(true);
    setInterfacesError('');
    try {
      const result = await window.electronAPI.probeInterfaces(deviceId);
      if (result.success) {
        setInterfaces(result.interfaces);
        setInterfaceSampleTime(result.sampleTime || new Date().toISOString());
      } else {
        setInterfaces([]);
        setInterfacesError(result.message || '接口探测失败');
      }
    } catch (err) {
      setInterfaces([]);
      setInterfacesError('接口探测异常');
      console.error('获取接口失败:', err);
    } finally {
      setInterfacesLoading(false);
    }
  }, [id]);

  // 加载设备最后一次接口采样结果（不触发重新采样）
  const loadSavedInterfaces = useCallback(async () => {
    const deviceId = Number(id);
    if (!deviceId || isNaN(deviceId)) return;
    try {
      const saved: InterfaceSnapshotResult = await window.electronAPI.getSavedInterfaces(deviceId);
      if (saved && saved.interfaces && saved.interfaces.length > 0) {
        setInterfaces(saved.interfaces);
        setInterfaceSampleTime(saved.sampleTime);
        setInterfacesError('');
      } else {
        setInterfaces(null);
        setInterfaceSampleTime(null);
      }
    } catch (err) {
      console.error('获取保存的接口采样失败:', err);
      setInterfaces(null);
      setInterfaceSampleTime(null);
    }
  }, [id]);

  // 加载性能历史（CPU/内存采样）
  const loadPerformance = useCallback(async () => {
    const deviceId = Number(id);
    if (!deviceId || isNaN(deviceId)) return;
    setPerfLoading(true);
    try {
      const history = await window.electronAPI.getPerformanceHistory(deviceId, 50);
      setPerfHistory(history || []);
    } catch (err) {
      console.error('获取性能历史失败:', err);
      setPerfHistory([]);
    } finally {
      setPerfLoading(false);
    }
  }, [id]);

  // 加载流量历史（接口收发速率采样）
  const loadTraffic = useCallback(async () => {
    const deviceId = Number(id);
    if (!deviceId || isNaN(deviceId)) return;
    setTrafficLoading(true);
    try {
      const history = await window.electronAPI.getTrafficHistory(deviceId, 50);
      setTrafficHistory(history || []);
    } catch (err) {
      console.error('获取流量历史失败:', err);
      setTrafficHistory([]);
    } finally {
      setTrafficLoading(false);
    }
  }, [id]);

  // 性能监控"刷新"：立即采集 CPU/内存，再重新加载历史
  const handlePerformanceRefresh = useCallback(async () => {
    const deviceId = Number(id);
    if (!deviceId || isNaN(deviceId)) return;
    setPerfLoading(true);
    try {
      await window.electronAPI.samplePerformanceNow(deviceId); // 立即采样入库
    } catch (err) {
      console.error('立即采样性能失败:', err);
    }
    await loadPerformance();
  }, [id, loadPerformance]);

  // 流量趋势"刷新"：立即采集接口收发速率，再重新加载历史
  const handleTrafficRefresh = useCallback(async () => {
    const deviceId = Number(id);
    if (!deviceId || isNaN(deviceId)) return;
    setTrafficLoading(true);
    try {
      await window.electronAPI.sampleTrafficNow(deviceId); // 立即采样入库
    } catch (err) {
      console.error('立即采样流量失败:', err);
    }
    await loadTraffic();
  }, [id, loadTraffic]);

  useEffect(() => {
    loadData(true);
    loadSavedInterfaces(); // 进入页面先显示上次采样结果，不自动重新采样
    loadPerformance();
    loadTraffic();
  }, [loadData, loadSavedInterfaces, loadPerformance, loadTraffic]);

  useEffect(() => {
    loadData(true);
  }, [loadData]);

  // 设备离线监测状态变化时同步状态
  useEffect(() => {
    const deviceId = Number(id);
    const unsub = window.electronAPI?.onDeviceStatusChanged?.((data) => {
      if (data.id === deviceId) {
        const newStatus: Device['status'] =
          data.status === 'online' || data.status === 'offline' ? data.status : 'unknown';
        setDevice(prev => (prev ? { ...prev, status: newStatus, last_checked: new Date().toISOString() } : prev));
      }
    });
    return () => {
      if (typeof unsub === 'function') unsub();
    };
  }, [id]);

  if (loading) {
    return (
      <div className="device-detail-page">
        <div className="empty-state">
          <div className="spinner"></div>
          <div className="title">加载中...</div>
        </div>
      </div>
    );
  }

  if (notFound || !device) {
    return (
      <div className="device-detail-page">
        <div className="empty-state">
          <div className="icon">🔍</div>
          <div className="title">设备不存在或已被删除</div>
          <button className="btn btn-primary" style={{ marginTop: 16 }} onClick={() => navigate('/devices')}>
            返回设备管理
          </button>
        </div>
      </div>
    );
  }

  const status = statusConfig[device.status] || statusConfig.unknown;
  const vendor = detailInfo ? getVendorName(detailInfo.sysObjectID) : '';
  const severityOrder = ['critical', 'high', 'medium', 'low'] as const;

  // 计算流量条宽度（相对所有接口最大速率）
  const ratePercent = (rate: number, ifaces: DeviceInterface[]): string => {
    if (!rate || !ifaces || ifaces.length === 0) return '0%';
    const maxRate = Math.max(...ifaces.map(i => Math.max(i.inRate, i.outRate)));
    if (!maxRate) return '0%';
    return `${Math.min(100, Math.round((rate / maxRate) * 100))}%`;
  };

  return (
    <div className="device-detail-page">
      {/* 顶部工具栏 */}
      <div className="detail-header">
        <button className="btn btn-secondary" onClick={() => navigate('/devices')}>
          ← 返回设备管理
        </button>
        <div className="detail-header-actions">
          <button
            className="btn btn-secondary"
            onClick={() => loadData(false)}
            disabled={probing}
          >
            刷新
          </button>
          <button className="btn btn-primary" onClick={() => loadData(true)} disabled={probing}>
            {probing ? '探测中...' : '重新探测'}
          </button>
        </div>
      </div>

      {/* 设备横幅 */}
      <div className="detail-banner" style={{ borderLeftColor: status.color }}>
        <div className="detail-banner-icon">🖥️</div>
        <div className="detail-banner-content">
          <div className="detail-banner-title-row">
            <h2 className="detail-banner-title">{device.name}</h2>
            <div className="detail-banner-badges">
              <span className="status-indicator">
                <span className={`status-dot ${status.dotClass}`}></span>
                {status.label}
              </span>
              <span className="badge badge-type">{deviceTypeLabels[device.device_type] || device.device_type}</span>
              {vendor && <span className="badge badge-vendor">{vendor}</span>}
            </div>
          </div>
          <div className="detail-banner-meta">
            <code>{device.ip}</code>
            {device.location && (
              <>
                <span className="meta-divider">|</span>
                <span>📍 {device.location}</span>
              </>
            )}
            {device.last_checked && (
              <>
                <span className="meta-divider">|</span>
                <span>最后检查 {formatTime(device.last_checked)}</span>
              </>
            )}
          </div>
        </div>
      </div>

      {/* 主体布局 */}
      <div className="detail-main-layout">
        {/* 左栏 */}
        <div className="detail-left-col">
          {/* 基本信息 */}
          <div className="card detail-info-card">
            <div className="card-header">基本信息</div>
            <div className="card-body">
              <div className="detail-grid">
                <div className="detail-item">
                  <label>设备名称</label>
                  <span>{device.name}</span>
                </div>
                <div className="detail-item">
                  <label>IP地址</label>
                  <span><code>{device.ip}</code></span>
                </div>
                <div className="detail-item">
                  <label>设备类型</label>
                  <span>{deviceTypeLabels[device.device_type] || device.device_type}</span>
                </div>
                <div className="detail-item">
                  <label>SNMP版本</label>
                  <span>{device.snmp_version}</span>
                </div>
                <div className="detail-item">
                  <label>端口</label>
                  <span>{device.port}</span>
                </div>
                <div className="detail-item">
                  <label>{device.snmp_version === 'v3' ? '用户名' : 'Community'}</label>
                  <span><code>{device.snmp_version === 'v3' ? device.snmp_username || '-' : device.community}</code></span>
                </div>
                {device.snmp_version === 'v3' && (
                  <>
                    <div className="detail-item">
                      <label>认证</label>
                      <span>
                        {device.snmp_auth_protocol && device.snmp_auth_protocol !== 'none'
                          ? `${device.snmp_auth_protocol.toUpperCase()}（已配置）`
                          : '无认证'}
                      </span>
                    </div>
                    <div className="detail-item">
                      <label>加密</label>
                      <span>
                        {device.snmp_priv_protocol && device.snmp_priv_protocol !== 'none'
                          ? `${device.snmp_priv_protocol.toUpperCase()}（已配置）`
                          : '不加密'}
                      </span>
                    </div>
                  </>
                )}
                <div className="detail-item">
                  <label>位置</label>
                  <span>{device.location || '-'}</span>
                </div>
                <div className="detail-item">
                  <label>添加时间</label>
                  <span>{formatTime(device.created_at)}</span>
                </div>
                <div className="detail-item detail-item-full">
                  <label>描述</label>
                  <span>{device.description || '-'}</span>
                </div>
              </div>
            </div>
          </div>

          {/* 系统信息 */}
          <div className="card detail-info-card">
            <div className="card-header">
              系统信息
              {probing && <span className="spinner spinner-sm"></span>}
            </div>
            <div className="card-body">
              {probing ? (
                <div className="empty-state" style={{ padding: '24px 16px' }}>
                  <div className="spinner"></div>
                  <div className="desc">正在通过 SNMP 探测设备信息...</div>
                </div>
              ) : detailInfo ? (
                <div className="detail-grid">
                  {detailInfo.sysName && (
                    <div className="detail-item detail-item-full">
                      <label>系统名称</label>
                      <span>{detailInfo.sysName}</span>
                    </div>
                  )}
                  {detailInfo.sysDescr && (
                    <div className="detail-item detail-item-full">
                      <label>系统描述</label>
                      <span className="sysdescr-text">{detailInfo.sysDescr}</span>
                    </div>
                  )}
                  <div className="detail-item">
                    <label>设备厂商</label>
                    <span>
                      {vendor
                        ? <span className="badge badge-vendor">{vendor}</span>
                        : detailInfo.sysObjectID
                          ? <span className="oid-code">{detailInfo.sysObjectID}</span>
                          : '-'}
                    </span>
                  </div>
                  <div className="detail-item">
                    <label>运行时间</label>
                    <span>{detailInfo.sysUpTime || '-'}</span>
                  </div>
                  <div className="detail-item">
                    <label>开机时间</label>
                    <span>{detailInfo.bootTime || '-'}</span>
                  </div>
                  <div className="detail-item">
                    <label>服务层级</label>
                    <span>{detailInfo.sysServices > 0 ? getServiceLayerDesc(detailInfo.sysServices) : '-'}</span>
                  </div>
                  {detailInfo.sysLocation && (
                    <div className="detail-item">
                      <label>系统位置</label>
                      <span>{detailInfo.sysLocation}</span>
                    </div>
                  )}
                  {detailInfo.sysContact && (
                    <div className="detail-item">
                      <label>联系人</label>
                      <span>{detailInfo.sysContact}</span>
                    </div>
                  )}
                  {detailInfo.sysObjectID && !vendor && (
                    <div className="detail-item detail-item-full">
                      <label>系统OID</label>
                      <span className="oid-code">{detailInfo.sysObjectID}</span>
                    </div>
                  )}
                </div>
              ) : (
                <div className="empty-state" style={{ padding: '24px 16px' }}>
                  <div className="icon">📡</div>
                  <div className="title">未获取到系统信息</div>
                  <div className="desc">设备可能不在线，或 SNMP 配置不正确</div>
                  <button className="btn btn-secondary" style={{ marginTop: 16 }} onClick={() => loadData(true)}>
                    重新探测
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* 右栏 */}
        <div className="detail-right-col">
          {/* 告警统计 */}
          <div className="card detail-info-card">
            <div className="card-header">告警统计</div>
            <div className="card-body">
              {alertSummary ? (
                <div className="alert-summary">
                  <div className="alert-summary-top">
                    <div className="alert-summary-stat">
                      <span className="stat-num">{alertSummary.total}</span>
                      <span className="stat-label">累计告警</span>
                    </div>
                    <div className="alert-summary-stat">
                      <span className="stat-num">{alertSummary.todayCount}</span>
                      <span className="stat-label">今日告警</span>
                    </div>
                    <div className="alert-summary-stat">
                      <span className="stat-num">{alertSummary.recentAlerts.filter(a => !a.acknowledged).length}</span>
                      <span className="stat-label">未确认</span>
                    </div>
                  </div>
                  <div className="alert-summary-severity">
                    {severityOrder.map(sev => {
                      const item = alertSummary.bySeverity.find(s => s.severity === sev);
                      const count = item ? item.count : 0;
                      return (
                        <span key={sev} className={`sev-badge sev-${sev}`}>
                          {severityLabels[sev]}: {count}
                        </span>
                      );
                    })}
                  </div>
                </div>
              ) : (
                <div className="empty-state" style={{ padding: '24px 16px' }}>
                  <div className="desc">暂无告警数据</div>
                </div>
              )}
            </div>
          </div>

          {/* 最近告警 */}
          <div className="card detail-info-card recent-card">
            <div className="card-header">
              最近告警
              {(alertSummary?.recentAlerts.length ?? 0) > 0 && (
                <button className="btn btn-secondary btn-sm" onClick={() => navigate('/events')}>
                  查看全部
                </button>
              )}
            </div>
            <div className="card-body">
              {alertSummary && alertSummary.recentAlerts.length > 0 ? (
                <div className="recent-alert-list">
                  {alertSummary.recentAlerts.map(alert => (
                    <div key={alert.id} className="recent-alert-item" onClick={() => navigate(`/events/${alert.id}`)}>
                      <span className={`sev-dot sev-dot-${alert.severity}`}></span>
                      <div className="recent-alert-main">
                        <div className="recent-alert-title">
                          <span className="recent-alert-type">{alert.attack_type}</span>
                          {!alert.acknowledged && <span className="recent-alert-flag">未确认</span>}
                        </div>
                        <div className="recent-alert-meta">
                          {alert.source_ip && <span>源 {alert.source_ip}</span>}
                          {alert.source_ip && alert.target_ip && <span className="meta-divider">→</span>}
                          {alert.target_ip && <span>目标 {alert.target_ip}</span>}
                        </div>
                      </div>
                      <span className="recent-alert-time">{formatTime(alert.timestamp)}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state" style={{ padding: '24px 16px' }}>
                  <div className="desc">该设备暂无告警记录</div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* 性能监控（CPU/内存/磁盘） */}
      <div className="card detail-info-card perf-card">
        <div className="card-header">
          <span>性能监控（CPU / 内存 / 磁盘）</span>
          {perfLoading && <span className="spinner spinner-sm"></span>}
          <button
            className="btn btn-secondary btn-sm iface-refresh"
            onClick={() => handlePerformanceRefresh()}
            disabled={perfLoading}
          >
            {perfLoading ? '采集中...' : '刷新'}
          </button>
        </div>
        <div className="card-body">
          {perfHistory.length === 0 ? (
            <div className="empty-state" style={{ padding: '24px 16px' }}>
              <div className="icon">📊</div>
              <div className="title">暂无性能采样数据</div>
              <div className="desc">启用性能监控后，系统会定时通过 SNMP 采集设备 CPU 和内存使用率</div>
            </div>
          ) : (
            <div className="perf-summary">
              {(() => {
                const latest = perfHistory[perfHistory.length - 1];
                return (
                  <div className="perf-current">
                    <div className="perf-metric">
                      <span className="perf-metric-label">当前 CPU</span>
                      <span className={`perf-metric-value ${latest.cpu_percent >= 90 ? 'perf-high' : latest.cpu_percent >= 70 ? 'perf-warn' : ''}`}>
                        {latest.cpu_percent >= 0 ? `${latest.cpu_percent}%` : 'N/A'}
                      </span>
                    </div>
                    <div className="perf-metric">
                      <span className="perf-metric-label">当前内存</span>
                      <span className={`perf-metric-value ${latest.mem_percent >= 90 ? 'perf-high' : latest.mem_percent >= 70 ? 'perf-warn' : ''}`}>
                        {latest.mem_percent >= 0 ? `${latest.mem_percent}%` : 'N/A'}
                      </span>
                    </div>
                    <div className="perf-metric">
                      <span className="perf-metric-label">当前磁盘（根分区）</span>
                      <span className={`perf-metric-value ${latest.disk_percent >= 90 ? 'perf-high' : latest.disk_percent >= 70 ? 'perf-warn' : ''}`}>
                        {latest.disk_percent >= 0 ? `${latest.disk_percent}%` : 'N/A'}
                      </span>
                    </div>
                  </div>
                );
              })()}
              {/* 磁盘分区列表：展示该设备所有分区使用率 */}
              {(() => {
                const latest = perfHistory[perfHistory.length - 1];
                if (!latest || !latest.disks || latest.disks.length === 0) return null;
                return (
                  <div className="perf-disk-list">
                    <div className="perf-chart-title">磁盘分区使用率</div>
                    {latest.disks.map((d) => (
                      <div key={d.name} className="perf-disk-item">
                        <span className="perf-disk-name" title={d.name}>{d.name || '(未命名)'}</span>
                        <div className="perf-disk-track">
                          <div
                            className={`perf-disk-fill ${d.percent >= 90 ? 'perf-disk-fill-high' : d.percent >= 70 ? 'perf-disk-fill-warn' : ''}`}
                            style={{ width: `${Math.max(2, d.percent)}%` }}
                          />
                        </div>
                        <span className="perf-disk-meta">{formatBytes(d.used)} / {formatBytes(d.size)}</span>
                        <span className="perf-disk-pct">{d.percent}%</span>
                      </div>
                    ))}
                  </div>
                );
              })()}
              <div className="perf-chart">
                <div className="perf-chart-title">使用率趋势（最近 {perfHistory.length} 次采样）</div>
                <div className="perf-chart-bars">
                  {perfHistory.map((s) => (
                    <div key={s.id} className="perf-bar-group" title={`${formatSampleTime(s.timestamp, true)}\nCPU ${s.cpu_percent >= 0 ? s.cpu_percent + '%' : 'N/A'} / 内存 ${s.mem_percent >= 0 ? s.mem_percent + '%' : 'N/A'} / 磁盘 ${s.disk_percent >= 0 ? s.disk_percent + '%' : 'N/A'}`}>
                      <div className="perf-bar-track">
                        <div className="perf-bar perf-bar-cpu" style={{ height: `${Math.max(2, s.cpu_percent >= 0 ? s.cpu_percent : 0)}%` }} />
                      </div>
                      <div className="perf-bar-track">
                        <div className="perf-bar perf-bar-mem" style={{ height: `${Math.max(2, s.mem_percent >= 0 ? s.mem_percent : 0)}%` }} />
                      </div>
                      <div className="perf-bar-track">
                        <div className="perf-bar perf-bar-disk" style={{ height: `${Math.max(2, s.disk_percent >= 0 ? s.disk_percent : 0)}%` }} />
                      </div>
                      <div className="perf-bar-time">{formatSampleTime(s.timestamp)}</div>
                    </div>
                  ))}
                </div>
                <div className="perf-legend">
                  <span className="perf-legend-item"><span className="perf-legend-dot perf-dot-cpu"></span>CPU</span>
                  <span className="perf-legend-item"><span className="perf-legend-dot perf-dot-mem"></span>内存</span>
                  <span className="perf-legend-item"><span className="perf-legend-dot perf-dot-disk"></span>磁盘</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* 流量趋势（收发速率历史） */}
      <div className="card detail-info-card traffic-card">
        <div className="card-header">
          <span>流量趋势（接口收发速率）</span>
          {trafficLoading && <span className="spinner spinner-sm"></span>}
          <button
            className="btn btn-secondary btn-sm iface-refresh"
            onClick={() => handleTrafficRefresh()}
            disabled={trafficLoading}
          >
            {trafficLoading ? '采集中...' : '刷新'}
          </button>
        </div>
        <div className="card-body">
          {trafficHistory.length === 0 ? (
            <div className="empty-state" style={{ padding: '24px 16px' }}>
              <div className="icon">📈</div>
              <div className="title">暂无流量采样数据</div>
              <div className="desc">启用流量监控后，系统会定时采集接口收发速率</div>
            </div>
          ) : (
            <div className="traffic-summary">
              {(() => {
                const latest = trafficHistory[trafficHistory.length - 1];
                return (
                  <div className="traffic-current">
                    <div className="traffic-metric">
                      <span className="traffic-metric-label">当前接收速率</span>
                      <span className="traffic-metric-value traffic-in">{formatRate(latest.in_rate)}</span>
                    </div>
                    <div className="traffic-metric">
                      <span className="traffic-metric-label">当前发送速率</span>
                      <span className="traffic-metric-value traffic-out">{formatRate(latest.out_rate)}</span>
                    </div>
                  </div>
                );
              })()}
              <div className="traffic-chart">
                <div className="traffic-chart-title">速率趋势（最近 {trafficHistory.length} 次采样）</div>
                <div className="traffic-chart-bars">
                  {trafficHistory.map((s) => (
                    <div key={s.id} className="traffic-bar-group" title={`${formatSampleTime(s.timestamp, true)}\n↓ ${formatRate(s.in_rate)} / ↑ ${formatRate(s.out_rate)}`}>
                      <div className="traffic-bar-track">
                        <div className="traffic-bar traffic-bar-in" style={{ height: `${Math.max(2, calcBarHeight(s.in_rate, trafficHistory))}%` }} />
                      </div>
                      <div className="traffic-bar-track">
                        <div className="traffic-bar traffic-bar-out" style={{ height: `${Math.max(2, calcBarHeight(s.out_rate, trafficHistory))}%` }} />
                      </div>
                      <div className="traffic-bar-time">{formatSampleTime(s.timestamp)}</div>
                    </div>
                  ))}
                </div>
                <div className="traffic-legend">
                  <span className="traffic-legend-item"><span className="traffic-legend-dot traffic-dot-in"></span>接收</span>
                  <span className="traffic-legend-item"><span className="traffic-legend-dot traffic-dot-out"></span>发送</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* 接口与流量（P1） */}
      <div className="card detail-info-card iface-card">
        <div className="card-header">
          <span>网络接口与流量</span>
          {interfacesLoading && <span className="spinner spinner-sm"></span>}
          {interfaces && interfaces.length > 0 && (
            <span className="iface-count">{interfaces.length} 个接口</span>
          )}
          {interfaceSampleTime && !interfacesLoading && (
            <span className="iface-sample-time">上次采样 {formatSampleTime(interfaceSampleTime, true)}</span>
          )}
          <button
            className="btn btn-secondary btn-sm iface-refresh"
            onClick={() => loadInterfaces()}
            disabled={interfacesLoading}
          >
            {interfacesLoading ? '采集中...' : '重新采样'}
          </button>
        </div>
        <div className="card-body">
          {interfacesLoading && !interfaces ? (
            <div className="empty-state" style={{ padding: '24px 16px' }}>
              <div className="spinner"></div>
              <div className="desc">正在通过 SNMP 采集接口流量（约需 3 秒）...</div>
            </div>
          ) : interfaces && interfaces.length > 0 ? (
            <div className="iface-table-wrap">
              <table className="iface-table">
                <thead>
                  <tr>
                    <th>接口</th>
                    <th>状态</th>
                    <th>IP 地址</th>
                    <th>物理速率</th>
                    <th>流入</th>
                    <th>流出</th>
                    <th>错误</th>
                    <th>MAC / MTU</th>
                  </tr>
                </thead>
                <tbody>
                  {interfaces.map(iface => {
                    const oper = ifOperStatusConfig[iface.operStatus] || ifOperStatusConfig.unknown;
                    const admin = ifAdminStatusConfig[iface.adminStatus] || ifAdminStatusConfig.unknown;
                    return (
                      <tr key={iface.index}>
                        <td className="iface-name-cell">
                          <div className="iface-name">{iface.name}</div>
                          <div className="iface-descr">{iface.type}{iface.descr && iface.descr !== iface.name ? ` · ${iface.descr}` : ''}</div>
                        </td>
                        <td className="iface-status-cell">
                          <div className="iface-status-line">
                            <span className={`iface-status-dot ${oper.dotClass}`}></span>
                            {oper.label}
                          </div>
                          <div className="iface-admin">管理:{admin.label}</div>
                        </td>
                        <td className="iface-ip">
                          {iface.ips && iface.ips.length > 0 ? (
                            iface.ips.map((ip, i) => (
                              <div key={i} className="iface-ip-line"><code>{ip}</code></div>
                            ))
                          ) : (
                            <span className="iface-ip-none">-</span>
                          )}
                        </td>
                        <td className="iface-speed">{formatIfSpeed(iface.speed)}</td>
                        <td>
                          <div className="iface-rate">
                            <span className="iface-rate-val">↓ {formatRate(iface.inRate)}</span>
                            <div className="iface-rate-bar">
                              <div className="iface-rate-bar-fill iface-rate-in" style={{ width: ratePercent(iface.inRate, interfaces) }}></div>
                            </div>
                          </div>
                        </td>
                        <td>
                          <div className="iface-rate">
                            <span className="iface-rate-val">↑ {formatRate(iface.outRate)}</span>
                            <div className="iface-rate-bar">
                              <div className="iface-rate-bar-fill iface-rate-out" style={{ width: ratePercent(iface.outRate, interfaces) }}></div>
                            </div>
                          </div>
                        </td>
                        <td className="iface-errors">
                          {(iface.inErrors > 0 || iface.outErrors > 0) ? (
                            <span className="iface-error-badge">
                              {iface.inErrors + iface.outErrors} (入{iface.inErrors}/出{iface.outErrors})
                            </span>
                          ) : (
                            <span className="iface-error-none">0</span>
                          )}
                        </td>
                        <td className="iface-mac">
                          {iface.mac ? <code>{iface.mac}</code> : '-'}
                          <div className="iface-mtu">MTU {iface.mtu || '-'}</div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              <div className="iface-footer">
                累计流量 · 入 {formatBytes(interfaces.reduce((s, i) => s + i.inOctets, 0))} / 出 {formatBytes(interfaces.reduce((s, i) => s + i.outOctets, 0))}
              </div>
            </div>
          ) : (
            <div className="empty-state" style={{ padding: '24px 16px' }}>
              <div className="icon">🔌</div>
              <div className="title">未获取到接口信息</div>
              <div className="desc">
                {interfacesError || '设备可能不在线，或 SNMP 不支持接口表查询'}
              </div>
              <button className="btn btn-secondary" style={{ marginTop: 16 }} onClick={() => loadInterfaces()}>
                重新采集
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DeviceDetail;
