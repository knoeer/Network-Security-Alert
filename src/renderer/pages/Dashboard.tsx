import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAlertListener } from '../hooks/useAlertListener';
import IpLocation from '../components/IpLocation';
import type { SecurityEvent } from '../types/global';
import './Dashboard.css';

interface AttackTop { attack_type: string; count: number; }
interface TrendItem { date: string; count: number; critical: number; high: number; medium: number; low: number; }
interface HourlyItem { hour: string; count: number; }
interface IpTop { count: number; }
interface DeviceStat { device_name: string; count: number; }

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const { latestAlert } = useAlertListener();
  const [stats, setStats] = useState<any>(null);
  const [attackTop, setAttackTop] = useState<AttackTop[]>([]);
  const [trend, setTrend] = useState<TrendItem[]>([]);
  const [hourlyTrend, setHourlyTrend] = useState<HourlyItem[]>([]);
  const [sourceIpTop, setSourceIpTop] = useState<any[]>([]);
  const [targetIpTop, setTargetIpTop] = useState<any[]>([]);
  const [deviceStats, setDeviceStats] = useState<DeviceStat[]>([]);
  const [deviceCount, setDeviceCount] = useState(0);
  const [loading, setLoading] = useState(true);

  const loadAll = useCallback(async () => {
    try {
      setLoading(true);
      const [
        statsData,
        attackTopData,
        trendData,
        hourlyData,
        sourceIpData,
        targetIpData,
        deviceStatsData,
        devicesData,
      ] = await Promise.all([
        window.electronAPI.getEventStats(),
        window.electronAPI.getAttackTop(8),
        window.electronAPI.getTrend(7),
        window.electronAPI.getHourlyTrend(),
        window.electronAPI.getSourceIpTop(8),
        window.electronAPI.getTargetIpTop(8),
        window.electronAPI.getDeviceAlertStats(),
        window.electronAPI.getDevices(),
      ]);

      setStats(statsData);
      setAttackTop(attackTopData);
      setTrend(trendData);
      setHourlyTrend(hourlyData);
      setSourceIpTop(sourceIpData);
      setTargetIpTop(targetIpData);
      setDeviceStats(deviceStatsData);
      setDeviceCount(devicesData.length);
    } catch (err) {
      console.error('加载仪表盘数据失败:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAll();
  }, [loadAll]);

  // 收到新告警时刷新数据
  useEffect(() => {
    if (latestAlert) {
      loadAll();
    }
  }, [latestAlert, loadAll]);

  const severityConfig: Record<string, { label: string; className: string; color: string }> = {
    critical: { label: '严重', className: 'badge-critical', color: '#b31412' },
    high: { label: '高危', className: 'badge-high', color: '#d93025' },
    medium: { label: '中等', className: 'badge-medium', color: '#f9ab00' },
    low: { label: '低危', className: 'badge-low', color: '#0d904f' },
  };

  const getSeverityCount = (severity: string): number => {
    if (!stats) return 0;
    const item = stats.bySeverity.find((s: any) => s.severity === severity);
    return item ? item.count : 0;
  };

  const formatTime = (ts: string) => {
    const d = new Date(ts);
    return d.toLocaleString('zh-CN', {
      month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  };

  // 计算攻击类型 TOP 的最大值（用于柱状图比例）
  const maxAttackCount = attackTop.length > 0 ? Math.max(...attackTop.map(a => a.count)) : 1;
  const maxSourceIpCount = sourceIpTop.length > 0 ? Math.max(...sourceIpTop.map((a: any) => a.count)) : 1;

  // 趋势图最大值
  const maxTrendCount = trend.length > 0 ? Math.max(...trend.map(t => t.count)) : 1;
  const maxHourlyCount = hourlyTrend.length > 0 ? Math.max(...hourlyTrend.map(h => h.count)) : 1;

  if (loading) {
    return (
      <div className="empty-state">
        <div className="spinner"></div>
        <div className="title">加载中...</div>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h1>安全概览</h1>
        <button className="btn btn-primary" onClick={loadAll}>刷新数据</button>
      </div>

      {/* 统计卡片 */}
      <div className="stats-grid">
        <div className="stat-card stat-card-total">
          <div className="stat-icon">📋</div>
          <div className="stat-info">
            <div className="stat-value">{stats?.total || 0}</div>
            <div className="stat-label">事件总数</div>
          </div>
        </div>
        <div className="stat-card stat-card-today">
          <div className="stat-icon">📅</div>
          <div className="stat-info">
            <div className="stat-value">{stats?.todayCount || 0}</div>
            <div className="stat-label">今日事件</div>
          </div>
        </div>
        <div className="stat-card stat-card-critical">
          <div className="stat-icon">🔴</div>
          <div className="stat-info">
            <div className="stat-value">{getSeverityCount('critical') + getSeverityCount('high')}</div>
            <div className="stat-label">高危/严重</div>
          </div>
        </div>
        <div className="stat-card stat-card-devices">
          <div className="stat-icon">🖥️</div>
          <div className="stat-info">
            <div className="stat-value">{deviceCount}</div>
            <div className="stat-label">监控设备</div>
          </div>
        </div>
      </div>

      {/* 趋势图（近7天） */}
      <div className="card trend-card">
        <div className="card-header">近7天告警趋势</div>
        <div className="card-body">
          {trend.length === 0 ? (
            <div className="empty-state"><div className="desc">暂无趋势数据</div></div>
          ) : (
            <div className="trend-chart">
              {trend.map((item, index) => {
                const height = item.count > 0 ? Math.max((item.count / maxTrendCount) * 120, 4) : 2;
                const pct = (n: number) => item.count > 0 ? (n / item.count) * 100 : 0;
                // 堆叠顺序：critical 在最底（最严重），依次 high → medium → low 向上堆叠
                const layers = [
                  { n: item.critical, cls: 'trend-bar-critical' },
                  { n: item.high, cls: 'trend-bar-high' },
                  { n: item.medium, cls: 'trend-bar-medium' },
                  { n: item.low, cls: 'trend-bar-low' },
                ];
                // 计算每层的 cumulative bottom（从下方层累加）
                let cumulative = 0;
                const stacked = layers.map(l => {
                  const h = pct(l.n);
                  const start = cumulative;
                  cumulative += h;
                  return { ...l, heightPct: h, bottomPct: start };
                });
                return (
                  <div key={item.date} className="trend-bar-group">
                    <div className="trend-bar-value">{item.count}</div>
                    <div className="trend-bar" style={{ height: `${height}px` }} title={`${item.date}: 共${item.count}条（严重${item.critical}/高危${item.high}/中等${item.medium}/低危${item.low}）`}>
                      {stacked.map((l, i) => l.n > 0 && (
                        <div key={i} className={l.cls} style={{ height: `${l.heightPct}%`, bottom: `${l.bottomPct}%` }} />
                      ))}
                    </div>
                    <div className="trend-bar-label">{item.date.slice(5)}</div>
                  </div>
                );
              })}
            </div>
          )}
          <div className="chart-legend">
            <span className="legend-item"><span className="legend-dot" style={{ background: '#b31412' }}></span>严重</span>
            <span className="legend-item"><span className="legend-dot" style={{ background: '#d93025' }}></span>高危</span>
            <span className="legend-item"><span className="legend-dot" style={{ background: '#f9ab00' }}></span>中等</span>
            <span className="legend-item"><span className="legend-dot" style={{ background: '#0d904f' }}></span>低危</span>
          </div>
        </div>
      </div>

      {/* 攻击类型 TOP 榜 */}
      <div className="dashboard-grid-3">
        <div className="card top-card">
          <div className="card-header">攻击类型 TOP 榜</div>
          <div className="card-body">
            {attackTop.length === 0 ? (
              <div className="empty-state"><div className="desc">暂无攻击数据</div></div>
            ) : (
              <div className="top-list">
                {attackTop.map((item, index) => (
                  <div key={item.attack_type} className="top-item">
                    <span className={`top-rank ${index < 3 ? 'top-rank-highlight' : ''}`}>{index + 1}</span>
                    <span className="top-name">{item.attack_type}</span>
                    <div className="top-bar-track">
                      <div className="top-bar-fill" style={{ width: `${(item.count / maxAttackCount) * 100}%` }} />
                    </div>
                    <span className="top-count">{item.count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* 来源 IP TOP 榜 */}
        <div className="card top-card">
          <div className="card-header">来源 IP TOP 榜</div>
          <div className="card-body">
            {sourceIpTop.length === 0 ? (
              <div className="empty-state"><div className="desc">暂无来源IP数据</div></div>
            ) : (
              <div className="top-list">
                {sourceIpTop.map((item: any, index) => (
                  <div key={item.source_ip} className="top-item">
                    <span className={`top-rank ${index < 3 ? 'top-rank-highlight' : ''}`}>{index + 1}</span>
                    <div className="top-name-wrap">
                      <code className="top-name">{item.source_ip}</code>
                      <IpLocation ip={item.source_ip || ''} />
                    </div>
                    <div className="top-bar-track">
                      <div className="top-bar-fill top-bar-fill-orange" style={{ width: `${(item.count / maxSourceIpCount) * 100}%` }} />
                    </div>
                    <span className="top-count">{item.count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* 目标 IP TOP 榜 */}
        <div className="card top-card">
          <div className="card-header">目标 IP TOP 榜</div>
          <div className="card-body">
            {targetIpTop.length === 0 ? (
              <div className="empty-state"><div className="desc">暂无目标IP数据</div></div>
            ) : (
              <div className="top-list">
                {targetIpTop.map((item: any, index) => (
                  <div key={item.target_ip} className="top-item">
                    <span className={`top-rank ${index < 3 ? 'top-rank-highlight' : ''}`}>{index + 1}</span>
                    <div className="top-name-wrap">
                      <code className="top-name">{item.target_ip}</code>
                      <IpLocation ip={item.target_ip || ''} />
                    </div>
                    <div className="top-bar-track">
                      <div className="top-bar-fill top-bar-fill-green" style={{ width: `${(item.count / maxSourceIpCount) * 100}%` }} />
                    </div>
                    <span className="top-count">{item.count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 近24小时趋势 + 设备分布 */}
      <div className="dashboard-grid-2">
        <div className="card hourly-card">
          <div className="card-header">近24小时告警分布</div>
          <div className="card-body">
            {hourlyTrend.length === 0 ? (
              <div className="empty-state"><div className="desc">暂无数据</div></div>
            ) : (
              <div className="hourly-chart">
                {hourlyTrend.map((item) => {
                  const pct = item.count > 0 ? Math.max((item.count / maxHourlyCount) * 100, 4) : 0;
                  return (
                    <div key={item.hour} className="hourly-bar-group" title={`${item.hour}: ${item.count}条`}>
                      {item.count > 0 && <div className="hourly-bar-value">{item.count}</div>}
                      <div className="hourly-bar" style={{ height: `${pct}%` }} />
                      <div className="hourly-bar-label">{item.hour}</div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header">设备告警分布</div>
          <div className="card-body">
            {deviceStats.length === 0 ? (
              <div className="empty-state"><div className="desc">暂无设备告警数据</div></div>
            ) : (
              <div className="top-list">
                {deviceStats.map((item) => (
                  <div key={item.device_name} className="top-item">
                    <span className="top-name">{item.device_name}</span>
                    <div className="top-bar-track">
                      <div className="top-bar-fill top-bar-fill-blue" style={{ width: `${(item.count / (Math.max(...deviceStats.map(d => d.count)) || 1)) * 100}%` }} />
                    </div>
                    <span className="top-count">{item.count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 最近事件 */}
      <div className="card recent-events-card">
        <div className="card-header">
          最近安全事件
          <button className="btn btn-secondary btn-sm" onClick={() => navigate('/events')}>
            查看全部
          </button>
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          {stats?.recentEvents && stats.recentEvents.length > 0 ? (
            <table className="table">
              <thead>
                <tr>
                  <th>时间</th>
                  <th>攻击类型</th>
                  <th>源IP</th>
                  <th>目标IP</th>
                  <th>设备</th>
                  <th>级别</th>
                </tr>
              </thead>
              <tbody>
                {stats.recentEvents.map((event: SecurityEvent) => (
                  <tr key={event.id} style={{ cursor: 'pointer' }} onClick={() => navigate(`/events/${event.id}`)}>
                    <td style={{ whiteSpace: 'nowrap' }}>{formatTime(event.timestamp)}</td>
                    <td>{event.attack_category || event.attack_type || '其他'}</td>
                    <td>
                      <div className="ip-cell">
                        <code>{event.source_ip}</code>
                        <IpLocation ip={event.source_ip || ''} />
                      </div>
                    </td>
                    <td>
                      <div className="ip-cell">
                        <code>{event.target_ip}</code>
                        <IpLocation ip={event.target_ip || ''} />
                      </div>
                    </td>
                    <td>{event.device_name}</td>
                    <td>
                      <span className={`badge ${severityConfig[event.severity]?.className || ''}`}>
                        {severityConfig[event.severity]?.label || event.severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="empty-state">
              <div className="icon">📭</div>
              <div className="title">暂无安全事件</div>
              <div className="desc">系统运行正常，未检测到安全威胁</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
