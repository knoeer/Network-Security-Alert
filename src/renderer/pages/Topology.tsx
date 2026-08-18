import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import type { Device, TopologyResult } from '../types/global';
import { deviceTypeLabels, statusConfig } from './device-utils';
import './Topology.css';

const Topology: React.FC = () => {
  const navigate = useNavigate();
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [topology, setTopology] = useState<TopologyResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [probing, setProbing] = useState(false);

  // 加载设备列表
  useEffect(() => {
    window.electronAPI?.getDevices().then((list) => {
      setDevices(list);
      setLoading(false);
      // 默认选中第一台在线设备
      const first = list.find((d) => d.status === 'online') || list[0];
      if (first) setSelectedId(first.id);
    });
  }, []);

  // 探测选中设备的拓扑
  const loadTopology = useCallback(async (id: number) => {
    if (!id) return;
    setProbing(true);
    try {
      const result = await window.electronAPI.probeTopology(id);
      setTopology(result);
    } catch (err) {
      console.error('拓扑探测失败:', err);
      setTopology(null);
    } finally {
      setProbing(false);
    }
  }, []);

  useEffect(() => {
    if (selectedId) loadTopology(selectedId);
  }, [selectedId, loadTopology]);

  const selectedDevice = devices.find((d) => d.id === selectedId);

  // 计算拓扑节点布局：中心设备 + ARP 邻居环绕
  const buildTopologyNodes = () => {
    if (!topology || !topology.success) return { nodes: [], links: [] };

    const center = {
      id: 'center',
      label: topology.deviceName,
      ip: topology.deviceIp,
      isCenter: true,
    };

    // ARP 邻居作为子节点（去重）
    const neighborMap = new Map<string, { ip: string; mac: string }>();
    for (const entry of topology.arp) {
      if (!neighborMap.has(entry.ip)) {
        neighborMap.set(entry.ip, { ip: entry.ip, mac: entry.mac });
      }
    }
    const neighbors = Array.from(neighborMap.values()).slice(0, 24); // 最多显示 24 个

    const nodes = [
      { ...center, x: 400, y: 220 },
      ...neighbors.map((n, i) => {
        const angle = (i / Math.max(neighbors.length, 1)) * Math.PI * 2 - Math.PI / 2;
        const radius = 180;
        return {
          id: `n${i}`,
          label: n.ip,
          ip: n.ip,
          mac: n.mac,
          isCenter: false,
          x: 400 + Math.cos(angle) * radius,
          y: 220 + Math.sin(angle) * radius,
        };
      }),
    ];

    const links = neighbors.map((n, i) => ({
      source: 400,
      sourceY: 220,
      target: nodes[i + 1].x,
      targetY: nodes[i + 1].y,
    }));

    return { nodes, links };
  };

  const { nodes, links } = buildTopologyNodes();

  return (
    <div className="topology-page">
      <div className="page-header">
        <h1>网络拓扑</h1>
        <span className="event-count-badge">基于路由表 / ARP 表</span>
      </div>

      {/* 设备选择器 */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-body" style={{ padding: '12px 16px' }}>
          <div className="topology-device-select">
            <label className="topology-select-label">选择设备：</label>
            <select
              className="select"
              value={selectedId ?? ''}
              onChange={(e) => setSelectedId(Number(e.target.value))}
              style={{ minWidth: 220 }}
            >
              {devices.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.name}（{d.ip}）{d.status === 'online' ? '· 在线' : '· 离线'}
                </option>
              ))}
            </select>
            <button
              className="btn btn-secondary"
              onClick={() => selectedId && loadTopology(selectedId)}
              disabled={probing}
            >
              {probing ? '探测中...' : '重新探测'}
            </button>
          </div>
        </div>
      </div>

      {loading ? (
        <div className="card"><div className="empty-state">
          <div className="spinner"></div><div className="title">加载中...</div>
        </div></div>
      ) : devices.length === 0 ? (
        <div className="card"><div className="empty-state">
          <div className="icon">🖥️</div>
          <div className="title">暂无设备</div>
          <div className="desc">请先在「设备管理」中添加 SNMP 设备</div>
          <button className="btn btn-primary" style={{ marginTop: 16 }} onClick={() => navigate('/devices')}>
            去添加设备
          </button>
        </div></div>
      ) : (
        <>
          {/* 拓扑可视化 */}
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header">
              拓扑视图
              {probing && <span className="spinner spinner-sm"></span>}
              {topology?.success && (
                <span className="topology-count">
                  {topology.arp.length} 个邻居 · {topology.routes.length} 条路由
                </span>
              )}
            </div>
            <div className="card-body">
              {!topology?.success ? (
                <div className="empty-state" style={{ padding: '32px 16px' }}>
                  <div className="icon">🔗</div>
                  <div className="title">暂无拓扑数据</div>
                  <div className="desc">
                    {topology?.message || '设备可能不在线，或 SNMP 不支持路由/ARP 表查询'}
                  </div>
                </div>
              ) : topology.arp.length === 0 ? (
                <div className="empty-state" style={{ padding: '32px 16px' }}>
                  <div className="icon">📭</div>
                  <div className="title">未发现邻居设备</div>
                  <div className="desc">该设备的 ARP 表为空，或未开启相关查询权限</div>
                </div>
              ) : (
                <div className="topology-canvas-wrap">
                  <svg className="topology-svg" viewBox="0 0 800 440">
                    {/* 连线 */}
                    {links.map((link, i) => (
                      <line
                        key={i}
                        x1={link.source}
                        y1={link.sourceY}
                        x2={link.target}
                        y2={link.targetY}
                        className="topology-link"
                      />
                    ))}
                    {/* 节点 */}
                    {nodes.map((node) =>
                      node.isCenter ? (
                        <g key={node.id} className="topology-node topology-node-center">
                          <circle cx={node.x} cy={node.y} r={42} className="topology-node-circle" />
                          <text x={node.x} y={node.y - 6} textAnchor="middle" className="topology-node-icon">🛡️</text>
                          <text x={node.x} y={node.y + 16} textAnchor="middle" className="topology-node-label">{node.label}</text>
                        </g>
                      ) : (
                        <g key={node.id} className="topology-node">
                          <circle cx={node.x} cy={node.y} r={26} className="topology-node-circle topology-node-circle-minor" />
                          <text x={node.x} y={node.y + 4} textAnchor="middle" className="topology-node-icon-minor">🖥️</text>
                          <text x={node.x} y={node.y + 40} textAnchor="middle" className="topology-node-label">{node.ip}</text>
                        </g>
                      )
                    )}
                  </svg>
                  {/* 中心设备信息 */}
                  <div className="topology-center-info">
                    <div className="topology-center-name">{topology.deviceName}</div>
                    <code>{topology.deviceIp}</code>
                    {selectedDevice && (
                      <div className="topology-center-type">
                        {deviceTypeLabels[selectedDevice.device_type] || selectedDevice.device_type}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* 路由表 + ARP 表 */}
          {topology?.success && (
            <div className="topology-tables">
              <div className="card">
                <div className="card-header">路由表（{topology.routes.length} 条）</div>
                <div className="card-body" style={{ padding: 0 }}>
                  {topology.routes.length === 0 ? (
                    <div className="empty-state" style={{ padding: '20px 16px' }}>
                      <div className="desc">无路由记录</div>
                    </div>
                  ) : (
                    <table className="table">
                      <thead>
                        <tr>
                          <th>目的网络</th>
                          <th>下一跳</th>
                          <th>类型</th>
                          <th>接口索引</th>
                          <th>度量值</th>
                        </tr>
                      </thead>
                      <tbody>
                        {topology.routes.map((r, i) => (
                          <tr key={i}>
                            <td><code>{r.destination || '0.0.0.0/0'}</code></td>
                            <td><code>{r.nextHop || '-'}</code></td>
                            <td>{r.type}</td>
                            <td>{r.ifIndex}</td>
                            <td>{r.metric}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>

              <div className="card">
                <div className="card-header">ARP 表（{topology.arp.length} 条）</div>
                <div className="card-body" style={{ padding: 0 }}>
                  {topology.arp.length === 0 ? (
                    <div className="empty-state" style={{ padding: '20px 16px' }}>
                      <div className="desc">无 ARP 记录</div>
                    </div>
                  ) : (
                    <table className="table">
                      <thead>
                        <tr>
                          <th>IP 地址</th>
                          <th>MAC 地址</th>
                          <th>类型</th>
                          <th>接口索引</th>
                        </tr>
                      </thead>
                      <tbody>
                        {topology.arp.map((a, i) => (
                          <tr key={i}>
                            <td><code>{a.ip}</code></td>
                            <td><code>{a.mac}</code></td>
                            <td>{a.type}</td>
                            <td>{a.ifIndex}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default Topology;
