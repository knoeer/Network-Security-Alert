import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import type { Device, DeviceInfo } from '../types/global';
import { deviceTypeLabels, formatTime } from './device-utils';
import './DeviceManager.css';

interface DeviceFormData {
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
}

const defaultFormData: DeviceFormData = {
  name: '',
  ip: '',
  port: 161,
  snmp_version: 'v2c',
  community: 'public',
  snmp_username: '',
  snmp_auth_protocol: 'sha',
  snmp_auth_key: '',
  snmp_priv_protocol: 'aes',
  snmp_priv_key: '',
  device_type: 'firewall',
  location: '',
  description: '',
};

const DeviceManager: React.FC = () => {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [formData, setFormData] = useState<DeviceFormData>(defaultFormData);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [testInfo, setTestInfo] = useState<DeviceInfo | null>(null);
  const [saving, setSaving] = useState(false);
  const [checking, setChecking] = useState(false);
  const [checkingId, setCheckingId] = useState<number | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    loadDevices();
    // 设备离线监测状态变化时自动刷新列表
    const unsub = window.electronAPI?.onDeviceStatusChanged?.((data) => {
      const { id, status } = data;
      const newStatus: Device['status'] = status === 'online' || status === 'offline' ? status : 'unknown';
      setDevices(prev => prev.map(d => {
        if (d.id === id) {
          return { ...d, status: newStatus, last_checked: new Date().toISOString() };
        }
        return d;
      }));
    });
    return () => {
      if (typeof unsub === 'function') unsub();
    };
  }, []);

  const loadDevices = async () => {
    try {
      setLoading(true);
      const data = await window.electronAPI.getDevices();
      setDevices(data);
    } catch (err) {
      console.error('Failed to load devices:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleAdd = () => {
    setEditingId(null);
    setFormData(defaultFormData);
    setTestResult(null);
    setTestInfo(null);
    setShowForm(true);
  };

  const handleEdit = (device: Device) => {
    setEditingId(device.id);
    setFormData({
      name: device.name,
      ip: device.ip,
      port: device.port,
      snmp_version: device.snmp_version,
      community: device.community,
      snmp_username: device.snmp_username || '',
      snmp_auth_protocol: device.snmp_auth_protocol || 'sha',
      snmp_auth_key: device.snmp_auth_key || '',
      snmp_priv_protocol: device.snmp_priv_protocol || 'aes',
      snmp_priv_key: device.snmp_priv_key || '',
      device_type: device.device_type,
      location: device.location,
      description: device.description,
    });
    setTestResult(null);
    setTestInfo(null);
    setShowForm(true);
  };

  const handleSave = async () => {
    if (!formData.name || !formData.ip) {
      alert('请填写设备名称和IP地址');
      return;
    }

    // 简单的 IP 格式校验
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipPattern.test(formData.ip)) {
      alert('请输入有效的IP地址');
      return;
    }

    // SNMPv3 必须填写用户名
    if (formData.snmp_version === 'v3' && !formData.snmp_username.trim()) {
      alert('SNMPv3 必须填写用户名');
      return;
    }

    try {
      setSaving(true);
      if (editingId) {
        await window.electronAPI.updateDevice({ ...formData, id: editingId });
      } else {
        await window.electronAPI.addDevice(formData);
      }
      setShowForm(false);
      loadDevices();
    } catch (err) {
      console.error('Failed to save device:', err);
      alert('保存失败');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (device: Device) => {
    if (!confirm(`确定要删除设备 "${device.name}" 吗？`)) return;
    try {
      await window.electronAPI.deleteDevice(device.id);
      loadDevices();
    } catch (err) {
      console.error('Failed to delete device:', err);
    }
  };

  // 测试连接（SNMP 探测）
  const handleTest = async () => {
    if (!formData.ip) {
      alert('请先填写IP地址');
      return;
    }
    setTestResult('正在探测...');
    setTestInfo(null);
    try {
      const result = await window.electronAPI.testDeviceConnection(formData);
      setTestResult(result.message);
      if (result.info) {
        setTestInfo(result.info);
      }
    } catch (err) {
      setTestResult('测试失败');
    }
  };

  // 探测单个设备（列表中的设备）
  const handleProbe = async (device: Device) => {
    setCheckingId(device.id);
    try {
      await window.electronAPI.probeDevice(device.id);
      loadDevices();
    } catch (err) {
      console.error('探测失败:', err);
    } finally {
      setCheckingId(null);
    }
  };

  // 批量检查所有设备
  const handleCheckAll = async () => {
    if (devices.length === 0) return;
    setChecking(true);
    try {
      const result = await window.electronAPI.checkAllDevices();
      alert(`检查完成：共 ${result.total} 台设备，在线 ${result.online} 台，离线 ${result.offline} 台`);
      loadDevices();
    } catch (err) {
      console.error('批量检查失败:', err);
      alert('批量检查失败');
    } finally {
      setChecking(false);
    }
  };

  // 查看设备详情（跳转详情页）
  const handleViewDetail = (device: Device) => {
    navigate(`/devices/${device.id}`);
  };

  const statusConfig: Record<string, { label: string; dotClass: string }> = {
    online: { label: '在线', dotClass: 'status-dot-online' },
    offline: { label: '离线', dotClass: 'status-dot-offline' },
    unknown: { label: '未知', dotClass: 'status-dot-offline' },
  };

  return (
    <div className="device-manager-page">
      <div className="page-header">
        <h1>设备管理</h1>
        <div className="page-header-actions">
          <button
            className="btn btn-secondary"
            onClick={handleCheckAll}
            disabled={checking || devices.length === 0}
          >
            {checking ? '检查中...' : '检查所有设备'}
          </button>
          <button className="btn btn-primary" onClick={handleAdd}>
            + 添加设备
          </button>
        </div>
      </div>

      {/* 设备列表 */}
      <div className="card">
        <div className="card-body" style={{ padding: 0 }}>
          {loading ? (
            <div className="empty-state">
              <div className="spinner"></div>
              <div className="title">加载中...</div>
            </div>
          ) : devices.length === 0 ? (
            <div className="empty-state">
              <div className="icon">🖥️</div>
              <div className="title">暂无设备</div>
              <div className="desc">点击"添加设备"开始监控安全设备</div>
              <button className="btn btn-primary" style={{ marginTop: 16 }} onClick={handleAdd}>
                + 添加设备
              </button>
            </div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>设备名称</th>
                  <th>IP地址</th>
                  <th>端口</th>
                  <th>SNMP版本</th>
                  <th>设备类型</th>
                  <th>状态</th>
                  <th>最后检查</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {devices.map(device => {
                  const status = statusConfig[device.status] || statusConfig.unknown;
                  return (
                    <tr
                      key={device.id}
                      className="device-row"
                      onClick={() => handleViewDetail(device)}
                    >
                      <td><strong>{device.name}</strong></td>
                      <td><code>{device.ip}</code></td>
                      <td>{device.port}</td>
                      <td>{device.snmp_version}</td>
                      <td>{deviceTypeLabels[device.device_type] || device.device_type}</td>
                      <td>
                        <span className="status-indicator">
                          <span className={`status-dot ${status.dotClass}`}></span>
                          {status.label}
                        </span>
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>
                        {formatTime(device.last_checked)}
                      </td>
                      <td onClick={e => e.stopPropagation()}>
                        <div className="action-btns">
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => handleViewDetail(device)}
                          >
                            详情
                          </button>
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => handleProbe(device)}
                            disabled={checkingId === device.id}
                          >
                            {checkingId === device.id ? '探测中...' : '探测'}
                          </button>
                          <button className="btn btn-secondary btn-sm" onClick={() => handleEdit(device)}>
                            编辑
                          </button>
                          <button className="btn btn-danger btn-sm" onClick={() => handleDelete(device)}>
                            删除
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* 添加/编辑弹窗 */}
      {showForm && (
        <div className="modal-overlay" onClick={() => setShowForm(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>{editingId ? '编辑设备' : '添加设备'}</h3>
              <button className="modal-close" onClick={() => setShowForm(false)}>✕</button>
            </div>
            <div className="modal-body">
              <div className="form-grid">
                <div className="form-group">
                  <label>设备名称 *</label>
                  <input className="input" value={formData.name}
                    onChange={e => setFormData({ ...formData, name: e.target.value })}
                    placeholder="例如：核心防火墙-01" />
                </div>
                <div className="form-group">
                  <label>IP地址 *</label>
                  <input className="input" value={formData.ip}
                    onChange={e => setFormData({ ...formData, ip: e.target.value })}
                    placeholder="例如：192.168.1.1" />
                </div>
                <div className="form-group">
                  <label>端口</label>
                  <input className="input" type="number" value={formData.port}
                    onChange={e => setFormData({ ...formData, port: Number(e.target.value) })} />
                </div>
                <div className="form-group">
                  <label>SNMP版本</label>
                  <select className="select" value={formData.snmp_version}
                    onChange={e => setFormData({ ...formData, snmp_version: e.target.value as DeviceFormData['snmp_version'] })}>
                    <option value="v1">v1</option>
                    <option value="v2c">v2c</option>
                    <option value="v3">v3</option>
                  </select>
                </div>
                {formData.snmp_version === 'v3' ? (
                  <>
                    <div className="form-group">
                      <label>用户名 *</label>
                      <input className="input" value={formData.snmp_username}
                        onChange={e => setFormData({ ...formData, snmp_username: e.target.value })}
                        placeholder="SNMPv3 用户名" />
                    </div>
                    <div className="form-group">
                      <label>认证协议</label>
                      <select className="select" value={formData.snmp_auth_protocol}
                        onChange={e => setFormData({ ...formData, snmp_auth_protocol: e.target.value as DeviceFormData['snmp_auth_protocol'] })}>
                        <option value="none">无认证</option>
                        <option value="md5">MD5</option>
                        <option value="sha">SHA</option>
                        <option value="sha224">SHA-224</option>
                        <option value="sha256">SHA-256</option>
                        <option value="sha384">SHA-384</option>
                        <option value="sha512">SHA-512</option>
                      </select>
                    </div>
                    <div className="form-group">
                      <label>认证密码</label>
                      <input className="input" type="password" value={formData.snmp_auth_key}
                        onChange={e => setFormData({ ...formData, snmp_auth_key: e.target.value })}
                        placeholder="认证密码" />
                    </div>
                    <div className="form-group">
                      <label>加密协议</label>
                      <select className="select" value={formData.snmp_priv_protocol}
                        onChange={e => setFormData({ ...formData, snmp_priv_protocol: e.target.value as DeviceFormData['snmp_priv_protocol'] })}>
                        <option value="none">不加密</option>
                        <option value="des">DES</option>
                        <option value="aes">AES</option>
                        <option value="aes256b">AES-256-B</option>
                        <option value="aes256r">AES-256-R</option>
                      </select>
                    </div>
                    <div className="form-group">
                      <label>加密密码</label>
                      <input className="input" type="password" value={formData.snmp_priv_key}
                        onChange={e => setFormData({ ...formData, snmp_priv_key: e.target.value })}
                        placeholder="加密密码" />
                    </div>
                  </>
                ) : (
                  <div className="form-group">
                    <label>Community</label>
                    <input className="input" value={formData.community}
                      onChange={e => setFormData({ ...formData, community: e.target.value })} />
                  </div>
                )}
                <div className="form-group">
                  <label>设备类型</label>
                  <select className="select" value={formData.device_type}
                    onChange={e => setFormData({ ...formData, device_type: e.target.value })}>
                    <option value="firewall">防火墙</option>
                    <option value="router">路由器</option>
                    <option value="switch">交换机</option>
                    <option value="ids">入侵检测系统(IDS)</option>
                    <option value="ips">入侵防御系统(IPS)</option>
                    <option value="other">其他</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>位置</label>
                  <input className="input" value={formData.location}
                    onChange={e => setFormData({ ...formData, location: e.target.value })}
                    placeholder="例如：数据中心A区" />
                </div>
                <div className="form-group form-group-full">
                  <label>描述</label>
                  <textarea className="input" value={formData.description}
                    onChange={e => setFormData({ ...formData, description: e.target.value })}
                    rows={2} placeholder="设备描述信息" />
                </div>
              </div>
              {testResult && (
                <div className={`test-result ${testResult.includes('在线') || testResult.includes('成功') ? 'test-success' : 'test-fail'}`}>
                  {testResult}
                </div>
              )}
              {testInfo && (
                <div className="device-info-preview">
                  <div className="info-title">设备系统信息</div>
                  {testInfo.sysName && <div><label>系统名称：</label>{testInfo.sysName}</div>}
                  {testInfo.sysDescr && <div><label>系统描述：</label>{testInfo.sysDescr}</div>}
                  {testInfo.sysUpTime && <div><label>运行时间：</label>{testInfo.sysUpTime}</div>}
                </div>
              )}
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={handleTest}>测试连接</button>
              <div className="modal-footer-right">
                <button className="btn btn-secondary" onClick={() => setShowForm(false)}>取消</button>
                <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
                  {saving ? '保存中...' : '保存'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};

export default DeviceManager;
