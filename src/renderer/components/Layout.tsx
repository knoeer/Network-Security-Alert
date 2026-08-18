import React, { useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { useAlertListener } from '../hooks/useAlertListener';
import AlertBanner from './AlertBanner';
import type { AlertData } from '../types/global';
import iconLogo from '../assets/icon.png';
import './Layout.css';

const Layout: React.FC = () => {
  const navigate = useNavigate();
  const { latestAlert } = useAlertListener();
  const [collapsed, setCollapsed] = useState(false);
  const [bannerAlerts, setBannerAlerts] = useState<AlertData[]>([]);
  const [trapStatus, setTrapStatus] = useState<{ status: string; port: number }>({ status: 'stopped', port: 162 });
  const [syslogStatus, setSyslogStatus] = useState<{ status: string; port: number }>({ status: 'stopped', port: 514 });
  const [unackCount, setUnackCount] = useState(0);

  // 获取未确认事件数量（侧边栏红色徽标）
  const loadUnackCount = async () => {
    try {
      const count = await window.electronAPI.getUnacknowledgedCount();
      setUnackCount(count);
    } catch (err) {
      console.error('获取未确认事件数失败:', err);
    }
  };

  // 获取 Trap 和 Syslog 状态
  const loadStatus = async () => {
    try {
      const [trap, syslog] = await Promise.all([
        window.electronAPI.getTrapStatus(),
        window.electronAPI.getSyslogStatus(),
      ]);
      setTrapStatus(trap);
      setSyslogStatus(syslog);
    } catch (err) {
      console.error('获取状态失败:', err);
    }
  };

  // 初始加载未确认事件数
  React.useEffect(() => {
    loadUnackCount();
    const timer = setInterval(loadUnackCount, 2000);
    return () => clearInterval(timer);
  }, []);

  // 监听未确认事件数变化（确认/删除事件后实时刷新）
  React.useEffect(() => {
    window.electronAPI?.onUnacknowledgedChanged(() => {
      loadUnackCount();
    });
  }, []);

  // 定时轮询状态（每 2 秒）
  React.useEffect(() => {
    loadStatus();
    const timer = setInterval(loadStatus, 2000);
    return () => clearInterval(timer);
  }, []);

  // 监听托盘操作引起的状态变化，实时刷新
  React.useEffect(() => {
    window.electronAPI?.onListenerStatusChanged((status) => {
      const st = status as { trap: { status: string; port: number }; syslog: { status: string; port: number } };
      setTrapStatus(st.trap);
      setSyslogStatus(st.syslog);
    });
  }, []);

  // 监听新的告警，添加到横幅队列 + 刷新未确认数
  React.useEffect(() => {
    if (latestAlert) {
      setBannerAlerts(prev => [...prev, latestAlert]);
      loadUnackCount();
      // 5秒后自动清除
      const timer = setTimeout(() => {
        setBannerAlerts(prev => prev.slice(1));
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [latestAlert]);

  const isTrapRunning = trapStatus.status === 'running';
  const isSyslogRunning = syslogStatus.status === 'running';

  const navItems = [
    { path: '/dashboard', label: '仪表盘', icon: '📊' },
    { path: '/events', label: '安全事件', icon: '🛡️' },
    { path: '/devices', label: '设备管理', icon: '🖥️' },
    { path: '/topology', label: '网络拓扑', icon: '🔗' },
    { path: '/settings', label: '系统设置', icon: '⚙️' },
  ];

  return (
    <div className="layout">
      {/* 实时告警横幅 */}
      {bannerAlerts.map((alert, index) => (
        <AlertBanner
          key={`${alert.timestamp}-${index}`}
          alert={alert}
          onClose={() => setBannerAlerts(prev => prev.filter((_, i) => i !== index))}
        />
      ))}

      {/* Sidebar */}
      <aside className={`sidebar ${collapsed ? 'sidebar-collapsed' : ''}`}>
        <div className="sidebar-header" onClick={() => !collapsed && navigate('/dashboard')}>
          <div className="sidebar-logo">
            <img src={iconLogo} alt="LOGO" className="sidebar-logo-img" />
          </div>
          <div className="sidebar-title">
            <span className="sidebar-title-main">SNMP安全告警</span>
            <span className="sidebar-title-sub">Network Security Alert</span>
          </div>
        </div>

        <nav className="sidebar-nav">
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              title={item.label}
              className={({ isActive }) =>
                `nav-item ${isActive ? 'nav-item-active' : ''}`
              }
              onClick={(e) => {
                // 拦截 Ctrl/Cmd/中键点击，防止触发浏览器"新窗口打开"从而误开多个软件实例
                if (e.ctrlKey || e.metaKey || e.button === 1 || e.shiftKey) {
                  e.preventDefault();
                  navigate(item.path);
                }
              }}
            >
              <span className="nav-icon">{item.icon}</span>
              <span className="nav-label">{item.label}</span>
              {item.path === '/events' && unackCount > 0 && (
                <span className="nav-badge">{unackCount > 99 ? '99+' : unackCount}</span>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="trap-status">
            <span className={`status-dot ${isTrapRunning ? 'status-dot-online' : 'status-dot-offline'}`}></span>
            <span>
              {isTrapRunning ? `SNMP Trap (${trapStatus.port})` : 'SNMP Trap 未启动'}
            </span>
          </div>
          <div className="trap-status" style={{ marginTop: 6 }}>
            <span className={`status-dot ${isSyslogRunning ? 'status-dot-online' : 'status-dot-offline'}`}></span>
            <span>
              {isSyslogRunning ? `Syslog (${syslogStatus.port})` : 'Syslog 未启动'}
            </span>
          </div>
        </div>

        {/* 收起/展开按钮 */}
        <button
          className="sidebar-collapse-btn"
          onClick={() => setCollapsed(!collapsed)}
          title={collapsed ? '展开菜单' : '收起菜单'}
        >
          <span className="collapse-icon">{collapsed ? '»' : '«'}</span>
          <span className="collapse-label">{collapsed ? '展开' : '收起'}</span>
        </button>
      </aside>

      {/* Main Content */}
      <div className="main-area">
        <header className="top-bar">
          <div className="top-bar-left">
            <h2 className="page-title">SNMP安全告警系统</h2>
          </div>
          <div className="top-bar-right">
            <button className="btn btn-sm btn-secondary" onClick={() => window.electronAPI?.minimizeToTray()}>
              最小化到托盘
            </button>
          </div>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default Layout;
