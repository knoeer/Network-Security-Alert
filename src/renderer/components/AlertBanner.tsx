import React, { useEffect, useState } from 'react';
import type { AlertData } from '../types/global';
import './AlertBanner.css';

interface AlertBannerProps {
  alert: AlertData;
  onClose: () => void;
}

/**
 * 主窗口内的实时告警通知横幅
 * 显示最新的告警信息，可点击查看详情
 */
const AlertBanner: React.FC<AlertBannerProps> = ({ alert, onClose }) => {
  const [visible, setVisible] = useState(true);
  const [isFlashing, setIsFlashing] = useState(true);

  useEffect(() => {
    // 闪烁 8 秒
    const flashTimer = setTimeout(() => setIsFlashing(false), 8000);
    // 30 秒后自动隐藏
    const hideTimer = setTimeout(() => setVisible(false), 30000);

    return () => {
      clearTimeout(flashTimer);
      clearTimeout(hideTimer);
    };
  }, []);

  if (!visible) return null;

  const severityConfig: Record<string, { label: string; className: string }> = {
    critical: { label: '严重', className: 'banner-critical' },
    high: { label: '高危', className: 'banner-high' },
    medium: { label: '中等', className: 'banner-medium' },
    low: { label: '低危', className: 'banner-low' },
  };

  const severity = severityConfig[alert.severity] || severityConfig.medium;

  return (
    <div className={`alert-banner ${severity.className} ${isFlashing ? 'flashing' : ''}`}>
      <div className="alert-banner-icon">⚠️</div>
      <div className="alert-banner-content">
        <div className="alert-banner-title">
          <span className="alert-banner-badge">{severity.label}</span>
          <span className="alert-banner-attack">{alert.attackType}</span>
        </div>
        <div className="alert-banner-detail">
          <code>{alert.sourceIp}</code>
          <span className="arrow">→</span>
          <code>{alert.targetIp}</code>
          <span className="divider">|</span>
          <span>{alert.deviceName}</span>
          <span className="divider">|</span>
          <span>{new Date(alert.timestamp).toLocaleTimeString('zh-CN')}</span>
        </div>
      </div>
      <button className="alert-banner-close" onClick={onClose}>✕</button>
    </div>
  );
};

export default AlertBanner;
