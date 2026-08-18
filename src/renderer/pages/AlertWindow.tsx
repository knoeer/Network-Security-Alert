import React, { useEffect, useState } from 'react';
import IpLocation from '../components/IpLocation';
import './AlertWindow.css';

interface AlertData {
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
  sourceAttackCount?: number;
  sourceAttackCountToday?: number;
  attackCategory?: string;
}

const AlertWindow: React.FC = () => {
  const [alertData, setAlertData] = useState<AlertData | null>(null);
  const [isFlashing, setIsFlashing] = useState(true);
  const [countdown, setCountdown] = useState<number | null>(null);

  useEffect(() => {
    // 从 URL hash 解析告警数据（Base64 编码，避免 URLSearchParams 二次解码）
    const hash = window.location.hash;
    const queryStr = hash.split('?')[1] || '';
    // 用正则提取 data 参数，避免 URLSearchParams 再次解码
    const match = queryStr.match(/data=([^&]+)/);
    const encoded = match ? match[1] : '';
    if (encoded) {
      try {
        // Base64 → 字节 → UTF-8 字符串（避免 atob 把 UTF-8 多字节当 Latin-1 字符造成乱码）
        const binary = atob(decodeURIComponent(encoded));
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
          bytes[i] = binary.charCodeAt(i);
        }
        const jsonStr = new TextDecoder('utf-8').decode(bytes);
        const data = JSON.parse(jsonStr);
        setAlertData(data);
      } catch (e) {
        console.error('Failed to parse alert data:', e);
      }
    }

    // 播放告警提示音（Web Audio API）
    playAlertTone();

    // 闪烁效果持续 15 秒
    const flashTimer = setTimeout(() => setIsFlashing(false), 15000);

    // 读取告警配置（是否自动关闭、秒数）
    let autoCloseTimer: ReturnType<typeof setTimeout> | null = null;
    let countdownInterval: ReturnType<typeof setInterval> | null = null;

    window.electronAPI?.getAlertConfig().then((config) => {
      // 仅在启用自动关闭时启动倒计时
      if (config.autoClose) {
        const seconds = config.seconds > 0 ? config.seconds : 30;
        setCountdown(seconds);

        countdownInterval = setInterval(() => {
          setCountdown(prev => {
            if (prev === null) return prev;
            if (prev <= 1) {
              if (countdownInterval) clearInterval(countdownInterval);
              window.electronAPI?.closeAlertSingle();
              return 0;
            }
            return prev - 1;
          });
        }, 1000);

        autoCloseTimer = setTimeout(() => {
          window.electronAPI?.closeAlertSingle();
        }, seconds * 1000);
      } else {
        // 不自动关闭
        setCountdown(null);
      }
    });

    return () => {
      clearTimeout(flashTimer);
      if (autoCloseTimer) clearTimeout(autoCloseTimer);
      if (countdownInterval) clearInterval(countdownInterval);
    };
  }, []);

  /**
   * 使用 Web Audio API 播放告警音效
   */
  const playAlertTone = () => {
    try {
      const AudioContext = window.AudioContext || (window as any).webkitAudioContext;
      if (!AudioContext) return;
      const ctx = new AudioContext();
      // 播放三声急促的提示音（根据严重级别）
      const beepCount = alertData?.severity === 'critical' ? 3 : alertData?.severity === 'high' ? 2 : 1;
      for (let i = 0; i < beepCount; i++) {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.type = 'sine';
        osc.frequency.value = alertData?.severity === 'critical' ? 660 : 880;
        const startTime = ctx.currentTime + i * 0.25;
        gain.gain.setValueAtTime(0, startTime);
        gain.gain.linearRampToValueAtTime(0.6, startTime + 0.02);
        gain.gain.linearRampToValueAtTime(0, startTime + 0.2);
        osc.start(startTime);
        osc.stop(startTime + 0.2);
      }
    } catch (e) {
      console.error('播放提示音失败:', e);
    }
  };

  // 叉号：一键关闭所有弹窗
  const handleCloseAll = () => {
    window.electronAPI?.closeAlert();
  };

  // 确认并关闭：只关闭当前弹窗
  const handleConfirmClose = () => {
    window.electronAPI?.closeAlertSingle();
  };

  const severityConfig: Record<string, { label: string; icon: string; className: string }> = {
    critical: { label: '严重', icon: '🔴', className: 'severity-critical' },
    high: { label: '高危', icon: '🟠', className: 'severity-high' },
    medium: { label: '中等', icon: '🟡', className: 'severity-medium' },
    low: { label: '低危', icon: '🟢', className: 'severity-low' },
  };

  const severity = alertData ? (severityConfig[alertData.severity] || severityConfig.medium) : null;

  return (
    <div className={`alert-window ${isFlashing ? 'flash' : ''}`}>
      {/* 顶部标题栏 */}
      <div className="alert-titlebar">
        <div className="alert-titlebar-left">
          <span className="alert-icon">⚠️</span>
          <span>安全告警</span>
        </div>
        <div className="alert-titlebar-right">
          {countdown !== null && (
            <span className="alert-countdown">{countdown}s</span>
          )}
          <button className="alert-close-btn" onClick={handleCloseAll} title="关闭所有弹窗">✕</button>
        </div>
      </div>

      {alertData && severity ? (
        <div className="alert-body">
          {/* 严重级别徽标 + 攻击类型 */}
          <div className="alert-head">
            <span className={`alert-severity-badge ${severity.className}`}>
              {severity.icon} {severity.label}
            </span>
            <div className="alert-attack-type">
              {alertData.attackCategory || alertData.attackType || '其他'}
            </div>
          </div>

          {/* 关键信息 */}
          <div className="alert-info-grid">
            <div className="alert-info-item">
              <label>源地址</label>
              <div className="alert-source-wrap">
                <code>{alertData.sourceIp}{alertData.sourcePort ? `:${alertData.sourcePort}` : ''}</code>
                <IpLocation ip={alertData.sourceIp} />
                {alertData.sourceAttackCount !== undefined && alertData.sourceAttackCount > 0 && (
                  <span className="alert-attack-count" title={`该源地址近24小时攻击 ${alertData.sourceAttackCountToday ?? 0} 次`}>
                    攻击 {alertData.sourceAttackCount} 次
                    {alertData.sourceAttackCountToday ? `（今日 ${alertData.sourceAttackCountToday}）` : ''}
                  </span>
                )}
              </div>
            </div>
            <div className="alert-info-item">
              <label>目标地址</label>
              <div className="alert-source-wrap">
                <code>{alertData.targetIp}{alertData.targetPort ? `:${alertData.targetPort}` : ''}</code>
                <IpLocation ip={alertData.targetIp} />
              </div>
            </div>
            <div className="alert-info-item">
              <label>设备名称</label>
              <span>{alertData.deviceName}</span>
            </div>
            <div className="alert-info-item">
              <label>发生时间</label>
              <span>{new Date(alertData.timestamp).toLocaleString('zh-CN')}</span>
            </div>
          </div>

          {/* 描述 */}
          {alertData.description && (
            <div className="alert-desc">
              <div className="alert-desc-label">事件描述</div>
              <div className="alert-desc-content">{alertData.description}</div>
            </div>
          )}
        </div>
      ) : (
        <div className="alert-body">
          <div className="empty-state">
            <div className="icon">⚠️</div>
            <div className="title">告警数据加载中...</div>
          </div>
        </div>
      )}

      {/* 底部按钮 */}
      <div className="alert-footer">
        <button className="btn btn-primary btn-sm" onClick={handleConfirmClose}>
          确认并关闭
        </button>
      </div>
    </div>
  );
};

export default AlertWindow;
