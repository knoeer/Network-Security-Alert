import React, { useEffect, useState } from 'react';
import type { IpLocation } from '../types/global';
import './IpLocation.css';

interface IpLocationProps {
  ip: string;
  className?: string;
}

// 前端内存缓存：同一会话内同一 IP 只查询一次，避免重复 IPC 调用（列表刷新/搜索重载时大幅减少查询）
const locCache = new Map<string, { display: string; source: IpLocation['source'] }>();

/**
 * IP 属地徽标组件
 * 异步查询 IP 归属地（离线库为主），并展示为小徽标
 * 内网 IP 显示"内网"，查询失败显示"未知"，不影响主流程
 */
const IpLocation: React.FC<IpLocationProps> = ({ ip, className }) => {
  const [loc, setLoc] = useState<IpLocation | null>(null);
  const [display, setDisplay] = useState<string>('');

  useEffect(() => {
    let cancelled = false;
    const cleanIp = (ip || '').trim();
    if (!cleanIp) {
      setLoc(null);
      setDisplay('');
      return;
    }
    // 内网 IP 直接显示内网，无需 IPC 查询
    if (/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/.test(cleanIp)) {
      setLoc({ country: '', province: '', city: '内网', isp: '', source: 'private', display: '内网' });
      setDisplay('内网');
      return;
    }
    // 命中前端缓存则直接复用，避免重复 IPC 调用
    const cached = locCache.get(cleanIp);
    if (cached) {
      setLoc({ country: '', province: '', city: cached.display, isp: '', source: cached.source, display: cached.display });
      setDisplay(cached.display);
      return;
    }
    setDisplay('');
    window.electronAPI
      .queryLocation(cleanIp)
      .then((result) => {
        if (cancelled) return;
        const display = result.display || '';
        locCache.set(cleanIp, { display, source: result.source || '' });
        setLoc(result);
        setDisplay(display);
      })
      .catch(() => {
        if (cancelled) return;
        setDisplay('');
      });
    return () => {
      cancelled = true;
    };
  }, [ip]);

  if (!display) return null;

  const isPrivate = loc?.source === 'private';

  return (
    <span className={`ip-loc-badge ${isPrivate ? 'ip-loc-private' : ''} ${className || ''}`} title={display}>
      📍 {display}
    </span>
  );
};

export default IpLocation;
