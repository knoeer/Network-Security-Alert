import { useEffect, useRef, useState } from 'react';
import type { AlertData } from '../types/global';

/**
 * 监听主进程推送的告警事件
 * 返回最新的告警数据（用于在主窗口显示实时提醒）
 */
export function useAlertListener() {
  const [latestAlert, setLatestAlert] = useState<AlertData | null>(null);
  const [alertCount, setAlertCount] = useState(0);
  const callbackRef = useRef<((data: AlertData) => void) | null>(null);

  useEffect(() => {
    if (!window.electronAPI?.onAlertReceived) return;

    window.electronAPI.onAlertReceived((data) => {
      const alert = data as AlertData;
      setLatestAlert(alert);
      setAlertCount(prev => prev + 1);

      // 调用自定义回调
      if (callbackRef.current) {
        callbackRef.current(alert);
      }
    });
  }, []);

  const onAlert = (callback: (data: AlertData) => void) => {
    callbackRef.current = callback;
  };

  const clearLatestAlert = () => {
    setLatestAlert(null);
  };

  return { latestAlert, alertCount, onAlert, clearLatestAlert };
}
