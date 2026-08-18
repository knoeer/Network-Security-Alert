/**
 * Syslog 接收服务
 * 监听 UDP 端口（默认 514），接收防火墙的 Syslog 日志
 */
import * as dgram from 'dgram';
import { parseSyslog, isThreatLog } from './syslog-parser';
import { findDeviceName, processAlert, saveAlertToDatabase, notifyWindows } from './alert-common';
import { saveRawLog } from './raw-logger';

let server: dgram.Socket | null = null;
let currentPort = 514;
let isRunning = false;

// 最近收到的日志（最多保留 50 条），用于调试面板
const recentLogs: Array<{ time: string; source: string; content: string; isThreat: boolean }> = [];
const MAX_LOGS = 50;

function addLog(source: string, content: string, isThreat: boolean): void {
  recentLogs.unshift({
    time: new Date().toISOString(),
    source,
    content: content.length > 500 ? content.slice(0, 500) + '...' : content,
    isThreat,
  });
  if (recentLogs.length > MAX_LOGS) {
    recentLogs.pop();
  }
}

/**
 * 获取最近收到的 Syslog 日志（调试用）
 */
export function getRecentLogs(): typeof recentLogs {
  return recentLogs;
}

/**
 * 清空调试日志
 */
export function clearRecentLogs(): void {
  recentLogs.length = 0;
}

/**
 * 处理收到的 Syslog 消息
 */
function handleMessage(msg: Buffer, rinfo: dgram.RemoteInfo): void {
  try {
    const rawMessage = msg.toString('utf8').trim();
    if (!rawMessage) return;

    const sourceAddress = rinfo.address;
    const threat = isThreatLog(rawMessage);

    // 保存原始报文（调试用途，原样保存不修改）
    saveRawLog('syslog', rawMessage, sourceAddress);

    // 记录到日志（用于调试面板）
    addLog(sourceAddress, rawMessage, threat);

    // 调试：打印所有收到的日志（方便排查威胁日志格式）
    console.log(`[Syslog] 来自 ${sourceAddress}:${rinfo.port}${threat ? ' [威胁]' : ''} | ${rawMessage.slice(0, 200)}${rawMessage.length > 200 ? '...' : ''}`);

    // 只处理安全威胁日志，过滤普通系统日志
    if (!threat) {
      return;
    }

    // 解析为告警数据
    const alert = parseSyslog(rawMessage, sourceAddress);

    // 保存原始报文（真正收到的原始数据，不做任何修改）
    alert.rawMessage = rawMessage;

    // 查找设备名称
    alert.deviceName = findDeviceName(sourceAddress);

    // 策略类日志（策略拒绝/放行）只入库记录，不弹窗（避免噪音过多）
    // 真正的威胁（端口扫描、DDoS、暴力破解等）才弹窗
    const isPolicyLog = /策略拒绝|策略放行|POLICYDENY|POLICYPERMIT/i.test(rawMessage);
    if (isPolicyLog) {
      saveAlertToDatabase(alert);
      notifyWindows(alert);
      console.log(`[Syslog] 策略日志已记录（不弹窗）: ${alert.attackType} ${alert.sourceIp} -> ${alert.targetIp}`);
    } else {
      processAlert(alert);
    }
  } catch (err) {
    console.error('处理 Syslog 消息失败:', err);
  }
}

/**
 * 启动 Syslog 接收服务
 * @param port 监听端口，默认 514
 */
export function startSyslogReceiver(port: number = 514): Promise<{ success: boolean; message: string }> {
  return new Promise((resolve) => {
    try {
      // 如果已经在运行，先停止
      if (server) {
        server.close();
        server = null;
      }

      server = dgram.createSocket('udp4');

      server.on('message', handleMessage);

      server.on('error', (err) => {
        console.error('Syslog 接收服务错误:', err);
        isRunning = false;
      });

      server.on('listening', () => {
        currentPort = port;
        isRunning = true;
        console.log(`Syslog 接收服务已启动，监听 UDP ${port} 端口`);
        resolve({ success: true, message: `已开始监听 UDP ${port} 端口` });
      });

      server.bind(port);
    } catch (err: any) {
      console.error('启动 Syslog 接收服务失败:', err);
      resolve({ success: false, message: `启动失败: ${err?.message || '未知错误'}` });
    }
  });
}

/**
 * 停止 Syslog 接收服务
 */
export function stopSyslogReceiver(): { success: boolean; message: string } {
  try {
    if (server) {
      server.close();
      server = null;
    }
    isRunning = false;
    console.log('Syslog 接收服务已停止');
    return { success: true, message: '已停止监听' };
  } catch (err: any) {
    console.error('停止 Syslog 接收服务失败:', err);
    return { success: false, message: `停止失败: ${err?.message || '未知错误'}` };
  }
}

/**
 * 获取 Syslog 接收服务状态
 */
export function getSyslogStatus(): { status: string; port: number } {
  return {
    status: isRunning ? 'running' : 'stopped',
    port: currentPort,
  };
}
