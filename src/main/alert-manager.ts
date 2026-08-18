/**
 * 告警管理器
 * 负责创建告警弹窗、播放提示音、闪烁提醒等
 */
import { BrowserWindow, screen } from 'electron';
import path from 'path';
import { Buffer } from 'buffer';

export interface AlertData {
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
  // 源地址攻击次数（弹窗标识）
  sourceAttackCount?: number;
  sourceAttackCountToday?: number;
  // 标准攻击类型（跨厂商统一分类）
  attackCategory?: string;
}

let alertWindow: BrowserWindow | null = null;
// 待显示告警队列（多窗口可排队）
const alertQueue: AlertData[] = [];
let isShowing = false;
// 暂停弹窗状态（true 时不再弹窗/播放声音，但仍入库和横幅通知）
let alertPaused = false;

/**
 * 设置暂停弹窗状态
 */
export function setAlertPaused(paused: boolean): void {
  alertPaused = paused;
  // 暂停时清空待显示队列，避免恢复后瞬间弹出大量旧告警
  if (paused) {
    alertQueue.length = 0;
    if (alertWindow && !alertWindow.isDestroyed()) {
      alertWindow.close();
      alertWindow = null;
    }
    isShowing = false;
  }
}

/**
 * 获取暂停弹窗状态
 */
export function isAlertPaused(): boolean {
  return alertPaused;
}

const isDev = !require('electron').app.isPackaged;

/**
 * 创建告警弹窗
 */
function createAlertWindow(alertData: AlertData): BrowserWindow {
  const window = new BrowserWindow({
    width: 500,
    height: 460,
    resizable: false,
    frame: false,
    alwaysOnTop: true,
    skipTaskbar: true,
    title: '安全告警',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  // 右下角定位
  const primaryDisplay = screen.getPrimaryDisplay();
  const { width: screenWidth, height: screenHeight } = primaryDisplay.workAreaSize;
  const { width: winWidth, height: winHeight } = window.getBounds();
  window.setPosition(screenWidth - winWidth - 20, screenHeight - winHeight - 20);

  // 用 Base64 编码避免 URL 解析歧义（比 encodeURIComponent 更可靠）
  const encoded = Buffer.from(JSON.stringify(alertData), 'utf-8').toString('base64');

  if (isDev) {
    window.loadURL(`http://localhost:5173/#/alert?data=${encoded}`);
  } else {
    window.loadFile(path.join(__dirname, '../renderer/index.html'), {
      hash: `/alert?data=${encoded}`,
    });
  }

  window.on('closed', () => {
    if (alertWindow === window) {
      alertWindow = null;
      isShowing = false;
      // 显示队列中的下一条告警
      showNextAlert();
    }
  });

  return window;
}

/**
 * 显示队列中的下一条告警
 */
function showNextAlert(): void {
  if (isShowing || alertQueue.length === 0) {
    return;
  }
  const nextAlert = alertQueue.shift();
  if (nextAlert) {
    isShowing = true;
    alertWindow = createAlertWindow(nextAlert);
  }
}

/**
 * 触发告警弹窗
 * 如果有告警正在显示，则进入队列等待
 */
export function showAlert(alertData: AlertData): void {
  if (isShowing && alertWindow && !alertWindow.isDestroyed()) {
    // 已有弹窗在显示，加入队列
    alertQueue.push(alertData);
  } else {
    isShowing = true;
    alertWindow = createAlertWindow(alertData);
  }
}

/**
 * 关闭当前告警弹窗
 */
export function closeAlert(): void {
  if (alertWindow && !alertWindow.isDestroyed()) {
    alertWindow.close();
    alertWindow = null;
    isShowing = false;
    showNextAlert();
  }
}

/**
 * 一键关闭所有弹窗（清空队列 + 关闭当前弹窗）
 */
export function closeAllAlerts(): void {
  alertQueue.length = 0;
  if (alertWindow && !alertWindow.isDestroyed()) {
    alertWindow.close();
    alertWindow = null;
  }
  isShowing = false;
}

/**
 * 获取当前告警队列长度
 */
export function getAlertQueueLength(): number {
  return alertQueue.length;
}

/**
 * 清空告警队列
 */
export function clearAlertQueue(): void {
  alertQueue.length = 0;
}
