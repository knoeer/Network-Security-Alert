import { app, BrowserWindow, ipcMain, Tray, Menu, nativeImage } from 'electron';
import path from 'path';
import { registerIpcHandlers } from './ipc-handlers';
import { getDatabase, closeDatabase } from './database';
import { queryOne } from './db-helper';
import { startTrapReceiver, stopTrapReceiver, getTrapStatus } from './snmp-receiver';
import { startSyslogReceiver, stopSyslogReceiver, getSyslogStatus } from './syslog-receiver';
import { showAlert, closeAlert, closeAllAlerts, setAlertPaused, isAlertPaused } from './alert-manager';
import type { AlertData } from './alert-manager';
import { startDeviceMonitor, stopDeviceMonitor } from './device-monitor';
import { backfillAttackCategories } from './event-classifier';
import { startPerformanceMonitor, stopPerformanceMonitor, cleanupPerformanceHistory } from './performance-monitor';
import { startTrafficMonitor, stopTrafficMonitor, cleanupTrafficHistory } from './traffic-monitor';

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let isQuitting = false;

const isDev = !app.isPackaged;

function createMainWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 1024,
    minHeight: 680,
    title: 'SNMP安全告警系统',
    icon: path.join(__dirname, '../../src/renderer/assets/icon.png'),
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
    show: false,
  });

  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
    // 不自动打开 DevTools，需要时按 Ctrl+Shift+I 或 F12 打开
    // mainWindow.webContents.openDevTools({ mode: 'detach' });
  } else {
    mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'));
  }

  // 拦截所有新窗口打开（按住 Ctrl/Cmd 点击链接、window.open、target=_blank 等）
  // 统一在本窗口内导航，避免误操作打开多个软件实例
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    // 仅允许在本应用内部的导航（阻止外部 URL 与重复打开）
    const isInternal =
      url.startsWith('http://localhost:5173') ||
      url.startsWith('file://') ||
      url.startsWith('http://127.0.0.1:5173');
    if (isInternal) {
      mainWindow?.webContents.loadURL(url);
    }
    // 拒绝创建新窗口
    return { action: 'deny' };
  });

  // 阻止导航离开应用（防止误导航到外部页面）
  mainWindow.webContents.on('will-navigate', (event, url) => {
    const isInternal =
      url.startsWith('http://localhost:5173') ||
      url.startsWith('http://127.0.0.1:5173') ||
      url.startsWith('file://');
    if (!isInternal) {
      event.preventDefault();
    }
  });

  mainWindow.once('ready-to-show', () => {
    mainWindow?.show();
  });

  mainWindow.on('close', (e) => {
    // 最小化到托盘而非关闭（除非真正退出）
    if (!isQuitting && tray) {
      e.preventDefault();
      mainWindow?.hide();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function createTray(): void {
  // 创建托盘图标（使用真实图标文件）
  let icon = nativeImage.createFromPath(
    path.join(__dirname, '../../src/renderer/assets/icon.png')
  );
  // 如果图标加载失败，用最小尺寸的备用图标
  if (icon.isEmpty()) {
    icon = nativeImage.createFromPath(
      path.join(__dirname, '../../src/renderer/assets/icon16.png')
    );
  }
  // Windows 下托盘图标需要调整为合适尺寸
  if (process.platform === 'win32') {
    icon = icon.resize({ width: 16, height: 16 });
  }

  tray = new Tray(icon);
  tray.setToolTip('SNMP安全告警系统');
  updateTrayMenu();

  // 单击托盘图标显示主窗口
  tray.on('click', () => {
    mainWindow?.show();
    mainWindow?.focus();
  });

  tray.on('double-click', () => {
    mainWindow?.show();
    mainWindow?.focus();
  });
}

/**
 * 更新托盘菜单（同步 Trap/Syslog 监听状态）
 */
function updateTrayMenu(): void {
  if (!tray) return;
  const trapStatus = getTrapStatus().status;
  const syslogStatus = getSyslogStatus().status;

  const contextMenu = Menu.buildFromTemplate([
    { label: '显示主窗口', click: () => { mainWindow?.show(); mainWindow?.focus(); } },
    {
      label: trapStatus === 'running' ? '停止 Trap 监听' : '启动 Trap 监听',
      click: async () => {
        if (trapStatus === 'running') {
          stopTrapReceiver();
        } else {
          const trapPort = Number(queryOne<{ value: string }>("SELECT value FROM config WHERE key = 'trap_port'")?.value || 162);
          await startTrapReceiver(trapPort);
        }
        updateTrayMenu(); // 更新菜单状态
        notifyStatusChange();
      },
    },
    {
      label: syslogStatus === 'running' ? '停止 Syslog 监听' : '启动 Syslog 监听',
      click: async () => {
        if (syslogStatus === 'running') {
          stopSyslogReceiver();
        } else {
          const syslogPort = Number(queryOne<{ value: string }>("SELECT value FROM config WHERE key = 'syslog_port'")?.value || 514);
          await startSyslogReceiver(syslogPort);
        }
        updateTrayMenu();
        notifyStatusChange();
      },
    },
    { type: 'separator' },
    {
      label: '暂停弹窗',
      type: 'checkbox',
      checked: isAlertPaused(),
      click: (menuItem) => {
        const paused = menuItem.checked;
        setAlertPaused(paused);
        // 持久化暂停状态，重启后保持
        try {
          const { execute } = require('./db-helper');
          execute('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', ['alert_paused', paused ? 'true' : 'false']);
        } catch (err) {
          console.error('保存弹窗暂停状态失败:', err);
        }
        updateTrayMenu(); // 刷新菜单勾选
      },
    },
    { type: 'separator' },
    { label: '退出', click: () => { isQuitting = true; tray?.destroy(); app.quit(); } },
  ]);

  tray.setContextMenu(contextMenu);
}

/**
 * 通知渲染进程监听状态已变化
 */
function notifyStatusChange(): void {
  BrowserWindow.getAllWindows().forEach((win) => {
    if (!win.isDestroyed()) {
      win.webContents.send('listener:statusChanged', {
        trap: getTrapStatus(),
        syslog: getSyslogStatus(),
      });
    }
  });
}

// IPC 处理器
ipcMain.handle('show-alert', (_event, alertData: AlertData) => {
  showAlert(alertData);
});

ipcMain.handle('close-alert', () => {
  // 弹窗右上角叉号：一键关闭所有弹窗
  closeAllAlerts();
});

ipcMain.handle('close-alert-single', () => {
  // 弹窗内"确认并关闭"：只关闭当前，显示下一条
  closeAlert();
});

ipcMain.handle('minimize-to-tray', () => {
  mainWindow?.hide();
});

// 应用生命周期
app.whenReady().then(async () => {
  // 取消应用菜单栏
  Menu.setApplicationMenu(null);

  // 初始化数据库（异步）
  await getDatabase();

  // 对历史事件回填标准攻击类型（跨厂商统一分类）
  backfillAttackCategories();

  // 注册 IPC 处理器
  registerIpcHandlers();

  // 恢复上次的"暂停弹窗"状态（持久化于 config 表）
  const pausedFromConfig = queryOne<{ value: string }>(
    "SELECT value FROM config WHERE key = 'alert_paused'"
  )?.value;
  setAlertPaused(pausedFromConfig === 'true');

  createMainWindow();
  createTray();

  // 自动启动 SNMP Trap 监听（如果配置中启用）
  const trapEnabled = queryOne<{ value: string }>(
    "SELECT value FROM config WHERE key = 'trap_enabled'"
  )?.value;
  if (trapEnabled === 'true') {
    const trapPort = Number(
      queryOne<{ value: string }>("SELECT value FROM config WHERE key = 'trap_port'")?.value || 162
    );
    startTrapReceiver(trapPort);
  }

  // 自动启动 Syslog 监听（如果配置中启用）
  const syslogEnabled = queryOne<{ value: string }>(
    "SELECT value FROM config WHERE key = 'syslog_enabled'"
  )?.value;
  if (syslogEnabled === 'true') {
    const syslogPort = Number(
      queryOne<{ value: string }>("SELECT value FROM config WHERE key = 'syslog_port'")?.value || 514
    );
    startSyslogReceiver(syslogPort);
  }

  // 自动启动设备离线监测（配置默认启用）
  startDeviceMonitor();

  // 自动启动设备性能监控（CPU/内存，配置默认启用）
  startPerformanceMonitor();

  // 自动启动接口流量监控（默认启用）
  startTrafficMonitor();

  // 启动时清理过旧的性能采样数据（保留 7 天）
  cleanupPerformanceHistory();
  cleanupTrafficHistory();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createMainWindow();
    } else {
      mainWindow?.show();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    // Windows下不退出，保持在托盘
  }
});

app.on('before-quit', () => {
  isQuitting = true;
  stopDeviceMonitor();
  stopPerformanceMonitor();
  stopTrafficMonitor();
  tray?.destroy();
  closeDatabase();
});
