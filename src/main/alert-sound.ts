/**
 * 告警提示音模块
 * 使用 Electron 的 shell.beep() 播放系统提示音
 * 也支持在渲染进程中用 Web Audio API 播放更丰富的告警音效
 */
import { shell, app } from 'electron';

/**
 * 播放系统提示音
 * 根据严重级别播放不同次数
 */
export function playAlertSound(severity: string): void {
  const beepCount = severity === 'critical' ? 3 : severity === 'high' ? 2 : 1;
  for (let i = 0; i < beepCount; i++) {
    setTimeout(() => {
      shell.beep();
    }, i * 300);
  }
}

/**
 * 在渲染进程中通过 Web Audio API 播放告警音效
 * 返回一段可注入到渲染进程的 JS（用于在页面内播放更明显的告警音）
 */
export function getAlertAudioScript(): string {
  return `
    (function() {
      try {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (!AudioContext) return;
        const ctx = new AudioContext();
        // 播放三声急促的提示音
        for (let i = 0; i < 3; i++) {
          const osc = ctx.createOscillator();
          const gain = ctx.createGain();
          osc.connect(gain);
          gain.connect(ctx.destination);
          osc.type = 'sine';
          osc.frequency.value = 880; // A5 音符
          const startTime = ctx.currentTime + i * 0.2;
          gain.gain.setValueAtTime(0, startTime);
          gain.gain.linearRampToValueAtTime(0.5, startTime + 0.02);
          gain.gain.linearRampToValueAtTime(0, startTime + 0.15);
          osc.start(startTime);
          osc.stop(startTime + 0.15);
        }
      } catch (e) {
        console.error('播放提示音失败:', e);
      }
    })();
  `;
}
