/**
 * SNMP Trap 接收服务
 * 使用 net-snmp 库监听 UDP 162 端口，接收安全设备的 Trap 通知
 */
import * as snmp from 'net-snmp';
import { parseTrap, ParsedTrap, getTrapTypeName } from './snmp-parser';
import { getOidMapping } from './oid-mapping';
import { AlertData, findDeviceName, processAlert } from './alert-common';
import { saveRawLog } from './raw-logger';

let receiver: snmp.Receiver | null = null;
let currentPort = 162;
let isRunning = false;

/**
 * 处理收到的 Trap
 */
function handleTrap(trap: any): void {
  try {
    console.log(`收到 SNMP Trap (${getTrapTypeName(trap.pdu?.type)}) 来自: ${trap.rinfo?.address}`);

    // 原始 Trap 报文（原样序列化，用于展示和调试）
    let rawTrapStr = '';
    try {
      rawTrapStr = JSON.stringify(trap, (key, value) => {
        // Buffer 转为可读字符串
        if (Buffer.isBuffer(value)) return value.toString('hex');
        return value;
      }, 2);
      saveRawLog('snmp', rawTrapStr, trap.rinfo?.address || '', trap.pdu?.type !== undefined ? `type_${trap.pdu.type}` : undefined);
    } catch (e) {
      console.error('保存原始 Trap 失败:', e);
    }

    // 解析 Trap
    const parsed: ParsedTrap = parseTrap(trap);

    // 根据 OID 映射攻击类型和严重级别
    const mapping = getOidMapping(parsed.oid);
    parsed.attackType = mapping.attackType;
    parsed.severity = mapping.severity;
    if (!parsed.description) {
      parsed.description = mapping.description;
    }

    // 查找设备名称
    parsed.deviceName = findDeviceName(parsed.deviceIp);

    // 构造告警数据
    const alert: AlertData = {
      attackType: parsed.attackType,
      sourceIp: parsed.sourceIp,
      sourcePort: parsed.sourcePort,
      targetIp: parsed.targetIp,
      targetPort: parsed.targetPort,
      severity: parsed.severity,
      deviceName: parsed.deviceName,
      deviceIp: parsed.deviceIp,
      description: parsed.description,
      oid: parsed.oid,
      timestamp: parsed.timestamp,
      rawMessage: rawTrapStr, // 原始 Trap 报文
    };

    // 完整告警处理流程（入库 + 通知 + 弹窗）
    processAlert(alert);
  } catch (err) {
    console.error('处理 Trap 失败:', err);
  }
}

/**
 * 启动 SNMP Trap 监听
 * @param port 监听端口，默认 162
 */
export function startTrapReceiver(port: number = 162): Promise<{ success: boolean; message: string }> {
  return new Promise((resolve) => {
    try {
      // 如果已经在运行，先停止
      if (receiver) {
        receiver.close();
        receiver = null;
      }

      // 创建 Trap 接收器
      receiver = snmp.createReceiver(
        { port, disableAuthorization: true },
        (error: Error | null, trap: any) => {
          if (error) {
            console.error('接收 Trap 错误:', error);
            return;
          }
          handleTrap(trap);
        }
      );

      currentPort = port;
      isRunning = true;

      console.log(`SNMP Trap 接收服务已启动，监听 UDP ${port} 端口`);
      resolve({ success: true, message: `已开始监听 UDP ${port} 端口` });
    } catch (err: any) {
      console.error('启动 Trap 接收服务失败:', err);
      resolve({ success: false, message: `启动失败: ${err?.message || '未知错误'}` });
    }
  });
}

/**
 * 停止 SNMP Trap 监听
 */
export function stopTrapReceiver(): { success: boolean; message: string } {
  try {
    if (receiver) {
      receiver.close();
      receiver = null;
    }
    isRunning = false;
    console.log('SNMP Trap 接收服务已停止');
    return { success: true, message: '已停止监听' };
  } catch (err: any) {
    console.error('停止 Trap 接收服务失败:', err);
    return { success: false, message: `停止失败: ${err?.message || '未知错误'}` };
  }
}

/**
 * 获取 Trap 接收服务状态
 */
export function getTrapStatus(): { status: string; port: number } {
  return {
    status: isRunning ? 'running' : 'stopped',
    port: currentPort,
  };
}

/**
 * 发送测试告警（用于开发调试）
 */
export function sendTestAlert(): void {
  const testAlert: AlertData = {
    attackType: '端口扫描',
    sourceIp: '192.168.1.100',
    sourcePort: 52341,
    targetIp: '192.168.1.1',
    targetPort: 445,
    severity: 'high',
    deviceName: '测试防火墙',
    deviceIp: '192.168.1.254',
    description: '检测到端口扫描活动（测试告警）',
    oid: '1.3.6.1.4.1.9.9.147.1.2.2.1',
    timestamp: new Date().toISOString(),
  };

  processAlert(testAlert);
}
