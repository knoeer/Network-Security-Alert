网络与安全告警系统 (Network-Security-Alert)

基于 Electron + React + TypeScript 的网络安全告警平台，通过双通道接收安全设备（防火墙等）的威胁告警，实现实时弹窗告警、事件查询统计、设备监测等功能。

<img width="1264" height="791" alt="image" src="https://github.com/user-attachments/assets/eeb8d5b8-c168-4de0-beeb-4e3c4b3a612b" />

<img width="1266" height="793" alt="image" src="https://github.com/user-attachments/assets/d2041b16-9d1d-4f0a-afab-6325f3d5856b" />

<img width="1266" height="793" alt="image" src="https://github.com/user-attachments/assets/4df65768-892e-4496-bd0a-71054bd9b4c3" />

<img width="1266" height="793" alt="image" src="https://github.com/user-attachments/assets/8e733bad-9e1a-43ac-a54b-cc9112f6dd79" />

<img width="1264" height="761" alt="image" src="https://github.com/user-attachments/assets/73ca17a4-8dfd-4e15-9d72-d7e1e1306abd" />

<img width="1584" height="771" alt="image" src="https://github.com/user-attachments/assets/daaab749-5f11-4e4f-91cc-895c1d128057" />

## 功能特性

- **多通道接收**：SNMP Trap（UDP 162）+ Syslog（UDP 514）双通道实时接收安全日志
- **多厂商兼容**：华为、CSSOS、思科等厂商日志解析（`syslog-parser.ts` / `vendor-parser.ts`）
- **实时告警弹窗**：按威胁等级弹窗提醒 + 提示音 + 横幅通知
- **安全事件库**：事件分类、筛选、统计、CSV/JSON 导出
- **设备监测**：SNMP 轮询设备在线状态、接口流量、CPU/内存
- **事件类型自定义**：可增删改事件类型、配置特征关键字自动分类、签名级手动归类
- **数据备份与恢复**：一键导出/导入完整应用数据
- **IP 属地查询**：公网 IP 归属地识别（内网 IP 直接标记）
- **托盘常驻**：最小化到系统托盘，支持暂停弹窗

## 技术栈

| 层 | 技术 |
|---|---|
| 桌面框架 | Electron 32 |
| 前端 | React 18 + Vite + TypeScript |
| 数据库 | sql.js（SQLite WASM 内存库 + 文件持久化） |
| 图表 | Chart.js |
| 打包 | electron-builder（NSIS 安装包） |

## 快速开始

```bash
# 安装依赖
npm install

# 开发模式（vite 热更新 + Electron）
npm run dev

# 类型检查
npm run typecheck

# 构建生产版本
npm run build

# 打包安装程序
npm run package
```

## 目录结构

```
├── src/                      # 源代码
│   ├── main/                 # Electron 主进程（服务接收、解析、告警、数据库）
│   ├── renderer/             # React 渲染进程（页面、组件、样式）
│   └── renderer/pages/       # 页面（仪表盘、事件列表、事件详情、系统设置）
├── config/                   # 配置文件（事件类型映射等）
├── package.json
├── tsconfig.main.json        # 主进程 TS 配置
├── tsconfig.renderer.json    # 渲染进程 TS 配置
└── vite.config.ts            # Vite 配置
```

## 主要模块

- **syslog-receiver.ts**：Syslog 服务接收
- **snmp-trap-receiver.ts**：SNMP Trap 服务接收
- **syslog-parser.ts / vendor-parser.ts**：多厂商日志解析
- **event-classifier.ts**：事件分类（内置规则 / 自定义关键字 / 签名级规则）
- **alert-manager.ts / alert-common.ts**：告警弹窗与入库
- **database.ts / db-helper.ts**：数据库管理与操作
- **monitor/**：设备监测与流量统计

## 开源协议

本仓库为个人项目，代码仅供参考学习。
