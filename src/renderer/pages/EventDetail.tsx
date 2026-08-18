import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import IpLocation from '../components/IpLocation';
import type { SecurityEvent, SourceAttackStats } from '../types/global';
import './EventDetail.css';

/**
 * 归类依据来源的中文标签
 * @param source user_rule/custom_keyword/builtin/default
 */
function classifySourceLabel(source?: string): string {
  switch (source) {
    case 'user_rule':
      return '用户归类规则';
    case 'custom_keyword':
      return '自定义类型特征关键字';
    case 'builtin':
      return '内置规则';
    default:
      return '内置规则';
  }
}

const EventDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [event, setEvent] = useState<SecurityEvent | null>(null);
  const [loading, setLoading] = useState(true);
  const [showRaw, setShowRaw] = useState(true);
  const [sourceStats, setSourceStats] = useState<SourceAttackStats | null>(null);
  // 动态加载的事件类型（内置 + 自定义）
  const [eventTypes, setEventTypes] = useState<Array<{ id: number; name: string }>>([]);

  // 加载事件类型列表（用于手动归类下拉）
  useEffect(() => {
    (async () => {
      try {
        const res = await window.electronAPI.listEventTypes();
        if (res.success) {
          setEventTypes(res.types.map((t) => ({ id: t.id, name: t.name })));
        }
      } catch (err) {
        console.error('加载事件类型失败:', err);
      }
    })();
  }, []);
  // 手动归类状态
  const [classifyCategory, setClassifyCategory] = useState('');
  const [classifyMsg, setClassifyMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // 手动归类：保存用户规则并更新当前事件类型
  const handleManualClassify = async () => {
    if (!event || !classifyCategory) return;
    if (!window.confirm(`确定将当前事件归类为"${classifyCategory}"吗？\n\n系统将学习该威胁特征，以后同类威胁自动归入该类型。`)) {
      return;
    }
    try {
      setClassifyMsg(null);
      const result = await window.electronAPI.manualClassify({
        id: event.id,
        category: classifyCategory,
        raw_trap: event.raw_trap,
      });
      if (result.success) {
        setClassifyMsg({ type: 'success', text: `已归类为"${classifyCategory}"，今后同类威胁自动归入` });
        setEvent((prev) => prev ? { ...prev, attack_category: classifyCategory } : prev);
        setClassifyCategory('');
      } else {
        setClassifyMsg({ type: 'error', text: result.message || '归类失败' });
      }
    } catch (err: any) {
      console.error('手动归类失败:', err);
      setClassifyMsg({ type: 'error', text: '归类失败：' + (err?.message || '未知错误') });
    }
  };

  // 解析 raw_trap 中的结构化字段（应用、威胁名称、动作、类别等）
  const extra = React.useMemo(() => {
    if (!event?.raw_trap) return null;
    try {
      const parsed = JSON.parse(event.raw_trap);
      return parsed as {
        application?: string;
        threatName?: string;
        action?: string;
        category?: string;
        protocol?: string;
        policy?: string;
        signId?: string;
        description?: string;
      };
    } catch {
      return null; // 兼容旧的非 JSON 原始数据
    }
  }, [event]);

  useEffect(() => {
    if (id) loadEvent(Number(id));
  }, [id]);

  const loadEvent = async (eventId: number) => {
    try {
      setLoading(true);
      const data = await window.electronAPI.getEventById(eventId);
      setEvent(data);

      // 加载该源地址的攻击次数统计
      if (data && data.source_ip) {
        try {
          const stats = await window.electronAPI.getSourceAttackCount(data.source_ip);
          setSourceStats(stats);
        } catch (err) {
          console.error('Failed to load source attack stats:', err);
          setSourceStats(null);
        }
      } else {
        setSourceStats(null);
      }
    } catch (err) {
      console.error('Failed to load event:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleToggleAcknowledge = async () => {
    if (!event) return;
    try {
      await window.electronAPI.acknowledgeEvent(event.id, !event.acknowledged);
      loadEvent(event.id);
    } catch (err) {
      console.error('确认操作失败:', err);
    }
  };

  const handleDelete = async () => {
    if (!event) return;
    if (!confirm('确定要删除这条事件吗？')) return;
    try {
      await window.electronAPI.deleteEvent(event.id);
      navigate('/events');
    } catch (err) {
      console.error('删除失败:', err);
    }
  };

  const severityConfig: Record<string, { label: string; className: string; icon: string; color: string }> = {
    critical: { label: '严重', className: 'badge-critical', icon: '🔴', color: '#b31412' },
    high: { label: '高危', className: 'badge-high', icon: '🟠', color: '#d93025' },
    medium: { label: '中等', className: 'badge-medium', icon: '🟡', color: '#e37400' },
    low: { label: '低危', className: 'badge-low', icon: '🟢', color: '#137333' },
  };

  if (loading) {
    return (
      <div className="empty-state">
        <div className="spinner"></div>
        <div className="title">加载中...</div>
      </div>
    );
  }

  if (!event) {
    return (
      <div className="empty-state">
        <div className="icon">🔍</div>
        <div className="title">事件不存在</div>
        <div className="desc">该安全事件记录未找到</div>
        <button className="btn btn-secondary" style={{ marginTop: 16 }} onClick={() => navigate('/events')}>
          返回列表
        </button>
      </div>
    );
  }

  const severityCfg = severityConfig[event.severity] || severityConfig.medium;

  return (
    <div className="event-detail-page">
      {/* 顶部工具栏 */}
      <div className="detail-header">
        <button className="btn btn-secondary" onClick={() => navigate('/events')}>
          ← 返回列表
        </button>
        <div className="detail-header-actions">
          <button className="btn btn-secondary" onClick={handleToggleAcknowledge}>
            {event.acknowledged ? '取消确认' : '确认事件'}
          </button>
          <button className="btn btn-danger" onClick={handleDelete}>
            删除事件
          </button>
        </div>
      </div>

      {/* 紧凑横幅头 */}
      <div className="detail-banner" style={{ borderLeftColor: severityCfg.color }}>
        <div className="detail-banner-icon">{severityCfg.icon}</div>
        <div className="detail-banner-content">
          <div className="detail-banner-title-row">
            <h1 className="detail-banner-title">
              {event.attack_category || event.attack_type || '其他'}
            </h1>
            <div className="detail-banner-badges">
              <span className={`badge ${severityCfg.className}`}>{severityCfg.label}</span>
              <span className={`badge ${event.acknowledged ? 'badge-acknowledged' : 'badge-unacknowledged'}`}>
                {event.acknowledged ? '已确认' : '未确认'}
              </span>
            </div>
          </div>
          <div className="detail-banner-meta">
            <span>#{event.id}</span>
            <span className="meta-divider">•</span>
            <span>{new Date(event.timestamp).toLocaleString('zh-CN')}</span>
            <span className="meta-divider">•</span>
            <span>{event.device_name}</span>
            <span className="meta-divider">•</span>
            <span>{classifySourceLabel(event.classify_source)}</span>
          </div>
        </div>
      </div>

      {/* 主体内容：左右两栏布局 */}
      <div className="detail-main-layout">
        {/* 左栏：网络流量 + 事件详情 */}
        <div className="detail-left-col">
          {/* 网络流向 */}
          <div className="card flow-card">
            <div className="card-header">网络流量信息</div>
            <div className="card-body">
              <div className="flow-diagram">
                <div className="flow-node flow-node-source">
                  <span className="flow-node-label">源地址</span>
                  <code className="flow-node-ip">{event.source_ip || '-'}</code>
                  <span className="flow-node-port">端口 {event.source_port || '-'}</span>
                  <IpLocation ip={event.source_ip || ''} />
                  {sourceStats && sourceStats.count > 0 && (
                    <span
                      className="source-attack-count"
                      title={`该源地址累计攻击 ${sourceStats.count} 次，近24小时 ${sourceStats.todayCount} 次`}
                    >
                      累计攻击 {sourceStats.count} 次
                      {sourceStats.todayCount > 0 ? ` · 近24h ${sourceStats.todayCount}` : ''}
                    </span>
                  )}
                </div>
                <div className="flow-arrow">→</div>
                <div className="flow-node flow-node-target">
                  <span className="flow-node-label">目标地址</span>
                  <code className="flow-node-ip">{event.target_ip || '-'}</code>
                  <span className="flow-node-port">端口 {event.target_port || '-'}</span>
                  <IpLocation ip={event.target_ip || ''} />
                </div>
              </div>
            </div>
          </div>

          {/* 事件详情 */}
          <div className="card detail-info-card">
            <div className="card-header">事件详情</div>
            <div className="card-body">
              <div className="detail-grid">
                <div className="detail-item">
                  <label>事件类型</label>
                  <span>{event.attack_category || event.attack_type || '其他'}</span>
                </div>
                <div className="detail-item">
                  <label>严重级别</label>
                  <span><span className={`badge ${severityCfg.className}`}>{severityCfg.label}</span></span>
                </div>
                <div className="detail-item">
                  <label>设备名称</label>
                  <span>{event.device_name}</span>
                </div>
                <div className="detail-item">
                  <label>设备 IP</label>
                  <span><code>{event.device_ip}</code></span>
                </div>
                <div className="detail-item">
                  <label>发生时间</label>
                  <span>{new Date(event.timestamp).toLocaleString('zh-CN')}</span>
                </div>
                <div className="detail-item">
                  <label>记录时间</label>
                  <span>{event.created_at ? new Date(event.created_at).toLocaleString('zh-CN') : '-'}</span>
                </div>
                <div className="detail-item detail-item-full">
                  <label>OID</label>
                  <span><code className="oid-code">{event.oid || '-'}</code></span>
                </div>

                {/* 扩展字段（华为 IPS 等结构化日志） */}
                {extra?.threatName && (
                  <div className="detail-item detail-item-full">
                    <label>威胁名称</label>
                    <span className="threat-name-value">{extra.threatName}</span>
                  </div>
                )}
                {extra?.category && (
                  <div className="detail-item">
                    <label>威胁类别</label>
                    <span>{extra.category}</span>
                  </div>
                )}
                {extra?.action && (
                  <div className="detail-item">
                    <label>动作</label>
                    <span>{extra.action}</span>
                  </div>
                )}
                {extra?.application && (
                  <div className="detail-item">
                    <label>应用</label>
                    <span>{extra.application}</span>
                  </div>
                )}
                {extra?.protocol && (
                  <div className="detail-item">
                    <label>协议</label>
                    <span>{extra.protocol}</span>
                  </div>
                )}
                {extra?.policy && (
                  <div className="detail-item">
                    <label>命中策略</label>
                    <span>{extra.policy}</span>
                  </div>
                )}
                {extra?.signId && (
                  <div className="detail-item">
                    <label>签名 ID</label>
                    <span>{extra.signId}</span>
                  </div>
                )}

              </div>
            </div>
          </div>

          {/* 手动归类：位于事件详情卡片下方 */}
          <div className="card section-card" style={{ marginTop: 12 }}>
            <div className="card-header">手动归类</div>
            <div className="card-body">
              <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 8 }}>
                <select
                  value={classifyCategory}
                  onChange={(e) => setClassifyCategory(e.target.value)}
                  style={{
                    flex: 1,
                    minWidth: 0,
                    fontSize: 12,
                    padding: '6px 8px',
                    borderRadius: 6,
                    border: '1px solid #ccc',
                    background: '#fff',
                  }}
                >
                  <option value="">选择类型...</option>
                  {eventTypes.length === 0 ? (
                    <option value="" disabled>加载中...</option>
                  ) : (
                    eventTypes.map((t) => (
                      <option key={t.id} value={t.name}>{t.name}</option>
                    ))
                  )}
                </select>
                <button
                  className="btn btn-primary btn-sm"
                  onClick={handleManualClassify}
                  disabled={!classifyCategory}
                  style={{ whiteSpace: 'nowrap' }}
                  title="学习该威胁特征，今后同类威胁自动归入所选类型"
                >
                  归类
                </button>
              </div>

              <div style={{ fontSize: 11, color: '#888', lineHeight: 1.5 }}>
                手动归类采用<b>签名级精确匹配</b>：系统会学习该威胁的签名特征（如华为 SignName/签名ID），
                以后收到<b>同签名</b>的威胁自动归入所选类型。
                此功能与"自定义事件类型的特征关键字"（关键词级匹配）互补——签名级更精确，关键字级更宽泛，优先级：签名规则 &gt; 关键字 &gt; 内置配置。
                可在系统设置-事件类型中删除规则。
              </div>

              {classifyMsg && (
                <div
                  style={{
                    marginTop: 6,
                    fontSize: 12,
                    color: classifyMsg.type === 'success' ? '#2f855a' : '#c53030',
                  }}
                >
                  {classifyMsg.text}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* 右栏：事件描述 + 原始数据 */}
        <div className="detail-right-col">
          <div className="card section-card">
            <div className="card-header">事件描述</div>
            <div className="card-body">
              <p className="description-text">{event.description || '无描述信息'}</p>
            </div>
          </div>

          {event.raw_trap && (
            <div className="card raw-card">
              <div className="card-header" onClick={() => setShowRaw(!showRaw)} style={{ cursor: 'pointer' }}>
                原始报文数据
                <span className="raw-toggle">{showRaw ? '收起 ▲' : '展开 ▼'}</span>
              </div>
              {showRaw && (
                <div className="card-body">
                  <pre className="raw-data">{event.raw_trap}</pre>
                </div>
              )}
            </div>
          )}

        </div>
      </div>
    </div>
  );
};

export default EventDetail;
