import React, { useEffect, useState, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import YesConfirmDialog from '../components/YesConfirmDialog';
import IpLocation from '../components/IpLocation';
import type { SecurityEvent, EventFilter } from '../types/global';
import './EventList.css';

const PAGE_SIZE = 20;
// 浏览状态存储键（保持用户离开前的页码/筛选条件）
const STATE_STORAGE_KEY = 'eventListBrowseState';

/**
 * 从 sessionStorage 读取保存的浏览状态（页码/筛选/滚动位置）
 * 用于用户离开事件列表后返回时恢复到原浏览位置
 */
function getSavedBrowseState(): { page: number; filter: EventFilter; scrollTop: number } {
  try {
    const raw = sessionStorage.getItem(STATE_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      const page = Number(parsed.page);
      return {
        page: Number.isInteger(page) && page >= 1 ? page : 1,
        filter: parsed.filter && typeof parsed.filter === 'object' ? parsed.filter : {},
        scrollTop: Number.isFinite(Number(parsed.scrollTop)) && Number(parsed.scrollTop) >= 0 ? Number(parsed.scrollTop) : 0,
      };
    }
  } catch (err) {
    console.error('读取事件列表浏览状态失败:', err);
  }
  return { page: 1, filter: {}, scrollTop: 0 };
}

// 获取事件列表的滚动容器（Layout 主内容区）
function getScrollContainer(): HTMLElement | null {
  return document.querySelector('.content') as HTMLElement | null;
}

const EventList: React.FC = () => {
  const navigate = useNavigate();
  // 初始状态优先从 sessionStorage 恢复（返回时保持浏览位置）
  const [initialState] = useState(getSavedBrowseState);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [page, setPage] = useState(initialState.page);
  const [filter, setFilter] = useState<EventFilter>(initialState.filter);
  // 搜索关键字（输入框即时显示用，防抖后合并进 filter）
  const [searchKeyword, setSearchKeyword] = useState<string>(initialState.filter?.keyword || '');
  const searchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [exporting, setExporting] = useState(false);
  const [showClearConfirm, setShowClearConfirm] = useState(false);
  const [jumpPage, setJumpPage] = useState('');
  // 各列宽度（可拖拽调整），初始默认宽度，需与 CSS 中 nth-child 一致
  const [colWidths, setColWidths] = useState<number[]>([36, 140, 110, 165, 165, 115, 70, 80, 200]);
  // 拖拽调整列宽：记录当前拖拽的列索引与起始位置
  const dragRef = useRef<{ index: number; startX: number; startWidth: number } | null>(null);
  const colWidthsRef = useRef(colWidths);
  colWidthsRef.current = colWidths;

  // 表头拖拽调整列宽
  const startColumnResize = (e: React.MouseEvent, index: number) => {
    e.preventDefault();
    e.stopPropagation();
    dragRef.current = { index, startX: e.clientX, startWidth: colWidthsRef.current[index] };
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    const onMouseMove = (ev: MouseEvent) => {
      if (!dragRef.current) return;
      const delta = ev.clientX - dragRef.current.startX;
      const newWidth = Math.max(40, Math.min(500, dragRef.current.startWidth + delta));
      setColWidths(prev => {
        const next = [...prev];
        next[dragRef.current!.index] = newWidth;
        return next;
      });
    };
    const onMouseUp = () => {
      dragRef.current = null;
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      document.removeEventListener('mousemove', onMouseMove);
      document.removeEventListener('mouseup', onMouseUp);
    };
    document.addEventListener('mousemove', onMouseMove);
    document.addEventListener('mouseup', onMouseUp);
  };

  // 页码或筛选变化时自动保存浏览状态（离开后返回可恢复）
  // 跳过首次挂载：避免把未恢复的 scrollTop=0 覆盖掉已保存的有效值
  const skipFirstSave = useRef(true);
  useEffect(() => {
    if (skipFirstSave.current) {
      skipFirstSave.current = false;
      return;
    }
    try {
      const scrollTop = getScrollContainer()?.scrollTop || 0;
      sessionStorage.setItem(STATE_STORAGE_KEY, JSON.stringify({ page, filter, scrollTop }));
    } catch (err) {
      console.error('保存事件列表浏览状态失败:', err);
    }
  }, [page, filter]);

  // 监听滚动并实时保存 scrollTop（滚动过程中持续更新）
  useEffect(() => {
    const el = getScrollContainer();
    if (!el) return;
    const onScroll = () => {
      try {
        const existing = sessionStorage.getItem(STATE_STORAGE_KEY);
        const state = existing ? JSON.parse(existing) : {};
        sessionStorage.setItem(STATE_STORAGE_KEY, JSON.stringify({ ...state, scrollTop: el.scrollTop }));
      } catch (err) {
        console.error('滚动时保存状态失败:', err);
      }
    };
    el.addEventListener('scroll', onScroll, { passive: true });
    return () => el.removeEventListener('scroll', onScroll);
  }, []);

  // 组件卸载时保存当前滚动位置（确保离开前状态完整）
  // 注意：若卸载瞬间 scrollTop 已被重置为 0，则保留已保存的有效值，避免覆盖
  useEffect(() => {
    return () => {
      try {
        const scrollTop = getScrollContainer()?.scrollTop || 0;
        const existing = sessionStorage.getItem(STATE_STORAGE_KEY);
        const state = existing ? JSON.parse(existing) : {};
        sessionStorage.setItem(STATE_STORAGE_KEY, JSON.stringify({
          ...state,
          scrollTop: scrollTop > 0 ? scrollTop : (state.scrollTop || 0),
        }));
      } catch (err) {
        console.error('卸载时保存滚动位置失败:', err);
      }
    };
  }, []);

  // 数据加载完成后恢复滚动位置（用 rAF 轮询，确保内容可滚动后再设置，避免被 clamp）
  useEffect(() => {
    if (!loading) {
      const saved = initialState.scrollTop;
      if (saved <= 0) return;
      const el = getScrollContainer();
      if (!el) return;
      let attempts = 0;
      const tryRestore = () => {
        // 内容高度足够（可滚动）时才设置，否则继续等待
        if (el.scrollHeight > el.clientHeight) {
          el.scrollTop = saved;
        } else if (attempts < 20) {
          attempts++;
          requestAnimationFrame(tryRestore);
        }
      };
      requestAnimationFrame(tryRestore);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loading, events]);

  // 重置并清除保存的浏览状态
  const resetBrowseState = () => {
    if (searchTimerRef.current) clearTimeout(searchTimerRef.current);
    setSearchKeyword('');
    setFilter({});
    setPage(1);
    try {
      sessionStorage.removeItem(STATE_STORAGE_KEY);
    } catch (err) {
      console.error('清除事件列表浏览状态失败:', err);
    }
    const el = getScrollContainer();
    if (el) el.scrollTop = 0;
  };

  // 刷新：保留当前筛选条件与页码，重新加载最新数据
  const handleRefresh = async () => {
    if (refreshing) return;
    setRefreshing(true);
    try {
      // 复用现有查询逻辑重新加载
      const result = await window.electronAPI.getEvents({
        ...filter,
        limit: PAGE_SIZE,
        offset: (page - 1) * PAGE_SIZE,
      });
      setEvents(result.events);
      setTotal(result.total);
      setSelectedIds(new Set());
    } catch (err) {
      console.error('刷新事件列表失败:', err);
    } finally {
      setRefreshing(false);
    }
  };

  const loadEvents = useCallback(async () => {
    try {
      setLoading(true);
      const result = await window.electronAPI.getEvents({
        ...filter,
        limit: PAGE_SIZE,
        offset: (page - 1) * PAGE_SIZE,
      });
      setEvents(result.events);
      setTotal(result.total);
      // 清空选择
      setSelectedIds(new Set());
    } catch (err) {
      console.error('Failed to load events:', err);
    } finally {
      setLoading(false);
    }
  }, [page, filter]);

  // 直接监听 page 和 filter，确保筛选变化立即触发加载
  useEffect(() => {
    loadEvents();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, filter]);

  const severityConfig: Record<string, { label: string; className: string }> = {
    critical: { label: '严重', className: 'badge-critical' },
    high: { label: '高危', className: 'badge-high' },
    medium: { label: '中等', className: 'badge-medium' },
    low: { label: '低危', className: 'badge-low' },
  };

  const formatTime = (ts: string) => {
    const d = new Date(ts);
    return d.toLocaleString('zh-CN');
  };

  const totalPages = Math.ceil(total / PAGE_SIZE);

  /**
   * 生成分页页码数组（含省略号）
   * 始终显示首页/尾页，当前页前后各 1 页，其余用 -1 表示省略号
   */
  const getPageNumbers = (): Array<number | -1> => {
    const pages: Array<number | -1> = [];
    const windowSize = 1; // 当前页前后显示页数

    for (let p = 1; p <= totalPages; p++) {
      // 显示首页、尾页、当前页及前后相邻页
      const isEdge = p === 1 || p === totalPages;
      const isNear = Math.abs(p - page) <= windowSize;
      if (isEdge || isNear) {
        pages.push(p);
      } else {
        // 若上一项不是省略号，则插入省略号
        if (pages[pages.length - 1] !== -1) {
          pages.push(-1);
        }
      }
    }
    return pages;
  };

  const pageNumbers = getPageNumbers();

  // 跳转到指定页码
  const goToPage = (target: number) => {
    if (!target || isNaN(target)) return;
    const clamped = Math.max(1, Math.min(totalPages, Math.floor(target)));
    setPage(clamped);
    setJumpPage('');
  };

  // 处理跳转输入框回车
  const handleJumpKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      goToPage(Number(jumpPage));
    }
  };

  const handleFilterChange = (key: keyof EventFilter, value: string) => {
    const trimmed = value?.trim() || '';
    setFilter(prev => ({ ...prev, [key]: trimmed || undefined }));
    setPage(1);
  };

  // 搜索框输入：即时更新显示，但通过防抖延迟触发真实筛选，避免每次按键都查询数据库导致卡顿
  const handleSearchChange = (value: string) => {
    setSearchKeyword(value);
    if (searchTimerRef.current) clearTimeout(searchTimerRef.current);
    searchTimerRef.current = setTimeout(() => {
      const trimmed = value.trim();
      setFilter(prev => {
        const next = { ...prev, keyword: trimmed || undefined };
        return next;
      });
      setPage(1);
    }, 350);
  };

  // 组件卸载时清理防抖定时器
  useEffect(() => {
    return () => {
      if (searchTimerRef.current) clearTimeout(searchTimerRef.current);
    };
  }, []);

  // 选择处理
  const toggleSelect = (id: number) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (selectedIds.size === events.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(events.map(e => e.id)));
    }
  };

  // 批量确认
  const handleBatchAcknowledge = async () => {
    if (selectedIds.size === 0) {
      alert('请先选择事件');
      return;
    }
    try {
      await window.electronAPI.acknowledgeEvents(Array.from(selectedIds), true);
      loadEvents();
    } catch (err) {
      console.error('批量确认失败:', err);
    }
  };

  // 一键确认所有未确认事件
  const handleAcknowledgeAll = async () => {
    if (!window.confirm('确定将所有未处理的安全事件标记为已确认吗？')) {
      return;
    }
    try {
      const result = await window.electronAPI.acknowledgeAllEvents();
      if (result && result.success) {
        loadEvents();
      }
    } catch (err) {
      console.error('一键确认全部失败:', err);
    }
  };

  // 批量删除
  const handleBatchDelete = async () => {
    if (selectedIds.size === 0) {
      alert('请先选择事件');
      return;
    }
    if (!confirm(`确定要删除选中的 ${selectedIds.size} 条事件吗？`)) return;
    try {
      await window.electronAPI.deleteEvents(Array.from(selectedIds));
      loadEvents();
    } catch (err) {
      console.error('批量删除失败:', err);
    }
  };

  // 单个确认切换
  const handleToggleAcknowledge = async (event: SecurityEvent) => {
    try {
      await window.electronAPI.acknowledgeEvent(event.id, !event.acknowledged);
      loadEvents();
    } catch (err) {
      console.error('确认操作失败:', err);
    }
  };

  // 单个删除
  const handleDelete = async (event: SecurityEvent) => {
    if (!confirm(`确定要删除这条事件吗？`)) return;
    try {
      await window.electronAPI.deleteEvent(event.id);
      loadEvents();
    } catch (err) {
      console.error('删除失败:', err);
    }
  };

  // 清空所有事件（先弹框确认输入 YES）
  const handleClearAll = () => {
    setShowClearConfirm(true);
  };

  const doClearAll = async () => {
    setShowClearConfirm(false);
    try {
      await window.electronAPI.clearEvents();
      setPage(1);
      setFilter({});
      try { sessionStorage.removeItem(STATE_STORAGE_KEY); } catch (err) { console.error('清除浏览状态失败:', err); }
      const el = getScrollContainer();
      if (el) el.scrollTop = 0;
      loadEvents();
    } catch (err) {
      console.error('清空失败:', err);
    }
  };

  // 导出事件
  const handleExport = async (format: 'csv' | 'json') => {
    try {
      setExporting(true);
      const result = await window.electronAPI.exportEvents(filter);
      const events = result.events;

      if (events.length === 0) {
        alert('没有可导出的事件');
        return;
      }

      let content: string;
      let filename: string;
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);

      if (format === 'json') {
        content = JSON.stringify(events, null, 2);
        filename = `安全事件_${timestamp}.json`;
      } else {
        // CSV 导出
        const headers = ['ID', '事件类型', '源IP', '源端口', '目标IP', '目标端口', '严重级别', '设备名称', '设备IP', '描述', 'OID', '时间', '确认状态'];
        const rows = events.map(e => [
          e.id,
          e.attack_category || e.attack_type || '其他',
          e.source_ip,
          e.source_port || '',
          e.target_ip,
          e.target_port || '',
          e.severity,
          e.device_name,
          e.device_ip,
          `"${(e.description || '').replace(/"/g, '""')}"`,
          e.oid,
          e.timestamp,
          e.acknowledged ? '已确认' : '未确认',
        ]);
        // 处理 CSV 中的逗号和引号
        const escapeCsv = (val: any) => {
          const str = String(val);
          if (str.includes(',') || str.includes('"') || str.includes('\n')) {
            return `"${str.replace(/"/g, '""')}"`;
          }
          return str;
        };
        content = [headers, ...rows].map(row => row.map(escapeCsv).join(',')).join('\n');
        // 添加 BOM 以便 Excel 正确识别 UTF-8
        content = '\uFEFF' + content;
        filename = `安全事件_${timestamp}.csv`;
      }

      // 创建下载
      const blob = new Blob([content], { type: format === 'csv' ? 'text/csv;charset=utf-8' : 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      alert(`成功导出 ${events.length} 条事件`);
    } catch (err) {
      console.error('导出失败:', err);
      alert('导出失败');
    } finally {
      setExporting(false);
    }
  };

  const allSelected = events.length > 0 && selectedIds.size === events.length;

  return (
    <div className="event-list-page">
      <div className="page-header">
        <h1>安全事件</h1>
        <span className="event-count-badge">共 {total} 条记录</span>
      </div>

      {/* 筛选栏 */}
      <div className="filter-bar card">
        <div className="card-body" style={{ padding: '12px 16px' }}>
          <div className="filter-row">
            <select
              className="select"
              value={filter.severity || ''}
              onChange={e => handleFilterChange('severity', e.target.value)}
            >
              <option value="">全部级别</option>
              <option value="critical">严重</option>
              <option value="high">高危</option>
              <option value="medium">中等</option>
              <option value="low">低危</option>
            </select>

            <input
              className="input"
              type="text"
              placeholder="搜索事件类型/设备/IP/端口/时间"
              value={searchKeyword}
              onChange={e => handleSearchChange(e.target.value)}
              style={{ width: 220 }}
            />

            <input
              className="input"
              type="datetime-local"
              value={filter.startTime || ''}
              onChange={e => handleFilterChange('startTime', e.target.value)}
              style={{ width: 180 }}
              title="开始时间（精确到分秒）"
            />

            <input
              className="input"
              type="datetime-local"
              value={filter.endTime || ''}
              onChange={e => handleFilterChange('endTime', e.target.value)}
              style={{ width: 180 }}
              title="结束时间（精确到分秒）"
            />

            <button
              className="btn btn-secondary btn-sm"
              onClick={resetBrowseState}
            >
              重置
            </button>
            <button
              className="btn btn-primary btn-sm"
              onClick={handleRefresh}
              disabled={refreshing}
              title="按当前筛选条件重新加载最新数据"
            >
              {refreshing ? '刷新中...' : '刷新'}
            </button>
          </div>
        </div>
      </div>

      {/* 批量操作工具栏 */}
      {selectedIds.size > 0 && (
        <div className="batch-toolbar">
          <span className="batch-info">已选择 {selectedIds.size} 条事件</span>
          <div className="batch-actions">
            <button className="btn btn-secondary btn-sm" onClick={handleBatchAcknowledge}>
              批量确认
            </button>
            <button className="btn btn-danger btn-sm" onClick={handleBatchDelete}>
              批量删除
            </button>
          </div>
        </div>
      )}

      {/* 工具栏 */}
      <div className="toolbar">
        <button
          className="btn btn-secondary btn-sm"
          onClick={() => handleExport('csv')}
          disabled={exporting || total === 0}
        >
          导出 CSV
        </button>
        <button
          className="btn btn-secondary btn-sm"
          onClick={() => handleExport('json')}
          disabled={exporting || total === 0}
        >
          导出 JSON
        </button>
        <button
          className="btn btn-secondary btn-sm"
          onClick={handleAcknowledgeAll}
          disabled={total === 0}
        >
          一键确认全部
        </button>
        <button
          className="btn btn-danger btn-sm"
          onClick={handleClearAll}
          disabled={total === 0}
          style={{ marginLeft: 'auto' }}
        >
          清空全部
        </button>
      </div>

      {/* 事件表格 */}
      <div className="card" style={{ marginTop: 12 }}>
        <div className="card-body" style={{ padding: 0 }}>
          {loading ? (
            <div className="empty-state">
              <div className="spinner"></div>
              <div className="title">加载中...</div>
            </div>
          ) : events.length === 0 ? (
            <div className="empty-state">
              <div className="icon">📭</div>
              <div className="title">暂无安全事件</div>
              <div className="desc">系统运行正常，未检测到安全威胁</div>
            </div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  {[
                    { key: 'checkbox', label: 'checkbox', width: colWidths[0] },
                    { key: 'time', label: '时间', width: colWidths[1] },
                    { key: 'attackType', label: '事件类型', width: colWidths[2] },
                    { key: 'sourceIp', label: '源IP:端口', width: colWidths[3] },
                    { key: 'targetIp', label: '目标IP:端口', width: colWidths[4] },
                    { key: 'device', label: '设备名称', width: colWidths[5] },
                    { key: 'severity', label: '级别', width: colWidths[6] },
                    { key: 'status', label: '状态', width: colWidths[7] },
                    { key: 'action', label: '操作', width: colWidths[8] },
                  ].map((col, idx) => (
                    <th
                      key={col.key}
                      className="resizeable-th"
                      style={{ width: col.width, minWidth: col.width }}
                    >
                      {col.key === 'checkbox' ? (
                        <input
                          type="checkbox"
                          checked={allSelected}
                          onChange={toggleSelectAll}
                        />
                      ) : (
                        col.label
                      )}
                      <span
                        className={`col-resizer ${idx === 8 ? 'col-resizer-disabled' : ''}`}
                        onMouseDown={(e) => startColumnResize(e, idx)}
                        title="拖拽调整列宽"
                      />
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {events.map(event => (
                  <tr key={event.id} style={{ cursor: 'pointer' }}
                    onClick={() => navigate(`/events/${event.id}`)}>
                    <td onClick={e => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={selectedIds.has(event.id)}
                        onChange={() => toggleSelect(event.id)}
                      />
                    </td>
                    <td style={{ whiteSpace: 'nowrap', fontSize: 12 }}>
                      {formatTime(event.timestamp)}
                    </td>
                    <td>
                      <div className="attack-cell">
                        <span className="attack-cell-main">{event.attack_category || '其他'}</span>
                      </div>
                    </td>
                    <td>
                      <div className="ip-cell">
                        <code>{event.source_ip}{event.source_port ? `:${event.source_port}` : ''}</code>
                        <IpLocation ip={event.source_ip || ''} />
                      </div>
                    </td>
                    <td>
                      <div className="ip-cell">
                        <code>{event.target_ip}{event.target_port ? `:${event.target_port}` : ''}</code>
                        <IpLocation ip={event.target_ip || ''} />
                      </div>
                    </td>
                    <td>{event.device_name}</td>
                    <td>
                      <span className={`badge ${severityConfig[event.severity]?.className || ''}`}>
                        {severityConfig[event.severity]?.label || event.severity}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`status-indicator ${event.acknowledged ? 'acknowledged' : 'unacknowledged'}`}
                      >
                        {event.acknowledged ? '已确认' : '未确认'}
                      </span>
                    </td>
                    <td onClick={e => e.stopPropagation()}>
                      <div className="action-btns">
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => navigate(`/events/${event.id}`)}
                        >
                          详情
                        </button>
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => handleToggleAcknowledge(event)}
                        >
                          {event.acknowledged ? '取消确认' : '确认'}
                        </button>
                        <button
                          className="btn btn-danger btn-sm"
                          onClick={() => handleDelete(event)}
                        >
                          删除
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* 分页 */}
      {totalPages > 1 && (
        <div className="pagination">
          <button
            className="btn btn-secondary btn-sm"
            disabled={page <= 1}
            onClick={() => setPage(p => Math.max(1, p - 1))}
          >
            « 上一页
          </button>

          {/* 页码数字按钮（含省略号） */}
          <div className="pagination-pages">
            {pageNumbers.map((p, idx) =>
              p === -1 ? (
                <span key={`ellipsis-${idx}`} className="page-ellipsis">…</span>
              ) : (
                <button
                  key={p}
                  className={`page-btn ${p === page ? 'page-btn-active' : ''}`}
                  onClick={() => setPage(p)}
                >
                  {p}
                </button>
              )
            )}
          </div>

          <button
            className="btn btn-secondary btn-sm"
            disabled={page >= totalPages}
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
          >
            下一页 »
          </button>

          <span className="page-info">
            共 {totalPages} 页
          </span>

          {/* 页码跳转输入框 */}
          <div className="page-jump">
            <span>跳至</span>
            <input
              className="input page-jump-input"
              type="number"
              min={1}
              max={totalPages}
              value={jumpPage}
              placeholder="页码"
              onChange={e => setJumpPage(e.target.value)}
              onKeyDown={handleJumpKeyDown}
            />
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => goToPage(Number(jumpPage))}
            >
              跳转
            </button>
          </div>
        </div>
      )}

      {/* 清空确认弹框（需输入 YES） */}
      {showClearConfirm && (
        <YesConfirmDialog
          title="清空全部安全事件"
          message="此操作将删除所有安全事件记录，且不可恢复！请输入 YES 确认删除。"
          confirmText="YES"
          onConfirm={doClearAll}
          onCancel={() => setShowClearConfirm(false)}
        />
      )}
    </div>
  );
};

export default EventList;
