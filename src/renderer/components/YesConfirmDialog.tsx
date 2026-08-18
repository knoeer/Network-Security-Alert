import React, { useState } from 'react';
import './YesConfirmDialog.css';

interface YesConfirmDialogProps {
  title: string;
  message: string;
  confirmText?: string;
  onConfirm: () => void;
  onCancel: () => void;
}

/**
 * 需要输入大写 YES 才能确认的危险操作弹框
 */
const YesConfirmDialog: React.FC<YesConfirmDialogProps> = ({
  title,
  message,
  confirmText = 'YES',
  onConfirm,
  onCancel,
}) => {
  const [input, setInput] = useState('');

  const isConfirmed = input.trim().toUpperCase() === confirmText.toUpperCase();

  return (
    <div className="yes-modal-overlay" onClick={onCancel}>
      <div className="yes-modal" onClick={e => e.stopPropagation()}>
        <div className="yes-modal-header">
          <span className="yes-modal-warning">⚠️</span>
          <h3>{title}</h3>
          <button className="yes-modal-close" onClick={onCancel}>✕</button>
        </div>
        <div className="yes-modal-body">
          <p className="yes-modal-message">{message}</p>
          <div className="yes-modal-input-wrap">
            <label>请输入 <code>{confirmText}</code> 确认删除</label>
            <input
              className="input yes-modal-input"
              type="text"
              value={input}
              onChange={e => setInput(e.target.value)}
              placeholder={`输入 ${confirmText} 以确认`}
              autoFocus
              onKeyDown={e => {
                if (e.key === 'Enter' && isConfirmed) onConfirm();
              }}
            />
          </div>
          <div className="yes-modal-actions">
            <button className="btn btn-secondary" onClick={onCancel}>取消</button>
            <button
              className="btn btn-danger"
              disabled={!isConfirmed}
              onClick={onConfirm}
            >
              确认删除
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default YesConfirmDialog;
