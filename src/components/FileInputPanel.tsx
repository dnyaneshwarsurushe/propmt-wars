import React, { useState } from 'react';
import { FileText } from 'lucide-react';

interface FileInputPanelProps {
  rawText: string;
  filename: string;
  csvSummary: string | null;
  onTextChange: (nextText: string) => void;
  onFileDrop: (file: File | undefined) => void;
}

export const FileInputPanel: React.FC<FileInputPanelProps> = ({
  rawText,
  filename,
  csvSummary,
  onTextChange,
  onFileDrop,
}) => {
  const [isDragging, setIsDragging] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const lineCount = rawText ? rawText.split('\n').length : 0;

  return (
    <section
      className={`card editor-card${isDragging ? ' dragging' : ''}${collapsed ? ' collapsed' : ''}`}
      onDragEnter={(e) => {
        e.preventDefault();
        setIsDragging(true);
      }}
      onDragOver={(e) => {
        e.preventDefault();
        setIsDragging(true);
      }}
      onDragLeave={(e) => {
        e.preventDefault();
        setIsDragging(false);
      }}
      onDrop={(e) => {
        e.preventDefault();
        setIsDragging(false);
        onFileDrop(e.dataTransfer.files?.[0]);
      }}
    >
      <div className="editor-head">
        <div className="editor-meta">
          <FileText size={15} />
          <strong>Raw Input</strong>
          <span className="pill-metric">{filename}</span>
          {csvSummary && <span className="pill-metric">{csvSummary}</span>}
          <span className="muted-text">
            {lineCount} {lineCount === 1 ? 'line' : 'lines'} · {rawText.length} chars
          </span>
        </div>
        <div className="editor-actions">
          <span className="muted-text">
            Paste text or drag &amp; drop a <code>.txt</code> / <code>.csv</code> file
          </span>
          <button
            type="button"
            className="btn btn-xs btn-ghost"
            aria-expanded={!collapsed}
            onClick={() => setCollapsed((c) => !c)}
          >
            {collapsed ? 'Expand Editor' : 'Collapse Editor'}
          </button>
        </div>
      </div>

      {!collapsed && (
        <textarea
          className="raw-input"
          aria-label="Raw input text"
          spellCheck={false}
          value={rawText}
          onChange={(e) => onTextChange(e.target.value)}
          placeholder="Paste logs, resumes, support tickets, clinical notes, or CSV data here — or click 'Load Sample Text'..."
        />
      )}
    </section>
  );
};
