import React, { useMemo, useRef, useState } from 'react';
import { Copy, Download, EyeOff, Filter, Link2, Sparkles, X } from 'lucide-react';
import { SAMPLES, type SampleDataset } from '../data/samples';
import { ENTITY_META, applyPartialMask } from '../engine/piiEngine';
import type { RedactionMode, SanitizationResult, SanitizedEntity } from '../engine/types';

interface DiffViewerProps {
  text: string;
  result: SanitizationResult;
  mode: RedactionMode;
  selectedId: string | null;
  onSelectEntity: (id: string | null) => void;
  onIgnoreValue: (value: string) => void;
  onLoadSample: (id: SampleDataset['id']) => void;
  onCopy: () => void;
  onDownload: () => void;
}

const MODE_BADGE: Record<RedactionMode, string> = {
  full: 'Full Mask',
  partial: 'Partial Mask · Context Kept',
  pseudonym: 'Consistent Pseudonym · USER_01',
};

export const DiffViewer: React.FC<DiffViewerProps> = ({
  text,
  result,
  mode,
  selectedId,
  onSelectEntity,
  onIgnoreValue,
  onLoadSample,
  onCopy,
  onDownload,
}) => {
  const [syncScroll, setSyncScroll] = useState(true);
  const [changedOnly, setChangedOnly] = useState(false);
  const leftRef = useRef<HTMLDivElement>(null);
  const rightRef = useRef<HTMLDivElement>(null);
  const syncingRef = useRef(false);

  const selectedEntity = useMemo(
    () => result.matches.find((m) => m.id === selectedId) ?? null,
    [result.matches, selectedId]
  );

  const linesData = useMemo(() => {
    if (!text) return [];
    const lines = text.split('\n');
    const starts: number[] = [];
    let offset = 0;
    for (const line of lines) {
      starts.push(offset);
      offset += line.length + 1;
    }

    const byLine = new Map<number, SanitizedEntity[]>();
    for (const match of result.matches) {
      const idx = match.line - 1;
      const list = byLine.get(idx);
      if (list) list.push(match);
      else byLine.set(idx, [match]);
    }

    return lines.map((lineText, idx) => ({
      lineNumber: idx + 1,
      lineStart: starts[idx],
      lineText,
      matches: byLine.get(idx) ?? [],
    }));
  }, [text, result.matches]);

  const visibleLines = useMemo(() => {
    if (!changedOnly) return linesData;
    return linesData.filter((l) => l.matches.length > 0);
  }, [linesData, changedOnly]);

  const handleScroll = (source: 'left' | 'right') => {
    if (!syncScroll || syncingRef.current) return;
    const fromEl = source === 'left' ? leftRef.current : rightRef.current;
    const toEl = source === 'left' ? rightRef.current : leftRef.current;
    if (!fromEl || !toEl) return;

    syncingRef.current = true;
    toEl.scrollTop = fromEl.scrollTop;
    toEl.scrollLeft = fromEl.scrollLeft;
    requestAnimationFrame(() => {
      syncingRef.current = false;
    });
  };

  const renderLineSegments = (
    lineText: string,
    lineStart: number,
    matches: SanitizedEntity[],
    side: 'original' | 'sanitized'
  ) => {
    if (matches.length === 0) {
      return <span>{lineText || ' '}</span>;
    }

    const nodes: React.ReactNode[] = [];
    let cursor = 0;

    matches.forEach((m, idx) => {
      const relStart = m.start - lineStart;
      const relEnd = m.end - lineStart;

      if (relStart > cursor) {
        nodes.push(
          <React.Fragment key={`txt-${idx}`}>{lineText.slice(cursor, relStart)}</React.Fragment>
        );
      }

      const meta = ENTITY_META[m.type];
      const isSelected = selectedId === m.id;
      const tokenClass = `token token-${m.type.toLowerCase()} ${
        side === 'sanitized' ? 'token-sanitized' : 'token-original'
      }${isSelected ? ' token-selected' : ''}`;

      nodes.push(
        <span
          key={m.id}
          role="button"
          tabIndex={0}
          aria-pressed={isSelected}
          className={tokenClass}
          title={`${meta.label} (${m.validation})\nClick or press Enter to inspect or whitelist`}
          onClick={() => onSelectEntity(isSelected ? null : m.id)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              onSelectEntity(isSelected ? null : m.id);
            }
          }}
        >
          {side === 'original' ? m.value : m.replacement}
        </span>
      );

      cursor = relEnd;
    });

    if (cursor < lineText.length) {
      nodes.push(<React.Fragment key="tail">{lineText.slice(cursor)}</React.Fragment>);
    }

    return nodes;
  };

  return (
    <section className="card diff-card" aria-label="Side-by-side diff view">
      <div className="diff-toolbar">
        <div className="diff-toolbar-group">
          <h2 className="card-title">Live Side-by-Side Diff</h2>
          <span className="pill-metric">{result.durationMs} ms local scan</span>
          <label className="toggle-chip">
            <input
              type="checkbox"
              checked={syncScroll}
              onChange={(e) => setSyncScroll(e.target.checked)}
            />
            <Link2 size={13} />
            Sync scroll
          </label>
          <label className="toggle-chip">
            <input
              type="checkbox"
              checked={changedOnly}
              onChange={(e) => setChangedOnly(e.target.checked)}
            />
            <Filter size={13} />
            Changed lines only
          </label>
        </div>

        <div className="diff-toolbar-group">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={onCopy}
            disabled={!text}
          >
            <Copy size={14} />
            Copy Output
          </button>
          <button
            type="button"
            className="btn btn-accent"
            onClick={onDownload}
            disabled={!text}
          >
            <Download size={14} />
            Download Sanitized File
          </button>
        </div>
      </div>

      {/* Interactive Entity Inspector */}
      {selectedEntity && (
        <div className="inspector-bar" role="region" aria-label="Selected entity inspector">
          <div className="inspector-info">
            <span className={`token token-${selectedEntity.type.toLowerCase()}`}>
              {ENTITY_META[selectedEntity.type].label}
            </span>
            <span className="pill-metric">
              Line {selectedEntity.line}:{selectedEntity.column}
            </span>
            <span className="muted-text">{selectedEntity.validation}</span>
            <code className="inspector-arrow">
              {applyPartialMask(selectedEntity.type, selectedEntity.value)} →{' '}
              <strong>{selectedEntity.replacement}</strong>
            </code>
          </div>
          <div className="inspector-actions">
            <button
              type="button"
              className="btn btn-xs btn-secondary"
              onClick={() => onIgnoreValue(selectedEntity.value)}
              title="Add this exact value to the local allowlist so it stays unredacted"
            >
              <EyeOff size={12} />
              Ignore / Whitelist Value
            </button>
            <button
              type="button"
              className="btn btn-xs btn-ghost"
              onClick={() => onSelectEntity(null)}
              aria-label="Close inspector"
            >
              <X size={13} />
            </button>
          </div>
        </div>
      )}

      {!text ? (
        <div className="quickstart-empty">
          <p className="quickstart-lead">
            Paste raw text above, drag &amp; drop a <code>.txt</code> / <code>.csv</code> file, or
            jump straight in with a noisy sample dataset:
          </p>
          <div className="quickstart-grid">
            {Object.values(SAMPLES).map((sample) => (
              <button
                key={sample.id}
                type="button"
                className="quickstart-card"
                onClick={() => onLoadSample(sample.id)}
              >
                <div className="quickstart-head">
                  <Sparkles size={14} />
                  <strong>{sample.label}</strong>
                </div>
                <p>{sample.description}</p>
              </button>
            ))}
          </div>
        </div>
      ) : (
        <div className="diff-split">
          <div className="diff-pane">
            <div className="diff-pane-head">
              <span>Original Input (Click any PII token to inspect)</span>
              <span className="pane-pill">{result.counts.TOTAL} detected</span>
            </div>
            <div
              ref={leftRef}
              className="diff-scroll"
              onScroll={() => handleScroll('left')}
            >
              {visibleLines.length === 0 ? (
                <div className="diff-empty">No lines contain detected PII with current filters.</div>
              ) : (
                visibleLines.map((line) => (
                  <div
                    key={`orig-${line.lineNumber}`}
                    className={`diff-row${line.matches.length > 0 ? ' diff-row-hit' : ''}`}
                  >
                    <span className="diff-ln">{line.lineNumber}</span>
                    <span className="diff-code">
                      {renderLineSegments(line.lineText, line.lineStart, line.matches, 'original')}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="diff-pane">
            <div className="diff-pane-head">
              <span>Sanitized Output (Redacted)</span>
              <span className="pane-pill">{MODE_BADGE[mode]}</span>
            </div>
            <div
              ref={rightRef}
              className="diff-scroll"
              onScroll={() => handleScroll('right')}
            >
              {visibleLines.length === 0 ? (
                <div className="diff-empty">No modified lines under current filter.</div>
              ) : (
                visibleLines.map((line) => (
                  <div
                    key={`san-${line.lineNumber}`}
                    className={`diff-row${line.matches.length > 0 ? ' diff-row-hit' : ''}`}
                  >
                    <span className="diff-ln">{line.lineNumber}</span>
                    <span className="diff-code">
                      {renderLineSegments(line.lineText, line.lineStart, line.matches, 'sanitized')}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </section>
  );
};
