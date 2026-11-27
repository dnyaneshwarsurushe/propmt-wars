import { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  FileText,
  Moon,
  Plus,
  RotateCcw,
  Shield,
  Sparkles,
  Sun,
  Trash2,
  Upload,
} from 'lucide-react';
import { AuditTabs } from './components/AuditTabs';
import { DiffViewer } from './components/DiffViewer';
import { DEFAULT_SAMPLE_ID, SAMPLES, type SampleDataset } from './data/samples';
import {
  CUSTOM_REGEX_TIMEOUT_MS,
  runCustomRegexInWorker,
} from './engine/customRegexRunner';
import {
  DEFAULT_ENABLED_TYPES,
  ENTITY_META,
  ENTITY_ORDER,
  applyPartialMask,
  sanitizeText,
  stripZeroWidthWithMap,
} from './engine/piiEngine';
import type {
  CustomMatchSpan,
  EnabledEntityMap,
  EntityType,
  RedactionMode,
} from './engine/types';

const MAX_UPLOAD_BYTES = 5 * 1024 * 1024; // 5 MB client-side safety guard

const MODE_OPTIONS: Array<{ id: RedactionMode; title: string; preview: string }> = [
  { id: 'full', title: 'Full Mask', preview: '[REDACTED]' },
  { id: 'partial', title: 'Partial Mask', preview: 'XXXX-XXXX-XXXX-9014' },
  { id: 'pseudonym', title: 'Consistent Pseudonym', preview: 'USER_01' },
];

export function App() {
  const [rawText, setRawText] = useState('');
  const [filename, setFilename] = useState('pasted_text.txt');
  const [sampleId, setSampleId] = useState<SampleDataset['id']>(DEFAULT_SAMPLE_ID);
  const [mode, setMode] = useState<RedactionMode>('full');
  const [typedFullMask, setTypedFullMask] = useState(false);
  const [strictAadhaarVerhoeff, setStrictAadhaarVerhoeff] = useState(false);
  const [strictPhoneContext, setStrictPhoneContext] = useState(false);
  const [customPattern, setCustomPattern] = useState('');
  const [customMatches, setCustomMatches] = useState<CustomMatchSpan[]>([]);
  const [customWorkerError, setCustomWorkerError] = useState<string | null>(null);
  const [showCustomRule, setShowCustomRule] = useState(false);
  const [ignoredValues, setIgnoredValues] = useState<string[]>([]);
  const [enabledTypes, setEnabledTypes] = useState<EnabledEntityMap>(DEFAULT_ENABLED_TYPES);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [editorCollapsed, setEditorCollapsed] = useState(false);
  const [theme, setTheme] = useState<'light' | 'dark'>('light');
  const [toast, setToast] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const toastTimerRef = useRef<number | null>(null);

  const notify = (msg: string) => {
    setToast(msg);
    if (toastTimerRef.current) window.clearTimeout(toastTimerRef.current);
    toastTimerRef.current = window.setTimeout(() => setToast(null), 2600);
  };

  const isCsv = filename.toLowerCase().endsWith('.csv');

  // Execute custom regex in an isolated Web Worker with a 500 ms ReDoS timeout
  useEffect(() => {
    let cancelled = false;
    const trimmed = customPattern.trim();

    if (!enabledTypes.CUSTOM || !trimmed || !rawText) {
      setCustomMatches([]);
      setCustomWorkerError(null);
      return;
    }

    setCustomMatches([]);
    setCustomWorkerError(null);
    const { cleanText, mapSpan } = stripZeroWidthWithMap(rawText);
    void runCustomRegexInWorker(cleanText, trimmed, CUSTOM_REGEX_TIMEOUT_MS).then((res) => {
      if (cancelled) return;
      const mappedMatches = res.matches.map((m) => {
        const { start, end } = mapSpan(m.start, m.end);
        return {
          start,
          end,
          value: rawText.slice(start, end),
        };
      });
      setCustomMatches(mappedMatches);
      setCustomWorkerError(res.customRegexError);
    });

    return () => {
      cancelled = true;
    };
  }, [rawText, customPattern, enabledTypes.CUSTOM]);

  const result = useMemo(
    () =>
      sanitizeText(rawText, {
        mode,
        enabledTypes,
        typedFullMask,
        strictAadhaarVerhoeff,
        strictPhoneContext,
        customPattern,
        customMatches,
        customRegexErrorOverride: customWorkerError,
        skipSyncCustomRegex: true,
        ignoredValues,
        isCsv,
      }),
    [
      rawText,
      mode,
      enabledTypes,
      typedFullMask,
      strictAadhaarVerhoeff,
      strictPhoneContext,
      customPattern,
      customMatches,
      customWorkerError,
      ignoredValues,
      isCsv,
    ]
  );

  const csvSummary = useMemo(() => {
    if (!isCsv || !rawText.trim()) return null;
    const rows = rawText.trim().split('\n');
    const cols = rows[0] ? rows[0].split(',').length : 0;
    return `${rows.length} rows × ${cols} cols`;
  }, [isCsv, rawText]);

  const loadSample = (targetId: SampleDataset['id']) => {
    const sample = SAMPLES[targetId];
    setSampleId(targetId);
    setRawText(sample.text);
    setFilename(sample.filename);
    setSelectedId(null);
    notify(`Loaded sample: ${sample.label}`);
  };

  const handleFile = (file: File | undefined) => {
    if (!file) return;
    if (file.size > MAX_UPLOAD_BYTES) {
      notify('File exceeds 5 MB client-side safety limit.');
      return;
    }
    const isTextOrCsv = /\.(txt|csv)$/i.test(file.name) || file.type.startsWith('text/');
    if (!isTextOrCsv) {
      notify('Please upload a .txt or .csv file.');
      return;
    }
    const reader = new FileReader();
    reader.onload = (ev) => {
      setRawText(String(ev.target?.result ?? ''));
      setFilename(file.name);
      setSelectedId(null);
      notify(`Loaded ${file.name} locally in browser memory`);
    };
    reader.readAsText(file);
  };

  const toggleEntity = (type: EntityType) => {
    setEnabledTypes((prev) => ({ ...prev, [type]: !prev[type] }));
    setSelectedId(null);
  };

  const handleIgnoreValue = (value: string) => {
    const trimmed = value.trim();
    if (!trimmed) return;
    setIgnoredValues((prev) => {
      if (prev.some((v) => v.toLowerCase() === trimmed.toLowerCase())) return prev;
      return [...prev, trimmed];
    });
    setSelectedId(null);
    notify('Added value to local allowlist');
  };

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(result.sanitizedText);
      notify('Sanitized output copied to clipboard');
    } catch {
      notify('Clipboard blocked; use Download Sanitized File instead.');
    }
  };

  const triggerDownload = (content: string, outName: string, mime: string) => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = outName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleDownloadSanitized = () => {
    const dot = filename.lastIndexOf('.');
    const base = dot > 0 ? filename.slice(0, dot) : filename;
    const outName = `${base}_sanitized${isCsv ? '.csv' : '.txt'}`;
    triggerDownload(
      result.sanitizedText,
      outName,
      isCsv ? 'text/csv;charset=utf-8' : 'text/plain;charset=utf-8'
    );
    notify(`Downloaded ${outName}`);
  };

  const handleDownloadAuditJson = () => {
    const report = {
      generatedAt: new Date().toISOString(),
      sourceFilename: filename,
      mode,
      riskSummary: result.risk,
      counts: result.counts,
      csvColumns: result.csvColumns,
      entities: result.matches.map((m) => ({
        line: m.line,
        column: m.column,
        type: m.type,
        safePreview: applyPartialMask(m.type, m.value),
        replacement: m.replacement,
        validation: m.validation,
      })),
      rejectedCandidates: result.rejected.map((r) => ({
        line: r.line,
        column: r.column,
        type: r.type,
        value: r.value,
        reason: r.reason,
      })),
    };
    triggerDownload(JSON.stringify(report, null, 2), 'pii_audit_report.json', 'application/json');
    notify('Downloaded privacy-safe audit report (JSON)');
  };

  const lineCount = rawText ? rawText.split('\n').length : 0;

  return (
    <div className={`app-root theme-${theme}`}>
      <div className="container">
        {/* Header */}
        <header className="topbar">
          <div className="brand">
            <div className="brand-icon" aria-hidden="true">
              <Shield size={20} />
            </div>
            <div>
              <div className="brand-title-row">
                <h1>PII Cleanroom</h1>
                <span className="client-badge">
                  <CheckCircle2 size={12} />
                  100% Client-Side · 0 Network Calls
                </span>
              </div>
              <p className="brand-sub">
                Local PII detection, Luhn &amp; Verhoeff verification &amp; compliant redaction studio
              </p>
            </div>
          </div>

          <div className="topbar-actions">
            <div className="sample-combo">
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => loadSample(sampleId)}
              >
                <Sparkles size={14} />
                Load Sample Text
              </button>
              <select
                aria-label="Choose sample dataset"
                value={sampleId}
                onChange={(e) => {
                  const next = e.target.value as SampleDataset['id'];
                  setSampleId(next);
                  if (rawText.trim()) loadSample(next);
                }}
              >
                {Object.values(SAMPLES).map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.label}
                  </option>
                ))}
              </select>
            </div>

            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => fileInputRef.current?.click()}
            >
              <Upload size={14} />
              Upload .txt / .csv
            </button>
            <input
              ref={fileInputRef}
              type="file"
              accept=".txt,.csv,text/plain,text/csv"
              hidden
              onChange={(e) => {
                handleFile(e.target.files?.[0]);
                e.target.value = '';
              }}
            />

            <button
              type="button"
              className="btn btn-ghost"
              onClick={() => {
                setRawText('');
                setFilename('pasted_text.txt');
                setSelectedId(null);
              }}
              disabled={!rawText}
            >
              <Trash2 size={14} />
              Clear
            </button>

            <button
              type="button"
              className="btn btn-ghost icon-only"
              onClick={() => setTheme((t) => (t === 'light' ? 'dark' : 'light'))}
              title={`Switch to ${theme === 'light' ? 'dark' : 'light'} theme`}
              aria-label="Toggle theme"
            >
              {theme === 'light' ? <Moon size={15} /> : <Sun size={15} />}
            </button>
          </div>
        </header>

        {/* Controls & Summary */}
        <section className="card controls-card">
          <div className="controls-top">
            <div>
              <span className="field-label">Redaction Mode</span>
              <div className="mode-row">
                <div className="mode-grid" role="radiogroup" aria-label="Redaction mode">
                  {MODE_OPTIONS.map((opt) => (
                    <button
                      key={opt.id}
                      type="button"
                      role="radio"
                      aria-checked={mode === opt.id}
                      className={`mode-btn${mode === opt.id ? ' active' : ''}`}
                      onClick={() => setMode(opt.id)}
                    >
                      <strong>{opt.title}</strong>
                      <code>
                        {opt.id === 'full' && typedFullMask ? '[REDACTED:TYPE]' : opt.preview}
                      </code>
                    </button>
                  ))}
                </div>

                {mode === 'full' && (
                  <label className="toggle-chip" title="Include entity category in full mask blocks">
                    <input
                      type="checkbox"
                      checked={typedFullMask}
                      onChange={(e) => setTypedFullMask(e.target.checked)}
                    />
                    Include entity tag
                  </label>
                )}
              </div>
            </div>

            <div className="kpi-strip">
              <div className={`kpi-box kpi-risk-${result.risk.level.toLowerCase()}`}>
                <span>Exposure Risk</span>
                <strong>
                  {result.risk.level} ({result.risk.score}/100)
                </strong>
              </div>
              <div className="kpi-box">
                <span>PII Entities</span>
                <strong>{result.counts.TOTAL}</strong>
              </div>
              <div
                className="kpi-box kpi-safe"
                title="13–19 digit strings that failed Luhn mod-10 checksum and were kept untouched"
              >
                <span>Luhn Guard Blocked</span>
                <strong>{result.counts.REJECTED_LUHN}</strong>
              </div>
            </div>
          </div>

          <div className="entity-strip">
            <div className="entity-strip-head">
              <span className="field-label">Entity Detectors &amp; Live Counts</span>
              <div className="policy-toggles">
                <label
                  className="toggle-chip"
                  title="Require cue words (call, phone, mobile, tel, contact) or CSV phone/mobile headers for bare 10-digit numbers"
                >
                  <input
                    type="checkbox"
                    checked={strictPhoneContext}
                    onChange={(e) => setStrictPhoneContext(e.target.checked)}
                  />
                  Strict phone context
                </label>
                <label
                  className="toggle-chip"
                  title="Require mathematical UIDAI Verhoeff checksum on 12-digit Aadhaar numbers"
                >
                  <input
                    type="checkbox"
                    checked={strictAadhaarVerhoeff}
                    onChange={(e) => setStrictAadhaarVerhoeff(e.target.checked)}
                  />
                  Strict Aadhaar Verhoeff
                </label>
                <button
                  type="button"
                  className="btn btn-xs btn-secondary"
                  onClick={() => setShowCustomRule((s) => !s)}
                >
                  <Plus size={12} />
                  {customPattern ? 'Custom Regex Active' : 'Custom Regex Rule'}
                </button>
              </div>
            </div>

            <div className="entity-chips">
              {ENTITY_ORDER.filter((type) => type !== 'CUSTOM' || customPattern.trim().length > 0).map(
                (type) => {
                  const meta = ENTITY_META[type];
                  const enabled = enabledTypes[type];
                  return (
                    <button
                      key={type}
                      type="button"
                      aria-pressed={enabled}
                      className={`entity-chip${enabled ? '' : ' off'}`}
                      onClick={() => toggleEntity(type)}
                    >
                      <span className={`dot dot-${type.toLowerCase()}`} />
                      <span>{meta.shortLabel}</span>
                      <span className="chip-count">{result.counts[type]}</span>
                    </button>
                  );
                }
              )}
            </div>

            {showCustomRule && (
              <div className="custom-rule-bar">
                <label htmlFor="customRegexInput" className="muted-text">
                  Custom Regex:
                </label>
                <input
                  id="customRegexInput"
                  type="text"
                  className="custom-regex-input mono"
                  value={customPattern}
                  onChange={(e) => setCustomPattern(e.target.value)}
                  placeholder="e.g. EMP-\d{4}|#INC-\d+|sk-[A-Za-z0-9]{16}"
                />
                {customPattern && (
                  <button
                    type="button"
                    className="btn btn-xs btn-ghost"
                    onClick={() => setCustomPattern('')}
                  >
                    Clear Rule
                  </button>
                )}
                {result.customRegexError && (
                  <span className="regex-error">
                    <AlertTriangle size={12} /> {result.customRegexError}
                  </span>
                )}
              </div>
            )}

            {ignoredValues.length > 0 && (
              <div className="allowlist-bar">
                <span className="muted-text">Allowlisted ({ignoredValues.length}):</span>
                {ignoredValues.map((val) => (
                  <button
                    key={val}
                    type="button"
                    className="allowlist-pill mono"
                    onClick={() =>
                      setIgnoredValues((prev) => prev.filter((item) => item !== val))
                    }
                    title="Click to remove from allowlist and resume redacting"
                  >
                    {val} ×
                  </button>
                ))}
                <button
                  type="button"
                  className="btn btn-xs btn-ghost"
                  onClick={() => setIgnoredValues([])}
                >
                  <RotateCcw size={11} />
                  Reset Allowlist
                </button>
              </div>
            )}
          </div>
        </section>

        {/* Raw Input Area */}
        <section
          className={`card editor-card${isDragging ? ' dragging' : ''}${
            editorCollapsed ? ' collapsed' : ''
          }`}
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
            handleFile(e.dataTransfer.files?.[0]);
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
                onClick={() => setEditorCollapsed((c) => !c)}
              >
                {editorCollapsed ? 'Expand Editor' : 'Collapse Editor'}
              </button>
            </div>
          </div>

          {!editorCollapsed && (
            <textarea
              className="raw-input"
              spellCheck={false}
              value={rawText}
              onChange={(e) => {
                setRawText(e.target.value);
                setSelectedId(null);
              }}
              placeholder="Paste logs, resumes, support tickets, clinical notes, or CSV data here — or click 'Load Sample Text'..."
            />
          )}
        </section>

        {/* Side-by-Side Diff */}
        <DiffViewer
          text={rawText}
          result={result}
          mode={mode}
          selectedId={selectedId}
          onSelectEntity={setSelectedId}
          onIgnoreValue={handleIgnoreValue}
          onLoadSample={loadSample}
          onCopy={handleCopy}
          onDownload={handleDownloadSanitized}
        />

        {/* Audit, Pseudonym Map, Checksum Guard, CSV Risk & Prompt Log */}
        <AuditTabs
          result={result}
          selectedId={selectedId}
          onSelectEntity={setSelectedId}
          onIgnoreValue={handleIgnoreValue}
          onDownloadAuditJson={handleDownloadAuditJson}
        />
      </div>

      {toast && (
        <div className="toast" role="status" aria-live="polite">
          {toast}
        </div>
      )}
    </div>
  );
}

export default App;
