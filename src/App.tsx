import { useEffect, useMemo, useRef, useState } from 'react';
import { CheckCircle2, Moon, Shield, Sparkles, Sun, Trash2, Upload } from 'lucide-react';
import { AuditTabs } from './components/AuditTabs';
import { ControlsPanel } from './components/ControlsPanel';
import { DiffViewer } from './components/DiffViewer';
import { FileInputPanel } from './components/FileInputPanel';
import { DEFAULT_SAMPLE_ID, SAMPLES, type SampleDataset } from './data/samples';
import { CUSTOM_REGEX_TIMEOUT_MS, runCustomRegexInWorker } from './engine/customRegexRunner';
import {
  DEFAULT_ENABLED_TYPES,
  escapeCsvFormulas,
  sanitizeText,
  stripZeroWidthWithMap,
} from './engine/piiEngine';
import type {
  CustomMatchSpan,
  EnabledEntityMap,
  EntityType,
  RedactionMode,
} from './engine/types';
import {
  MAX_UPLOAD_BYTES,
  buildAuditReportJson,
  decodeTextFileBuffer,
  getSafeFilenameBase,
  triggerFileDownload,
} from './utils/fileHelpers';

export function App() {
  const [rawText, setRawText] = useState('');
  const [filename, setFilename] = useState('pasted_text.txt');
  const [sampleId, setSampleId] = useState<SampleDataset['id']>(DEFAULT_SAMPLE_ID);
  const [mode, setMode] = useState<RedactionMode>('full');
  const [typedFullMask, setTypedFullMask] = useState(false);
  const [strictAadhaarVerhoeff, setStrictAadhaarVerhoeff] = useState(false);
  const [strictPhoneContext, setStrictPhoneContext] = useState(false);
  const [escapeCsvFormulaCells, setEscapeCsvFormulaCells] = useState(true);
  const [customPattern, setCustomPattern] = useState('');
  const [customMatches, setCustomMatches] = useState<CustomMatchSpan[]>([]);
  const [customWorkerError, setCustomWorkerError] = useState<string | null>(null);
  const [ignoredValues, setIgnoredValues] = useState<string[]>([]);
  const [enabledTypes, setEnabledTypes] = useState<EnabledEntityMap>(DEFAULT_ENABLED_TYPES);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [theme, setTheme] = useState<'light' | 'dark'>('light');
  const [clearSignal, setClearSignal] = useState(0);
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
      const mapped = res.matches.map((m) => {
        const { start, end } = mapSpan(m.start, m.end);
        return { start, end, value: rawText.slice(start, end) };
      });
      setCustomMatches(mapped);
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
    reader.onerror = () => notify('Failed to read file locally. Check file permissions or encoding.');
    reader.onload = (ev) => {
      const buffer = ev.target?.result;
      if (!(buffer instanceof ArrayBuffer)) {
        notify('Unsupported file read result.');
        return;
      }
      const decoded = decodeTextFileBuffer(buffer);
      if (decoded.error || decoded.text === undefined) {
        notify(decoded.error ?? 'Failed to decode file.');
        return;
      }
      setRawText(decoded.text);
      setFilename(file.name);
      setSelectedId(null);
      notify(`Loaded ${file.name} locally in browser memory`);
    };
    reader.readAsArrayBuffer(file);
  };

  const handleRawTextChange = (next: string) => {
    if (next.length > MAX_UPLOAD_BYTES) {
      setRawText(next.slice(0, MAX_UPLOAD_BYTES));
      notify('Input truncated at 5 MB client-side safety limit.');
    } else {
      setRawText(next);
    }
    setSelectedId(null);
  };

  const handleClear = () => {
    setRawText('');
    setFilename('pasted_text.txt');
    setSelectedId(null);
    setCustomMatches([]);
    setCustomWorkerError(null);
    setClearSignal((c) => c + 1);
  };

  const handleIgnoreValue = (value: string) => {
    const trimmed = value.trim();
    if (!trimmed) return;
    setIgnoredValues((prev) =>
      prev.some((v) => v.toLowerCase() === trimmed.toLowerCase()) ? prev : [...prev, trimmed]
    );
    setSelectedId(null);
    notify('Added value to local allowlist');
  };

  const getExportText = () =>
    isCsv && escapeCsvFormulaCells ? escapeCsvFormulas(result.sanitizedText) : result.sanitizedText;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(getExportText());
      notify('Sanitized output copied to clipboard');
    } catch {
      notify('Clipboard blocked; use Download Sanitized File instead.');
    }
  };

  const handleDownloadSanitized = () => {
    const safeBase = getSafeFilenameBase(filename);
    const outName = `${safeBase}_sanitized${isCsv ? '.csv' : '.txt'}`;
    triggerFileDownload(
      getExportText(),
      outName,
      isCsv ? 'text/csv;charset=utf-8' : 'text/plain;charset=utf-8'
    );
    notify(`Downloaded ${outName}`);
  };

  const handleDownloadAuditJson = () => {
    const json = buildAuditReportJson(filename, isCsv, mode, result);
    triggerFileDownload(json, 'pii_audit_report.json', 'application/json');
    notify('Downloaded privacy-safe audit report (JSON)');
  };

  const toggleEntity = (type: EntityType) => {
    setEnabledTypes((prev) => ({ ...prev, [type]: !prev[type] }));
    setSelectedId(null);
  };

  return (
    <div className={`app-root theme-${theme}`}>
      <div className="container">
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
              onClick={handleClear}
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

        <ControlsPanel
          mode={mode}
          onModeChange={setMode}
          typedFullMask={typedFullMask}
          onTypedFullMaskChange={setTypedFullMask}
          isCsv={isCsv}
          escapeCsvFormulaCells={escapeCsvFormulaCells}
          onEscapeCsvFormulaCellsChange={setEscapeCsvFormulaCells}
          strictPhoneContext={strictPhoneContext}
          onStrictPhoneContextChange={setStrictPhoneContext}
          strictAadhaarVerhoeff={strictAadhaarVerhoeff}
          onStrictAadhaarVerhoeffChange={setStrictAadhaarVerhoeff}
          customPattern={customPattern}
          onCustomPatternChange={setCustomPattern}
          enabledTypes={enabledTypes}
          onToggleEntity={toggleEntity}
          ignoredValues={ignoredValues}
          onRemoveIgnoredValue={(val) =>
            setIgnoredValues((prev) => prev.filter((item) => item !== val))
          }
          onResetAllowlist={() => setIgnoredValues([])}
          result={result}
        />

        <FileInputPanel
          rawText={rawText}
          filename={filename}
          csvSummary={csvSummary}
          onTextChange={handleRawTextChange}
          onFileDrop={handleFile}
        />

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

        <AuditTabs
          result={result}
          selectedId={selectedId}
          resetSignal={clearSignal}
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
