import React, { useState } from 'react';
import { AlertTriangle, Plus, RotateCcw } from 'lucide-react';
import { ENTITY_META, ENTITY_ORDER } from '../engine/piiEngine';
import type {
  EnabledEntityMap,
  EntityType,
  RedactionMode,
  SanitizationResult,
} from '../engine/types';

const MODE_OPTIONS: Array<{ id: RedactionMode; title: string; preview: string }> = [
  { id: 'full', title: 'Full Mask', preview: '[REDACTED]' },
  { id: 'partial', title: 'Partial Mask', preview: 'XXXX-XXXX-XXXX-9014' },
  { id: 'pseudonym', title: 'Consistent Pseudonym', preview: 'USER_01' },
];

interface ControlsPanelProps {
  mode: RedactionMode;
  onModeChange: (mode: RedactionMode) => void;
  typedFullMask: boolean;
  onTypedFullMaskChange: (val: boolean) => void;
  isCsv: boolean;
  escapeCsvFormulaCells: boolean;
  onEscapeCsvFormulaCellsChange: (val: boolean) => void;
  strictPhoneContext: boolean;
  onStrictPhoneContextChange: (val: boolean) => void;
  strictAadhaarVerhoeff: boolean;
  onStrictAadhaarVerhoeffChange: (val: boolean) => void;
  customPattern: string;
  onCustomPatternChange: (val: string) => void;
  enabledTypes: EnabledEntityMap;
  onToggleEntity: (type: EntityType) => void;
  ignoredValues: string[];
  onRemoveIgnoredValue: (val: string) => void;
  onResetAllowlist: () => void;
  result: SanitizationResult;
}

export const ControlsPanel: React.FC<ControlsPanelProps> = ({
  mode,
  onModeChange,
  typedFullMask,
  onTypedFullMaskChange,
  isCsv,
  escapeCsvFormulaCells,
  onEscapeCsvFormulaCellsChange,
  strictPhoneContext,
  onStrictPhoneContextChange,
  strictAadhaarVerhoeff,
  onStrictAadhaarVerhoeffChange,
  customPattern,
  onCustomPatternChange,
  enabledTypes,
  onToggleEntity,
  ignoredValues,
  onRemoveIgnoredValue,
  onResetAllowlist,
  result,
}) => {
  const [showCustomRule, setShowCustomRule] = useState(false);

  return (
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
                  onClick={() => onModeChange(opt.id)}
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
                  onChange={(e) => onTypedFullMaskChange(e.target.checked)}
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
            {isCsv && (
              <label
                className="toggle-chip"
                title="Neutralize leading =, +, -, @ characters in exported CSV data cells to prevent spreadsheet formula injection"
              >
                <input
                  type="checkbox"
                  checked={escapeCsvFormulaCells}
                  onChange={(e) => onEscapeCsvFormulaCellsChange(e.target.checked)}
                />
                CSV formula guard
              </label>
            )}
            <label
              className="toggle-chip"
              title="Require cue words (call, phone, mobile, tel, contact) or CSV phone/mobile headers for bare 10-digit numbers"
            >
              <input
                type="checkbox"
                checked={strictPhoneContext}
                onChange={(e) => onStrictPhoneContextChange(e.target.checked)}
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
                onChange={(e) => onStrictAadhaarVerhoeffChange(e.target.checked)}
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
                  onClick={() => onToggleEntity(type)}
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
              onChange={(e) => onCustomPatternChange(e.target.value)}
              placeholder="e.g. EMP-\d{4}|#INC-\d+|sk-[A-Za-z0-9]{16}"
            />
            {customPattern && (
              <button
                type="button"
                className="btn btn-xs btn-ghost"
                onClick={() => onCustomPatternChange('')}
              >
                Clear Rule
              </button>
            )}
            {result.customRegexError && (
              <span className="regex-error" role="alert">
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
                onClick={() => onRemoveIgnoredValue(val)}
                title="Click to remove from allowlist and resume redacting"
              >
                {val} ×
              </button>
            ))}
            <button type="button" className="btn btn-xs btn-ghost" onClick={onResetAllowlist}>
              <RotateCcw size={11} />
              Reset Allowlist
            </button>
          </div>
        )}
      </div>
    </section>
  );
};
