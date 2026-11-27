import React, { useEffect, useMemo, useState } from 'react';
import { EyeOff, FileJson, Search, ShieldAlert, ShieldCheck, Table2 } from 'lucide-react';
import { ENTITY_META, applyPartialMask } from '../engine/piiEngine';
import type { SanitizationResult } from '../engine/types';

interface AuditTabsProps {
  result: SanitizationResult;
  selectedId: string | null;
  resetSignal?: number;
  onSelectEntity: (id: string | null) => void;
  onIgnoreValue: (value: string) => void;
  onDownloadAuditJson: () => void;
}

type TabId = 'audit' | 'mapping' | 'luhn' | 'csv' | 'prompt';

export const AuditTabs: React.FC<AuditTabsProps> = ({
  result,
  selectedId,
  resetSignal = 0,
  onSelectEntity,
  onIgnoreValue,
  onDownloadAuditJson,
}) => {
  const [activeTab, setActiveTab] = useState<TabId>('audit');
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    setSearchQuery('');
  }, [resetSignal]);

  const filteredMatches = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return result.matches;
    return result.matches.filter((m) => {
      const label = ENTITY_META[m.type].label.toLowerCase();
      return (
        label.includes(q) ||
        m.replacement.toLowerCase().includes(q) ||
        m.validation.toLowerCase().includes(q) ||
        applyPartialMask(m.type, m.value).toLowerCase().includes(q)
      );
    });
  }, [result.matches, searchQuery]);

  return (
    <section className="card audit-card" aria-label="Audit and logs">
      <div className="tabs-header">
        <div className="tabs-list" role="tablist">
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'audit'}
            className={`tab-btn${activeTab === 'audit' ? ' active' : ''}`}
            onClick={() => setActiveTab('audit')}
          >
            Audit Log ({result.counts.TOTAL})
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'mapping'}
            className={`tab-btn${activeTab === 'mapping' ? ' active' : ''}`}
            onClick={() => setActiveTab('mapping')}
          >
            Pseudonym Map ({result.pseudonymMappings.length})
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'luhn'}
            className={`tab-btn${activeTab === 'luhn' ? ' active' : ''}`}
            onClick={() => setActiveTab('luhn')}
          >
            Checksum Rejected ({result.rejected.length})
          </button>
          {result.csvColumns.length > 0 && (
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'csv'}
              className={`tab-btn${activeTab === 'csv' ? ' active' : ''}`}
              onClick={() => setActiveTab('csv')}
            >
              CSV Column Risk ({result.csvColumns.length})
            </button>
          )}
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'prompt'}
            className={`tab-btn${activeTab === 'prompt' ? ' active' : ''}`}
            onClick={() => setActiveTab('prompt')}
          >
            Prompt &amp; Design Log
          </button>
        </div>

        <button
          type="button"
          className="btn btn-xs btn-secondary"
          onClick={onDownloadAuditJson}
          disabled={!result.originalText}
          title="Download privacy-safe audit metadata JSON (contains no raw unmasked PII)"
        >
          <FileJson size={13} />
          Export Audit JSON
        </button>
      </div>

      <div className="tab-body">
        {activeTab === 'audit' && (
          <>
            {result.matches.length > 0 && (
              <div className="audit-filter-row">
                <div className="search-box">
                  <Search size={13} />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Filter audit log by entity, mask, or rule..."
                    aria-label="Filter audit log"
                  />
                </div>
                <span className="muted-text">
                  Showing {filteredMatches.length} of {result.matches.length} entities
                </span>
              </div>
            )}

            <div className="table-scroll">
              <table className="audit-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Line : Col</th>
                    <th>Entity Type</th>
                    <th>Original (Safe Preview)</th>
                    <th>Replacement</th>
                    <th>Validation Rule</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredMatches.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="empty-cell">
                        No PII entities match current filters.
                      </td>
                    </tr>
                  ) : (
                    filteredMatches.map((m, idx) => {
                      const meta = ENTITY_META[m.type];
                      const isSelected = selectedId === m.id;
                      return (
                        <tr
                          key={m.id}
                          className={isSelected ? 'row-selected' : undefined}
                          onClick={() => onSelectEntity(isSelected ? null : m.id)}
                        >
                          <td>{idx + 1}</td>
                          <td className="mono">
                            {m.line}:{m.column}
                          </td>
                          <td>
                            <span className={`token token-${m.type.toLowerCase()}`}>
                              {meta.shortLabel}
                            </span>
                          </td>
                          <td className="mono">{applyPartialMask(m.type, m.value)}</td>
                          <td className="mono">{m.replacement}</td>
                          <td>{m.validation}</td>
                          <td>
                            <button
                              type="button"
                              className="btn btn-xs btn-ghost"
                              onClick={(e) => {
                                e.stopPropagation();
                                onIgnoreValue(m.value);
                              }}
                              title="Whitelist this value (exclude from redaction)"
                            >
                              <EyeOff size={12} />
                              Ignore
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {activeTab === 'mapping' && (
          <>
            <p className="tab-hint">
              <ShieldCheck size={14} /> Consistent pseudonymization normalizes recurring identifiers
              (e.g., matching emails or differently formatted Aadhaar/phone numbers) to identical
              placeholders in memory only.
            </p>
            <div className="table-scroll">
              <table className="audit-table">
                <thead>
                  <tr>
                    <th>Placeholder</th>
                    <th>Entity Type</th>
                    <th>Occurrences</th>
                    <th>Safe Context Preview</th>
                  </tr>
                </thead>
                <tbody>
                  {result.pseudonymMappings.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="empty-cell">
                        {result.mode === 'pseudonym'
                          ? 'No entities detected to map yet.'
                          : 'Switch to "Consistent Pseudonym" mode to generate the mapping table.'}
                      </td>
                    </tr>
                  ) : (
                    result.pseudonymMappings.map((entry) => (
                      <tr key={entry.normalizedKey}>
                        <td className="mono">
                          <strong>{entry.placeholder}</strong>
                        </td>
                        <td>
                          <span className={`token token-${entry.type.toLowerCase()}`}>
                            {ENTITY_META[entry.type].shortLabel}
                          </span>
                        </td>
                        <td>{entry.occurrences}</td>
                        <td className="mono">
                          {applyPartialMask(entry.type, entry.sampleOriginal)}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {activeTab === 'luhn' && (
          <>
            <p className="tab-hint">
              <ShieldAlert size={14} /> Candidates failing Luhn mod-10 (cards) or Verhoeff (when
              Strict Aadhaar mode is enabled) are spared from redaction.
            </p>
            <div className="table-scroll">
              <table className="audit-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Line : Col</th>
                    <th>Type</th>
                    <th>Candidate (Safe Preview)</th>
                    <th>Rejection Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {result.rejected.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="empty-cell">
                        No checksum-rejected candidates encountered.
                      </td>
                    </tr>
                  ) : (
                    result.rejected.map((r, idx) => (
                      <tr key={`${r.start}-${idx}`}>
                        <td>{idx + 1}</td>
                        <td className="mono">
                          {r.line}:{r.column}
                        </td>
                        <td>
                          <span className={`token token-${r.type.toLowerCase()}`}>
                            {ENTITY_META[r.type].shortLabel}
                          </span>
                        </td>
                        <td className="mono">{applyPartialMask(r.type, r.value)}</td>
                        <td>{r.reason}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {activeTab === 'csv' && (
          <>
            <p className="tab-hint">
              <Table2 size={14} /> Automatic column-level PII exposure profiling for tabular CSV
              imports. Delimiters and row structure are preserved verbatim upon export.
            </p>
            <div className="table-scroll">
              <table className="audit-table">
                <thead>
                  <tr>
                    <th>Column #</th>
                    <th>Header</th>
                    <th>PII Hits</th>
                    <th>Detected Categories</th>
                  </tr>
                </thead>
                <tbody>
                  {result.csvColumns.map((col) => (
                    <tr key={col.columnIndex}>
                      <td className="mono">{col.columnIndex + 1}</td>
                      <td className="mono">
                        <strong>{col.header}</strong>
                      </td>
                      <td>{col.entityCount}</td>
                      <td>
                        {col.types.length === 0 ? (
                          <span className="muted-text">Clean (0 PII)</span>
                        ) : (
                          <div className="csv-type-list">
                            {col.types.map((t) => (
                              <span key={t} className={`token token-${t.toLowerCase()}`}>
                                {ENTITY_META[t].shortLabel}
                              </span>
                            ))}
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}

        {activeTab === 'prompt' && (
          <div className="prompt-log">
            <div className="prompt-step">
              <div className="prompt-step-head">
                <strong>1. Architecture &amp; Client-Side Isolation</strong>
                <span className="pill-metric">React + TypeScript + Vite</span>
              </div>
              <p>
                Built as a strictly browser-resident React + TypeScript application with zero
                network dependencies, no external fonts/CDNs, and deterministic in-memory
                sanitization. Tested independently via Vitest (<code>src/engine/piiEngine.test.ts</code>).
              </p>
            </div>
            <div className="prompt-step">
              <div className="prompt-step-head">
                <strong>2. Precision Detection, Luhn &amp; Verhoeff Checksums</strong>
                <span className="pill-metric">Regex + Checksums</span>
              </div>
              <p>
                Detects emails, Indian &amp; international phones, IPv4 (0–255 octet bounds,
                excluding software tags like <code>v1.2.3.4</code>) &amp; IPv6, Indian PAN, Indian
                Aadhaar (UIDAI 2–9 prefix with Verhoeff validation annotation &amp; optional strict
                mode), Luhn-validated credit cards, and user-defined custom regex rules.
              </p>
            </div>
            <div className="prompt-step">
              <div className="prompt-step-head">
                <strong>3. Redaction Modes, Allowlist &amp; CSV Column Profiling</strong>
                <span className="pill-metric">Full / Partial / Pseudonym</span>
              </div>
              <p>
                Supports Full Mask (<code>[REDACTED]</code> or typed <code>[REDACTED:TYPE]</code>),
                Partial Mask, and Consistent Pseudonymization (<code>USER_01</code>,{' '}
                <code>PAN_01</code>, etc.). Includes interactive entity inspection, per-value
                allowlist ignoring, CSV column risk analysis, changed-lines filtering, and 1-click
                export (full record in <code>PROMPT_LOG.md</code>).
              </p>
            </div>
          </div>
        )}
      </div>
    </section>
  );
};
