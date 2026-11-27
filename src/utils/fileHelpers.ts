import { applyPartialMask, sanitizeText } from '../engine/piiEngine';
import type { RedactionMode, SanitizationResult } from '../engine/types';

export const MAX_UPLOAD_BYTES = 5 * 1024 * 1024; // 5 MB client-side safety limit

/**
 * Decodes an uploaded file buffer, handling UTF-8 / UTF-16 BOMs and rejecting binary payloads.
 */
export function decodeTextFileBuffer(buffer: ArrayBuffer): { text?: string; error?: string } {
  const bytes = new Uint8Array(buffer);
  let encoding: 'utf-8' | 'utf-16le' | 'utf-16be' = 'utf-8';
  let offset = 0;

  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    encoding = 'utf-16le';
    offset = 2;
  } else if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    encoding = 'utf-16be';
    offset = 2;
  } else {
    if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
      offset = 3;
    }
    const probeLimit = Math.min(bytes.length, 8192);
    for (let i = offset; i < probeLimit; i++) {
      if (bytes[i] === 0) {
        return { error: 'Binary file detected. Please upload plain UTF-8/UTF-16 .txt or .csv text.' };
      }
    }
  }

  return { text: new TextDecoder(encoding).decode(bytes.subarray(offset)) };
}

/**
 * Sanitizes an uploaded filename so exported download names never echo raw PII.
 */
export function getSafeFilenameBase(rawName: string): string {
  const dot = rawName.lastIndexOf('.');
  const rawBase = dot > 0 ? rawName.slice(0, dot) : rawName;
  const cleaned = sanitizeText(rawBase, {
    mode: 'full',
    fullMaskToken: 'redacted',
    strictPhoneContext: false,
  }).sanitizedText;
  return cleaned.replace(/[^A-Za-z0-9._-]+/g, '_') || 'sanitized_output';
}

export function triggerFileDownload(content: string, outName: string, mime: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = outName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Builds a privacy-safe audit JSON payload containing partial-masked previews only.
 */
export function buildAuditReportJson(
  filename: string,
  isCsv: boolean,
  mode: RedactionMode,
  result: SanitizationResult
): string {
  const safeSourceName = `${getSafeFilenameBase(filename)}${isCsv ? '.csv' : '.txt'}`;
  const report = {
    generatedAt: new Date().toISOString(),
    sourceFilename: safeSourceName,
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
      safePreview: applyPartialMask(r.type, r.value),
      reason: r.reason,
    })),
  };
  return JSON.stringify(report, null, 2);
}
