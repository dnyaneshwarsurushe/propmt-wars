import type {
  CsvColumnRisk,
  DetectedEntity,
  EnabledEntityMap,
  EntityMeta,
  EntityType,
  PseudonymEntry,
  RejectedCandidate,
  RiskSummary,
  SanitizationCounts,
  SanitizationResult,
  SanitizeOptions,
  SanitizedEntity,
} from './types';

export const ENTITY_ORDER: EntityType[] = [
  'EMAIL',
  'PHONE',
  'IP_ADDRESS',
  'PAN',
  'AADHAAR',
  'CREDIT_CARD',
  'CUSTOM',
];

export const ENTITY_META: Record<EntityType, EntityMeta> = {
  EMAIL: {
    id: 'EMAIL',
    label: 'Email Address',
    shortLabel: 'Email',
    prefix: 'USER',
    priority: 1,
    exampleMask: 'a***@domain.com',
    severityWeight: 8,
  },
  CREDIT_CARD: {
    id: 'CREDIT_CARD',
    label: 'Credit Card (Luhn)',
    shortLabel: 'Credit Card',
    prefix: 'CARD',
    priority: 2,
    exampleMask: 'XXXX-XXXX-XXXX-9014',
    severityWeight: 25,
  },
  IP_ADDRESS: {
    id: 'IP_ADDRESS',
    label: 'IP Address (v4/v6)',
    shortLabel: 'IP Address',
    prefix: 'IP',
    priority: 3,
    exampleMask: '192.168.XXX.XXX',
    severityWeight: 6,
  },
  PAN: {
    id: 'PAN',
    label: 'Indian PAN',
    shortLabel: 'Indian PAN',
    prefix: 'PAN',
    priority: 4,
    exampleMask: 'XXXXX2318J',
    severityWeight: 20,
  },
  AADHAAR: {
    id: 'AADHAAR',
    label: 'Indian Aadhaar',
    shortLabel: 'Aadhaar',
    prefix: 'AADHAAR',
    priority: 5,
    exampleMask: 'XXXX XXXX 3340',
    severityWeight: 25,
  },
  PHONE: {
    id: 'PHONE',
    label: 'Phone Number',
    shortLabel: 'Phone',
    prefix: 'PHONE',
    priority: 6,
    exampleMask: '+91-XXXXXX4510',
    severityWeight: 10,
  },
  CUSTOM: {
    id: 'CUSTOM',
    label: 'Custom Pattern',
    shortLabel: 'Custom',
    prefix: 'CUSTOM',
    priority: 7,
    exampleMask: 'XX***XX',
    severityWeight: 12,
  },
};

export const DEFAULT_ENABLED_TYPES: EnabledEntityMap = {
  EMAIL: true,
  PHONE: true,
  IP_ADDRESS: true,
  PAN: true,
  AADHAAR: true,
  CREDIT_CARD: true,
  CUSTOM: true,
};

// UIDAI Verhoeff dihedral D5 tables
const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/**
 * Validates UIDAI Aadhaar 12-digit Verhoeff checksum.
 */
export function isValidVerhoeff(rawValue: string): boolean {
  const digits = rawValue.replace(/\D/g, '');
  if (!/^[2-9]\d{11}$/.test(digits)) return false;
  let c = 0;
  for (let i = 0; i < digits.length; i++) {
    const digit = digits.charCodeAt(digits.length - 1 - i) - 48;
    c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]];
  }
  return c === 0;
}

/**
 * Validates a 13–19 digit candidate using the Luhn (mod-10) algorithm.
 * Rejects uniform repeated digit strings (e.g., 0000000000000000).
 */
export function isValidLuhn(rawValue: string): boolean {
  const digits = rawValue.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  if (/^(\d)\1+$/.test(digits)) return false;

  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = digits.charCodeAt(i) - 48;
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

export function detectCardNetwork(rawValue: string): string {
  const digits = rawValue.replace(/\D/g, '');
  if (/^4\d{12}(\d{3})?(\d{3})?$/.test(digits)) return 'Visa';
  if (/^(5[1-5]\d{14}|2(22[1-9]|2[3-9]\d|[3-6]\d{2}|7[01]\d|720)\d{12})$/.test(digits)) {
    return 'Mastercard';
  }
  if (/^3[47]\d{13}$/.test(digits)) return 'Amex';
  if (/^(60|6521|6522)\d{12,15}$/.test(digits)) return 'RuPay';
  if (/^6(?:011|5\d{2})\d{12}$/.test(digits)) return 'Discover';
  return 'Card';
}

export function isValidIPv6(candidate: string): boolean {
  if (!candidate || !candidate.includes(':')) return false;
  const colonCount = (candidate.match(/:/g) || []).length;
  if (!candidate.includes('::') && colonCount < 7) return false;
  if (candidate.includes(':::')) return false;

  const halves = candidate.split('::');
  if (halves.length > 2) return false;

  const parseGroups = (part: string) => (part === '' ? [] : part.split(':'));
  const left = parseGroups(halves[0]);
  const right = halves.length === 2 ? parseGroups(halves[1]) : [];
  const allGroups = left.concat(right);

  if (halves.length === 1 && allGroups.length !== 8) return false;
  if (halves.length === 2 && allGroups.length >= 8) return false;

  return allGroups.every((group) => /^[0-9A-Fa-f]{1,4}$/.test(group));
}

function isCardLikeShape(rawValue: string): boolean {
  const trimmed = rawValue.trim();
  if (/^\d{13,19}$/.test(trimmed)) return true;
  if (/^\d{4}([ .-])\d{4}\1\d{4}\1\d{1,7}$/.test(trimmed)) return true;
  if (/^\d{4}([ .-])\d{6}\1\d{4,5}$/.test(trimmed)) return true;
  return false;
}

export const ZERO_WIDTH_REGEX = /[\u200B-\u200D\u2060\uFEFF]/g;
const ZERO_WIDTH_CHAR_REGEX = /[\u200B-\u200D\u2060\uFEFF]/;

/**
 * Strips invisible zero-width characters before regex matching while preserving
 * an exact index map back to the original text offsets.
 */
export function stripZeroWidthWithMap(text: string): {
  cleanText: string;
  mapSpan: (cleanStart: number, cleanEnd: number) => { start: number; end: number };
} {
  if (!ZERO_WIDTH_CHAR_REGEX.test(text)) {
    return {
      cleanText: text,
      mapSpan: (cleanStart, cleanEnd) => ({ start: cleanStart, end: cleanEnd }),
    };
  }

  const cleanChars: string[] = [];
  const cleanToOrig: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (!ZERO_WIDTH_CHAR_REGEX.test(ch)) {
      cleanChars.push(ch);
      cleanToOrig.push(i);
    }
  }

  return {
    cleanText: cleanChars.join(''),
    mapSpan: (cleanStart, cleanEnd) => {
      if (cleanEnd <= cleanStart || cleanToOrig.length === 0) {
        const idx = cleanToOrig[cleanStart] ?? text.length;
        return { start: idx, end: idx };
      }
      const start = cleanToOrig[cleanStart] ?? 0;
      const end = (cleanToOrig[cleanEnd - 1] ?? text.length - 1) + 1;
      return { start, end };
    },
  };
}

function findRegexMatches(
  text: string,
  regex: RegExp,
  onMatch: (match: RegExpExecArray) => void
): void {
  const flags = regex.flags.includes('g') ? regex.flags : `${regex.flags}g`;
  const re = new RegExp(regex.source, flags);
  let match: RegExpExecArray | null;
  let guard = 0;
  while ((match = re.exec(text)) !== null) {
    guard++;
    if (guard > 50000) break;
    if (match[0].length === 0) {
      re.lastIndex++;
      continue;
    }
    onMatch(match);
  }
}

function buildLineLocator(text: string): (index: number) => { line: number; column: number } {
  const lineStarts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10) lineStarts.push(i + 1);
  }
  return (index: number) => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (lineStarts[mid] <= index) lo = mid + 1;
      else hi = mid - 1;
    }
    const lineIdx = Math.max(0, hi);
    return {
      line: lineIdx + 1,
      column: index - lineStarts[lineIdx] + 1,
    };
  };
}

function canonicalizeIPv6(raw: string): string {
  const lower = raw.trim().toLowerCase();
  const halves = lower.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = halves.length === 2 ? Math.max(0, 8 - (left.length + right.length)) : 0;
  const full = [...left, ...Array(missing).fill('0'), ...right];
  return full.map((g) => g.padStart(4, '0')).join(':');
}

export function normalizeValue(type: EntityType, value: string): string {
  const clean = value.replace(ZERO_WIDTH_REGEX, '');
  switch (type) {
    case 'EMAIL':
      return clean.trim().toLowerCase();
    case 'IP_ADDRESS':
      return clean.includes(':') ? canonicalizeIPv6(clean) : clean.trim().toLowerCase();
    case 'PAN':
      return clean.trim().toUpperCase();
    case 'AADHAAR':
    case 'CREDIT_CARD':
      return clean.replace(/\D/g, '');
    case 'PHONE': {
      const digits = clean.replace(/\D/g, '');
      // Canonicalize Indian 10-digit ([6-9]xxxxxxxxx), 0-prefixed (0[6-9]...), and +91/91-prefixed numbers
      if (digits.length === 10 && /^[6-9]\d{9}$/.test(digits)) return `91${digits}`;
      if (digits.length === 11 && /^0[6-9]\d{9}$/.test(digits)) return `91${digits.slice(1)}`;
      return digits;
    }
    case 'CUSTOM':
      return clean.trim();
  }
}

export function applyPartialMask(type: EntityType, value: string): string {
  const clean = value.replace(ZERO_WIDTH_REGEX, '');
  switch (type) {
    case 'CREDIT_CARD':
    case 'AADHAAR': {
      const totalDigits = clean.replace(/\D/g, '').length;
      const keepAfter = totalDigits - 4;
      let seen = 0;
      return clean.replace(/\d/g, (ch) => {
        seen++;
        return seen <= keepAfter ? 'X' : ch;
      });
    }
    case 'PAN':
      return `XXXXX${clean.slice(5)}`;
    case 'EMAIL': {
      const atIdx = clean.indexOf('@');
      if (atIdx <= 0) return '***';
      const localChars = Array.from(clean.slice(0, atIdx));
      const domain = clean.slice(atIdx);
      return localChars.length === 1 ? `*${domain}` : `${localChars[0]}***${domain}`;
    }
    case 'PHONE': {
      const totalDigits = clean.replace(/\D/g, '').length;
      const keepTail = 4;
      let prefixDigitsToKeep = 0;
      if (clean.trim().startsWith('+')) {
        const ccMatch = clean.trim().match(/^\+(\d{1,3})(?=[\s().-])/);
        if (ccMatch) prefixDigitsToKeep = ccMatch[1].length;
      }
      let digitIdx = 0;
      return clean.replace(/\d/g, (ch) => {
        digitIdx++;
        if (digitIdx <= prefixDigitsToKeep) return ch;
        if (digitIdx > totalDigits - keepTail) return ch;
        return 'X';
      });
    }
    case 'IP_ADDRESS': {
      if (clean.includes('.')) {
        const parts = clean.split('.');
        if (parts.length === 4) return `${parts[0]}.${parts[1]}.XXX.XXX`;
      }
      if (clean.includes(':')) {
        const parts = clean.split(':');
        let kept = 0;
        return parts
          .map((part) => {
            if (part === '') return '';
            kept++;
            return kept <= 2 ? part : 'XXXX';
          })
          .join(':');
      }
      return '[REDACTED]';
    }
    case 'CUSTOM': {
      if (clean.length <= 4) return '*'.repeat(clean.length);
      return `${clean.slice(0, 2)}${'*'.repeat(Math.min(6, clean.length - 4))}${clean.slice(-2)}`;
    }
  }
}

function computeRiskSummary(matches: DetectedEntity[]): RiskSummary {
  if (matches.length === 0) return { score: 0, level: 'Clean' };
  const rawWeight = matches.reduce((sum, m) => sum + ENTITY_META[m.type].severityWeight, 0);
  const score = Math.min(100, rawWeight);
  let level: RiskSummary['level'] = 'Low';
  if (score >= 80) level = 'Critical';
  else if (score >= 55) level = 'High';
  else if (score >= 25) level = 'Moderate';
  return { score, level };
}

function splitCsvRowCells(row: string): Array<{ start: number; end: number; value: string }> {
  const cells: Array<{ start: number; end: number; value: string }> = [];
  let inQuotes = false;
  let cellStart = 0;
  for (let i = 0; i < row.length; i++) {
    const ch = row[i];
    if (ch === '"') {
      inQuotes = !inQuotes;
    } else if (ch === ',' && !inQuotes) {
      cells.push({
        start: cellStart,
        end: i,
        value: row.slice(cellStart, i).replace(/^"|"$/g, '').trim(),
      });
      cellStart = i + 1;
    }
  }
  cells.push({
    start: cellStart,
    end: row.length,
    value: row.slice(cellStart).replace(/^"|"$/g, '').trim(),
  });
  return cells;
}

/**
 * Parses CSV lines (supporting quoted cells) to compute per-column PII exposure.
 */
function analyzeCsvColumns(text: string, matches: DetectedEntity[]): CsvColumnRisk[] {
  const lines = text.split('\n');
  if (lines.length < 2) return [];

  const headers = splitCsvRowCells(lines[0]);
  if (headers.length <= 1) return [];

  const columnHits: Array<{ count: number; types: Set<EntityType> }> = headers.map(() => ({
    count: 0,
    types: new Set<EntityType>(),
  }));

  const matchesByLine = new Map<number, DetectedEntity[]>();
  for (const m of matches) {
    const arr = matchesByLine.get(m.line);
    if (arr) arr.push(m);
    else matchesByLine.set(m.line, [m]);
  }

  let lineOffset = lines[0].length + 1;
  for (let rowIdx = 1; rowIdx < lines.length; rowIdx++) {
    const lineText = lines[rowIdx];
    const rowMatches = matchesByLine.get(rowIdx + 1);
    if (rowMatches && rowMatches.length > 0 && lineText.trim()) {
      const cells = splitCsvRowCells(lineText);
      for (const m of rowMatches) {
        const relStart = m.start - lineOffset;
        const colIdx = cells.findIndex((c) => relStart >= c.start && relStart <= c.end);
        if (colIdx >= 0 && colIdx < columnHits.length) {
          columnHits[colIdx].count += 1;
          columnHits[colIdx].types.add(m.type);
        }
      }
    }
    lineOffset += lineText.length + 1;
  }

  return headers.map((h, idx) => ({
    columnIndex: idx,
    header: h.value || `Column ${idx + 1}`,
    entityCount: columnHits[idx].count,
    types: Array.from(columnHits[idx].types),
  }));
}

function buildCsvHeaderLookup(text: string): (index: number) => string | null {
  const firstNl = text.indexOf('\n');
  if (firstNl === -1) return () => null;
  const headerLine = text.slice(0, firstNl);
  if (!headerLine.includes(',')) return () => null;
  const headers = splitCsvRowCells(headerLine);
  if (headers.length <= 1) return () => null;

  return (index: number) => {
    if (index <= firstNl) return null;
    const lineStart = text.lastIndexOf('\n', index - 1) + 1;
    const rawLineEnd = text.indexOf('\n', index);
    const lineEnd = rawLineEnd === -1 ? text.length : rawLineEnd;
    const row = text.slice(lineStart, lineEnd);
    const cells = splitCsvRowCells(row);
    const rel = index - lineStart;
    const colIdx = cells.findIndex((c) => rel >= c.start && rel <= c.end);
    return colIdx >= 0 && colIdx < headers.length ? headers[colIdx].value : null;
  };
}

function hasBarePhoneContextCue(
  cleanText: string,
  start: number,
  end: number,
  getCsvHeader: (idx: number) => string | null
): boolean {
  const csvHeader = getCsvHeader(start);
  if (csvHeader && /(?:phone|mobile)/i.test(csvHeader)) return true;

  const lineStart = cleanText.lastIndexOf('\n', start - 1) + 1;
  const rawLineEnd = cleanText.indexOf('\n', end);
  const lineEnd = rawLineEnd === -1 ? cleanText.length : rawLineEnd;

  const beforeRaw = cleanText.slice(Math.max(lineStart, start - 80), start);
  const sepIdx = Math.max(beforeRaw.lastIndexOf('|'), beforeRaw.lastIndexOf(';'));
  const before = sepIdx >= 0 ? beforeRaw.slice(sepIdx + 1) : beforeRaw;

  const afterRaw = cleanText.slice(end, Math.min(lineEnd, end + 30));
  const afterSep = afterRaw.search(/[|;]/);
  const after = afterSep >= 0 ? afterRaw.slice(0, afterSep) : afterRaw;

  // Reject if immediately preceded by an explicit non-phone ID keyword (e.g., "order 8827364519")
  if (/\b(?:order|id|ref|invoice|txn|batch|ticket|account|acc)\b\s*[:#-]?\s*$/i.test(before)) {
    return false;
  }

  return /\b(?:calls?|phones?|mobiles?|tel|telephone|contacts?)\b/i.test(`${before} ${after}`);
}

function isWordOrDigitBefore(text: string, index: number, extraBlocked = ''): boolean {
  if (index <= 0) return false;
  const ch = text[index - 1];
  return /[\dA-Za-z]/.test(ch) || extraBlocked.includes(ch);
}

function isWordOrDigitAfter(text: string, index: number, extraBlocked = ''): boolean {
  if (index >= text.length) return false;
  const ch = text[index];
  return /[\dA-Za-z]/.test(ch) || extraBlocked.includes(ch);
}

/**
 * Precomputes start indices of isolated 4-group (4-4-4-4) 16-digit blocks in O(N) time
 * so non-Luhn 16-digit IDs aren't sliced into 12-digit Aadhaars, while longer runs
 * (such as 7-group Aadhaar + Card sequences) remain detectable without O(N^2) scans.
 */
function buildIsolatedFourGroupStarts(text: string): Set<number> {
  const isolatedStarts = new Set<number>();
  const isDigit = (idx: number) => idx >= 0 && idx < text.length && text[idx] >= '0' && text[idx] <= '9';
  const isFourDigits = (idx: number) =>
    idx + 4 <= text.length && isDigit(idx) && isDigit(idx + 1) && isDigit(idx + 2) && isDigit(idx + 3);

  for (const sep of [' ', '-']) {
    let i = 0;
    while (i + 19 <= text.length) {
      if (!isFourDigits(i) || isWordOrDigitBefore(text, i, '-') || isWordOrDigitAfter(text, i + 4, '-')) {
        i++;
        continue;
      }
      let groupCount = 1;
      let end = i + 4;
      while (
        end + 5 <= text.length &&
        text[end] === sep &&
        isFourDigits(end + 1) &&
        !isWordOrDigitAfter(text, end + 5, '-')
      ) {
        groupCount++;
        end += 5;
      }
      if (groupCount === 4 && !isWordOrDigitAfter(text, end, '-')) {
        isolatedStarts.add(i);
      }
      i = end + 1;
    }
  }
  return isolatedStarts;
}

export interface DetectOptions {
  enabledTypes?: Partial<EnabledEntityMap>;
  strictAadhaarVerhoeff?: boolean;
  strictPhoneContext?: boolean;
  customPattern?: string;
  customMatches?: Array<{ start: number; end: number; value: string }>;
  customRegexErrorOverride?: string | null;
  skipSyncCustomRegex?: boolean;
  ignoredValues?: string[];
}

export function detectPII(
  text: string,
  options: DetectOptions = {}
): {
  matches: DetectedEntity[];
  rejected: RejectedCandidate[];
  ignoredCount: number;
  customRegexError: string | null;
} {
  const enabled: EnabledEntityMap = {
    ...DEFAULT_ENABLED_TYPES,
    ...options.enabledTypes,
  };
  const strictVerhoeff = Boolean(options.strictAadhaarVerhoeff);
  const ignoredSet = new Set(
    (options.ignoredValues ?? [])
      .map((v) => v.replace(ZERO_WIDTH_REGEX, '').trim().toLowerCase())
      .filter(Boolean)
  );

  const { cleanText, mapSpan } = stripZeroWidthWithMap(text);
  const locate = buildLineLocator(text);
  const getCsvHeader = buildCsvHeaderLookup(cleanText);
  const candidates: Omit<DetectedEntity, 'id'>[] = [];
  const candidateKeys = new Set<string>();
  const rejectedCandidates: RejectedCandidate[] = [];
  const rejectedKeys = new Set<string>();
  let customRegexError: string | null = options.customRegexErrorOverride ?? null;

  const pushMappedCandidate = (
    cStart: number,
    cEnd: number,
    item: Omit<DetectedEntity, 'id' | 'start' | 'end' | 'value' | 'line' | 'column'>
  ) => {
    const { start, end } = mapSpan(cStart, cEnd);
    const key = `${item.type}:${start}:${end}`;
    if (candidateKeys.has(key)) return;
    candidateKeys.add(key);
    const pos = locate(start);
    candidates.push({
      ...item,
      value: text.slice(start, end),
      start,
      end,
      line: pos.line,
      column: pos.column,
    });
  };

  const pushMappedRejected = (
    cStart: number,
    cEnd: number,
    item: Omit<RejectedCandidate, 'start' | 'end' | 'value' | 'line' | 'column'>
  ) => {
    const { start, end } = mapSpan(cStart, cEnd);
    const key = `${item.type}:${start}:${end}`;
    if (rejectedKeys.has(key)) return;
    rejectedKeys.add(key);
    const pos = locate(start);
    rejectedCandidates.push({
      ...item,
      value: text.slice(start, end),
      start,
      end,
      line: pos.line,
      column: pos.column,
    });
  };

  // 1. Credit Cards (multi-start, exact group sizes with ' ', '-', or '.' separators, plus 13-19 contiguous digits)
  if (enabled.CREDIT_CARD) {
    const cardGroupRegexes: RegExp[] = [
      // 4-4-4-4 (16 digits)
      /^\d{4}([ .-])\d{4}\1\d{4}\1\d{4}/,
      // 4-4-4-4-3 (19 digits)
      /^\d{4}([ .-])\d{4}\1\d{4}\1\d{4}\1\d{3}/,
      // 4-4-4-1 (13 digits)
      /^\d{4}([ .-])\d{4}\1\d{4}\1\d/,
      // 4-6-5 (Amex 15 digits)
      /^\d{4}([ .-])\d{6}\1\d{5}/,
      // 4-6-4 (Diners 14 digits)
      /^\d{4}([ .-])\d{6}\1\d{4}/,
    ];

    for (let i = 0; i < cleanText.length; i++) {
      const ch = cleanText[i];
      if (ch < '0' || ch > '9') continue;
      if (isWordOrDigitBefore(cleanText, i, '+')) continue;

      const slice = cleanText.slice(i, i + 25);

      // Contiguous 13–19 digits
      const contig = slice.match(/^\d{13,19}/);
      if (contig) {
        const raw = contig[0];
        const end = i + raw.length;
        if (!isWordOrDigitAfter(cleanText, end)) {
          if (isValidLuhn(raw)) {
            pushMappedCandidate(i, end, {
              type: 'CREDIT_CARD',
              validation: `Luhn Valid (${detectCardNetwork(raw)})`,
            });
          } else {
            pushMappedRejected(i, end, {
              type: 'CREDIT_CARD',
              reason: 'Failed Luhn checksum (false positive prevented)',
            });
          }
        }
      }

      // Grouped card shapes (try every pattern at this valid start offset)
      for (const re of cardGroupRegexes) {
        const m = slice.match(re);
        if (!m) continue;
        const raw = m[0];
        const end = i + raw.length;
        if (isWordOrDigitAfter(cleanText, end)) continue;

        if (isValidLuhn(raw)) {
          pushMappedCandidate(i, end, {
            type: 'CREDIT_CARD',
            validation: `Luhn Valid (${detectCardNetwork(raw)})`,
          });
        } else if (isCardLikeShape(raw)) {
          pushMappedRejected(i, end, {
            type: 'CREDIT_CARD',
            reason: 'Failed Luhn checksum (false positive prevented)',
          });
        }
      }
    }
  }

  // 2. Emails (supports Unicode letters in local part and domain)
  if (enabled.EMAIL) {
    findRegexMatches(
      cleanText,
      /(?<![\p{L}\p{N}._%+-])[\p{L}\p{N}._%+-]+@[\p{L}\p{N}.-]+\.[\p{L}]{2,}(?![\p{L}\p{N}])/gu,
      (m) => {
        pushMappedCandidate(m.index, m.index + m[0].length, {
          type: 'EMAIL',
          validation: 'Email format',
        });
      }
    );
  }

  // 3. IP Addresses (IPv4 & IPv6)
  if (enabled.IP_ADDRESS) {
    findRegexMatches(
      cleanText,
      /(?<![\d.A-Za-z])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.A-Za-z])/g,
      (m) => {
        pushMappedCandidate(m.index, m.index + m[0].length, {
          type: 'IP_ADDRESS',
          validation: 'IPv4 (0–255 octets)',
        });
      }
    );

    findRegexMatches(
      cleanText,
      /(?<![A-Fa-f0-9:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![A-Fa-f0-9:])/g,
      (m) => {
        if (!isValidIPv6(m[0])) return;
        pushMappedCandidate(m.index, m.index + m[0].length, {
          type: 'IP_ADDRESS',
          validation: 'IPv6 format',
        });
      }
    );
  }

  // 4. Indian PAN
  if (enabled.PAN) {
    const standardHolders = new Set(['P', 'C', 'H', 'F', 'A', 'T', 'B', 'L', 'J', 'G']);
    findRegexMatches(cleanText, /(?<![A-Za-z0-9])[A-Z]{5}[0-9]{4}[A-Z](?![A-Za-z0-9])/g, (m) => {
      const holder = m[0][3];
      pushMappedCandidate(m.index, m.index + m[0].length, {
        type: 'PAN',
        validation: standardHolders.has(holder)
          ? `PAN format (holder '${holder}')`
          : 'PAN 5A-4N-1A format',
      });
    });
  }

  // 5. Indian Aadhaar (multi-start, exact 4-4-4 and 12-digit forms, optional Verhoeff strictness)
  if (enabled.AADHAAR) {
    const isolatedFourGroupStarts = buildIsolatedFourGroupStarts(cleanText);
    for (let i = 0; i < cleanText.length; i++) {
      const ch = cleanText[i];
      if (ch < '2' || ch > '9') continue;
      if (isWordOrDigitBefore(cleanText, i, '-')) continue;

      const slice = cleanText.slice(i, i + 15);
      const grouped = slice.match(/^[2-9]\d{3}([ -])\d{4}\1\d{4}/);
      const contig = slice.match(/^[2-9]\d{11}/);

      const candidatesHere: Array<{ raw: string; sep: string | null }> = [];
      if (grouped) candidatesHere.push({ raw: grouped[0], sep: grouped[1] });
      if (contig) candidatesHere.push({ raw: contig[0], sep: null });

      for (const { raw, sep } of candidatesHere) {
        const end = i + raw.length;
        if (isWordOrDigitAfter(cleanText, end, '-')) continue;
        if (sep && isolatedFourGroupStarts.has(i)) continue;

        const verhoeffOk = isValidVerhoeff(raw);
        if (strictVerhoeff && !verhoeffOk) {
          pushMappedRejected(i, end, {
            type: 'AADHAAR',
            reason: 'Failed Verhoeff checksum (Strict Aadhaar mode)',
          });
          continue;
        }

        pushMappedCandidate(i, end, {
          type: 'AADHAAR',
          validation: verhoeffOk
            ? 'UIDAI Verhoeff Valid'
            : '12-digit UIDAI format (unverified checksum)',
        });
      }
    }
  }

  // 6. Phone Numbers
  if (enabled.PHONE) {
    // 6a. International '+' prefixed phones (always on)
    for (let i = 0; i < cleanText.length; i++) {
      if (cleanText[i] !== '+') continue;
      if (isWordOrDigitBefore(cleanText, i, '+')) continue;

      const slice = cleanText.slice(i, i + 32);
      const ccMatch = slice.match(/^\+\d{1,3}/);
      if (!ccMatch) continue;

      let curLen = ccMatch[0].length;
      for (let g = 0; g < 5; g++) {
        const rest = slice.slice(curLen);
        const nextGroup = rest.match(/^[ .-]?\(?\d{1,10}\)?/);
        if (!nextGroup) break;
        curLen += nextGroup[0].length;
        const end = i + curLen;
        if (isWordOrDigitAfter(cleanText, end)) continue;

        const raw = slice.slice(0, curLen);
        const digits = raw.replace(/\D/g, '');
        if (digits.length >= 10 && digits.length <= 15) {
          pushMappedCandidate(i, end, {
            type: 'PHONE',
            validation: 'International E.164 phone',
          });
        }
      }
    }

    // 6b. Prefixed & formatted local/landline phone patterns (always on)
    const prefixedAndFormattedPatterns = [
      // Parenthesized area code: (415) 555-0199
      /(?<![\dA-Za-z(])\(\d{3,5}\)[ .-]?\d{3,4}[ .-]?\d{4}(?![\dA-Za-z])/g,
      // Space/dash/dot-separated Indian STD landlines (0 + 2-4 digit STD + 6-8 digit subscriber, e.g. 011 2345 6789, 022-26541234)
      /(?<![\dA-Za-z-])0\d{2,4}[ .-]\d{3,4}[ .-]?\d{3,4}(?![\dA-Za-z-])/g,
      // Separated 10-digit formats: 98765-43210, 555-123-4567
      /(?<![\dA-Za-z-])(?:\d{5}[ .-]\d{5}|\d{3}[ .-]\d{3}[ .-]\d{4})(?![\dA-Za-z-])/g,
      // 0-prefixed 11-digit mobile: 09876543210
      /(?<![\dA-Za-z+-])0[6-9]\d{9}(?![\dA-Za-z-])/g,
    ];

    for (const pattern of prefixedAndFormattedPatterns) {
      findRegexMatches(cleanText, pattern, (m) => {
        const raw = m[0];
        const digits = raw.replace(/\D/g, '');
        if (digits.length < 10 || digits.length > 15) return;
        // STD landlines with spaces/hyphens are 10-11 digits total
        if (raw.startsWith('0') && digits.length > 11) return;
        pushMappedCandidate(m.index, m.index + raw.length, {
          type: 'PHONE',
          validation: raw.startsWith('0') ? 'STD / 0-prefixed phone' : 'Formatted phone number',
        });
      });
    }

    // 6c. Bare 10-digit numbers [6-9]\d{9}: always detected by default (use cue words to rank confidence);
    // when strictPhoneContext is enabled, require a context cue word or CSV phone/mobile header.
    const strictPhone = Boolean(options.strictPhoneContext);
    findRegexMatches(cleanText, /(?<![\dA-Za-z+-])[6-9]\d{9}(?![\dA-Za-z-])/g, (m) => {
      const start = m.index;
      const end = start + m[0].length;
      const hasCue = hasBarePhoneContextCue(cleanText, start, end, getCsvHeader);
      if (strictPhone && !hasCue) return;
      pushMappedCandidate(start, end, {
        type: 'PHONE',
        validation: hasCue
          ? '10-digit mobile (high confidence: context cue)'
          : '10-digit mobile (medium confidence: [6-9] pattern)',
      });
    });
  }

  // 7. Optional Custom User Regex (supplied from Web Worker or sync fallback)
  if (enabled.CUSTOM) {
    if (options.customMatches) {
      for (const cm of options.customMatches) {
        if (cm.end > cm.start && !cm.value.includes('\n')) {
          const pos = locate(cm.start);
          const key = `CUSTOM:${cm.start}:${cm.end}`;
          if (!candidateKeys.has(key)) {
            candidateKeys.add(key);
            candidates.push({
              type: 'CUSTOM',
              value: text.slice(cm.start, cm.end),
              start: cm.start,
              end: cm.end,
              line: pos.line,
              column: pos.column,
              validation: 'Custom regex pattern (worker)',
            });
          }
        }
      }
    } else if (!options.skipSyncCustomRegex && options.customPattern && options.customPattern.trim()) {
      try {
        const customRe = new RegExp(options.customPattern.trim(), 'g');
        findRegexMatches(cleanText, customRe, (m) => {
          if (m[0].includes('\n')) return;
          pushMappedCandidate(m.index, m.index + m[0].length, {
            type: 'CUSTOM',
            validation: 'Custom regex pattern',
          });
        });
      } catch (err) {
        customRegexError = err instanceof Error ? err.message : 'Invalid regular expression';
      }
    }
  }

  // Filter out allowlisted values before optimal non-overlapping selection
  const activeCandidates: Omit<DetectedEntity, 'id'>[] = [];
  const ignoredSpans: Array<{ start: number; end: number }> = [];
  for (const c of candidates) {
    if (ignoredSet.has(c.value.replace(ZERO_WIDTH_REGEX, '').trim().toLowerCase())) {
      ignoredSpans.push({ start: c.start, end: c.end });
    } else {
      activeCandidates.push(c);
    }
  }

  // Count distinct non-overlapping ignored spans
  ignoredSpans.sort((a, b) => a.start - b.start || a.end - b.end);
  let ignoredCount = 0;
  let lastIgnoredEnd = -1;
  for (const sp of ignoredSpans) {
    if (sp.start >= lastIgnoredEnd) {
      ignoredCount++;
      lastIgnoredEnd = sp.end;
    }
  }

  // Optimal Weighted Interval Scheduling (DP):
  // Maximize (matched entity count, matched characters, sum of negative entity priority)
  // so an over-long candidate never drops an adjacent entity.
  activeCandidates.sort((a, b) => {
    if (a.end !== b.end) return a.end - b.end;
    if (a.start !== b.start) return a.start - b.start;
    return ENTITY_META[a.type].priority - ENTITY_META[b.type].priority;
  });

  const n = activeCandidates.length;
  const matches: DetectedEntity[] = [];

  if (n > 0) {
    interface DPState {
      count: number;
      chars: number;
      prioScore: number;
      take: boolean;
      prevIdx: number;
    }

    const dp: DPState[] = new Array(n);
    const isBetter = (a: DPState, b: DPState): boolean => {
      if (a.count !== b.count) return a.count > b.count;
      if (a.chars !== b.chars) return a.chars > b.chars;
      return a.prioScore > b.prioScore;
    };

    const findLastNonOverlapping = (idx: number): number => {
      const targetStart = activeCandidates[idx].start;
      let lo = 0;
      let hi = idx - 1;
      let ans = -1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (activeCandidates[mid].end <= targetStart) {
          ans = mid;
          lo = mid + 1;
        } else {
          hi = mid - 1;
        }
      }
      return ans;
    };

    for (let i = 0; i < n; i++) {
      const c = activeCandidates[i];
      const len = c.end - c.start;
      const prio = -ENTITY_META[c.type].priority;
      const pIdx = findLastNonOverlapping(i);

      const takeState: DPState = {
        count: (pIdx >= 0 ? dp[pIdx].count : 0) + 1,
        chars: (pIdx >= 0 ? dp[pIdx].chars : 0) + len,
        prioScore: (pIdx >= 0 ? dp[pIdx].prioScore : 0) + prio,
        take: true,
        prevIdx: pIdx,
      };

      const skipState: DPState =
        i > 0
          ? { ...dp[i - 1], take: false, prevIdx: i - 1 }
          : { count: 0, chars: 0, prioScore: 0, take: false, prevIdx: -1 };

      dp[i] = isBetter(takeState, skipState) ? takeState : skipState;
    }

    const chosen: Omit<DetectedEntity, 'id'>[] = [];
    let cur = n - 1;
    while (cur >= 0) {
      if (dp[cur].take) {
        chosen.push(activeCandidates[cur]);
        cur = dp[cur].prevIdx;
      } else {
        cur = dp[cur].prevIdx;
      }
    }
    chosen.reverse();

    chosen.forEach((c, idx) => {
      matches.push({
        ...c,
        id: `ent_${idx + 1}_${c.start}`,
      });
    });
  }

  // Keep only rejected candidates that do not overlap any accepted match using an O(R log R + M) two-pointer sweep
  rejectedCandidates.sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start));
  const rejected: RejectedCandidate[] = [];
  let lastRejEnd = -1;
  let matchIdx = 0;
  for (const r of rejectedCandidates) {
    while (matchIdx < matches.length && matches[matchIdx].end <= r.start) {
      matchIdx++;
    }
    const overlapsAccepted = matchIdx < matches.length && matches[matchIdx].start < r.end;
    if (!overlapsAccepted && r.start >= lastRejEnd) {
      rejected.push(r);
      lastRejEnd = r.end;
    }
  }

  return { matches, rejected, ignoredCount, customRegexError };
}

export function sanitizeText(text: string, options: SanitizeOptions = {}): SanitizationResult {
  const t0 = typeof performance !== 'undefined' ? performance.now() : Date.now();
  const mode = options.mode ?? 'full';
  const fullMaskToken = options.fullMaskToken ?? '[REDACTED]';
  const typedFullMask = Boolean(options.typedFullMask);

  const { matches, rejected, ignoredCount, customRegexError } = detectPII(text, {
    enabledTypes: options.enabledTypes,
    strictAadhaarVerhoeff: options.strictAadhaarVerhoeff,
    strictPhoneContext: options.strictPhoneContext,
    customPattern: options.customPattern,
    customMatches: options.customMatches,
    customRegexErrorOverride: options.customRegexErrorOverride,
    skipSyncCustomRegex: options.skipSyncCustomRegex,
    ignoredValues: options.ignoredValues,
  });

  const counts: SanitizationCounts = {
    EMAIL: 0,
    PHONE: 0,
    IP_ADDRESS: 0,
    PAN: 0,
    AADHAAR: 0,
    CREDIT_CARD: 0,
    CUSTOM: 0,
    TOTAL: matches.length,
    REJECTED_LUHN: rejected.filter((r) => r.type === 'CREDIT_CARD').length,
    REJECTED_VERHOEFF: rejected.filter((r) => r.type === 'AADHAAR').length,
    IGNORED: ignoredCount,
  };

  const typeCounters: Partial<Record<EntityType, number>> = {};
  const pseudonymMap = new Map<string, PseudonymEntry>();
  const pseudonymMappings: PseudonymEntry[] = [];

  let sanitized = '';
  let cursor = 0;
  const annotatedMatches: SanitizedEntity[] = [];

  for (const match of matches) {
    counts[match.type] += 1;

    let replacement: string;
    if (mode === 'full') {
      replacement = typedFullMask ? `[REDACTED:${match.type}]` : fullMaskToken;
    } else if (mode === 'partial') {
      replacement = applyPartialMask(match.type, match.value);
    } else {
      const normKey = `${match.type}::${normalizeValue(match.type, match.value)}`;
      const existing = pseudonymMap.get(normKey);
      if (existing) {
        existing.occurrences += 1;
        replacement = existing.placeholder;
      } else {
        const nextCount = (typeCounters[match.type] ?? 0) + 1;
        typeCounters[match.type] = nextCount;
        const placeholder = `${ENTITY_META[match.type].prefix}_${String(nextCount).padStart(2, '0')}`;
        const entry: PseudonymEntry = {
          type: match.type,
          placeholder,
          sampleOriginal: match.value,
          normalizedKey: normKey,
          occurrences: 1,
        };
        pseudonymMap.set(normKey, entry);
        pseudonymMappings.push(entry);
        replacement = placeholder;
      }
    }

    const sanitizedStart = sanitized.length + (match.start - cursor);
    sanitized += text.slice(cursor, match.start) + replacement;
    const sanitizedEnd = sanitized.length;
    cursor = match.end;

    annotatedMatches.push({
      ...match,
      replacement,
      sanitizedStart,
      sanitizedEnd,
    });
  }

  sanitized += text.slice(cursor);
  const t1 = typeof performance !== 'undefined' ? performance.now() : Date.now();

  const shouldAnalyzeCsv =
    options.isCsv ||
    (text.includes(',') && text.includes('\n') && text.split('\n')[0].split(',').length >= 3);

  return {
    originalText: text,
    sanitizedText: sanitized,
    mode,
    matches: annotatedMatches,
    rejected,
    counts,
    pseudonymMappings,
    risk: computeRiskSummary(matches),
    csvColumns: shouldAnalyzeCsv ? analyzeCsvColumns(text, matches) : [],
    customRegexError,
    durationMs: Math.max(0, Number((t1 - t0).toFixed(2))),
  };
}
