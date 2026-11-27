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
  if (/^\d{4}([ -])\d{4}\1\d{4}\1\d{1,7}$/.test(trimmed)) return true;
  if (/^\d{4}([ -])\d{6}\1\d{4,5}$/.test(trimmed)) return true;
  return false;
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

export function normalizeValue(type: EntityType, value: string): string {
  switch (type) {
    case 'EMAIL':
    case 'IP_ADDRESS':
      return value.trim().toLowerCase();
    case 'PAN':
      return value.trim().toUpperCase();
    case 'AADHAAR':
    case 'CREDIT_CARD':
    case 'PHONE':
      return value.replace(/\D/g, '');
    case 'CUSTOM':
      return value.trim();
  }
}

export function applyPartialMask(type: EntityType, value: string): string {
  switch (type) {
    case 'CREDIT_CARD':
    case 'AADHAAR': {
      const totalDigits = value.replace(/\D/g, '').length;
      const keepAfter = totalDigits - 4;
      let seen = 0;
      return value.replace(/\d/g, (ch) => {
        seen++;
        return seen <= keepAfter ? 'X' : ch;
      });
    }
    case 'PAN':
      return `XXXXX${value.slice(5)}`;
    case 'EMAIL': {
      const atIdx = value.indexOf('@');
      if (atIdx <= 0) return '***';
      const local = value.slice(0, atIdx);
      const domain = value.slice(atIdx);
      return local.length === 1 ? `*${domain}` : `${local[0]}***${domain}`;
    }
    case 'PHONE': {
      const totalDigits = value.replace(/\D/g, '').length;
      const keepTail = 4;
      let prefixDigitsToKeep = 0;
      if (value.trim().startsWith('+')) {
        const ccMatch = value.trim().match(/^\+(\d{1,3})(?=[\s().-])/);
        if (ccMatch) prefixDigitsToKeep = ccMatch[1].length;
      }
      let digitIdx = 0;
      return value.replace(/\d/g, (ch) => {
        digitIdx++;
        if (digitIdx <= prefixDigitsToKeep) return ch;
        if (digitIdx > totalDigits - keepTail) return ch;
        return 'X';
      });
    }
    case 'IP_ADDRESS': {
      if (value.includes('.')) {
        const parts = value.split('.');
        if (parts.length === 4) return `${parts[0]}.${parts[1]}.XXX.XXX`;
      }
      if (value.includes(':')) {
        const parts = value.split(':');
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
      if (value.length <= 4) return '*'.repeat(value.length);
      return `${value.slice(0, 2)}${'*'.repeat(Math.min(6, value.length - 4))}${value.slice(-2)}`;
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

/**
 * Parses CSV lines (supporting quoted cells) to compute per-column PII exposure.
 */
function analyzeCsvColumns(text: string, matches: DetectedEntity[]): CsvColumnRisk[] {
  const lines = text.split('\n');
  if (lines.length < 2) return [];

  const splitCsvRow = (row: string): Array<{ start: number; end: number; value: string }> => {
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
  };

  const headers = splitCsvRow(lines[0]);
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
      const cells = splitCsvRow(lineText);
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
 * Checks whether a 4-4-4 Aadhaar candidate is strictly the prefix of an isolated
 * 4-group (4-4-4-4) 16-digit block so non-Luhn 16-digit IDs aren't sliced,
 * while 7-group (4-4-4 + 4-4-4-4) Aadhaar+Card sequences remain detectable.
 */
function isIsolatedFourGroupPrefix(text: string, start: number, end: number, sep: string): boolean {
  const isFourDigits = (idx: number) => /^\d{4}$/.test(text.slice(idx, idx + 4));
  let leading = 0;
  let pos = start;
  while (pos >= 5 && text[pos - 1] === sep && isFourDigits(pos - 5) && !isWordOrDigitBefore(text, pos - 5, '-')) {
    leading++;
    pos -= 5;
  }

  let trailing = 0;
  pos = end;
  while (
    pos + 5 <= text.length &&
    text[pos] === sep &&
    isFourDigits(pos + 1) &&
    !isWordOrDigitAfter(text, pos + 5, '-')
  ) {
    trailing++;
    pos += 5;
  }

  return leading + 3 + trailing === 4;
}

export interface DetectOptions {
  enabledTypes?: Partial<EnabledEntityMap>;
  strictAadhaarVerhoeff?: boolean;
  customPattern?: string;
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
    (options.ignoredValues ?? []).map((v) => v.trim().toLowerCase()).filter(Boolean)
  );

  const locate = buildLineLocator(text);
  const candidates: Omit<DetectedEntity, 'id'>[] = [];
  const candidateKeys = new Set<string>();
  const rejectedCandidates: RejectedCandidate[] = [];
  const rejectedKeys = new Set<string>();
  let customRegexError: string | null = null;

  const pushCandidate = (item: Omit<DetectedEntity, 'id'>) => {
    const key = `${item.type}:${item.start}:${item.end}`;
    if (candidateKeys.has(key)) return;
    candidateKeys.add(key);
    candidates.push(item);
  };

  const pushRejected = (item: RejectedCandidate) => {
    const key = `${item.type}:${item.start}:${item.end}`;
    if (rejectedKeys.has(key)) return;
    rejectedKeys.add(key);
    rejectedCandidates.push(item);
  };

  // 1. Credit Cards (multi-start, exact group sizes: 4-4-4-4, 4-4-4-4-3, 4-4-4-1, 4-6-5, 4-6-4, and 13-19 contiguous digits)
  if (enabled.CREDIT_CARD) {
    const cardGroupRegexes: RegExp[] = [
      // 4-4-4-4 (16 digits)
      /^\d{4}([ -])\d{4}\1\d{4}\1\d{4}/,
      // 4-4-4-4-3 (19 digits)
      /^\d{4}([ -])\d{4}\1\d{4}\1\d{4}\1\d{3}/,
      // 4-4-4-1 (13 digits)
      /^\d{4}([ -])\d{4}\1\d{4}\1\d/,
      // 4-6-5 (Amex 15 digits)
      /^\d{4}([ -])\d{6}\1\d{5}/,
      // 4-6-4 (Diners 14 digits)
      /^\d{4}([ -])\d{6}\1\d{4}/,
    ];

    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (ch < '0' || ch > '9') continue;
      if (isWordOrDigitBefore(text, i, '+')) continue;

      const slice = text.slice(i, i + 25);

      // Contiguous 13–19 digits
      const contig = slice.match(/^\d{13,19}/);
      if (contig) {
        const raw = contig[0];
        const end = i + raw.length;
        if (!isWordOrDigitAfter(text, end)) {
          const pos = locate(i);
          if (isValidLuhn(raw)) {
            pushCandidate({
              type: 'CREDIT_CARD',
              value: raw,
              start: i,
              end,
              line: pos.line,
              column: pos.column,
              validation: `Luhn Valid (${detectCardNetwork(raw)})`,
            });
          } else {
            pushRejected({
              type: 'CREDIT_CARD',
              value: raw,
              start: i,
              end,
              line: pos.line,
              column: pos.column,
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
        if (isWordOrDigitAfter(text, end)) continue;

        const pos = locate(i);
        if (isValidLuhn(raw)) {
          pushCandidate({
            type: 'CREDIT_CARD',
            value: raw,
            start: i,
            end,
            line: pos.line,
            column: pos.column,
            validation: `Luhn Valid (${detectCardNetwork(raw)})`,
          });
        } else if (isCardLikeShape(raw)) {
          pushRejected({
            type: 'CREDIT_CARD',
            value: raw,
            start: i,
            end,
            line: pos.line,
            column: pos.column,
            reason: 'Failed Luhn checksum (false positive prevented)',
          });
        }
      }
    }
  }

  // 2. Emails
  if (enabled.EMAIL) {
    findRegexMatches(
      text,
      /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9])/g,
      (m) => {
        const start = m.index;
        const pos = locate(start);
        pushCandidate({
          type: 'EMAIL',
          value: m[0],
          start,
          end: start + m[0].length,
          line: pos.line,
          column: pos.column,
          validation: 'Email format',
        });
      }
    );
  }

  // 3. IP Addresses (IPv4 & IPv6)
  if (enabled.IP_ADDRESS) {
    findRegexMatches(
      text,
      /(?<![\d.A-Za-z])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.A-Za-z])/g,
      (m) => {
        const start = m.index;
        const pos = locate(start);
        pushCandidate({
          type: 'IP_ADDRESS',
          value: m[0],
          start,
          end: start + m[0].length,
          line: pos.line,
          column: pos.column,
          validation: 'IPv4 (0–255 octets)',
        });
      }
    );

    findRegexMatches(
      text,
      /(?<![A-Fa-f0-9:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![A-Fa-f0-9:])/g,
      (m) => {
        if (!isValidIPv6(m[0])) return;
        const start = m.index;
        const pos = locate(start);
        pushCandidate({
          type: 'IP_ADDRESS',
          value: m[0],
          start,
          end: start + m[0].length,
          line: pos.line,
          column: pos.column,
          validation: 'IPv6 format',
        });
      }
    );
  }

  // 4. Indian PAN
  if (enabled.PAN) {
    const standardHolders = new Set(['P', 'C', 'H', 'F', 'A', 'T', 'B', 'L', 'J', 'G']);
    findRegexMatches(text, /(?<![A-Za-z0-9])[A-Z]{5}[0-9]{4}[A-Z](?![A-Za-z0-9])/g, (m) => {
      const start = m.index;
      const pos = locate(start);
      const holder = m[0][3];
      pushCandidate({
        type: 'PAN',
        value: m[0],
        start,
        end: start + m[0].length,
        line: pos.line,
        column: pos.column,
        validation: standardHolders.has(holder)
          ? `PAN format (holder '${holder}')`
          : 'PAN 5A-4N-1A format',
      });
    });
  }

  // 5. Indian Aadhaar (multi-start, exact 4-4-4 and 12-digit forms, optional Verhoeff strictness)
  if (enabled.AADHAAR) {
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (ch < '2' || ch > '9') continue;
      if (isWordOrDigitBefore(text, i, '-')) continue;

      const slice = text.slice(i, i + 15);
      const grouped = slice.match(/^[2-9]\d{3}([ -])\d{4}\1\d{4}/);
      const contig = slice.match(/^[2-9]\d{11}/);

      const candidatesHere: Array<{ raw: string; sep: string | null }> = [];
      if (grouped) candidatesHere.push({ raw: grouped[0], sep: grouped[1] });
      if (contig) candidatesHere.push({ raw: contig[0], sep: null });

      for (const { raw, sep } of candidatesHere) {
        const end = i + raw.length;
        if (isWordOrDigitAfter(text, end, '-')) continue;
        if (sep && isIsolatedFourGroupPrefix(text, i, end, sep)) continue;

        const pos = locate(i);
        const verhoeffOk = isValidVerhoeff(raw);
        if (strictVerhoeff && !verhoeffOk) {
          pushRejected({
            type: 'AADHAAR',
            value: raw,
            start: i,
            end,
            line: pos.line,
            column: pos.column,
            reason: 'Failed Verhoeff checksum (Strict Aadhaar mode)',
          });
          continue;
        }

        pushCandidate({
          type: 'AADHAAR',
          value: raw,
          start: i,
          end,
          line: pos.line,
          column: pos.column,
          validation: verhoeffOk
            ? 'UIDAI Verhoeff Valid'
            : '12-digit UIDAI format (unverified checksum)',
        });
      }
    }
  }

  // 6. Phone Numbers (multi-start + multi-group prefixes for E.164 so trailing entities aren't swallowed)
  if (enabled.PHONE) {
    // 6a. International '+' prefixed phones: emit every valid 1..5 group prefix with 10..15 digits
    for (let i = 0; i < text.length; i++) {
      if (text[i] !== '+') continue;
      if (isWordOrDigitBefore(text, i, '+')) continue;

      const slice = text.slice(i, i + 32);
      const ccMatch = slice.match(/^\+\d{1,3}/);
      if (!ccMatch) continue;

      let curLen = ccMatch[0].length;
      for (let g = 0; g < 5; g++) {
        const rest = slice.slice(curLen);
        const nextGroup = rest.match(/^[ .-]?\(?\d{1,10}\)?/);
        if (!nextGroup) break;
        curLen += nextGroup[0].length;
        const end = i + curLen;
        if (isWordOrDigitAfter(text, end)) continue;

        const raw = slice.slice(0, curLen);
        const digits = raw.replace(/\D/g, '');
        if (digits.length >= 10 && digits.length <= 15) {
          const pos = locate(i);
          pushCandidate({
            type: 'PHONE',
            value: raw,
            start: i,
            end,
            line: pos.line,
            column: pos.column,
            validation: 'International E.164 phone',
          });
        }
      }
    }

    // 6b. Local & formatted phone patterns (multi-start via regex without greedy over-consumption)
    const localPhonePatterns = [
      /(?<![\dA-Za-z(])\(\d{3,5}\)[ .-]?\d{3,4}[ .-]?\d{4}(?![\dA-Za-z])/g,
      /(?<![\dA-Za-z-])(?:\d{5}[ .-]\d{5}|\d{3}[ .-]\d{3}[ .-]\d{4}|0\d{2,4}[ .-]\d{6,8})(?![\dA-Za-z-])/g,
      /(?<![\dA-Za-z+-])(?:0?[6-9]\d{9})(?![\dA-Za-z-])/g,
    ];

    for (const pattern of localPhonePatterns) {
      findRegexMatches(text, pattern, (m) => {
        const raw = m[0];
        const digits = raw.replace(/\D/g, '');
        if (digits.length < 10 || digits.length > 15) return;
        const start = m.index;
        const end = start + raw.length;
        const pos = locate(start);
        pushCandidate({
          type: 'PHONE',
          value: raw,
          start,
          end,
          line: pos.line,
          column: pos.column,
          validation: '10+ digit phone format',
        });
      });
    }
  }

  // 7. Optional Custom User Regex
  if (enabled.CUSTOM && options.customPattern && options.customPattern.trim()) {
    try {
      const customRe = new RegExp(options.customPattern.trim(), 'g');
      findRegexMatches(text, customRe, (m) => {
        // Ignore multiline matches to keep line-by-line diff exact
        if (m[0].includes('\n')) return;
        const start = m.index;
        const pos = locate(start);
        pushCandidate({
          type: 'CUSTOM',
          value: m[0],
          start,
          end: start + m[0].length,
          line: pos.line,
          column: pos.column,
          validation: 'Custom regex pattern',
        });
      });
    } catch (err) {
      customRegexError = err instanceof Error ? err.message : 'Invalid regular expression';
    }
  }

  // Filter out allowlisted values before optimal non-overlapping selection
  const activeCandidates: Omit<DetectedEntity, 'id'>[] = [];
  const ignoredSpans: Array<{ start: number; end: number }> = [];
  for (const c of candidates) {
    if (ignoredSet.has(c.value.trim().toLowerCase())) {
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

  // Keep only rejected candidates that do not overlap any accepted match, deduplicated cleanly
  const nonOverlappingRejected = rejectedCandidates
    .filter((r) => !matches.some((m) => r.start < m.end && r.end > m.start))
    .sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start));

  const rejected: RejectedCandidate[] = [];
  let lastRejEnd = -1;
  for (const r of nonOverlappingRejected) {
    if (r.start >= lastRejEnd) {
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
    customPattern: options.customPattern,
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
