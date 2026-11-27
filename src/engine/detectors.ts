import { hasBarePhoneContextCue } from './csv';
import { ENTITY_META } from './metadata';
import type { DetectedEntity, EntityType, RejectedCandidate } from './types';
import {
  ZERO_WIDTH_REGEX,
  detectCardNetwork,
  isCardLikeShape,
  isValidIPv6,
  isValidLuhn,
  isValidVerhoeff,
} from './validators';

export type CandidateDraft = Omit<DetectedEntity, 'id'>;

export interface SpanCollector {
  candidates: CandidateDraft[];
  rejectedCandidates: RejectedCandidate[];
  pushCandidate: (
    cStart: number,
    cEnd: number,
    item: Omit<DetectedEntity, 'id' | 'start' | 'end' | 'value' | 'line' | 'column'>
  ) => void;
  pushRejected: (
    cStart: number,
    cEnd: number,
    item: Omit<RejectedCandidate, 'start' | 'end' | 'value' | 'line' | 'column'>
  ) => void;
  pushRawCandidate: (item: CandidateDraft) => void;
}

const CARD_GROUP_REGEXES: RegExp[] = [
  /^\d{4}([ .-])\d{4}\1\d{4}\1\d{4}/,
  /^\d{4}([ .-])\d{4}\1\d{4}\1\d{4}\1\d{3}/,
  /^\d{4}([ .-])\d{4}\1\d{4}\1\d/,
  /^\d{4}([ .-])\d{6}\1\d{5}/,
  /^\d{4}([ .-])\d{6}\1\d{4}/,
];

const STANDARD_PAN_HOLDERS = new Set(['P', 'C', 'H', 'F', 'A', 'T', 'B', 'L', 'J', 'G']);

export function buildLineLocator(text: string): (index: number) => { line: number; column: number } {
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
    return { line: lineIdx + 1, column: index - lineStarts[lineIdx] + 1 };
  };
}

export function createSpanCollector(
  originalText: string,
  mapSpan: (cStart: number, cEnd: number) => { start: number; end: number },
  locate: (index: number) => { line: number; column: number }
): SpanCollector {
  const candidates: CandidateDraft[] = [];
  const candidateKeys = new Set<string>();
  const rejectedCandidates: RejectedCandidate[] = [];
  const rejectedKeys = new Set<string>();

  const toPositionedSpan = (cStart: number, cEnd: number) => {
    const { start, end } = mapSpan(cStart, cEnd);
    const pos = locate(start);
    return { start, end, value: originalText.slice(start, end), line: pos.line, column: pos.column };
  };

  const pushRawCandidate = (item: CandidateDraft) => {
    const key = `${item.type}:${item.start}:${item.end}`;
    if (candidateKeys.has(key)) return;
    candidateKeys.add(key);
    candidates.push(item);
  };

  const pushCandidate: SpanCollector['pushCandidate'] = (cStart, cEnd, item) => {
    pushRawCandidate({ ...item, ...toPositionedSpan(cStart, cEnd) });
  };

  const pushRejected: SpanCollector['pushRejected'] = (cStart, cEnd, item) => {
    const span = toPositionedSpan(cStart, cEnd);
    const key = `${item.type}:${span.start}:${span.end}`;
    if (rejectedKeys.has(key)) return;
    rejectedKeys.add(key);
    rejectedCandidates.push({ ...item, ...span });
  };

  return { candidates, rejectedCandidates, pushCandidate, pushRejected, pushRawCandidate };
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
    if (++guard > 50000) break;
    if (match[0].length === 0) {
      re.lastIndex++;
      continue;
    }
    onMatch(match);
  }
}

function isWordOrDigitBoundary(text: string, index: number, extraBlocked = ''): boolean {
  if (index < 0 || index >= text.length) return false;
  const ch = text[index];
  return /[\dA-Za-z]/.test(ch) || extraBlocked.includes(ch);
}

/**
 * Precomputes start indices of isolated 4-group (4-4-4-4) 16-digit blocks in O(N) time
 * so non-Luhn 16-digit IDs aren't sliced into 12-digit Aadhaars, while longer runs remain detectable.
 */
function buildIsolatedFourGroupStarts(text: string): Set<number> {
  const isolatedStarts = new Set<number>();
  const isDigit = (idx: number) => idx >= 0 && idx < text.length && text[idx] >= '0' && text[idx] <= '9';
  const isFourDigits = (idx: number) =>
    idx + 4 <= text.length && isDigit(idx) && isDigit(idx + 1) && isDigit(idx + 2) && isDigit(idx + 3);

  for (const sep of [' ', '-']) {
    let i = 0;
    while (i + 19 <= text.length) {
      if (
        !isFourDigits(i) ||
        isWordOrDigitBoundary(text, i - 1, '-') ||
        isWordOrDigitBoundary(text, i + 4, '-')
      ) {
        i++;
        continue;
      }
      let groupCount = 1;
      let end = i + 4;
      while (
        end + 5 <= text.length &&
        text[end] === sep &&
        isFourDigits(end + 1) &&
        !isWordOrDigitBoundary(text, end + 5, '-')
      ) {
        groupCount++;
        end += 5;
      }
      if (groupCount === 4 && !isWordOrDigitBoundary(text, end, '-')) {
        isolatedStarts.add(i);
      }
      i = end + 1;
    }
  }
  return isolatedStarts;
}

export function detectCreditCards(cleanText: string, collector: SpanCollector): void {
  const recordCardCandidate = (start: number, end: number, raw: string, requireCardShape: boolean) => {
    if (isValidLuhn(raw)) {
      collector.pushCandidate(start, end, {
        type: 'CREDIT_CARD',
        validation: `Luhn Valid (${detectCardNetwork(raw)})`,
      });
    } else if (!requireCardShape || isCardLikeShape(raw)) {
      collector.pushRejected(start, end, {
        type: 'CREDIT_CARD',
        reason: 'Failed Luhn checksum (false positive prevented)',
      });
    }
  };

  for (let i = 0; i < cleanText.length; i++) {
    const ch = cleanText[i];
    if (ch < '0' || ch > '9') continue;
    if (isWordOrDigitBoundary(cleanText, i - 1, '+')) continue;

    const slice = cleanText.slice(i, i + 25);
    const contig = slice.match(/^\d{13,19}/);
    if (contig && !isWordOrDigitBoundary(cleanText, i + contig[0].length)) {
      recordCardCandidate(i, i + contig[0].length, contig[0], false);
    }

    for (const re of CARD_GROUP_REGEXES) {
      const m = slice.match(re);
      if (!m) continue;
      const end = i + m[0].length;
      if (!isWordOrDigitBoundary(cleanText, end)) {
        recordCardCandidate(i, end, m[0], true);
      }
    }
  }
}

export function detectEmails(cleanText: string, collector: SpanCollector): void {
  findRegexMatches(
    cleanText,
    /(?<![\p{L}\p{N}._%+-])[\p{L}\p{N}._%+-]+@[\p{L}\p{N}.-]+\.[\p{L}]{2,}(?![\p{L}\p{N}])/gu,
    (m) => {
      collector.pushCandidate(m.index, m.index + m[0].length, {
        type: 'EMAIL',
        validation: 'Email format',
      });
    }
  );
}

export function detectIpAddresses(cleanText: string, collector: SpanCollector): void {
  findRegexMatches(
    cleanText,
    /(?<![\d.A-Za-z])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.A-Za-z])/g,
    (m) => {
      collector.pushCandidate(m.index, m.index + m[0].length, {
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
      collector.pushCandidate(m.index, m.index + m[0].length, {
        type: 'IP_ADDRESS',
        validation: 'IPv6 format',
      });
    }
  );
}

export function detectIndianPan(cleanText: string, collector: SpanCollector): void {
  findRegexMatches(cleanText, /(?<![A-Za-z0-9])[A-Z]{5}[0-9]{4}[A-Z](?![A-Za-z0-9])/g, (m) => {
    const holder = m[0][3];
    collector.pushCandidate(m.index, m.index + m[0].length, {
      type: 'PAN',
      validation: STANDARD_PAN_HOLDERS.has(holder)
        ? `PAN format (holder '${holder}')`
        : 'PAN 5A-4N-1A format',
    });
  });
}

export function detectAadhaar(
  cleanText: string,
  collector: SpanCollector,
  strictVerhoeff: boolean
): void {
  const isolatedFourGroupStarts = buildIsolatedFourGroupStarts(cleanText);
  for (let i = 0; i < cleanText.length; i++) {
    const ch = cleanText[i];
    if (ch < '2' || ch > '9') continue;
    if (isWordOrDigitBoundary(cleanText, i - 1, '-')) continue;

    const slice = cleanText.slice(i, i + 15);
    const grouped = slice.match(/^[2-9]\d{3}([ -])\d{4}\1\d{4}/);
    const contig = slice.match(/^[2-9]\d{11}/);

    const candidatesHere: Array<{ raw: string; hasSep: boolean }> = [];
    if (grouped) candidatesHere.push({ raw: grouped[0], hasSep: true });
    if (contig) candidatesHere.push({ raw: contig[0], hasSep: false });

    for (const { raw, hasSep } of candidatesHere) {
      const end = i + raw.length;
      if (isWordOrDigitBoundary(cleanText, end, '-')) continue;
      if (hasSep && isolatedFourGroupStarts.has(i)) continue;

      const verhoeffOk = isValidVerhoeff(raw);
      if (strictVerhoeff && !verhoeffOk) {
        collector.pushRejected(i, end, {
          type: 'AADHAAR',
          reason: 'Failed Verhoeff checksum (Strict Aadhaar mode)',
        });
        continue;
      }

      collector.pushCandidate(i, end, {
        type: 'AADHAAR',
        validation: verhoeffOk
          ? 'UIDAI Verhoeff Valid'
          : '12-digit UIDAI format (unverified checksum)',
      });
    }
  }
}

export function detectPhones(
  cleanText: string,
  collector: SpanCollector,
  getCsvHeader: (idx: number) => string | null,
  strictPhoneContext: boolean
): void {
  // 1. International '+' prefixed phones (emit every valid 1..5 group prefix with 10..15 digits)
  for (let i = 0; i < cleanText.length; i++) {
    if (cleanText[i] !== '+' || isWordOrDigitBoundary(cleanText, i - 1, '+')) continue;

    const slice = cleanText.slice(i, i + 32);
    const ccMatch = slice.match(/^\+\d{1,3}/);
    if (!ccMatch) continue;

    let curLen = ccMatch[0].length;
    for (let g = 0; g < 5; g++) {
      const nextGroup = slice.slice(curLen).match(/^[ .-]?\(?\d{1,10}\)?/);
      if (!nextGroup) break;
      curLen += nextGroup[0].length;
      const end = i + curLen;
      if (isWordOrDigitBoundary(cleanText, end)) continue;

      const digits = slice.slice(0, curLen).replace(/\D/g, '');
      if (digits.length >= 10 && digits.length <= 15) {
        collector.pushCandidate(i, end, { type: 'PHONE', validation: 'International E.164 phone' });
      }
    }
  }

  // 2. Prefixed & formatted local/landline patterns
  const formattedPatterns = [
    /(?<![\dA-Za-z(])\(\d{3,5}\)[ .-]?\d{3,4}[ .-]?\d{4}(?![\dA-Za-z])/g,
    /(?<![\dA-Za-z-])0\d{2,4}[ .-]\d{3,4}[ .-]?\d{3,4}(?![\dA-Za-z-])/g,
    /(?<![\dA-Za-z-])(?:\d{5}[ .-]\d{5}|\d{3}[ .-]\d{3}[ .-]\d{4})(?![\dA-Za-z-])/g,
    /(?<![\dA-Za-z+-])0[6-9]\d{9}(?![\dA-Za-z-])/g,
  ];
  for (const pattern of formattedPatterns) {
    findRegexMatches(cleanText, pattern, (m) => {
      const raw = m[0];
      const digits = raw.replace(/\D/g, '');
      if (digits.length < 10 || digits.length > 15) return;
      if (raw.startsWith('0') && digits.length > 11) return;
      collector.pushCandidate(m.index, m.index + raw.length, {
        type: 'PHONE',
        validation: raw.startsWith('0') ? 'STD / 0-prefixed phone' : 'Formatted phone number',
      });
    });
  }

  // 3. Bare 10-digit mobile numbers [6-9]\d{9}
  findRegexMatches(cleanText, /(?<![\dA-Za-z+-])[6-9]\d{9}(?![\dA-Za-z-])/g, (m) => {
    const start = m.index;
    const end = start + m[0].length;
    const hasCue = hasBarePhoneContextCue(cleanText, start, end, getCsvHeader);
    if (strictPhoneContext && !hasCue) return;
    collector.pushCandidate(start, end, {
      type: 'PHONE',
      validation: hasCue
        ? '10-digit mobile (high confidence: context cue)'
        : '10-digit mobile (medium confidence: [6-9] pattern)',
    });
  });
}

export function detectCustomPattern(
  originalText: string,
  cleanText: string,
  collector: SpanCollector,
  locate: (index: number) => { line: number; column: number },
  options: {
    customMatches?: Array<{ start: number; end: number; value: string }>;
    customPattern?: string;
    skipSyncCustomRegex?: boolean;
  }
): string | null {
  if (options.customMatches) {
    for (const cm of options.customMatches) {
      if (cm.end > cm.start && !cm.value.includes('\n')) {
        const pos = locate(cm.start);
        collector.pushRawCandidate({
          type: 'CUSTOM',
          value: originalText.slice(cm.start, cm.end),
          start: cm.start,
          end: cm.end,
          line: pos.line,
          column: pos.column,
          validation: 'Custom regex pattern (worker)',
        });
      }
    }
    return null;
  }

  if (options.skipSyncCustomRegex || !options.customPattern?.trim()) return null;

  try {
    const customRe = new RegExp(options.customPattern.trim(), 'g');
    findRegexMatches(cleanText, customRe, (m) => {
      if (m[0].includes('\n')) return;
      collector.pushCandidate(m.index, m.index + m[0].length, {
        type: 'CUSTOM',
        validation: 'Custom regex pattern',
      });
    });
    return null;
  } catch (err) {
    return err instanceof Error ? err.message : 'Invalid regular expression';
  }
}

export function partitionAllowlisted(
  candidates: CandidateDraft[],
  ignoredSet: Set<string>
): { activeCandidates: CandidateDraft[]; ignoredCount: number } {
  const activeCandidates: CandidateDraft[] = [];
  const ignoredSpans: Array<{ start: number; end: number }> = [];

  for (const c of candidates) {
    if (ignoredSet.has(c.value.replace(ZERO_WIDTH_REGEX, '').trim().toLowerCase())) {
      ignoredSpans.push({ start: c.start, end: c.end });
    } else {
      activeCandidates.push(c);
    }
  }

  ignoredSpans.sort((a, b) => a.start - b.start || a.end - b.end);
  let ignoredCount = 0;
  let lastIgnoredEnd = -1;
  for (const sp of ignoredSpans) {
    if (sp.start >= lastIgnoredEnd) {
      ignoredCount++;
      lastIgnoredEnd = sp.end;
    }
  }

  return { activeCandidates, ignoredCount };
}

/**
 * Selects the optimal non-overlapping subset via weighted interval scheduling DP,
 * maximizing (matched entity count, matched characters, priority).
 */
export function selectOptimalMatches(activeCandidates: CandidateDraft[]): DetectedEntity[] {
  const sorted = [...activeCandidates].sort(
    (a, b) =>
      a.end - b.end ||
      a.start - b.start ||
      ENTITY_META[a.type].priority - ENTITY_META[b.type].priority
  );
  const n = sorted.length;
  if (n === 0) return [];

  interface DPState {
    count: number;
    chars: number;
    prioScore: number;
    take: boolean;
    prevIdx: number;
  }

  const dp: DPState[] = new Array(n);
  const isBetter = (a: DPState, b: DPState): boolean =>
    a.count !== b.count ? a.count > b.count : a.chars !== b.chars ? a.chars > b.chars : a.prioScore > b.prioScore;

  const findLastNonOverlapping = (idx: number): number => {
    const targetStart = sorted[idx].start;
    let lo = 0;
    let hi = idx - 1;
    let ans = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (sorted[mid].end <= targetStart) {
        ans = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return ans;
  };

  for (let i = 0; i < n; i++) {
    const c = sorted[i];
    const pIdx = findLastNonOverlapping(i);
    const takeState: DPState = {
      count: (pIdx >= 0 ? dp[pIdx].count : 0) + 1,
      chars: (pIdx >= 0 ? dp[pIdx].chars : 0) + (c.end - c.start),
      prioScore: (pIdx >= 0 ? dp[pIdx].prioScore : 0) - ENTITY_META[c.type].priority,
      take: true,
      prevIdx: pIdx,
    };
    const skipState: DPState =
      i > 0
        ? { ...dp[i - 1], take: false, prevIdx: i - 1 }
        : { count: 0, chars: 0, prioScore: 0, take: false, prevIdx: -1 };
    dp[i] = isBetter(takeState, skipState) ? takeState : skipState;
  }

  const chosen: CandidateDraft[] = [];
  for (let cur = n - 1; cur >= 0; cur = dp[cur].prevIdx) {
    if (dp[cur].take) chosen.push(sorted[cur]);
  }
  chosen.reverse();

  return chosen.map((c, idx) => ({ ...c, id: `ent_${idx + 1}_${c.start}` }));
}

export function filterNonOverlappingRejected(
  rejectedCandidates: RejectedCandidate[],
  matches: DetectedEntity[]
): RejectedCandidate[] {
  const sorted = [...rejectedCandidates].sort(
    (a, b) => a.start - b.start || b.end - b.start - (a.end - a.start)
  );
  const rejected: RejectedCandidate[] = [];
  let lastRejEnd = -1;
  let matchIdx = 0;

  for (const r of sorted) {
    while (matchIdx < matches.length && matches[matchIdx].end <= r.start) matchIdx++;
    const overlapsAccepted = matchIdx < matches.length && matches[matchIdx].start < r.end;
    if (!overlapsAccepted && r.start >= lastRejEnd) {
      rejected.push(r);
      lastRejEnd = r.end;
    }
  }
  return rejected;
}

export function getTypeWeight(type: EntityType): number {
  return ENTITY_META[type].severityWeight;
}
