import { analyzeCsvColumns, buildCsvHeaderLookup, escapeCsvFormulas, parseCsvRecords } from './csv';
import {
  buildLineLocator,
  createSpanCollector,
  detectAadhaar,
  detectCreditCards,
  detectCustomPattern,
  detectEmails,
  detectIndianPan,
  detectIpAddresses,
  detectPhones,
  filterNonOverlappingRejected,
  partitionAllowlisted,
  selectOptimalMatches,
} from './detectors';
import {
  DEFAULT_ENABLED_TYPES,
  ENTITY_META,
  ENTITY_ORDER,
  computeRiskSummary,
} from './metadata';
import type {
  DetectedEntity,
  EnabledEntityMap,
  EntityType,
  PseudonymEntry,
  RejectedCandidate,
  SanitizationCounts,
  SanitizationResult,
  SanitizeOptions,
  SanitizedEntity,
} from './types';
import {
  ZERO_WIDTH_REGEX,
  applyPartialMask,
  detectCardNetwork,
  isValidIPv6,
  isValidLuhn,
  isValidVerhoeff,
  normalizeValue,
  stripZeroWidthWithMap,
} from './validators';

export {
  DEFAULT_ENABLED_TYPES,
  ENTITY_META,
  ENTITY_ORDER,
  ZERO_WIDTH_REGEX,
  applyPartialMask,
  detectCardNetwork,
  escapeCsvFormulas,
  isValidIPv6,
  isValidLuhn,
  isValidVerhoeff,
  normalizeValue,
  parseCsvRecords,
  stripZeroWidthWithMap,
};

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

/**
 * Detects PII entities across normalized text, evaluates checksums, and resolves overlaps.
 */
export function detectPII(
  text: string,
  options: DetectOptions = {}
): {
  matches: DetectedEntity[];
  rejected: RejectedCandidate[];
  ignoredCount: number;
  customRegexError: string | null;
} {
  const enabled: EnabledEntityMap = { ...DEFAULT_ENABLED_TYPES, ...options.enabledTypes };
  const ignoredSet = new Set(
    (options.ignoredValues ?? [])
      .map((v) => v.replace(ZERO_WIDTH_REGEX, '').trim().toLowerCase())
      .filter(Boolean)
  );

  const { cleanText, mapSpan } = stripZeroWidthWithMap(text);
  const locate = buildLineLocator(text);
  const getCsvHeader = buildCsvHeaderLookup(cleanText);
  const collector = createSpanCollector(text, mapSpan, locate);

  if (enabled.CREDIT_CARD) detectCreditCards(cleanText, collector);
  if (enabled.EMAIL) detectEmails(cleanText, collector);
  if (enabled.IP_ADDRESS) detectIpAddresses(cleanText, collector);
  if (enabled.PAN) detectIndianPan(cleanText, collector);
  if (enabled.AADHAAR) {
    detectAadhaar(cleanText, collector, Boolean(options.strictAadhaarVerhoeff));
  }
  if (enabled.PHONE) {
    detectPhones(cleanText, collector, getCsvHeader, Boolean(options.strictPhoneContext));
  }

  let customRegexError = options.customRegexErrorOverride ?? null;
  if (enabled.CUSTOM) {
    const syncError = detectCustomPattern(text, cleanText, collector, locate, options);
    if (syncError) customRegexError = syncError;
  }

  const { activeCandidates, ignoredCount } = partitionAllowlisted(collector.candidates, ignoredSet);
  const matches = selectOptimalMatches(activeCandidates);
  const rejected = filterNonOverlappingRejected(collector.rejectedCandidates, matches);

  return { matches, rejected, ignoredCount, customRegexError };
}

function resolveReplacement(
  match: DetectedEntity,
  mode: NonNullable<SanitizeOptions['mode']>,
  fullMaskToken: string,
  typedFullMask: boolean,
  typeCounters: Partial<Record<EntityType, number>>,
  pseudonymMap: Map<string, PseudonymEntry>,
  pseudonymMappings: PseudonymEntry[]
): string {
  if (mode === 'full') {
    return typedFullMask ? `[REDACTED:${match.type}]` : fullMaskToken;
  }
  if (mode === 'partial') {
    return applyPartialMask(match.type, match.value);
  }

  const normKey = `${match.type}::${normalizeValue(match.type, match.value)}`;
  const existing = pseudonymMap.get(normKey);
  if (existing) {
    existing.occurrences += 1;
    return existing.placeholder;
  }

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
  return placeholder;
}

/**
 * Sanitizes raw text using Full Mask, Partial Mask, or Consistent Pseudonymization.
 */
export function sanitizeText(text: string, options: SanitizeOptions = {}): SanitizationResult {
  const t0 = typeof performance !== 'undefined' ? performance.now() : Date.now();
  const mode = options.mode ?? 'full';
  const fullMaskToken = options.fullMaskToken ?? '[REDACTED]';
  const typedFullMask = Boolean(options.typedFullMask);

  const { matches, rejected, ignoredCount, customRegexError } = detectPII(text, options);

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
  const annotatedMatches: SanitizedEntity[] = [];

  let sanitized = '';
  let cursor = 0;

  for (const match of matches) {
    counts[match.type] += 1;
    const replacement = resolveReplacement(
      match,
      mode,
      fullMaskToken,
      typedFullMask,
      typeCounters,
      pseudonymMap,
      pseudonymMappings
    );
    const sanitizedStart = sanitized.length + (match.start - cursor);
    sanitized += text.slice(cursor, match.start) + replacement;
    const sanitizedEnd = sanitized.length;
    cursor = match.end;

    annotatedMatches.push({ ...match, replacement, sanitizedStart, sanitizedEnd });
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
