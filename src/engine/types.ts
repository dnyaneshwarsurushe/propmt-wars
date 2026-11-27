export type EntityType =
  | 'EMAIL'
  | 'PHONE'
  | 'IP_ADDRESS'
  | 'PAN'
  | 'AADHAAR'
  | 'CREDIT_CARD'
  | 'CUSTOM';

export type RedactionMode = 'full' | 'partial' | 'pseudonym';

export interface EntityMeta {
  id: EntityType;
  label: string;
  shortLabel: string;
  prefix: string;
  priority: number;
  exampleMask: string;
  severityWeight: number;
}

export interface DetectedEntity {
  id: string;
  type: EntityType;
  value: string;
  start: number;
  end: number;
  line: number;
  column: number;
  validation: string;
}

export interface SanitizedEntity extends DetectedEntity {
  replacement: string;
  sanitizedStart: number;
  sanitizedEnd: number;
}

export interface RejectedCandidate {
  type: 'CREDIT_CARD' | 'AADHAAR';
  value: string;
  start: number;
  end: number;
  line: number;
  column: number;
  reason: string;
}

export interface PseudonymEntry {
  type: EntityType;
  placeholder: string;
  sampleOriginal: string;
  normalizedKey: string;
  occurrences: number;
}

export type EnabledEntityMap = Record<EntityType, boolean>;

export interface SanitizationCounts {
  EMAIL: number;
  PHONE: number;
  IP_ADDRESS: number;
  PAN: number;
  AADHAAR: number;
  CREDIT_CARD: number;
  CUSTOM: number;
  TOTAL: number;
  REJECTED_LUHN: number;
  REJECTED_VERHOEFF: number;
  IGNORED: number;
}

export interface RiskSummary {
  score: number; // 0-100
  level: 'Clean' | 'Low' | 'Moderate' | 'High' | 'Critical';
}

export interface CsvColumnRisk {
  columnIndex: number;
  header: string;
  entityCount: number;
  types: EntityType[];
}

export interface SanitizationResult {
  originalText: string;
  sanitizedText: string;
  mode: RedactionMode;
  matches: SanitizedEntity[];
  rejected: RejectedCandidate[];
  counts: SanitizationCounts;
  pseudonymMappings: PseudonymEntry[];
  risk: RiskSummary;
  csvColumns: CsvColumnRisk[];
  customRegexError: string | null;
  durationMs: number;
}

export interface CustomMatchSpan {
  start: number;
  end: number;
  value: string;
}

export interface SanitizeOptions {
  mode?: RedactionMode;
  enabledTypes?: Partial<EnabledEntityMap>;
  fullMaskToken?: string;
  typedFullMask?: boolean;
  strictAadhaarVerhoeff?: boolean;
  strictPhoneContext?: boolean;
  customPattern?: string;
  customMatches?: CustomMatchSpan[];
  customRegexErrorOverride?: string | null;
  skipSyncCustomRegex?: boolean;
  ignoredValues?: string[];
  isCsv?: boolean;
}
