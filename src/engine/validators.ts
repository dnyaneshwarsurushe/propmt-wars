import type { EntityType } from './types';

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

export const ZERO_WIDTH_REGEX = /[\u200B-\u200D\u2060\uFEFF]/g;
const ZERO_WIDTH_CHAR_REGEX = /[\u200B-\u200D\u2060\uFEFF]/;

/**
 * Strips invisible zero-width characters before matching while preserving
 * an exact index map back to original text offsets.
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

/**
 * Identifies common payment card networks from BIN prefixes.
 */
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

/**
 * Validates standard and compressed IPv6 addresses while rejecting HH:MM:SS timestamps.
 */
export function isValidIPv6(candidate: string): boolean {
  if (!candidate || !candidate.includes(':')) return false;
  const colonCount = (candidate.match(/:/g) || []).length;
  if (!candidate.includes('::') && colonCount < 7) return false;
  if (candidate.includes(':::')) return false;

  const halves = candidate.split('::');
  if (halves.length > 2) return false;

  const parseGroups = (part: string) => (part === '' ? [] : part.split(':'));
  const allGroups = parseGroups(halves[0]).concat(halves.length === 2 ? parseGroups(halves[1]) : []);

  if (halves.length === 1 && allGroups.length !== 8) return false;
  if (halves.length === 2 && allGroups.length >= 8) return false;

  return allGroups.every((group) => /^[0-9A-Fa-f]{1,4}$/.test(group));
}

export function isCardLikeShape(rawValue: string): boolean {
  const trimmed = rawValue.trim();
  return (
    /^\d{13,19}$/.test(trimmed) ||
    /^\d{4}([ .-])\d{4}\1\d{4}\1\d{1,7}$/.test(trimmed) ||
    /^\d{4}([ .-])\d{6}\1\d{4,5}$/.test(trimmed)
  );
}

function canonicalizeIPv6(raw: string): string {
  const halves = raw.trim().toLowerCase().split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = halves.length === 2 ? Math.max(0, 8 - (left.length + right.length)) : 0;
  return [...left, ...Array(missing).fill('0'), ...right]
    .map((g) => g.padStart(4, '0'))
    .join(':');
}

/**
 * Canonicalizes values across formatting variants for consistent pseudonymization.
 */
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
      if (digits.length === 10 && /^[6-9]\d{9}$/.test(digits)) return `91${digits}`;
      if (digits.length === 11 && /^0[6-9]\d{9}$/.test(digits)) return `91${digits.slice(1)}`;
      return digits;
    }
    case 'CUSTOM':
      return clean.trim();
  }
}

function maskDigitsKeepTail(value: string, keepTail: number, keepLeading = 0): string {
  const totalDigits = value.replace(/\D/g, '').length;
  let digitIdx = 0;
  return value.replace(/\d/g, (ch) => {
    digitIdx++;
    if (digitIdx <= keepLeading || digitIdx > totalDigits - keepTail) return ch;
    return 'X';
  });
}

/**
 * Generates a partial mask preserving verification context while obscuring sensitive tokens.
 */
export function applyPartialMask(type: EntityType, value: string): string {
  const clean = value.replace(ZERO_WIDTH_REGEX, '');
  switch (type) {
    case 'CREDIT_CARD':
    case 'AADHAAR':
      return maskDigitsKeepTail(clean, 4);
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
      const ccMatch = clean.trim().startsWith('+')
        ? clean.trim().match(/^\+(\d{1,3})(?=[\s().-])/)
        : null;
      return maskDigitsKeepTail(clean, 4, ccMatch ? ccMatch[1].length : 0);
    }
    case 'IP_ADDRESS': {
      if (clean.includes('.')) {
        const parts = clean.split('.');
        if (parts.length === 4) return `${parts[0]}.${parts[1]}.XXX.XXX`;
      }
      if (clean.includes(':')) {
        let kept = 0;
        return clean
          .split(':')
          .map((part) => (part === '' ? '' : ++kept <= 2 ? part : 'XXXX'))
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
