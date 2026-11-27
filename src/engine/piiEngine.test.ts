import { describe, expect, it } from 'vitest';
import { SAMPLES } from '../data/samples';
import { detectPII, isValidIPv6, isValidLuhn, isValidVerhoeff, sanitizeText } from './piiEngine';

describe('Luhn & Verhoeff Checksum Validation', () => {
  it('accepts valid Visa, Mastercard, Amex, and Discover numbers', () => {
    expect(isValidLuhn('4532-1234-5678-9014')).toBe(true);
    expect(isValidLuhn('5425 2334 3010 9903')).toBe(true);
    expect(isValidLuhn('4111111111111111')).toBe(true);
    expect(isValidLuhn('3782 822463 10005')).toBe(true);
    expect(isValidLuhn('6011000990139424')).toBe(true);
  });

  it('rejects random 16-digit numeric strings and all-zeros', () => {
    expect(isValidLuhn('4532-1234-5678-9010')).toBe(false);
    expect(isValidLuhn('1234567890123456')).toBe(false);
    expect(isValidLuhn('9988776655443322')).toBe(false);
    expect(isValidLuhn('0000000000000000')).toBe(false);
  });

  it('validates UIDAI Aadhaar Verhoeff checksums accurately', () => {
    // 23456789012 -> let's test known Verhoeff-valid vs invalid 12-digit UIDAI strings
    expect(isValidVerhoeff('2341 2341 2346')).toBe(true);
    expect(isValidVerhoeff('2341-2341-2347')).toBe(false);
    expect(isValidVerhoeff('134123412346')).toBe(false); // starts with 1
  });
});

describe('PII Pattern Detection', () => {
  it('detects all 6 PII entity types while ignoring dates, versions, timestamps, and invalid IPs', () => {
    const input = [
      'Date: 2026-11-27 Time: 12:34:56 Epoch: 1732700000',
      'Invalid IP: 999.168.1.1 Version: v1.2.3.4',
      'Email: alice.verma+ops@secure-mail.co.in',
      'Phones: +91 98765 43210, +919876543211, (415) 555-0199, 9123456789',
      'IPs: 192.168.10.25 and 2001:0db8:85a3::8a2e:0370:7334',
      'PAN: ABCDE1234F | Lowercase non-PAN: abcde1234f',
      'Aadhaar: 2345 6789 0123 and 4512-8891-3340',
      'Valid Card: 4532-1234-5678-9014 | Non-Luhn 16d: 1234-5678-9012-3456',
    ].join('\n');

    const { matches, rejected } = detectPII(input);
    const byType = matches.reduce<Record<string, string[]>>((acc, m) => {
      acc[m.type] = acc[m.type] ?? [];
      acc[m.type].push(m.value);
      return acc;
    }, {});

    expect(byType.EMAIL).toEqual(['alice.verma+ops@secure-mail.co.in']);
    expect(byType.PHONE).toEqual([
      '+91 98765 43210',
      '+919876543211',
      '(415) 555-0199',
      '9123456789',
    ]);
    expect(byType.IP_ADDRESS).toEqual(['192.168.10.25', '2001:0db8:85a3::8a2e:0370:7334']);
    expect(byType.PAN).toEqual(['ABCDE1234F']);
    expect(byType.AADHAAR).toEqual(['2345 6789 0123', '4512-8891-3340']);
    expect(byType.CREDIT_CARD).toEqual(['4532-1234-5678-9014']);
    expect(rejected).toHaveLength(1);
    expect(rejected[0].value).toBe('1234-5678-9012-3456');
    expect(isValidIPv6('12:34:56')).toBe(false);
  });

  it('filters synthetic Aadhaar candidates when strictAadhaarVerhoeff is enabled', () => {
    const input = 'Valid: 2341 2341 2346 | Invalid: 2341-2341-2347';
    const strict = sanitizeText(input, { strictAadhaarVerhoeff: true });
    expect(strict.counts.AADHAAR).toBe(1);
    expect(strict.counts.REJECTED_VERHOEFF).toBe(1);
    expect(strict.sanitizedText).toContain('2341-2341-2347');
  });
});

describe('Three Redaction Modes, Allowlist & Custom Regex', () => {
  const sample =
    'User bob@acme.com PAN BNZAA2318J Aadhaar 4512 8891 3340 Card 4532-1234-5678-9014 IP 10.24.198.7 Phone +91-9820144510.\n' +
    'Repeat: bob@acme.com and +91 98201 44510 and 4512-8891-3340 and alice@acme.com.';

  it('Full Mask supports both [REDACTED] and typed [REDACTED:TYPE]', () => {
    const res = sanitizeText(sample, { mode: 'full' });
    expect(res.counts.TOTAL).toBe(10);
    expect(res.sanitizedText).not.toContain('bob@acme.com');
    expect(res.sanitizedText).toContain('[REDACTED]');

    const typed = sanitizeText(sample, { mode: 'full', typedFullMask: true });
    expect(typed.sanitizedText).toContain('[REDACTED:EMAIL]');
    expect(typed.sanitizedText).toContain('[REDACTED:PAN]');
  });

  it('Partial Mask preserves verification context', () => {
    const res = sanitizeText(sample, { mode: 'partial' });
    expect(res.sanitizedText).toContain('b***@acme.com');
    expect(res.sanitizedText).toContain('XXXXX2318J');
    expect(res.sanitizedText).toContain('XXXX XXXX 3340');
    expect(res.sanitizedText).toContain('XXXX-XXXX-XXXX-9014');
    expect(res.sanitizedText).toContain('10.24.XXX.XXX');
    expect(res.sanitizedText).toContain('+91-XXXXXX4510');
  });

  it('Consistent Pseudonymization maps recurring entities identically across formats', () => {
    const res = sanitizeText(sample, { mode: 'pseudonym' });
    expect(res.sanitizedText).toContain(
      'User USER_01 PAN PAN_01 Aadhaar AADHAAR_01 Card CARD_01 IP IP_01 Phone PHONE_01.'
    );
    expect(res.sanitizedText).toContain(
      'Repeat: USER_01 and PHONE_01 and AADHAAR_01 and USER_02.'
    );
    expect(res.pseudonymMappings.find((m) => m.placeholder === 'USER_01')?.occurrences).toBe(2);
    expect(res.pseudonymMappings.find((m) => m.placeholder === 'PHONE_01')?.occurrences).toBe(2);
    expect(res.pseudonymMappings.find((m) => m.placeholder === 'AADHAAR_01')?.occurrences).toBe(2);
  });

  it('Supports custom regex rules, handles invalid regex safely, and respects allowlist', () => {
    const text = 'Employee EMP-4821 contacted support@company.com and bob@acme.com';
    const customRes = sanitizeText(text, {
      mode: 'partial',
      customPattern: 'EMP-\\d{4}',
      ignoredValues: ['support@company.com'],
    });
    expect(customRes.counts.CUSTOM).toBe(1);
    expect(customRes.counts.IGNORED).toBe(1);
    expect(customRes.sanitizedText).toContain('EM****21');
    expect(customRes.sanitizedText).toContain('support@company.com');
    expect(customRes.sanitizedText).toContain('b***@acme.com');

    const badRegex = sanitizeText(text, { customPattern: '[unclosed' });
    expect(badRegex.customRegexError).toBeTruthy();
  });
});

describe('Sample Datasets, Risk Scoring & CSV Column Profiling', () => {
  it('detects expected Luhn-valid cards, computes risk, and profiles CSV columns', () => {
    const support = sanitizeText(SAMPLES.support_ticket.text, { mode: 'pseudonym' });
    expect(support.counts.CREDIT_CARD).toBe(2);
    expect(support.counts.REJECTED_LUHN).toBe(1);
    expect(support.risk.level).toBe('Critical');

    const hr = sanitizeText(SAMPLES.hr_resume.text, { mode: 'partial' });
    expect(hr.counts.CREDIT_CARD).toBe(1);
    expect(hr.counts.REJECTED_LUHN).toBe(1);

    const csv = sanitizeText(SAMPLES.billing_csv.text, { mode: 'full', isCsv: true });
    expect(csv.counts.CREDIT_CARD).toBe(3);
    expect(csv.counts.REJECTED_LUHN).toBe(3);
    expect(csv.csvColumns.length).toBe(8);
    expect(csv.csvColumns.find((c) => c.header === 'txn_ref_16d')?.entityCount).toBe(0);
    expect(csv.csvColumns.find((c) => c.header === 'email')?.entityCount).toBe(3);

    const origLines = SAMPLES.billing_csv.text.split('\n');
    const sanLines = csv.sanitizedText.split('\n');
    expect(sanLines).toHaveLength(origLines.length);
    origLines.forEach((line, idx) => {
      expect(sanLines[idx].split(',')).toHaveLength(line.split(',').length);
    });
  });
});
