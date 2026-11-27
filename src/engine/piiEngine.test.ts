import { describe, expect, it } from 'vitest';
import { SAMPLES } from '../data/samples';
import { CUSTOM_REGEX_TIMEOUT_ERROR, runCustomRegexInWorker } from './customRegexRunner';
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

describe('Adjacent Entities & Non-Suppressing Rejected Spans', () => {
  const PHONE_PREFIXED = '09876543210';
  const PHONE_E164 = '+91 98765 43210';
  const CARD_4444 = '4111 1111 1111 1111';
  const CARD_AMEX = '3782 822463 10005';
  const AADHAAR_444 = '2341 2341 2346';
  const AADHAAR_12 = '234123412346';
  const PAN = 'ABCDE1234F';

  const adjacentPairs: Array<{
    name: string;
    input: string;
    expected: Array<{ type: string; value: string }>;
  }> = [
    // Phone & Card (both orders)
    {
      name: 'cued bare phone + card (4-4-4-4)',
      input: `call 9876543210 ${CARD_4444}`,
      expected: [
        { type: 'PHONE', value: '9876543210' },
        { type: 'CREDIT_CARD', value: CARD_4444 },
      ],
    },
    {
      name: '0-prefixed phone + card (4-4-4-4)',
      input: `${PHONE_PREFIXED} ${CARD_4444}`,
      expected: [
        { type: 'PHONE', value: PHONE_PREFIXED },
        { type: 'CREDIT_CARD', value: CARD_4444 },
      ],
    },
    {
      name: 'E.164 phone + Amex card (4-6-5)',
      input: `${PHONE_E164} ${CARD_AMEX}`,
      expected: [
        { type: 'PHONE', value: PHONE_E164 },
        { type: 'CREDIT_CARD', value: CARD_AMEX },
      ],
    },
    {
      name: 'card (4-4-4-4) + prefixed phone',
      input: `${CARD_4444} ${PHONE_PREFIXED}`,
      expected: [
        { type: 'CREDIT_CARD', value: CARD_4444 },
        { type: 'PHONE', value: PHONE_PREFIXED },
      ],
    },
    {
      name: 'Amex card (4-6-5) + E.164 phone',
      input: `${CARD_AMEX} ${PHONE_E164}`,
      expected: [
        { type: 'CREDIT_CARD', value: CARD_AMEX },
        { type: 'PHONE', value: PHONE_E164 },
      ],
    },
    // Phone & Aadhaar (both orders)
    {
      name: 'prefixed phone + Aadhaar (4-4-4)',
      input: `${PHONE_PREFIXED} ${AADHAAR_444}`,
      expected: [
        { type: 'PHONE', value: PHONE_PREFIXED },
        { type: 'AADHAAR', value: AADHAAR_444 },
      ],
    },
    {
      name: 'E.164 phone + Aadhaar (12-digit)',
      input: `${PHONE_E164} ${AADHAAR_12}`,
      expected: [
        { type: 'PHONE', value: PHONE_E164 },
        { type: 'AADHAAR', value: AADHAAR_12 },
      ],
    },
    {
      name: 'Aadhaar (4-4-4) + prefixed phone',
      input: `${AADHAAR_444} ${PHONE_PREFIXED}`,
      expected: [
        { type: 'AADHAAR', value: AADHAAR_444 },
        { type: 'PHONE', value: PHONE_PREFIXED },
      ],
    },
    {
      name: 'Aadhaar (12-digit) + E.164 phone',
      input: `${AADHAAR_12} ${PHONE_E164}`,
      expected: [
        { type: 'AADHAAR', value: AADHAAR_12 },
        { type: 'PHONE', value: PHONE_E164 },
      ],
    },
    // Phone & PAN (both orders)
    {
      name: 'prefixed phone + PAN',
      input: `${PHONE_PREFIXED} ${PAN}`,
      expected: [
        { type: 'PHONE', value: PHONE_PREFIXED },
        { type: 'PAN', value: PAN },
      ],
    },
    {
      name: 'PAN + prefixed phone',
      input: `${PAN} ${PHONE_PREFIXED}`,
      expected: [
        { type: 'PAN', value: PAN },
        { type: 'PHONE', value: PHONE_PREFIXED },
      ],
    },
    // Card & Aadhaar (both orders)
    {
      name: 'card (4-4-4-4) + Aadhaar (4-4-4)',
      input: `${CARD_4444} ${AADHAAR_444}`,
      expected: [
        { type: 'CREDIT_CARD', value: CARD_4444 },
        { type: 'AADHAAR', value: AADHAAR_444 },
      ],
    },
    {
      name: 'Aadhaar (4-4-4) + card (4-4-4-4)',
      input: `${AADHAAR_444} ${CARD_4444}`,
      expected: [
        { type: 'AADHAAR', value: AADHAAR_444 },
        { type: 'CREDIT_CARD', value: CARD_4444 },
      ],
    },
    // Card & PAN (both orders)
    {
      name: 'card (4-4-4-4) + PAN',
      input: `${CARD_4444} ${PAN}`,
      expected: [
        { type: 'CREDIT_CARD', value: CARD_4444 },
        { type: 'PAN', value: PAN },
      ],
    },
    {
      name: 'PAN + card (4-4-4-4)',
      input: `${PAN} ${CARD_4444}`,
      expected: [
        { type: 'PAN', value: PAN },
        { type: 'CREDIT_CARD', value: CARD_4444 },
      ],
    },
    // Aadhaar & PAN (both orders)
    {
      name: 'Aadhaar (4-4-4) + PAN',
      input: `${AADHAAR_444} ${PAN}`,
      expected: [
        { type: 'AADHAAR', value: AADHAAR_444 },
        { type: 'PAN', value: PAN },
      ],
    },
    {
      name: 'PAN + Aadhaar (4-4-4)',
      input: `${PAN} ${AADHAAR_444}`,
      expected: [
        { type: 'PAN', value: PAN },
        { type: 'AADHAAR', value: AADHAAR_444 },
      ],
    },
  ];

  for (const tc of adjacentPairs) {
    it(`detects adjacent ${tc.name}`, () => {
      const { matches } = detectPII(tc.input);
      expect(matches.map((m) => ({ type: m.type, value: m.value }))).toEqual(tc.expected);
    });
  }

  it('never lets a rejected Luhn span suppress a valid entity inside or adjacent to it', () => {
    const input = '2341 2341 2346 4111 1111 1111 1111 | 4532-1234-5678-9010 9876543210';
    const { matches, rejected } = detectPII(input);
    expect(matches.map((m) => ({ type: m.type, value: m.value }))).toEqual([
      { type: 'AADHAAR', value: '2341 2341 2346' },
      { type: 'CREDIT_CARD', value: '4111 1111 1111 1111' },
      { type: 'PHONE', value: '9876543210' },
    ]);
    expect(rejected.map((r) => r.value)).toEqual(['4532-1234-5678-9010']);
  });
});

describe('Phone Context Cues, Extended Formats & Zero-Width Mapping', () => {
  it('always detects 9876543210 alone and next to other numbers while excluding dates and epochs', () => {
    // Alone
    const alone = sanitizeText('9876543210', { mode: 'full' });
    expect(alone.counts.PHONE).toBe(1);
    expect(alone.sanitizedText).toBe('[REDACTED]');

    // Next to card, Aadhaar, and PAN without cue words
    const nextToCard = sanitizeText('9876543210 4111 1111 1111 1111', { mode: 'full' });
    expect(nextToCard.matches.map((m) => m.type)).toEqual(['PHONE', 'CREDIT_CARD']);
    expect(nextToCard.sanitizedText).toBe('[REDACTED] [REDACTED]');

    const nextToAadhaar = sanitizeText('2345 6789 0124 9876543210', { mode: 'full' });
    expect(nextToAadhaar.matches.map((m) => m.type)).toEqual(['AADHAAR', 'PHONE']);
    expect(nextToAadhaar.sanitizedText).toBe('[REDACTED] [REDACTED]');

    const nextToPan = sanitizeText('9876543210 ABCDE1234F', { mode: 'full' });
    expect(nextToPan.matches.map((m) => m.type)).toEqual(['PHONE', 'PAN']);

    // Dates and epoch timestamps stay excluded
    const nonPhones = detectPII('Date: 2026-11-27 | Epoch: 1732700000');
    expect(nonPhones.matches).toHaveLength(0);
  });

  it('uses cue words to rank confidence by default and enforces cues when strictPhoneContext is enabled', () => {
    const defaultCued = detectPII('call 9876543210 | ref 8827364519');
    expect(defaultCued.matches).toHaveLength(2);
    expect(defaultCued.matches[0].validation).toContain('high confidence');
    expect(defaultCued.matches[1].validation).toContain('medium confidence');

    const bareOrder = detectPII('order 8827364519', { strictPhoneContext: true });
    expect(bareOrder.matches).toHaveLength(0);

    const cuedStrict = detectPII('Please call 8827364519 or tel 9876543210 or contact 7766554433', {
      strictPhoneContext: true,
    });
    expect(cuedStrict.matches.map((m) => m.value)).toEqual([
      '8827364519',
      '9876543210',
      '7766554433',
    ]);

    const csvPhone = detectPII('id,customer_phone,order_id\n1,8827364519,9876543210', {
      strictPhoneContext: true,
    });
    expect(csvPhone.matches.map((m) => m.value)).toEqual(['8827364519']);

    const csvMobile = detectPII('id,user_mobile,ref\n1,8827364519,9876543210', {
      strictPhoneContext: true,
    });
    expect(csvMobile.matches.map((m) => m.value)).toEqual(['8827364519']);

    const prefixed = detectPII('ref +918827364519 and alt 08827364519', {
      strictPhoneContext: true,
    });
    expect(prefixed.matches.map((m) => m.value)).toEqual(['+918827364519', '08827364519']);
  });

  it('detects dotted cards, spaced Indian landlines, and accented Unicode emails', () => {
    const input =
      'Card 4111.1111.1111.1111 | Landline 011 2345 6789 and 0124 456789 | Email ñandú@correo.es';
    const res = sanitizeText(input, { mode: 'partial' });
    expect(res.counts.CREDIT_CARD).toBe(1);
    expect(res.counts.PHONE).toBe(2);
    expect(res.counts.EMAIL).toBe(1);
    expect(res.sanitizedText).toContain('XXXX.XXXX.XXXX.1111');
    expect(res.sanitizedText).toContain('XXX XXXX 6789');
    expect(res.sanitizedText).toContain('ñ***@correo.es');
  });

  it('strips zero-width characters before matching and maps offsets back to original text', () => {
    const input = 'Reach \u200Bñan\u200Bdú@correo.es or card 4111.\u200C1111.1111.1111 end.';
    const res = sanitizeText(input, { mode: 'full' });
    expect(res.counts.EMAIL).toBe(1);
    expect(res.counts.CREDIT_CARD).toBe(1);
    expect(res.sanitizedText).toBe('Reach \u200B[REDACTED] or card [REDACTED] end.');
    expect(res.matches[0].start).toBe(7); // skips leading zero-width char before 'ñ'
    expect(input.slice(res.matches[0].start, res.matches[0].end)).toBe('ñan\u200Bdú@correo.es');
  });
});

describe('Custom Regex Worker Timeout (ReDoS Protection)', () => {
  it('terminates catastrophic backtracking (a+)+$ within 500 ms and sets customRegexError', async () => {
    const evilInput = `${'a'.repeat(30)}!`;
    const result = await runCustomRegexInWorker(evilInput, '(a+)+$', 500);
    expect(result.timedOut).toBe(true);
    expect(result.matches).toEqual([]);
    expect(result.customRegexError).toBe(CUSTOM_REGEX_TIMEOUT_ERROR);
  });
});
