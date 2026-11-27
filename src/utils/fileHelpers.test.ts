import { describe, expect, it } from 'vitest';
import { sanitizeText } from '../engine/piiEngine';
import {
  buildAuditReportJson,
  decodeTextFileBuffer,
  getSafeFilenameBase,
} from './fileHelpers';

describe('File Helpers & Privacy-Safe Audit Serialization', () => {
  it('decodes UTF-8 BOM, UTF-16LE BOM, and rejects binary null-byte payloads', () => {
    const utf8Bom = new Uint8Array([0xef, 0xbb, 0xbf, 0x68, 0x69]).buffer;
    expect(decodeTextFileBuffer(utf8Bom)).toEqual({ text: 'hi' });

    const utf16Le = new Uint8Array([0xff, 0xfe, 0x68, 0x00, 0x69, 0x00]).buffer;
    expect(decodeTextFileBuffer(utf16Le)).toEqual({ text: 'hi' });

    const binary = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01]).buffer;
    expect(decodeTextFileBuffer(binary).error).toMatch(/Binary file detected/);
  });

  it('sanitizes filenames and strips raw rejected values from Audit JSON', () => {
    expect(getSafeFilenameBase('rahul_ABCDE1234F_kyc.txt')).toBe('rahul_redacted_kyc');

    const res = sanitizeText('Aadhaar 2341-2341-2347 | Email bob@acme.com', {
      strictAadhaarVerhoeff: true,
    });
    const json = buildAuditReportJson('bob@acme.com_report.txt', false, 'full', res);
    expect(json).not.toContain('bob@acme.com');
    expect(json).not.toContain('2341-2341-2347');
    expect(json).toContain('XXXX-XXXX-2347');
  });
});
