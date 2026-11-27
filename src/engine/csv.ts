import type { CsvColumnRisk, DetectedEntity, EntityType } from './types';

export interface CsvCellSpan {
  start: number;
  end: number;
  value: string;
  quoted: boolean;
}

const CSV_FORMULA_PREFIX_RE = /^[=+\-@\t\r]/;
const BARE_PHONE_CUE_RE = /\b(?:calls?|phones?|mobiles?|tel|telephone|contacts?)\b/i;
const NON_PHONE_ID_PREFIX_RE = /\b(?:order|id|ref|invoice|txn|batch|ticket|account|acc)\b\s*[:#-]?\s*$/i;

/**
 * Stateful RFC-4180 CSV parser supporting multiline quoted cells and escaped quotes ("").
 */
export function parseCsvRecords(text: string): CsvCellSpan[][] {
  if (!text) return [];
  const records: CsvCellSpan[][] = [];
  let currentRow: CsvCellSpan[] = [];
  let cellStart = 0;
  let inQuotes = false;
  let cellQuoted = false;

  const pushCell = (end: number) => {
    const trimmed = text.slice(cellStart, end).trim();
    const isQuoted =
      cellQuoted || (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2);
    const unquoted = isQuoted
      ? trimmed.replace(/^"|"$/g, '').replace(/""/g, '"').trim()
      : trimmed;
    currentRow.push({ start: cellStart, end, value: unquoted, quoted: isQuoted });
  };

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"') {
      if (inQuotes && text[i + 1] === '"') {
        i++;
      } else {
        if (!inQuotes && text.slice(cellStart, i).trim() === '') cellQuoted = true;
        inQuotes = !inQuotes;
      }
    } else if (ch === ',' && !inQuotes) {
      pushCell(i);
      cellStart = i + 1;
      cellQuoted = false;
    } else if ((ch === '\n' || ch === '\r') && !inQuotes) {
      pushCell(i);
      if (ch === '\r' && text[i + 1] === '\n') i++;
      if (currentRow.some((c) => c.value.length > 0) || currentRow.length > 1) {
        records.push(currentRow);
      }
      currentRow = [];
      cellStart = i + 1;
      cellQuoted = false;
    }
  }

  if (cellStart < text.length || currentRow.length > 0) {
    pushCell(text.length);
    if (currentRow.some((c) => c.value.length > 0) || currentRow.length > 1) {
      records.push(currentRow);
    }
  }

  return records;
}

/**
 * Neutralizes spreadsheet formula injection (=, +, -, @, tab, CR) in non-header CSV cells.
 */
export function escapeCsvFormulas(csvText: string): string {
  const records = parseCsvRecords(csvText);
  if (records.length < 2 || records[0].length <= 1) return csvText;

  const edits: Array<{ insertAt: number }> = [];
  for (let r = 1; r < records.length; r++) {
    for (const cell of records[r]) {
      const raw = csvText.slice(cell.start, cell.end);
      const leadingSpaces = raw.length - raw.trimStart().length;
      const trimmedStart = raw.slice(leadingSpaces);
      if (!trimmedStart) continue;

      if (trimmedStart.startsWith('"')) {
        if (CSV_FORMULA_PREFIX_RE.test(trimmedStart.slice(1))) {
          edits.push({ insertAt: cell.start + leadingSpaces + 1 });
        }
      } else if (CSV_FORMULA_PREFIX_RE.test(trimmedStart)) {
        edits.push({ insertAt: cell.start + leadingSpaces });
      }
    }
  }

  if (edits.length === 0) return csvText;
  let out = '';
  let cursor = 0;
  for (const e of edits) {
    out += csvText.slice(cursor, e.insertAt) + "'";
    cursor = e.insertAt;
  }
  return out + csvText.slice(cursor);
}

function buildIndexedCsvCellLookup(records: CsvCellSpan[][]): (index: number) => number {
  if (records.length < 2 || records[0].length <= 1) return () => -1;
  const cells: Array<{ start: number; end: number; colIdx: number }> = [];
  for (let r = 1; r < records.length; r++) {
    for (let colIdx = 0; colIdx < records[r].length; colIdx++) {
      cells.push({ start: records[r][colIdx].start, end: records[r][colIdx].end, colIdx });
    }
  }
  return (index: number) => {
    let lo = 0;
    let hi = cells.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (index < cells[mid].start) hi = mid - 1;
      else if (index > cells[mid].end) lo = mid + 1;
      else return cells[mid].colIdx;
    }
    return -1;
  };
}

/**
 * Computes per-column PII exposure across multiline CSV records.
 */
export function analyzeCsvColumns(text: string, matches: DetectedEntity[]): CsvColumnRisk[] {
  const records = parseCsvRecords(text);
  if (records.length < 2 || records[0].length <= 1) return [];

  const headers = records[0];
  const columnHits = headers.map(() => ({ count: 0, types: new Set<EntityType>() }));
  const findColIdx = buildIndexedCsvCellLookup(records);

  for (const m of matches) {
    const colIdx = findColIdx(m.start);
    if (colIdx >= 0 && colIdx < columnHits.length) {
      columnHits[colIdx].count += 1;
      columnHits[colIdx].types.add(m.type);
    }
  }

  return headers.map((h, idx) => ({
    columnIndex: idx,
    header: h.value || `Column ${idx + 1}`,
    entityCount: columnHits[idx].count,
    types: Array.from(columnHits[idx].types),
  }));
}

export function buildCsvHeaderLookup(text: string): (index: number) => string | null {
  if (!text.includes(',') || !text.includes('\n')) return () => null;
  const records = parseCsvRecords(text);
  if (records.length < 2 || records[0].length <= 1) return () => null;
  const headers = records[0];
  const findColIdx = buildIndexedCsvCellLookup(records);

  return (index: number) => {
    const colIdx = findColIdx(index);
    return colIdx >= 0 && colIdx < headers.length ? headers[colIdx].value : null;
  };
}

/**
 * Checks whether a bare 10-digit number is accompanied by a nearby phone cue word
 * or resides in a CSV column whose header contains "phone" or "mobile".
 */
export function hasBarePhoneContextCue(
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

  if (NON_PHONE_ID_PREFIX_RE.test(before)) return false;
  return BARE_PHONE_CUE_RE.test(`${before} ${after}`);
}
