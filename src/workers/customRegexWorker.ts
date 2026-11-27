/**
 * Isolated Web Worker for executing user-supplied custom regex patterns
 * safely off the main UI thread so catastrophic backtracking can be terminated.
 */
export interface CustomRegexWorkerRequest {
  id: number;
  text: string;
  pattern: string;
}

export interface CustomRegexMatchSpan {
  start: number;
  end: number;
  value: string;
}

export interface CustomRegexWorkerResponse {
  id: number;
  matches: CustomRegexMatchSpan[];
  error: string | null;
}

self.onmessage = (event: MessageEvent<CustomRegexWorkerRequest>) => {
  const { id, text, pattern } = event.data;
  try {
    const re = new RegExp(pattern, 'g');
    const matches: CustomRegexMatchSpan[] = [];
    let match: RegExpExecArray | null;
    while ((match = re.exec(text)) !== null) {
      if (match[0].length === 0) {
        re.lastIndex++;
        continue;
      }
      if (!match[0].includes('\n')) {
        matches.push({
          start: match.index,
          end: match.index + match[0].length,
          value: match[0],
        });
      }
      if (matches.length >= 50000) break;
    }
    const res: CustomRegexWorkerResponse = { id, matches, error: null };
    self.postMessage(res);
  } catch (err) {
    const res: CustomRegexWorkerResponse = {
      id,
      matches: [],
      error: err instanceof Error ? err.message : 'Invalid regular expression',
    };
    self.postMessage(res);
  }
};
