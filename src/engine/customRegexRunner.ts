import type {
  CustomRegexMatchSpan,
  CustomRegexWorkerResponse,
} from '../workers/customRegexWorker';

export const CUSTOM_REGEX_TIMEOUT_MS = 500;
export const CUSTOM_REGEX_TIMEOUT_ERROR = 'Pattern too slow, simplify it';

export interface CustomRegexRunResult {
  matches: CustomRegexMatchSpan[];
  customRegexError: string | null;
  timedOut: boolean;
}

/**
 * Runs a user-supplied custom regex pattern inside an isolated worker
 * (Browser Web Worker or Node worker_threads in tests) with a strict timeout.
 * Terminates the worker on timeout to prevent UI freezes from catastrophic backtracking.
 */
export function runCustomRegexInWorker(
  text: string,
  pattern: string,
  timeoutMs = CUSTOM_REGEX_TIMEOUT_MS
): Promise<CustomRegexRunResult> {
  const trimmed = pattern.trim();
  if (!trimmed || !text) {
    return Promise.resolve({ matches: [], customRegexError: null, timedOut: false });
  }

  // Validate syntax upfront cleanly before spawning a worker
  try {
    new RegExp(trimmed, 'g');
  } catch (err) {
    return Promise.resolve({
      matches: [],
      customRegexError: err instanceof Error ? err.message : 'Invalid regular expression',
      timedOut: false,
    });
  }

  // Browser Web Worker path
  if (typeof Worker !== 'undefined') {
    return new Promise((resolve) => {
      const worker = new Worker(new URL('../workers/customRegexWorker.ts', import.meta.url), {
        type: 'module',
      });
      let settled = false;

      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        worker.terminate();
        resolve({
          matches: [],
          customRegexError: CUSTOM_REGEX_TIMEOUT_ERROR,
          timedOut: true,
        });
      }, timeoutMs);

      worker.onmessage = (ev: MessageEvent<CustomRegexWorkerResponse>) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        worker.terminate();
        resolve({
          matches: ev.data.matches,
          customRegexError: ev.data.error,
          timedOut: false,
        });
      };

      worker.onerror = (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        worker.terminate();
        resolve({
          matches: [],
          customRegexError: err.message || 'Custom regex worker failed',
          timedOut: false,
        });
      };

      worker.postMessage({ id: 1, text, pattern: trimmed });
    });
  }

  // Node.js worker_threads fallback for Vitest / non-DOM test environments
  return runInNodeWorker(text, trimmed, timeoutMs);
}

async function runInNodeWorker(
  text: string,
  pattern: string,
  timeoutMs: number
): Promise<CustomRegexRunResult> {
  const modName = 'node:' + 'worker_threads';
  const { Worker: NodeWorker } = (await import(/* @vite-ignore */ modName)) as {
    Worker: new (
      code: string,
      opts: { eval: boolean; workerData: { text: string; pattern: string } }
    ) => {
      on(event: 'message', cb: (msg: { matches: CustomRegexMatchSpan[]; error: string | null }) => void): void;
      on(event: 'error', cb: (err: Error) => void): void;
      terminate(): Promise<number>;
    };
  };

  const workerScript = `
    const { parentPort, workerData } = require('node:worker_threads');
    try {
      const re = new RegExp(workerData.pattern, 'g');
      const matches = [];
      let m;
      while ((m = re.exec(workerData.text)) !== null) {
        if (m[0].length === 0) { re.lastIndex++; continue; }
        if (!m[0].includes('\\n')) {
          matches.push({ start: m.index, end: m.index + m[0].length, value: m[0] });
        }
        if (matches.length >= 50000) break;
      }
      parentPort.postMessage({ matches, error: null });
    } catch (err) {
      parentPort.postMessage({ matches: [], error: err && err.message ? err.message : 'Invalid regular expression' });
    }
  `;

  return new Promise((resolve) => {
    const worker = new NodeWorker(workerScript, {
      eval: true,
      workerData: { text, pattern },
    });
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      void worker.terminate();
      resolve({
        matches: [],
        customRegexError: CUSTOM_REGEX_TIMEOUT_ERROR,
        timedOut: true,
      });
    }, timeoutMs);

    worker.on('message', (msg) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      void worker.terminate();
      resolve({
        matches: msg.matches,
        customRegexError: msg.error,
        timedOut: false,
      });
    });

    worker.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      void worker.terminate();
      resolve({
        matches: [],
        customRegexError: err.message,
        timedOut: false,
      });
    });
  });
}
