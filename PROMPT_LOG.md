# Chronological Prompt & Engineering Log — PII Cleanroom (`propmt-wars`)

This log records every chronological prompt iteration, what the model built or changed, and what the user reviewed or corrected.

---

## Iteration 1 — Initial Problem Statement & Zero-Network Baseline
- **Exact Prompt**:
  > Background: Organizations and individuals frequently share text logs, resumes, support tickets, or clinical notes containing sensitive Personally Identifiable Information (PII), creating severe privacy and compliance risks. Design and build a browser-based data sanitization tool that allows users to paste raw text or upload a .txt/.csv file and automatically detect, classify, and redact sensitive PII entirely on the client side without sending data to any external server. Mandatory Functional Requirements & Constraints: Pattern Detection (emails, phone numbers, IP addresses, Indian PAN/Aadhaar formats, credit card numbers), Validation Logic (Luhn algorithm), Three Redaction Modes (Full Mask, Partial Mask, Consistent Pseudonymization), Audit & Export (live side-by-side diff view with entity detection counts and 1-click download). Expected Deliverables: Working web app with 1-click sample noisy text loader, side-by-side diff view, downloadable sanitized output, and prompt log.
- **What the Model Changed**:
  - Built an initial standalone HTML/CSS/UMD JavaScript sanitizer in `scratch/pii-sanitizer/` with regex detection, Luhn validation, 3 redaction modes, side-by-side diff view, 1-click sample loader, and Node.js unit tests.
- **What the User Corrected / Directed**:
  - Cloned `https://github.com/dnyaneshwarsurushe/propmt-wars.git` and instructed: *"redo the revious task"* → chose *"Rebuild the PII Sanitizer from scratch with a different stack or design"*.

---

## Iteration 2 — React + TypeScript + Vite Rebuild (`propmt-wars`)
- **Exact Prompts**:
  > `clone this repo https://github.com/dnyaneshwarsurushe/propmt-wars.git`  
  > `redo the revious task` *(selected: Rebuild the PII Sanitizer from scratch with a different stack or design)*
- **What the Model Changed**:
  - Scaffolded a React 19 + TypeScript + Vite + Vitest application (`src/engine/piiEngine.ts`, `src/engine/types.ts`, `src/components/DiffViewer.tsx`, `src/components/AuditTabs.tsx`, `src/App.tsx`, `src/data/samples.ts`).
  - Added strict TypeScript checks, Light/Dark cleanroom UI, synchronized side-by-side diff with changed-lines filter, privacy-safe JSON audit export, and 7 Vitest unit tests.
- **What the User Corrected / Directed**:
  - Asked *"clarify me what i need to do"*, then asked *"make it better"*.

---

## Iteration 3 — UX, Checksum Depth & Sample Files
- **Exact Prompts**:
  > `make it better`  
  > `check my github repo and give me score out off 100`  
  > `give me files` → `not this sample files`  
  > `and check any thing api key is leaked`  
  > `1 how to do it`  
  > `i want to public website`
- **What the Model Changed**:
  - Added UIDAI Verhoeff checksum annotation + Strict Aadhaar toggle, Custom Regex input, Typed Full Mask (`[REDACTED:TYPE]`), Entity Inspector bar, local Allowlist (`Ignore`), Exposure Risk score, CSV Column Risk profiling, and Quick-Start sample cards.
  - Audited `origin/main` (identified unpushed local commit `9c8e4b2`), verified zero leaked secrets across git history and source files, created 3 uploadable `.txt`/`.csv` sample test files (`sample-pii-files/`), and added GitHub Actions CI + GitHub Pages deployment workflows (`.github/workflows/ci.yml`, `.github/workflows/deploy.yml`).
- **What the User Corrected**:
  - Clarified *"not this sample files"* when source links were listed instead of noisy `.txt`/`.csv` test input files.
  - Identified real detection, ReDoS, false-positive, format, and prompt-log bugs in Iterations 4 and 5 below.

---

## Iteration 4 — Adjacent Entities & Non-Suppressing Rejected Spans
- **Exact Prompt**:
  > In src/engine/piiEngine.ts, a phone number directly followed by a space and a card (9876543210 4111 1111 1111 1111), or an Aadhaar directly followed by a phone, loses the second entity. Make candidate detection try every valid start offset and group size (4-4-4-4, 4-6-5, 12 digits) instead of one greedy span. A rejected span must never suppress a valid entity inside it. Add vitest cases for every adjacent pair of phone, card, Aadhaar and PAN, in both orders.
- **What the Model Changed**:
  - Replaced single-regex greedy matching in `detectPII` with multi-offset candidate generation across `4-4-4-4`, `4-4-4-4-3`, `4-4-4-1`, `4-6-5`, `4-6-4`, and `13–19` digit cards, `4-4-4` and `12-digit` Aadhaars, and multi-prefix E.164 phones.
  - Removed `reservedCardRanges` suppression and switched overlap resolution to weighted interval scheduling DP maximizing `(entity count, matched characters, priority)`.
  - Added 17 Vitest cases in `src/engine/piiEngine.test.ts` testing all 12 ordered adjacent pairs plus rejected-span non-suppression.
- **What the User Corrected**:
  - Followed up with 4 additional bug reports (ReDoS freeze, bare 10-digit phone false positives, missed real formats, and rewriting this prompt log).

---

## Iteration 5 — ReDoS Worker Guard, Phone Context Cues, Format Extensions, Zero-Width Mapping & Security Checks
- **Exact Prompts**:
  > 2. Custom regex can freeze the tab (Medium). The pattern (a+)+$ on 24 characters took 1.4 s, and the time roughly doubles with each extra character. A slightly longer input hung my probe for close to two minutes. The README claims loop protection, but that covers only zero-length matches.  
  > Fix prompt: "Custom regex patterns can hang the UI through catastrophic backtracking. Run custom-rule matching in a Web Worker with a 500 ms timeout, terminate it on timeout, and show 'Pattern too slow, simplify it' in customRegexError. Add a test using (a+)+$."
  >
  > 3. Ten-digit IDs starting 6–9 count as phones (Low). order 8827364519 is flagged as a phone number. This is hard to avoid completely, so a context cue would help.  
  > Fix prompt: "Reduce phone false positives: for bare 10-digit numbers without a +91 or 0 prefix, require a nearby cue word (call, phone, mobile, tel, contact) or a CSV column header containing 'phone' or 'mobile'. Keep prefixed formats always on. Add tests for both."
  >
  > 4. Some real formats are missed (Low). Dotted cards such as 4111.1111.1111.1111. Landlines with spaces, such as 011 2345 6789. Emails with accented local parts, such as ñandú@correo.es. Emails with zero-width characters.  
  > Fix prompt: "Extend detection in piiEngine.ts: allow . as a card separator, space-separated Indian landlines (STD code plus 6–8 digits), and Unicode letters in the email local part. Strip zero-width characters before matching but map offsets back to the original text. Add tests."
  >
  > 5. Prompt log is thin (Low). PROMPT_LOG.md summarises features but doesn't record the prompts you actually gave, which the deliverable asks for.  
  > Fix prompt: "Rewrite PROMPT_LOG.md as a chronological log. For each iteration, give the exact prompt I sent, what the model changed, and what I corrected, including one section for the bugs above."
  >
  > `add security checks`
- **What the Model Changed**:
  - **ReDoS Protection**: Added `src/workers/customRegexWorker.ts` and `src/engine/customRegexRunner.ts` (Browser Web Worker + Node `worker_threads` parity) with a strict 500 ms timeout, worker termination, and `customRegexError = 'Pattern too slow, simplify it'`, wired into `src/App.tsx`.
  - **Phone Context Cues**: Updated `src/engine/piiEngine.ts` (`hasBarePhoneContextCue`) so bare 10-digit `[6-9]\d{9}` numbers require a nearby cue word (`call`, `phone`, `mobile`, `tel`, `contact`) or a CSV header containing `phone`/`mobile`, while `+91`/`0`-prefixed and formatted numbers remain always enabled.
  - **Extended Formats & Zero-Width Mapping**: Added `.` separator support for cards, spaced Indian STD landlines (`011 2345 6789`), Unicode `\p{L}` email local/domain parts (`ñandú@correo.es`), and `stripZeroWidthWithMap` to strip invisible characters before matching while mapping `[start, end)` back to original text.
  - **Security Checks**: Added production CSP (`connect-src 'none'`, `object-src 'none'`) in `vite.config.ts`, 5 MB client upload guard in `src/App.tsx`, and CI checks (`npm audit --audit-level=high`, CSP & zero-external-URL checks, and secret scanning) in `.github/workflows/ci.yml`.
  - **Chronological Log & Tests**: Rewrote `PROMPT_LOG.md` chronologically and expanded `src/engine/piiEngine.test.ts` with tests for `(a+)+$` timeout, cue/CSV/prefixed phones, dotted cards, spaced landlines, accented emails, and zero-width offset mapping.
