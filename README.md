# PII Cleanroom (`propmt-wars`)

A 100% client-side, zero-network data sanitization workbench built with **React 19, TypeScript, Vite, and Vitest** to detect, validate, and redact sensitive PII from logs, resumes, support tickets, clinical notes, and CSV exports directly inside browser memory.

## Features

- **Zero Server / Offline Safe**: Runs strictly in local browser memory with zero external API calls or CDNs.
- **6 Built-in PII Detectors + Custom Regex**:
  - **Email Addresses** (`user@domain.tld`)
  - **Phone Numbers** (Indian `+91` / 10-digit mobile, landlines, and international E.164, excluding dates/epochs)
  - **IP Addresses** (strict IPv4 `0–255` octets excluding software versions like `v1.2.3.4`, plus IPv6)
  - **Indian PAN** (`[A-Z]{5}[0-9]{4}[A-Z]`)
  - **Indian Aadhaar** (12-digit UIDAI `2–9` prefix with Verhoeff checksum annotation + optional Strict Verhoeff mode)
  - **Credit Card Numbers** (13–19 digits validated via the **Luhn mod-10 algorithm** to prevent false positives on random 16-digit IDs)
  - **Custom Regex Rule**: Add ad-hoc organization patterns (e.g. `EMP-\d{4}|#INC-\d+`) on the fly
- **Three Redaction Modes**:
  1. **Full Mask**: `[REDACTED]` (with optional entity tag `[REDACTED:EMAIL]`)
  2. **Partial Mask**: Context-preserving masking (`XXXX-XXXX-XXXX-9014`, `a***@domain.com`, `XXXXX2318J`, `+91-XXXXXX4510`, `192.168.XXX.XXX`)
  3. **Consistent Pseudonymization**: Normalizes recurring identifiers to identical document-wide tokens (`USER_01`, `PHONE_01`, `PAN_01`, `AADHAAR_01`, `CARD_01`, `IP_01`)
- **Auditability & Export**:
  - Live **Side-by-Side Diff View** with synchronized scroll, **Changed lines only** filter, and click-to-inspect pairing
  - Per-value **Allowlist / Ignore** controls
  - **Exposure Risk Score** (`0–100`) & **CSV Column Risk Profiling**
  - 1-click **Sample Loader** (3 presets), `.txt`/`.csv` drag-and-drop upload, 1-click sanitized file download, and privacy-safe JSON audit export

## Local Setup & Verification

```powershell
# Install dependencies
npm.cmd install

# Run unit tests (Vitest)
npm.cmd test

# Typecheck & build production bundle
npm.cmd run build

# Start local dev server
npm.cmd run dev
```

See [PROMPT_LOG.md](./PROMPT_LOG.md) for the engineering and prompt design log.
