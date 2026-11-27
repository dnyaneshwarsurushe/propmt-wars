# Prompt & Engineering Log — PII Cleanroom (`propmt-wars`)

## Overview
Built **PII Cleanroom**, a 100% client-side browser data sanitization workbench using **React 19 + TypeScript + Vite + Vitest**, residing in the `propmt-wars` repository with zero external APIs or CDNs.

## Design & Prompt Iterations

### 1. Stack & Zero-Server Privacy Isolation
- **Goal**: Allow users to paste raw logs/notes/resumes or upload `.txt`/`.csv` files and sanitize PII strictly in browser memory.
- **Decision**: Built with React + TypeScript + Vite (`base: './'`) using system UI and monospace font stacks (zero external fonts, scripts, or network requests). Added live scan latency (`durationMs`), Light/Dark themes, and privacy-safe JSON audit export (containing partial-masked previews only, never raw PII).

### 2. Precision Detection, Luhn & Verhoeff Checksums (`src/engine/piiEngine.ts`)
- **Entities**:
  - `EMAIL`: Boundary-aware email detection.
  - `PHONE`: Supports Indian (`+91-9876543210`, `+919876543210`, `9876543210`, `022-26541234`) and international E.164/US formats while excluding ISO dates (`2026-11-27`), `HH:MM:SS` timestamps, and 10-digit epoch timestamps (`1732700000`).
  - `IP_ADDRESS`: IPv4 (`0–255` octet validation, excluding software version tags like `v1.2.3.4`) and validated IPv6 (`isValidIPv6`).
  - `PAN`: Indian PAN `[A-Z]{5}[0-9]{4}[A-Z]` with alphanumeric boundary checks and holder-type annotation.
  - `AADHAAR`: 12-digit UIDAI format (`[2-9]` leading digit) with full **Verhoeff dihedral D5 checksum** annotation (`isValidVerhoeff`) and an optional **Strict Aadhaar Verhoeff** filter toggle.
  - `CREDIT_CARD`: 13–19 digit sequences validated with the **Luhn (mod-10) algorithm** (`isValidLuhn`), rejecting all-zero/uniform strings and reserving non-Luhn card-shaped spans so 16-digit tracking IDs remain untouched.
  - `CUSTOM`: User-defined regex rule with syntax error reporting and infinite-loop protection.

### 3. Three Redaction Modes, Diff Inspector & CSV Profiling
- **Modes**: Full Mask (`[REDACTED]` or `[REDACTED:TYPE]`), Partial Mask, and Consistent Pseudonymization (`USER_01`, `PHONE_01`, `PAN_01`, `AADHAAR_01`, `CARD_01`, `IP_01`).
- **Workbench Features**: Quick-start preset cards, synchronized side-by-side diff with **Changed lines only** filter, interactive entity inspector with 1-click **Ignore / Allowlist**, exposure risk scoring (`0–100`), CSV column-level PII exposure profiling, and 1-click `.txt`/`.csv` export.
