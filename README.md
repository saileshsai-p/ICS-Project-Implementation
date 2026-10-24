# SecuShare Version 2.0 — Secure File Sharing Web Application

A lightweight, high-security, locally runnable file-sharing web application based on the research paper:

> **"Design and Implementation of a Secure File Sharing Web Application with Expiry and Malware Detection"**  
> *International Journal of Research Publication and Reviews (IJRPR)*  
> [Reference PDF](https://ijrpr.com/uploads/V6ISSUE5/IJRPR46303.pdf)

---

## 1. Project Overview & Version 2 Evolution

SecuShare shares files locally without cloud storage, subscriptions or a database. Version 2.0 extends the baseline paper prototype with six features (detailed in section 2): download limits and one-time links, AES-256-GCM encryption at rest, automatic expiry cleanup, SHA-256 integrity verification, user accounts with persistent sessions, and optional recipient-restricted links.

Intended for **local academic demonstration**, not production deployment.

### Architectural Principles
- **Self-contained**: Node.js ES modules and native built-ins (`node:crypto`, `node:fs/promises`, `node:stream`); only `express` and `multer` as dependencies.
- **No database**: JSON stores with atomic writes (`.tmp` + rename) and a serialized queue. Safe for a **single process only**.
- **Single access gate**: every download passes `accessService.js:canDownload()` before any file operation or decryption.
- **Fail-closed delivery**: corrupted ciphertext, altered tags, tampered wrapped keys and digest mismatches abort before any byte is sent; failures are logged server-side and returned as generic errors.
- **Explicit key handling**: a fresh install generates and persists the master key before first use; an install that already holds encrypted data treats a missing key as a fatal startup error rather than generating a replacement (section 5).
- **Honest disclaimers**: no virus scanning. Files are marked `not_scanned` (section 11).

---

## 2. Security Features

### A. Download Limits & One-Time Links
Policies: `unlimited` (until expiry), `one_time` (revoked after the first successful download), `limited` (configurable integer).

Allowance is consumed in `metadataService.js:consumeDownloadAllowance()` via a serialized promise queue, **only** after every preflight check passes (token, lifecycle status, expiry, password, GCM decryption, SHA-256 verification) and immediately before streaming. Simultaneous requests cannot double-spend a one-time link **within a single process**. The download page shows the remaining allowance without exposing storage keys or paths.

### B. AES-256-GCM Encryption at Rest
Each file gets a fresh random 32-byte Data Encryption Key (DEK), wrapped with AES-256-GCM under the server Master Key (`FILE_ENCRYPTION_MASTER_KEY`). Fresh 12-byte nonces are generated for both content encryption and DEK wrapping.

Multer streams the upload into `storage/temp/`; the plaintext is encrypted with `crypto.createCipheriv('aes-256-gcm', dek, nonce)` straight into `storage/files/<storedName>`, and the temporary plaintext is deleted immediately afterwards. On download, decryption streams into a private temporary file and both the content tag and the unwrapped DEK tag are validated before any byte reaches the client.

### C. Automatic Expiry Cleanup & Restart Recovery
Records move through `active` → `deleting` → `deleted`. Links past `expiresAt` are rejected by `canDownload()` with `410 Gone`.

`cleanupService.js` runs a non-overlapping cycle (default 60 s), takes read leases from `operationCoordinator.js` so files being streamed are never unlinked mid-transfer, recovers interrupted deletions on restart, and removes stale temporary fragments. A record advances to `deleted` **only** when its file is confirmed gone; a failed deletion stays `deleting` with the error recorded for retry.

### D. SHA-256 File Integrity Verification
Before encryption the digest of the original file is computed by streaming (`fileIntegrityService.js`) and stored in `metadata.json`. After decryption it is recomputed and compared with `crypto.timingSafeEqual`.

On mismatch the temporary plaintext is unlinked, the lease released, nothing is sent, and a diagnostic line is logged (`routes/download.js`) containing only the record id and stored filename — never keys, passwords, session identifiers or file contents. GCM authentication failures, tampered wrapped keys and digest mismatches are logged as distinct causes; clients get a generic message.

> SHA-256 detects corruption and tampering of stored data. It is **not** malware detection (section 11).

### E. Authentication & Persistent Sessions
Accounts use email + password (min 8 chars), hashed with `crypto.scrypt` using a unique 16-byte salt and 64-byte key length; plaintext is never stored. Email uniqueness is enforced on the normalized lowercase form.

Sessions live server-side in `data/sessions.json` and survive restarts, use 256-bit random identifiers rotated on login to prevent fixation, default to 7 days (`SESSION_LIFETIME_MS`), and set `HttpOnly`, `SameSite=Lax`, `Path=/` (plus `Secure` when `NODE_ENV=production`). Logout deletes the server-side record and clears the cookie. Failed logins are rate-limited to 5 per 5 minutes per IP+email, returning `429`.

### F. Recipient-Based Authorization
An uploader may optionally list authorized recipient emails (normalized, deduplicated). Anonymous uploads remain fully supported.

- **Public link** (no recipients): downloadable without login; password, expiry and limits still apply.
- **Restricted link**: requires login, and only an account whose email matches the list may download. Addresses that have not registered yet are honoured once that account is created.
- A restricted link with a file password requires **both**; neither bypasses the other.
- After login or registration the user returns to the intended share link; open redirects are blocked (same-origin relative paths only).

> Authorization is **address matching only**. Email ownership is never verified (section 10).

---

## 3. Technology Stack

| Layer | Technology | Details |
|---|---|---|
| **Backend Runtime** | Node.js (v24.x / 18.11+) | Native ES Modules (`"type": "module"`) |
| **HTTP Framework** | Express.js 4.21 | Modular routing, static asset serving, custom error handling |
| **File Processing** | Multer 1.4 | Streaming multipart upload handling to private temporary folder |
| **Cryptography** | `node:crypto` | AES-256-GCM envelope encryption, SHA-256 hashing, `scrypt` password hashing |
| **Streams & I/O** | `node:stream`, `node:fs/promises` | Memory-efficient streaming pipelines and safe file paths |
| **Concurrency Guard** | Custom Promise Queue | Atomic metadata read-modify-write and download allowance checks |
| **Frontend UI** | HTML5, CSS3, Vanilla JS | Cybersecurity dark aesthetic, responsive, zero external CDN dependencies |
| **Test Runner** | Native `node:test` | 92 individual test cases across 5 suites, run against disposable temporary directories (see section 8) |

---

## 4. Architecture & Repository File Tree

```
├── .env.example               # Placeholder environment template (copy to .env)
├── data/                      # Runtime state - git-ignored, auto-created on first start
│   ├── metadata.json          # Persistent JSON store for file records
│   ├── users.json             # Persistent JSON store for user accounts (scrypt hashes)
│   └── sessions.json          # Persistent JSON store for active server-side sessions
├── middleware/
│   ├── authMiddleware.js      # Cookie parsing, persistent session authentication, requireAuth
│   ├── errorHandler.js        # Global error interceptor (prevents stack/path leakage)
│   ├── rateLimiter.js         # Sliding-window brute-force limiter for passwords & logins
│   ├── securityHeaders.js     # Strict CSP, nosniff, DENY framing headers
│   └── uploadValidation.js    # Multer configuration with 50 MB default ceiling
├── routes/
│   ├── auth.js                # POST /api/auth/register, /login, /logout, GET /me
│   ├── download.js            # GET & POST /api/files/:token/download (decryption & verification)
│   ├── pages.js               # HTML page delivery (/, /share/:token, /login, /register)
│   └── upload.js              # POST /api/files (integrity hashing, AES encryption, recipients)
├── services/
│   ├── accessService.js       # Central authorization gate (expiry, allowance, password, recipient check)
│   ├── authService.js         # Open redirect validation and safe URL destination helpers
│   ├── cleanupService.js      # Background expiry worker, retry-safe deletion, consistency audit
│   ├── config.js              # Central runtime paths + disposable-location safety guard
│   ├── encryptionService.js   # AES-256-GCM envelope encryption, master key lifecycle
│   ├── fileIntegrityService.js# Streaming SHA-256 calculation and timing-safe comparison
│   ├── fileService.js         # Unguessable storage filenames, path traversal defenses, deletion results
│   ├── malwareScanner.js      # Modular scanner interface (explicitly 'not_scanned')
│   ├── metadataService.js     # Atomic metadata serialization, backward-compatible defaults
│   ├── migrationService.js    # Safe migration of legacy plaintext files to Version 2
│   ├── operationCoordinator.js# In-memory download lease tracking to coordinate with cleanup
│   ├── passwordService.js     # Salted scrypt hashing and timing-safe password verification
│   ├── sessionService.js      # File-backed server session store with 7-day default expiry
│   └── userService.js         # User registration, email normalization, scrypt verification
├── public/
│   ├── index.html             # Upload homepage with recipient field & result card
│   ├── download.html          # Recipient download page with security & allowance badges
│   ├── login.html             # User login page with redirect destination handling
│   ├── register.html          # User registration page with min-length validation
│   ├── css/
│   │   └── style.css          # Cybersecurity theme (navy/slate/cyan, responsive)
│   └── js/
│       ├── auth.js            # Client-side session state, navbar injection, and logout
│       ├── download.js        # Recipient download logic, auth required/denied states
│       └── upload.js          # Drag-and-drop, upload progress, recipient list parsing
├── storage/                   # Runtime state - git-ignored, auto-created on first start
│   ├── files/                 # Permanent private encrypted storage (AES-256-GCM ciphertext)
│   ├── quarantine/            # Reserved for future ClamAV malware quarantine (unused)
│   └── temp/                  # Multer holding directory and verified decryption staging
├── tests/
│   ├── setup.mjs              # Isolation bootstrap: redirects all storage to a temp dir
│   ├── helpers/
│   │   └── childRunner.js     # Disposable installations + child-process probes
│   ├── app.test.js            # Entrypoint & baseline suite (16 cases)
│   ├── v2.test.js             # Version 2 security suite (19 cases, Features A-D)
│   ├── auth_authorization.test.js # Authentication & recipient authorization (39 cases)
│   ├── keyManagement.test.js  # Master key lifecycle & isolation guard (8 cases)
│   └── resilience.test.js     # Cleanup failures, streaming race, tamper matrix (10 cases)
└── README.md                  # Comprehensive technical documentation & experimental evaluation
```

---

## 5. Cryptographic Key Management & Setup

### Master Key Specification
The application requires a **256-bit (32-byte) Master Encryption Key** configured outside of version control.

### Generating a Secure Master Key
Use Node.js built-in `crypto`:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```
Or OpenSSL:
```bash
openssl rand -hex 32
```

### Environment Variable Configuration
Copy the template and edit it:
```bash
cp .env.example .env          # Linux / macOS
Copy-Item .env.example .env   # Windows PowerShell
```
Then set `FILE_ENCRYPTION_MASTER_KEY` inside `.env`. Alternatively export it into the shell:
```bash
# Linux/macOS
export FILE_ENCRYPTION_MASTER_KEY="your_64_character_hex_master_key_here"

# Windows PowerShell
$env:FILE_ENCRYPTION_MASTER_KEY="your_64_character_hex_master_key_here"
```
Quoted and unquoted values in `.env` are both accepted; surrounding quotes are stripped.

### Key Resolution Behaviour
Resolved once at startup: (1) `process.env.FILE_ENCRYPTION_MASTER_KEY`, (2) the `.env` entry, (3) first-run initialization — **only** for a verifiably fresh installation.

Case 3 is deliberately narrow: *fresh* means `storage/files/` holds no files **and** no metadata record has encryption enabled. A new key is then generated, appended to `.env`, and **read back and verified before anything is encrypted with it**, so first-run files stay decryptable after a restart. If it cannot be persisted, startup fails rather than using a key that would be lost.

If encrypted data already exists and the key is missing, startup **fails** and no replacement is generated — a new key could not decrypt existing files and would mask the real problem. A malformed key is also a hard error and is never overwritten.

> [!CAUTION]
> **Key Backup & Disaster Recovery**:  
> In envelope encryption, file Data Encryption Keys (DEKs) are wrapped under the Master Key. **Loss of the Master Key renders all stored ciphertext permanently unrecoverable.** There is no key rotation and no recovery path in this project. Always store a backup of the Master Key somewhere safe.

---

## 5b. Environment Variables Reference

Every variable below was verified against the source. All are optional except the master key.

| Variable | Default | Read in | Purpose |
|---|---|---|---|
| `FILE_ENCRYPTION_MASTER_KEY` | *(see section 5)* | `services/encryptionService.js` | 32-byte master key (64 hex or 44 base64 chars) wrapping every per-file DEK. **Required** once encrypted data exists. |
| `PORT` | `3000` | `server.js` | HTTP listen port. |
| `NODE_ENV` | *(unset)* | `middleware/authMiddleware.js` | When `production`, adds `Secure` to the session cookie. Leave unset for plain-HTTP localhost, or the browser will drop the cookie. |
| `MAX_FILE_SIZE_BYTES` | `52428800` (50 MB) | `middleware/uploadValidation.js` | Maximum accepted upload size. |
| `MAX_EXPIRY_DAYS` | `365` | `routes/upload.js` | Upper bound on link lifetime. The lower bound is fixed at 1 minute. |
| `SESSION_LIFETIME_MS` | `604800000` (7 days) | `services/sessionService.js` | Session lifetime. |
| `SESSION_COOKIE_NAME` | `secushare_session` | `services/sessionService.js` | Session cookie name. |
| `CLEANUP_INTERVAL_MS` | `60000` | `services/cleanupService.js` | Interval between expiry-cleanup cycles. |
| `TEMP_FILE_MAX_AGE_MS` | `900000` (15 min) | `services/cleanupService.js` | Age at which an *unreferenced* temp file is removed. Files in use by a live request are always skipped. |
| `SECUSHARE_DATA_DIR` | `./data` | `services/config.js` | **Testing only.** Redirects the JSON stores. |
| `SECUSHARE_STORAGE_DIR` | `./storage` | `services/config.js` | **Testing only.** Redirects file storage. |
| `SECUSHARE_ENV_FILE` | `./.env` | `services/config.js` | **Testing only.** Redirects the key file. |

The three `SECUSHARE_*` variables exist so tests and benchmarks can never touch real data. The test suite and benchmark set them automatically and **refuse to run** if they still resolve inside the project tree.

---

## 6. Installation & Running the Application

**Prerequisites:** Node.js **v20.6+** (verified on v24.14.1 — the test script's `--import` needs v20.6+) and npm. No database, external service or network access required.

```bash
npm install

cp .env.example .env          # Linux / macOS
Copy-Item .env.example .env   # Windows PowerShell
# paste a key from: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

npm start       # or: npm run dev   (auto-reload)
```

Then open `http://localhost:3000`.

Skipping the `.env` step is safe on a brand-new installation — a key is generated and persisted on first start. On an installation that already has uploads, a missing key is a fatal startup error by design (section 5).

---

## 7. Migration of Legacy Files (Version 1 to Version 2)

Version 1 stored files unencrypted. `npm run migrate` upgrades them in place.

Per record it verifies the legacy file exists, computes the original SHA-256, encrypts it under a fresh DEK wrapped by the Master Key, **test-decrypts and confirms the digest matches before replacing anything**, then updates `metadata.json` with the `encryption`, `integrity` and `storageFormat: 'encrypted-v2'` blocks. Share tokens, passwords, expiry timestamps and download limits are preserved.

---

## 8. Automated Testing & Verification

The test suite runs using Node's native test runner (`node:test`) and spins up the server on an ephemeral port.

### Running Tests Safely

```bash
npm test
```

That is the **only** supported command. It expands to:

```
node --test --import ./tests/setup.mjs tests/app.test.js
```

`tests/setup.mjs` must load before any application module, because the services resolve their paths at import time. It creates a unique temp directory, points `SECUSHARE_DATA_DIR` / `SECUSHARE_STORAGE_DIR` / `SECUSHARE_ENV_FILE` at it, generates a throwaway key (overriding any real one), asserts the redirection took effect, and on exit removes only what it created.

> [!IMPORTANT]
> **Do not run `node --test tests/app.test.js` directly.** Without the bootstrap the suites would operate on real data — the authentication suite resets the user and session stores. `assertDisposableDataLocations()` in `services/config.js` makes this a hard failure instead: the run aborts before any file is touched, naming the missing variable. Covered by test K8.

Real `data/`, `storage/` and `.env` are never read or written by a test run, verified by SHA-256 hashing before and after a full run.

### How to Read the Test Count

Node's summary line reports **109 tests**, but that number counts grouping wrappers as tests. The honest figure is:

| Level | Count | What it is |
|---|---|---|
| Top-level suites | 5 | `test('Suite: ...')` containers |
| Group wrappers | 12 | `Feature A-D`, `Section 1-5`, `Section 1-3` containers |
| **Individual test cases** | **92** | Actual assertions-bearing tests |
| Node's reported total | 109 | 92 cases + 17 containers |

Per-suite breakdown of the 92 cases:

| Suite | File | Cases |
|---|---|---|
| Secure File Sharing Baseline Implementation | `app.test.js` | 16 |
| SecuShare Version 2 Security Enhancements | `v2.test.js` | 19 |
| SecuShare Authentication & Recipient Authorization | `auth_authorization.test.js` | 39 |
| Master Key Lifecycle | `keyManagement.test.js` | 8 |
| Resilience and Failure Handling | `resilience.test.js` | 10 |
| **Total** | | **92** |

### Latest Verified Result

```
ℹ tests 109      (= 92 individual cases + 17 suite/group wrappers)
ℹ pass 109
ℹ fail 0
ℹ skipped 0
ℹ todo 0
```

Tests exercise real AES-256-GCM encryption, real SHA-256 hashing, real filesystem I/O and a real HTTP server. Nothing security-relevant is mocked.

**Master Key Lifecycle** (`keyManagement.test.js`, K1–K8) — each case runs in its own child process with its own disposable installation, since key resolution depends on filesystem state at startup. Covers: fresh-install generation, decryptability from a later process, unpersistable key, missing key with existing data, ciphertext-only detection, quoted vs unquoted `.env` values, malformed key, and the isolation guard.

**Resilience** (`resilience.test.js`, R1–R10) — a failed deletion stays `deleting` and is never reported `deleted`; the consistency audit reports orphans without removing them; a 24 MB download paused mid-stream survives a cleanup cycle byte-for-byte; a refused download releases its lease; plus six tampering scenarios asserted individually (section 9).

---

## 9. Experimental Performance Evaluation

### Running the Benchmark Safely

```bash
npm run benchmark                    # 5 trials per size (default)
BENCH_TRIALS=10 npm run benchmark    # more trials
```

Like the test suite, the benchmark builds its **own disposable installation** in the OS temp folder with a throwaway key, refuses to start if the configured paths are not disposable, and removes only what it created. It never measures, modifies or pollutes real project data. Earlier versions of this script wrote ~25 permanent records into the real `data/` and `storage/` on every run; that is fixed.

### Test Environment (recorded by the script itself)
- **Node.js**: v24.14.1
- **Platform**: win32 x64, Windows build 10.0.26300
- **CPU**: AMD Ryzen 7 7730U, 16 logical processors
- **Memory**: 13.84 GiB
- **Trials**: 5 per payload size, fresh random (incompressible) payload per trial
- **Topology**: client and server in the **same Node process** over loopback HTTP

### Latency

Timing boundaries are explicit. Upload = request dispatch until the JSON response is parsed. Download = request dispatch until the **complete** response body has been received. Both therefore include loopback HTTP transfer, multipart parsing, SHA-256 hashing, AES-256-GCM work, JSON metadata I/O and response handling — they are end-to-end request timings, not isolated cryptographic throughput.

| File Size | Upload mean | Upload median | Upload SD | Download mean | Download median | Download SD |
|---|---|---|---|---|---|---|
| **10 KB** | 21.54 ms | 12.17 ms | 19.71 ms | 12.44 ms | 11.26 ms | 2.65 ms |
| **100 KB** | 11.45 ms | 11.58 ms | 1.25 ms | 11.64 ms | 11.16 ms | 1.07 ms |
| **1 MB** | 19.38 ms | 19.53 ms | 1.54 ms | 18.51 ms | 18.68 ms | 1.10 ms |
| **10 MB** | 85.36 ms | 85.65 ms | 3.74 ms | 96.86 ms | 98.06 ms | 5.89 ms |

> [!NOTE]
> These are figures from **one run on one machine**. They do not demonstrate consistent performance. Note the 10 KB upload standard deviation (19.71 ms) exceeding its own median (12.17 ms) — a first-trial warm-up artefact, which is exactly why median and SD are reported rather than a lone mean. Repeated runs vary by tens of percent.

### On-Disk Storage Overhead

Measured by locating the ciphertext for **each individual upload via its own metadata record** and calling `stat()` on that one file:

```
Storage overhead (%) = ((stored ciphertext size − original size) / original size) × 100
```

| File Size | Original bytes | Stored ciphertext bytes | Overhead bytes | Overhead % |
|---|---|---|---|---|
| **10 KB** | 10,240 | 10,240 | 0 | 0.0000 % |
| **100 KB** | 102,400 | 102,400 | 0 | 0.0000 % |
| **1 MB** | 1,048,576 | 1,048,576 | 0 | 0.0000 % |
| **10 MB** | 10,485,760 | 10,485,760 | 0 | 0.0000 % |

Identical across all 5 trials at every size. AES-GCM is a **counter-based (CTR) construction**, so ciphertext length equals plaintext length; the 12-byte nonce and 16-byte authentication tag live in `metadata.json`, accounted for below.

> [!WARNING]
> **Methodology correction.** The earlier benchmark computed `downloaded_length − original_length`, which is 0 whenever a download is correct and measured nothing about storage. The 0 % result is genuine, but only the current method establishes it.

### Metadata Overhead (measured, not assumed)

Measured as the byte difference in `metadata.json` before and after one controlled 1 KB upload:

| Measurement | Bytes | Definition |
|---|---|---|
| `metadata.json` growth from one upload | **1,284** | File size after minus before; one 1 KB upload; `JSON.stringify` indent 2 |
| Whole record, serialized | 1,210 | All fields of the new record, indent 2 |
| `encryption` + `integrity` + `storageFormat` only | 644 | The crypto-specific additions, indent 2 |

This figure depends on pretty-print indentation and filename length, so it describes this configuration rather than a universal constant. The previously documented "+380 bytes" was never measured by the script and was incorrect.

### Security Enforcement Trials

| Scenario | Method | Result |
|---|---|---|
| **Concurrent one-time link** | 10 simultaneous requests on a `one_time` link | 1 allowed (200), 9 refused (410) — correct. Single-process scope only. |
| **Incorrect expected SHA-256 digest** | Replace stored digest, ciphertext intact | Refused 500, reported as integrity failure |
| **Modified ciphertext** | Flip 1 byte on disk | Refused 500, GCM authentication failure |
| **Modified authentication tag** | Flip 1 byte of stored tag | Refused 500, GCM authentication failure |
| **Modified wrapped data key** | Flip 1 byte of wrapped DEK | Refused 500, key unwrap failure |
| **Truncated ciphertext** | Remove 5 trailing bytes | Refused 500, GCM authentication failure |
| **Missing encrypted file** | Unlink the ciphertext | Refused 404, reported as not found |

All 6 behaved as specified (6/6). Each also asserts that **no plaintext appears in the response** and **no download allowance is consumed**.

> [!WARNING]
> **Methodology correction.** The earlier benchmark claimed "5 tampered files rejected via GCM auth failure", but it only overwrote the *expected digest* and never touched ciphertext, accepting any HTTP 500 as proof. The scenarios above are distinct and each asserted against its own failure class.

### Expiry Cleanup Timing

| Cycle duration | Records scanned | Files deleted | Deletion verified |
|---|---|---|---|
| **6.81 ms** | 29 | 1 | Yes — fixture present before, absent after, record status `deleted` |

The benchmark creates its own fixture, expires it, runs one cycle, and confirms the file is gone and the record reached `deleted` before reporting the timing. This is the cost of **one full cycle over 29 records**, including rewriting the whole JSON store — not a per-file cost, and it grows with record count. The previously documented "2.07 ms" was not measured and verified no deletion.

> [!CAUTION]
> None of these results constitute penetration testing, malware detection, or evidence of production readiness.

---

## 10. Security Limitations & Operational Assumptions

This application is built for **local academic demonstration**. It is not production-ready, and the following are known, accepted limitations rather than oversights.

1. **Single-Process Metadata**: The serialized queue in `metadataService.js` guarantees atomicity within a single Node.js process **only**. Every verified concurrency result in this document is scoped to one process. Running multiple instances against the same JSON files would allow lost updates and could let a one-time link be consumed twice; that would require a shared transactional store (SQLite WAL, PostgreSQL, Redis locks). **No multi-process safety is claimed.**
2. **Non-Atomic Write Fallback**: Writes use `.tmp` + `rename`, which is atomic. On Windows, if `rename` fails with `EPERM`/`EBUSY` after retries, the code falls back to overwriting the target directly — that fallback is not atomic, and there is no `fsync`, so a crash at that moment could corrupt the store.
3. **Local Metadata Store Integrity**: Digests and wrapped keys live in the same unauthenticated `metadata.json` as the records. An attacker with write access to both the filesystem and that file could alter ciphertext and expected digests together. AES-GCM protects ciphertext tampering only while the wrapped key in metadata remains intact.
4. **Key and Data Co-location**: The master key (`.env`), the wrapped per-file keys (`metadata.json`) and the ciphertext (`storage/files/`) all sit in the same project folder. Encryption at rest protects the stored files; it does **not** protect against anyone who can read the whole directory.
5. **No Key Rotation**: `masterKeyId` is a fixed `'v1'`. There is no mechanism to re-wrap existing DEKs under a new master key, and no AAD binding ciphertext to its record.
6. **Malware Scanning Inactivity**: Active antivirus detection (ClamAV) is deliberately **out of scope**. See section 11.
7. **Anonymous Uploads, No File Ownership**: Uploading requires no account and records carry no owner. This is an intentional design decision carried over from the baseline. `requireAuth` exists but is applied to no route; authentication governs recipient-restricted downloads only.
8. **Recipient Restriction Is Address Matching**: A restricted link checks the logged-in account's email string against the authorized list. Email ownership is **never verified**, so anyone who holds the link and registers a listed address will pass. This is documented, not fixed.
9. **Rate Limiting Is In-Memory and Narrow**: Login limiting is 5 failures per 5 minutes keyed by IP **and** email, so many different emails from one IP are not throttled; counters reset when the process restarts. Registration records no failures and is effectively unlimited. The unauthenticated `GET` download route has no rate limit, and each request on an unlimited link triggers a full decrypt and SHA-256 pass.
10. **Cookie `Secure` Flag Is Environment-Dependent**: `Secure` is set only when `NODE_ENV=production`. Correct for http://localhost, but it must be enabled for any real deployment.
11. **Deleted Records Are Retained Indefinitely**: Records transition to `deleted` but are never purged, so filenames, recipient lists and wrapped keys persist and `metadata.json` grows without bound.
12. **Orphan Files Are Reported, Not Removed**: The startup audit reports stored files with no metadata record but deletes nothing, since an "orphan" may equally be a file whose metadata write was interrupted. Resolution is manual by design.
13. **No Penetration Testing**: No adversarial security assessment has been performed. The frontend has not been formally reviewed for XSS, and the CSP permits `'unsafe-inline'`.

---

## 10b. Repository Hygiene & Runtime Data

`data/*.json` are **runtime state**, not source code: upload metadata, account records (emails + scrypt hashes) and live session identifiers.

**Status.** `.gitignore` excludes `data/`, `storage/`, `.env`, `.env.*` (except `.env.example`), `*.key`, `*.pem`. `.env` has **never** been committed (`git log --all -- .env` is empty). The three `data/*.json` files *were* committed earlier and have since been untracked with `git rm --cached` — **staged, pending commit**. They remain on disk and the app keeps working.

**Untracking ≠ erasing history.** Their contents still exist in earlier commits. Removing them from history needs a rewrite, a force-push, and breaks every clone:

```bash
# Requires git-filter-repo. Destructive and irreversible - back up the repo first.
git filter-repo --path data/metadata.json --path data/users.json --path data/sessions.json --invert-paths
```

> [!IMPORTANT]
> This rewrite has **not** been performed. It must be a deliberate decision.

**If the remote is public**, treat the committed contents as disclosed: emails are public; passwords are salted scrypt hashes (not plaintext) but offline-crackable, so change any real reused password. Invalidate the committed session IDs by clearing `data/sessions.json` (this logs everyone out, so it was not done automatically). Then either rewrite history or make the repository private. For submission, the simplest path is to keep the files untracked and ship empty `[]` stores.

---

## 11. Malware Scanning: Explicit Scope Exclusion

> **Active ClamAV scanning was excluded from the project scope. The implementation does not establish that uploaded files are malware-free.**

A deliberate scope decision, not an unfinished feature. Precisely:

- No scanner is ever invoked. `malwareScanner.js:scanFile()` only returns `not_scanned`, and although `routes/upload.js` imports it, the sole reference is inside a comment block.
- Every upload is recorded `scanStatus: 'not_scanned'`.
- `accessService.js:canDownload()` rejects only `'infected'`; the stricter `!== 'clean'` rule is **commented out**, so `not_scanned` files download normally. Test 39 marks a record `infected` by hand and confirms a 403 — that exercises the gate, not a scanner.
- `storage/quarantine/` is created but unused. No ClamAV/`clamd`/`clamdjs` dependency exists.

What *is* verified cryptographically is that a download is byte-for-byte identical to the upload (SHA-256 + AES-GCM). **File integrity is not file safety:** a malicious file would be stored, verified and delivered intact like any other.

### Future ClamAV Integration Blueprint
Prepared hook points, if scanning were added later:

1. **`malwareScanner.js`** — connect to `clamd` (TCP `127.0.0.1:3310` or UNIX socket), stream via `INSTREAM`, parse `clean` vs `infected`.
2. **`routes/upload.js`** — scan the temp file before encryption; on `INFECTED`, delete it and return 400. The hook comment marks the spot.
3. **`accessService.js`** — enable the strict check: `if (record.scanStatus !== SCAN_STATUS.CLEAN) return { allowed: false };`
