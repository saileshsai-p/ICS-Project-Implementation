# SecuShare — Secure File Sharing Web Application (Baseline)

A lightweight, secure, locally runnable file-sharing web application based on the research paper:

> **"Design and Implementation of a Secure File Sharing Web Application with Expiry and Malware Detection"**  
> *International Journal of Research Publication and Reviews (IJRPR)*  
> [Reference PDF](https://ijrpr.com/uploads/V6ISSUE5/IJRPR46303.pdf)

---

## 1. Project Overview

SecuShare enables a sender to upload a file on a local workstation, optionally protect it with a password, select a sharing link expiration window (1 hour, 6 hours, 24 hours, or 7 days), and generate a cryptographically unguessable sharing URL. A recipient can open that link and download the file **only** if the link has not expired and the required password (if any) is correctly verified by the server.

### Design Principles for this Baseline Implementation
- **Zero Cloud & Zero Subscriptions**: 100% self-contained on the local machine.
- **Ultra-Lean Dependencies**: Only **`express`** and **`multer`**.
- **No Third-Party Frameworks**: Built using standard ES modules, Node.js built-ins (`crypto`, `fs/promises`), semantic HTML5, modern CSS3, and vanilla JavaScript.
- **Single Access Gate**: All download attempts must pass through a centralized backend security check. Files are stored in private storage and are never exposed via static URLs.
- **ClamAV-Ready Modular Architecture**: The baseline implementation excludes active antivirus scanning, but includes the interface, lifecycle states, storage folders, and hook points to integrate ClamAV in the next development phase with minimal changes.

---

## 2. Technology Stack

| Layer | Technology | Details |
|---|---|---|
| **Backend Runtime** | Node.js (v24.x / 18.11+) | ES Modules (`"type": "module"`) |
| **Web Server** | Express.js | Lightweight HTTP routing & static asset delivery |
| **File Uploads** | Multer | Streaming multipart uploads to temporary holding directory |
| **File Storage** | Local File System | Isolated private directory (`storage/files/`) |
| **Metadata Store** | Local JSON File | Atomic writes (`.tmp` + rename) with serialized task queue |
| **Tokens & Hashes** | Node.js `crypto` | 256-bit URL-safe tokens, `crypto.scrypt` with random 16-byte salt, `timingSafeEqual` |
| **Security Headers** | Custom Middleware | CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, etc. |
| **Brute-Force Protection**| In-memory sliding limiter | Blocks rapid password guesses (max 5 failed attempts per 5 minutes) |
| **Frontend** | HTML5, CSS3, Vanilla JS | Cybersecurity dark aesthetic, drag & drop, no external CDN dependencies |
| **Testing** | Node built-in `node:test` | Automated runner with native `fetch` across 14 test scenarios |

---

## 3. Architecture & Code Organization

```
ICS_PROJECT/
├── package.json               # Dependency manifest & npm scripts
├── server.js                  # Application entry point, server setup & lifecycle initialization
├── routes/
│   ├── upload.js              # POST /api/files (file processing, password hashing, token generation)
│   ├── download.js            # GET /api/files/:token, GET & POST /api/files/:token/download
│   └── pages.js               # Serves HTML frontend pages (/, /share/:token)
├── middleware/
│   ├── securityHeaders.js     # Applies OWASP security headers
│   ├── rateLimiter.js         # In-memory sliding-window limiter for password attempts
│   ├── uploadValidation.js    # Multer configuration & file size enforcement (50 MB)
│   └── errorHandler.js        # Safe global error handler (no path or stack leakage)
├── services/
│   ├── fileService.js         # Safe server-side filenames, directory isolation, cleanup
│   ├── metadataService.js     # Atomic JSON updates, serialized write queue, query helpers
│   ├── passwordService.js     # scrypt password hashing & timing-safe verification
│   ├── accessService.js       # Central authorization gate (expiry, password, file status)
│   └── malwareScanner.js      # ClamAV-ready stub interface (explicit 'not_scanned' status)
├── public/
│   ├── index.html             # Page A (Upload) and Page B (Share Result)
│   ├── download.html          # Page C (Recipient Download Page)
│   ├── css/
│   │   └── style.css          # Modern cybersecurity dark theme (navy/slate/cyan, responsive)
│   └── js/
│       ├── upload.js          # Drag & drop, progress bar, form submission, clipboard copy
│       └── download.js        # File metadata verification, password submission, blob download
├── storage/
│   ├── files/                 # Private permanent file storage
│   ├── quarantine/            # ClamAV quarantine directory (reserved for future phase)
│   └── temp/                  # Multer temporary holding directory
├── data/
│   └── metadata.json          # Persistent JSON metadata registry
├── tests/
│   └── app.test.js            # Automated test suite covering 14 security scenarios
├── .gitignore
└── README.md
```

---

## 4. Security Implementation Details

1. **Unguessable Identifiers**:
   - Each upload generates a 256-bit URL-safe share token (`crypto.randomBytes(32).toString('base64url')`).
   - The file is saved on disk with a UUID filename (`crypto.randomUUID() + ext`). The user-provided original filename is stored in metadata only.
2. **Password Security**:
   - Passwords are encrypted using Node's native `crypto.scrypt` with a unique 16-byte random salt per file.
   - Verification uses `crypto.timingSafeEqual` to eliminate timing side-channel attacks.
   - Passwords are submitted in the POST request body—**never in URLs or query strings**.
3. **Single Centralized Access Enforcement**:
   - `accessService.js:canDownload(record, providedPassword)` is the single gatekeeper. It checks:
     - File existence in metadata
     - Lifecycle status (`'active'`)
     - Timestamp expiration (`Date.now() <= expiresAt`)
     - Scanner status (rejects `'infected'`)
     - Disk file presence
     - Password validity
4. **Storage Isolation**:
   - Uploaded files are stored in `storage/files/`, completely separate from `public/`.
   - Direct HTTP access to `/storage/...` returns `404 Not Found`.
5. **Atomic Data Persistence**:
   - `metadataService.js` serializes all disk reads/writes using an asynchronous queue to prevent race conditions. Writes go to a temporary file (`metadata.tmp.json`) and are atomically renamed to `metadata.json`.

---

## 5. Prerequisites & Installation

### Prerequisites
- **Node.js** v18.11 or newer (tested and verified on **Node.js v24.14.1**).
- No database installation required.

### Installation
Open a terminal in the project directory:

```bash
# If using Windows PowerShell and script execution is restricted, run:
npm.cmd install

# Or standard npm:
npm install
```

---

## 6. Running the Application

### Development Mode (with automatic reload on file changes)
Uses Node's built-in `--watch` flag:
```bash
npm run dev
```

### Production / Standard Mode
```bash
npm start
```

### Accessing the Website
Once started, open your web browser to:
```
http://localhost:3000
```

### Configuration Options
You can configure the server via standard environment variables:
- `PORT`: Server port (default: `3000`)
- `MAX_FILE_SIZE_BYTES`: Maximum upload size in bytes (default: `52428800` = 50 MB)

Example in PowerShell:
```powershell
$env:PORT=4000; node server.js
```

---

## 7. How to Use the Application

### Step 1: Upload a File
1. Navigate to `http://localhost:3000`.
2. Drag and drop any file up to 50 MB onto the drop zone, or click **Browse Files**.
3. *(Optional)* Enter a download password. Click the eye icon to preview it.
4. Select the link expiration duration: Choose from quick presets (**1 Minute**, **5 Minutes**, **15 Minutes**, **1 Hour**, **6 Hours**, **24 Hours**, **7 Days**, **30 Days**) or select **Custom Duration** to specify any number of **Minutes**, **Hours**, or **Days**. A live preview displays the exact target expiration date and time.
5. Click **Upload and Generate Link**. A progress bar will reflect the upload.

### Step 2: Share the Link
1. Once uploaded, the **File Ready to Share** screen appears.
2. Click **Copy Link** to copy the generated URL (e.g. `http://localhost:3000/share/vV4-v9...`).
3. You will see summary metadata: original filename, formatted size, expiration date/time, and password status.
4. You can click **Open Download Page** to test the recipient view immediately.

### Step 3: Recipient Download
1. Open the copied URL in your browser (or an incognito window).
2. The page fetches file metadata:
   - If the link has **expired**, it displays a clear **"Link Expired"** alert.
   - If the link is **invalid**, it displays a **"File Not Found"** alert.
   - If **password protected**, the recipient must enter the password.
3. Click **Download File**. The file streams directly to the browser with its original filename preserved.

---

## 8. Automated Testing

The project includes an automated test suite executed with Node's native test runner (`node:test`) and native `fetch` across an ephemeral port.

### Run Tests
```bash
npm test
```
Or directly:
```bash
node --test tests/app.test.js
```

### Verified Test Scenarios

All 14 required research paper scenarios have been executed and verified:

| # | Test Scenario | Verified Outcome |
|---|---|---|
| 1 | Upload a valid file | Returns 201 Created with share token and public metadata |
| 2 | Reject a missing file | Returns 400 Bad Request with descriptive message |
| 3 | Reject a file exceeding size limit (50MB) | Returns 413 Payload Too Large |
| 4 | Upload a file without a password | Stored with null password hash/salt; direct access allowed |
| 5 | Upload a file with a password | Stored with salted scrypt hash; hash never returned to client |
| 6 | Download with the correct password | Returns 200 OK and matching binary file content |
| 7 | Reject an incorrect password | Returns 401 Unauthorized with generic "Incorrect password." |
| 8 | Reject an expired link | Returns 410 Gone on both metadata and download routes |
| 9 | Reject an invalid or nonexistent token | Returns 404 Not Found |
| 10 | Reject a request for a missing stored file | Returns 404 when physical file is missing from disk |
| 11 | Block direct static URL access | Access to `/storage/files/...` returns 404 Not Found |
| 12 | Verify metadata disk persistence | Metadata survives across application restarts |
| 13 | Confirm files are marked `not_scanned` | Returns `scanStatus: "not_scanned"` |
| 14 | Confirm no file is reported as malware-free | No file is falsely reported as `"clean"` or `"verified"` |
| 15 | Flexible expiry allows 1 minute expiration | Returns 201 Created with ~60s expiry window |
| 16 | Flexible expiry allows custom days | Returns 201 Created with custom days (e.g. 14 days) |

---

## 9. Future ClamAV Integration Blueprint

In this baseline phase, antivirus scanning is **deliberately excluded**. The application displays an honest `"Unscanned (Baseline)"` badge and never reports files as malware-free.

The architecture is prepared for ClamAV integration in the next project phase:

### 1. `services/malwareScanner.js`
- Currently returns `{ status: 'not_scanned' }`.
- When ClamAV is added, replace the body of `scanFile(filePath)` to connect to the ClamAV daemon (`clamd` via TCP port 3310 or UNIX domain socket) or invoke `clamscan`:
  ```javascript
  // Future phase ClamAV implementation:
  export async function scanFile(filePath) {
    const result = await clamdClient.scanFile(filePath);
    if (result.isInfected) {
      return { status: 'infected', viruses: result.viruses };
    }
    return { status: 'clean' };
  }
  ```

### 2. `routes/upload.js`
- Step 4 of the upload route contains a marked hook (`[FUTURE CLAMAV INTEGRATION HOOK]`).
- The temporary file in `storage/temp/` can be scanned before moving to `storage/files/`. If infected, it can be quarantined in `storage/quarantine/` or immediately unlinked.

### 3. `services/accessService.js`
- The centralized `canDownload()` function already checks for `record.scanStatus === SCAN_STATUS.INFECTED`.
- In the next phase, enforce that `record.scanStatus === SCAN_STATUS.CLEAN` before allowing downloads.

---

## 10. Current Limitations & Assumptions

1. **Single-Node Storage**: Designed for local execution on a single computer using the local filesystem.
2. **In-Memory Rate Limiting**: The brute-force password limiter resides in memory; it resets when the server process terminates.
3. **Automatic File Purging**: Expired files remain on disk with download access blocked by the backend; automatic cron deletion will be introduced in subsequent phases.
4. **No User Accounts**: Anonymous upload and recipient workflow, as specified by the baseline paper.
