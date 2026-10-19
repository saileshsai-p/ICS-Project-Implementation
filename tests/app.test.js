import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { app, startServer } from '../server.js';
import { getAllFiles, updateFileRecord } from '../services/metadataService.js';
import { getSafeFilePath, cleanupFile } from '../services/fileService.js';
import { SCAN_STATUS } from '../services/malwareScanner.js';
import crypto from 'node:crypto';
import { registerV2Tests } from './v2.test.js';
import { registerAuthTests } from './auth_authorization.test.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configure test master encryption key (32 bytes)
process.env.FILE_ENCRYPTION_MASTER_KEY =
  process.env.FILE_ENCRYPTION_MASTER_KEY || crypto.randomBytes(32).toString('hex');

let server;
let baseUrl;

test.before(async () => {
  // Start the server on an ephemeral free port (port 0)
  server = await startServer(0);
  const port = server.address().port;
  baseUrl = `http://127.0.0.1:${port}`;
});

test.after(async () => {
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('Suite: Secure File Sharing Baseline Implementation', async (t) => {

  let noPasswordToken = null;
  let passwordProtectedToken = null;
  let sampleContent = 'Antigravity secure file sharing test content payload 1234567890';

  // Scenario 1: Upload a valid file
  await t.test('1. Upload a valid file', async () => {
    const formData = new FormData();
    const blob = new Blob([sampleContent], { type: 'text/plain' });
    formData.append('file', blob, 'sample_test.txt');
    formData.append('expiry', '24h');

    const res = await fetch(`${baseUrl}/api/files`, {
      method: 'POST',
      body: formData
    });

    assert.equal(res.status, 201, 'Should return 201 Created');
    const data = await res.json();
    assert.equal(data.success, true);
    assert.ok(data.file.shareToken, 'Must generate shareToken');
    assert.equal(data.file.originalName, 'sample_test.txt');
    assert.equal(data.file.hasPassword, false);
    assert.equal(data.file.scanStatus, SCAN_STATUS.NOT_SCANNED);

    noPasswordToken = data.file.shareToken;
  });

  // Scenario 2: Reject a missing file
  await t.test('2. Reject a missing file', async () => {
    const formData = new FormData();
    formData.append('expiry', '24h');

    const res = await fetch(`${baseUrl}/api/files`, {
      method: 'POST',
      body: formData
    });

    assert.equal(res.status, 400, 'Should return 400 Bad Request');
    const data = await res.json();
    assert.ok(data.error.includes('No file uploaded'));
  });

  // Scenario 3: Reject a file that exceeds the configured size limit
  await t.test('3. Reject a file that exceeds the configured size limit (50MB)', async () => {
    // Generate a payload slightly larger than 50MB (50 * 1024 * 1024 + 1024 bytes)
    // To be fast and efficient in memory, create a sparse or repeated blob
    const oversizeBytes = 50 * 1024 * 1024 + 1024;
    const chunk = new Uint8Array(1024 * 1024); // 1MB chunk
    const chunks = [];
    for (let i = 0; i < 51; i++) {
      chunks.push(chunk);
    }
    const oversizeBlob = new Blob(chunks, { type: 'application/octet-stream' });

    const formData = new FormData();
    formData.append('file', oversizeBlob, 'huge_file.bin');

    const res = await fetch(`${baseUrl}/api/files`, {
      method: 'POST',
      body: formData
    });

    assert.equal(res.status, 413, 'Should return 413 Payload Too Large');
    const data = await res.json();
    assert.ok(data.error.includes('exceeds the maximum permitted limit'));
  });

  // Scenario 4: Upload a file without a password
  await t.test('4. Upload a file without a password', async () => {
    const formData = new FormData();
    const blob = new Blob(['No password file contents'], { type: 'text/plain' });
    formData.append('file', blob, 'public_doc.txt');
    formData.append('expiry', '1h');

    const res = await fetch(`${baseUrl}/api/files`, {
      method: 'POST',
      body: formData
    });

    assert.equal(res.status, 201);
    const data = await res.json();
    assert.equal(data.file.hasPassword, false);

    // Verify metadata record directly
    const all = await getAllFiles();
    const record = all.find((r) => r.shareToken === data.file.shareToken);
    assert.ok(record);
    assert.equal(record.passwordHash, null);
    assert.equal(record.passwordSalt, null);
  });

  // Scenario 5: Upload a file with a password
  await t.test('5. Upload a file with a password', async () => {
    const formData = new FormData();
    const blob = new Blob(['Top secret confidential content'], { type: 'text/plain' });
    formData.append('file', blob, 'confidential.txt');
    formData.append('password', 'SuperSecret123!');
    formData.append('expiry', '6h');

    const res = await fetch(`${baseUrl}/api/files`, {
      method: 'POST',
      body: formData
    });

    assert.equal(res.status, 201);
    const data = await res.json();
    assert.equal(data.file.hasPassword, true);
    assert.ok(!data.file.passwordHash, 'Response must NEVER leak passwordHash');
    assert.ok(!data.file.passwordSalt, 'Response must NEVER leak passwordSalt');

    passwordProtectedToken = data.file.shareToken;

    // Verify metadata record has salted hash and no plaintext password
    const all = await getAllFiles();
    const record = all.find((r) => r.shareToken === passwordProtectedToken);
    assert.ok(record.passwordHash && typeof record.passwordHash === 'string');
    assert.ok(record.passwordSalt && typeof record.passwordSalt === 'string');
    assert.ok(!JSON.stringify(record).includes('SuperSecret123!'), 'Plaintext password must never be stored');
  });

  // Scenario 6: Download with the correct password
  await t.test('6. Download with the correct password', async () => {
    assert.ok(passwordProtectedToken);

    const res = await fetch(`${baseUrl}/api/files/${passwordProtectedToken}/download`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'SuperSecret123!' })
    });

    assert.equal(res.status, 200, 'Should allow download with correct password');
    const downloadedText = await res.text();
    assert.equal(downloadedText, 'Top secret confidential content');
  });

  // Scenario 7: Reject an incorrect password
  await t.test('7. Reject an incorrect password', async () => {
    assert.ok(passwordProtectedToken);

    const res = await fetch(`${baseUrl}/api/files/${passwordProtectedToken}/download`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'WrongPasswordGuess!' })
    });

    assert.equal(res.status, 401, 'Should return 401 Unauthorized for incorrect password');
    const data = await res.json();
    assert.equal(data.error, 'Incorrect password.');
  });

  // Scenario 8: Reject an expired link
  await t.test('8. Reject an expired link', async () => {
    // Create an expired file by setting expiresAt to the past
    const formData = new FormData();
    const blob = new Blob(['Expired link contents'], { type: 'text/plain' });
    formData.append('file', blob, 'expired_test.txt');

    const uploadRes = await fetch(`${baseUrl}/api/files`, {
      method: 'POST',
      body: formData
    });
    const uploadData = await uploadRes.json();
    const expiredToken = uploadData.file.shareToken;

    // Manually mutate metadata record to have an expired timestamp (1 hour ago)
    const all = await getAllFiles();
    const rec = all.find((r) => r.shareToken === expiredToken);
    await updateFileRecord(rec.id, {
      expiresAt: new Date(Date.now() - 3600000).toISOString()
    });

    // Check metadata endpoint
    const metaRes = await fetch(`${baseUrl}/api/files/${expiredToken}`);
    assert.equal(metaRes.status, 410, 'Metadata route should return 410 Gone for expired link');

    // Attempt download
    const dlRes = await fetch(`${baseUrl}/api/files/${expiredToken}/download`);
    assert.equal(dlRes.status, 410, 'Download route should return 410 Gone for expired link');
    const dlData = await dlRes.json();
    assert.ok(dlData.error.includes('expired'));
  });

  // Scenario 9: Reject an invalid or nonexistent token
  await t.test('9. Reject an invalid or nonexistent token', async () => {
    const invalidToken = 'nonexistent-token-1234567890';

    const metaRes = await fetch(`${baseUrl}/api/files/${invalidToken}`);
    assert.equal(metaRes.status, 404, 'Should return 404 for invalid token');

    const dlRes = await fetch(`${baseUrl}/api/files/${invalidToken}/download`);
    assert.equal(dlRes.status, 404, 'Should return 404 for invalid token download');
  });

  // Scenario 10: Reject a request for a missing stored file
  await t.test('10. Reject a request for a missing stored file', async () => {
    const formData = new FormData();
    const blob = new Blob(['File will be deleted from disk'], { type: 'text/plain' });
    formData.append('file', blob, 'missing_disk.txt');

    const uploadRes = await fetch(`${baseUrl}/api/files`, {
      method: 'POST',
      body: formData
    });
    const uploadData = await uploadRes.json();
    const token = uploadData.file.shareToken;

    // Delete the file from the private storage directory
    const all = await getAllFiles();
    const rec = all.find((r) => r.shareToken === token);
    const diskPath = getSafeFilePath(rec.storedName);
    await cleanupFile(diskPath);

    // Attempt download
    const dlRes = await fetch(`${baseUrl}/api/files/${token}/download`);
    assert.equal(dlRes.status, 404, 'Should return 404 when file is missing from disk');
    const dlData = await dlRes.json();
    assert.ok(dlData.error.includes('could not be found in storage'));
  });

  // Scenario 11: Confirm that uploaded files cannot be accessed through public static URLs
  await t.test('11. Confirm that uploaded files cannot be accessed through public static URLs', async () => {
    assert.ok(noPasswordToken);
    const all = await getAllFiles();
    const rec = all.find((r) => r.shareToken === noPasswordToken);

    // Attempt to access /storage/files/<filename>
    const directRes1 = await fetch(`${baseUrl}/storage/files/${rec.storedName}`);
    assert.equal(directRes1.status, 404, 'Direct access to /storage/files/ must be 404');

    // Attempt to access /files/<filename>
    const directRes2 = await fetch(`${baseUrl}/files/${rec.storedName}`);
    assert.equal(directRes2.status, 404, 'Direct access to /files/ must be 404');
  });

  // Scenario 12: Confirm that metadata persists across application restarts
  await t.test('12. Confirm that metadata persists across application restarts', async () => {
    // Read from disk fresh
    const beforeRecords = await getAllFiles();
    assert.ok(beforeRecords.length > 0, 'Metadata store should have records');

    // Simulate restart by inspecting the raw data/metadata.json file on disk
    const dataDir = path.resolve(__dirname, '../data/metadata.json');
    const rawData = await fs.readFile(dataDir, 'utf-8');
    const parsed = JSON.parse(rawData);

    assert.equal(parsed.length, beforeRecords.length, 'Stored records match memory records on disk');
    const sample = parsed.find((r) => r.shareToken === noPasswordToken);
    assert.ok(sample, 'Saved share token must persist in metadata.json file');
  });

  // Scenario 13: Confirm that files are marked not_scanned in this version
  await t.test('13. Confirm that files are marked not_scanned in this version', async () => {
    const metaRes = await fetch(`${baseUrl}/api/files/${noPasswordToken}`);
    const metaData = await metaRes.json();

    assert.equal(metaData.scanStatus, 'not_scanned', 'Public metadata must report scanStatus as not_scanned');

    const all = await getAllFiles();
    const record = all.find((r) => r.shareToken === noPasswordToken);
    assert.equal(record.scanStatus, 'not_scanned', 'Record scanStatus must be not_scanned');
  });

  // Scenario 14: Confirm that no file is incorrectly reported as malware-free
  await t.test('14. Confirm that no file is incorrectly reported as malware-free', async () => {
    const all = await getAllFiles();
    for (const file of all) {
      assert.notEqual(file.scanStatus, 'clean', 'No file must be reported as clean');
      assert.notEqual(file.scanStatus, 'verified', 'No file must be reported as verified');
    }
  });

  // Scenario 15: Flexible expiry allows 1 minute expiration
  await t.test('15. Flexible expiry allows 1 minute expiration', async () => {
    const formData = new FormData();
    const blob = new Blob(['One minute test'], { type: 'text/plain' });
    formData.append('file', blob, 'one_min.txt');
    formData.append('expiry', '1m');

    const before = Date.now();
    const res = await fetch(`${baseUrl}/api/files`, {
      method: 'POST',
      body: formData
    });
    assert.equal(res.status, 201);
    const data = await res.json();
    const expiryMs = new Date(data.file.expiresAt).getTime();
    const diffSeconds = Math.round((expiryMs - before) / 1000);
    // Should be approximately 60 seconds (allow small margin: 55s to 65s)
    assert.ok(diffSeconds >= 55 && diffSeconds <= 65, `Expiry should be ~60s, got ${diffSeconds}s`);
  });

  // Scenario 16: Flexible expiry allows any number of days
  await t.test('16. Flexible expiry allows custom number of days (e.g. 14 days)', async () => {
    const formData = new FormData();
    const blob = new Blob(['Fourteen days test'], { type: 'text/plain' });
    formData.append('file', blob, 'two_weeks.txt');
    formData.append('expiryValue', '14');
    formData.append('expiryUnit', 'days');

    const before = Date.now();
    const res = await fetch(`${baseUrl}/api/files`, {
      method: 'POST',
      body: formData
    });
    assert.equal(res.status, 201);
    const data = await res.json();
    const expiryMs = new Date(data.file.expiresAt).getTime();
    const diffDays = Math.round((expiryMs - before) / (24 * 60 * 60 * 1000));
    assert.equal(diffDays, 14, `Expiry should be 14 days, got ${diffDays}`);
  });

});

// Register Version 2 security enhancement tests
registerV2Tests(() => baseUrl);

// Register User Authentication and Recipient Authorization tests
registerAuthTests(() => baseUrl);
