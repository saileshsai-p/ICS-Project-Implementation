import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import crypto from 'node:crypto';

import { updateFileRecord, getFileByToken, addFileRecord } from '../services/metadataService.js';
import { getSafeFilePath, fileExists, TEMP_DIR } from '../services/fileService.js';
import { verifySha256Digest } from '../services/fileIntegrityService.js';
import { wrapDek, unwrapDek } from '../services/encryptionService.js';
import { runCleanupCycle } from '../services/cleanupService.js';
import { acquireDownloadLease, hasActiveDownloads } from '../services/operationCoordinator.js';
import { migrateLegacyRecord } from '../services/migrationService.js';
import { FILE_STATUS } from '../services/accessService.js';

export function registerV2Tests(urlOrGetter) {
  test('Suite: SecuShare Version 2 Security Enhancements', async (suite) => {
    const baseUrl = typeof urlOrGetter === 'function' ? urlOrGetter() : urlOrGetter;

    await suite.test('Feature A: Download limits and atomic consumption', async (t) => {

      await t.test('A1. One-time download allows 1st attempt and rejects 2nd attempt', async () => {
        const formData = new FormData();
        const content = 'One-time link secret payload ' + crypto.randomUUID();
        formData.append('file', new Blob([content], { type: 'text/plain' }), 'onetime.txt');
        formData.append('downloadPolicy', 'one_time');

        const uploadRes = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: formData });
        assert.equal(uploadRes.status, 201);
        const uploadData = await uploadRes.json();
        const token = uploadData.file.shareToken;
        assert.equal(uploadData.file.downloadPolicy, 'one_time');
        assert.equal(uploadData.file.downloadLimit, 1);

        // 1st download attempt: must succeed
        const dl1 = await fetch(`${baseUrl}/api/files/${token}/download`);
        assert.equal(dl1.status, 200);
        const text1 = await dl1.text();
        assert.equal(text1, content);

        // 2nd download attempt: must be rejected with 410 Gone
        const dl2 = await fetch(`${baseUrl}/api/files/${token}/download`);
        assert.equal(dl2.status, 410);
        const dl2Data = await dl2.json();
        assert.ok(dl2Data.error.includes('download limit'));

        // Metadata endpoint should also report limit exhausted
        const metaRes = await fetch(`${baseUrl}/api/files/${token}`);
        assert.equal(metaRes.status, 410);
        const metaData = await metaRes.json();
        assert.equal(metaData.limitExhausted, true);
      });

      await t.test('A2. Configurable download limit allows exact number of downloads', async () => {
        const formData = new FormData();
        const content = 'Three downloads allowance ' + crypto.randomUUID();
        formData.append('file', new Blob([content], { type: 'text/plain' }), 'triple.txt');
        formData.append('downloadPolicy', 'limited');
        formData.append('downloadLimit', '3');

        const uploadRes = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: formData });
        assert.equal(uploadRes.status, 201);
        const uploadData = await uploadRes.json();
        const token = uploadData.file.shareToken;
        assert.equal(uploadData.file.downloadLimit, 3);

        // Attempt 1 -> 200
        const dl1 = await fetch(`${baseUrl}/api/files/${token}/download`);
        assert.equal(dl1.status, 200);

        // Attempt 2 -> 200
        const dl2 = await fetch(`${baseUrl}/api/files/${token}/download`);
        assert.equal(dl2.status, 200);

        // Attempt 3 -> 200
        const dl3 = await fetch(`${baseUrl}/api/files/${token}/download`);
        assert.equal(dl3.status, 200);

        // Attempt 4 -> 410 (Limit exhausted)
        const dl4 = await fetch(`${baseUrl}/api/files/${token}/download`);
        assert.equal(dl4.status, 410);
      });

      await t.test('A3. Incorrect password does not consume download allowance', async () => {
        const formData = new FormData();
        const content = 'Protected one-time file';
        formData.append('file', new Blob([content], { type: 'text/plain' }), 'protected_onetime.txt');
        formData.append('password', 'SecretPass999!');
        formData.append('downloadPolicy', 'one_time');

        const uploadRes = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: formData });
        const uploadData = await uploadRes.json();
        const token = uploadData.file.shareToken;

        // Try with wrong password
        const wrongRes = await fetch(`${baseUrl}/api/files/${token}/download`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: 'WrongPassword' })
        });
        assert.equal(wrongRes.status, 401);

        // Verify count in metadata is still 0
        const record = await getFileByToken(token);
        assert.equal(record.downloadCount, 0);

        // Now download with correct password -> must succeed
        const correctRes = await fetch(`${baseUrl}/api/files/${token}/download`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: 'SecretPass999!' })
        });
        assert.equal(correctRes.status, 200);
        const downloaded = await correctRes.text();
        assert.equal(downloaded, content);

        // Now allowance must be 1, so another attempt fails
        const followUpRes = await fetch(`${baseUrl}/api/files/${token}/download`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: 'SecretPass999!' })
        });
        assert.equal(followUpRes.status, 410);
      });

      await t.test('A4. Concurrent requests on a one-time link allow strictly 1 download', async () => {
        const formData = new FormData();
        const content = 'Concurrent race condition test ' + crypto.randomUUID();
        formData.append('file', new Blob([content], { type: 'text/plain' }), 'race.txt');
        formData.append('downloadPolicy', 'one_time');

        const uploadRes = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: formData });
        const uploadData = await uploadRes.json();
        const token = uploadData.file.shareToken;

        // Launch 6 simultaneous requests
        const requests = Array.from({ length: 6 }, () =>
          fetch(`${baseUrl}/api/files/${token}/download`)
        );

        const responses = await Promise.all(requests);
        const statusCodes = responses.map((r) => r.status);

        const successCount = statusCodes.filter((s) => s === 200).length;
        const rejectedCount = statusCodes.filter((s) => s === 410).length;

        assert.equal(successCount, 1, `Exactly 1 concurrent request must succeed (got ${successCount})`);
        assert.equal(rejectedCount, 5, `Remaining 5 concurrent requests must be rejected 410`);

        const record = await getFileByToken(token);
        assert.equal(record.downloadCount, 1);
      });

      await t.test('A5. Download limit and count persist in metadata storage', async () => {
        const formData = new FormData();
        formData.append('file', new Blob(['Persistence test'], { type: 'text/plain' }), 'persist.txt');
        formData.append('downloadPolicy', 'limited');
        formData.append('downloadLimit', '5');

        const uploadRes = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: formData });
        const uploadData = await uploadRes.json();
        const token = uploadData.file.shareToken;

        // Consume 2 allowances
        await fetch(`${baseUrl}/api/files/${token}/download`);
        await fetch(`${baseUrl}/api/files/${token}/download`);

        // Check metadata record
        const record = await getFileByToken(token);
        assert.equal(record.downloadPolicy, 'limited');
        assert.equal(record.downloadLimit, 5);
        assert.equal(record.downloadCount, 2);
      });
    });

    await suite.test('Feature B: AES-256-GCM encryption at rest', async (t) => {

      await t.test('B1. Permanent stored file is encrypted ciphertext (differs from plaintext)', async () => {
        const plaintextContent = 'Sensitive confidential plaintext that must NEVER appear unencrypted on disk';
        const formData = new FormData();
        formData.append('file', new Blob([plaintextContent], { type: 'text/plain' }), 'secret_doc.txt');

        const uploadRes = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: formData });
        const uploadData = await uploadRes.json();
        const token = uploadData.file.shareToken;

        const record = await getFileByToken(token);
        assert.ok(record.encryption);
        assert.equal(record.encryption.enabled, true);
        assert.equal(record.encryption.algorithm, 'aes-256-gcm');
        assert.ok(record.encryption.wrappedDek);
        assert.ok(record.encryption.contentNonce);
        assert.ok(record.encryption.contentTag);

        // Read physical file from storage/files/
        const diskPath = getSafeFilePath(record.storedName);
        const storedBytes = await fs.readFile(diskPath);
        const storedString = storedBytes.toString('utf-8');

        // Confirm stored ciphertext does NOT contain the plaintext string
        assert.ok(!storedString.includes('Sensitive confidential plaintext'), 'Stored file must NOT contain plaintext');
        assert.notEqual(storedString, plaintextContent);

        // Download returns the exact original plaintext
        const dlRes = await fetch(`${baseUrl}/api/files/${token}/download`);
        assert.equal(dlRes.status, 200);
        const recoveredText = await dlRes.text();
        assert.equal(recoveredText, plaintextContent);
      });

      await t.test('B2. Binary files (random bytes) are preserved with byte-for-byte fidelity', async () => {
        const randomBytes = crypto.randomBytes(32 * 1024); // 32 KB random binary
        const formData = new FormData();
        formData.append('file', new Blob([randomBytes], { type: 'application/octet-stream' }), 'data.bin');

        const uploadRes = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: formData });
        const uploadData = await uploadRes.json();
        const token = uploadData.file.shareToken;

        const dlRes = await fetch(`${baseUrl}/api/files/${token}/download`);
        assert.equal(dlRes.status, 200);
        const arrayBuf = await dlRes.arrayBuffer();
        const downloadedBytes = Buffer.from(arrayBuf);

        assert.equal(downloadedBytes.length, randomBytes.length);
        assert.equal(Buffer.compare(downloadedBytes, randomBytes), 0, 'Binary content must match byte-for-byte');
      });

      await t.test('B3. Tampered ciphertext causes GCM authentication failure', async () => {
        const formData = new FormData();
        formData.append('file', new Blob(['Content to tamper with'], { type: 'text/plain' }), 'tamper_cipher.txt');

        const uploadRes = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: formData });
        const uploadData = await uploadRes.json();
        const token = uploadData.file.shareToken;

        const record = await getFileByToken(token);
        const diskPath = getSafeFilePath(record.storedName);

        // Read stored ciphertext and flip bytes
        const originalBytes = await fs.readFile(diskPath);
        const tamperedBytes = Buffer.from(originalBytes);
        tamperedBytes[0] ^= 0xff; // Flip bits
        await fs.writeFile(diskPath, tamperedBytes);

        // Attempt download -> GCM authentication must fail, 500 returned
        const dlRes = await fetch(`${baseUrl}/api/files/${token}/download`);
        assert.equal(dlRes.status, 500);
        const dlData = await dlRes.json();
        assert.ok(dlData.error);
        assert.ok(!JSON.stringify(dlData).includes('Content to tamper'));
      });

      await t.test('B4. Tampered wrapped DEK metadata is rejected', async () => {
        const formData = new FormData();
        formData.append('file', new Blob(['DEK tamper test'], { type: 'text/plain' }), 'tamper_dek.txt');

        const uploadRes = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: formData });
        const uploadData = await uploadRes.json();
        const token = uploadData.file.shareToken;

        const record = await getFileByToken(token);
        // Tamper wrapped DEK in metadata by flipping bits
        const dekBuf = Buffer.from(record.encryption.wrappedDek, 'hex');
        dekBuf[0] ^= 0xff;
        const tamperedWrappedDek = dekBuf.toString('hex');
        await updateFileRecord(record.id, {
          encryption: {
            ...record.encryption,
            wrappedDek: tamperedWrappedDek
          }
        });

        // Attempt download -> unwrap fails, 500 returned
        const dlRes = await fetch(`${baseUrl}/api/files/${token}/download`);
        assert.equal(dlRes.status, 500);
      });

      await t.test('B5. Wrong master key fails safely without exposing data', () => {
        const dek = crypto.randomBytes(32);
        const masterKey1 = crypto.randomBytes(32);
        const masterKey2 = crypto.randomBytes(32);

        const wrapped = wrapDek(dek, masterKey1);

        // Unwrapping with a different master key must throw authentication error
        assert.throws(() => {
          unwrapDek(wrapped.wrappedDekHex, wrapped.dekWrappingNonceHex, wrapped.dekWrappingTagHex, masterKey2);
        }, /Master key verification failed|Unsupported state/i);
      });

      await t.test('B6. Temporary plaintext file in temp/ is removed after download', async () => {
        const formData = new FormData();
        formData.append('file', new Blob(['Temp cleanup check'], { type: 'text/plain' }), 'temp_clean.txt');

        const uploadRes = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: formData });
        const uploadData = await uploadRes.json();
        const token = uploadData.file.shareToken;

        // Perform download
        const dlRes = await fetch(`${baseUrl}/api/files/${token}/download`);
        assert.equal(dlRes.status, 200);
        await dlRes.text();

        // Check temp directory: no dec_* files should remain
        const tempFiles = await fs.readdir(TEMP_DIR);
        const decFiles = tempFiles.filter((f) => f.startsWith('dec_'));
        assert.equal(decFiles.length, 0, 'All temporary decrypted files must be cleaned up');
      });

      await t.test('B7. Legacy plaintext records can be migrated to encrypted-v2 safely', async () => {
        // Create an unencrypted legacy record directly
        const legacyId = crypto.randomUUID();
        const legacyStoredName = `legacy_${Date.now()}.txt`;
        const legacyContent = 'Legacy unencrypted baseline document 12345';
        const legacyDiskPath = getSafeFilePath(legacyStoredName);
        await fs.writeFile(legacyDiskPath, legacyContent, 'utf-8');

        const legacyRecord = {
          id: legacyId,
          shareToken: crypto.randomBytes(32).toString('base64url'),
          originalName: 'legacy_doc.txt',
          storedName: legacyStoredName,
          mimeType: 'text/plain',
          size: Buffer.byteLength(legacyContent),
          passwordHash: null,
          passwordSalt: null,
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
          createdAt: new Date().toISOString(),
          status: FILE_STATUS.ACTIVE,
          scanStatus: 'not_scanned'
        };

        await addFileRecord(legacyRecord);

        // Run migration on this legacy record
        const migrationResult = await migrateLegacyRecord(legacyRecord);
        assert.equal(migrationResult.migrated, true);
        assert.ok(migrationResult.record.encryption);
        assert.equal(migrationResult.record.encryption.enabled, true);
        assert.equal(migrationResult.record.storageFormat, 'encrypted-v2');
        assert.ok(migrationResult.record.integrity);

        // Verify permanent file on disk is now ciphertext
        const storedBytes = await fs.readFile(legacyDiskPath);
        assert.notEqual(storedBytes.toString('utf-8'), legacyContent);

        // Verify download recovers the original plaintext
        const dlRes = await fetch(`${baseUrl}/api/files/${legacyRecord.shareToken}/download`);
        assert.equal(dlRes.status, 200);
        const text = await dlRes.text();
        assert.equal(text, legacyContent);
      });
    });

    await suite.test('Feature C: Automatic deletion after expiry and restart recovery', async (t) => {

      await t.test('C1. Expired file is rejected immediately prior to cleanup', async () => {
        const formData = new FormData();
        formData.append('file', new Blob(['Immediate expiry test'], { type: 'text/plain' }), 'imm_exp.txt');
        formData.append('expiry', '24h');

        const uploadRes = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: formData });
        const uploadData = await uploadRes.json();
        const token = uploadData.file.shareToken;

        // Mutate expiry to 1 hour ago
        const record = await getFileByToken(token);
        await updateFileRecord(record.id, {
          expiresAt: new Date(Date.now() - 3600000).toISOString()
        });

        // Immediate rejection
        const dlRes = await fetch(`${baseUrl}/api/files/${token}/download`);
        assert.equal(dlRes.status, 410);
      });

      await t.test('C2. Expired file is physically removed from storage by cleanup cycle', async () => {
        const formData = new FormData();
        formData.append('file', new Blob(['Auto cleanup physical removal'], { type: 'text/plain' }), 'cleanup_test.txt');

        const uploadRes = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: formData });
        const uploadData = await uploadRes.json();
        const token = uploadData.file.shareToken;

        const record = await getFileByToken(token);
        const diskPath = getSafeFilePath(record.storedName);
        assert.equal(await fileExists(record.storedName), true);

        // Expire the file
        await updateFileRecord(record.id, {
          expiresAt: new Date(Date.now() - 1000).toISOString()
        });

        // Run cleanup cycle
        const cycleResult = await runCleanupCycle();
        assert.ok(cycleResult.deleted >= 1);

        // Confirm physical file is deleted from storage
        assert.equal(await fileExists(record.storedName), false, 'Permanent storage file must be deleted');

        // Confirm record status is now 'deleted'
        const updatedRecord = await getFileByToken(token);
        assert.equal(updatedRecord.status, FILE_STATUS.DELETED);
      });

      await t.test('C3. Interrupted DELETING record is reconciled and removed on cycle', async () => {
        const formData = new FormData();
        formData.append('file', new Blob(['Crash recovery test'], { type: 'text/plain' }), 'crash_rec.txt');

        const uploadRes = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: formData });
        const uploadData = await uploadRes.json();
        const token = uploadData.file.shareToken;

        const record = await getFileByToken(token);
        // Simulate crash by manually setting status to 'deleting'
        await updateFileRecord(record.id, { status: FILE_STATUS.DELETING });

        // Run cleanup cycle (simulates startup reconciliation)
        const cycleResult = await runCleanupCycle();
        assert.ok(cycleResult.deleted >= 1);

        // Confirm file is deleted
        assert.equal(await fileExists(record.storedName), false);
        const updated = await getFileByToken(token);
        assert.equal(updated.status, FILE_STATUS.DELETED);
      });

      await t.test('C4. Active download lease prevents cleanup from deleting file while streaming', async () => {
        const formData = new FormData();
        formData.append('file', new Blob(['Lease coordination test'], { type: 'text/plain' }), 'lease.txt');

        const uploadRes = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: formData });
        const uploadData = await uploadRes.json();
        const token = uploadData.file.shareToken;

        const record = await getFileByToken(token);

        // Expire file
        await updateFileRecord(record.id, {
          expiresAt: new Date(Date.now() - 1000).toISOString()
        });

        // Acquire simulated active download lease
        const releaseLease = acquireDownloadLease(record.id);
        assert.equal(hasActiveDownloads(record.id), true);

        // Run cleanup cycle -> must skip this file because download is active
        const cycleResult = await runCleanupCycle();
        assert.ok(cycleResult.skippedBusy >= 1, 'Cleanup must skip busy record');
        assert.equal(await fileExists(record.storedName), true, 'File must not be deleted while lease active');

        // Release lease and run cleanup -> now file is deleted
        releaseLease();
        assert.equal(hasActiveDownloads(record.id), false);

        await runCleanupCycle();
        assert.equal(await fileExists(record.storedName), false, 'File deleted after lease release');
      });
    });

    await suite.test('Feature D: SHA-256 integrity verification', async (t) => {

      await t.test('D1. Correct SHA-256 digest stored at upload and verified upon download', async () => {
        const plaintext = 'Integrity verification golden payload ' + crypto.randomUUID();
        const expectedSha256 = crypto.createHash('sha256').update(plaintext).digest('hex');

        const formData = new FormData();
        formData.append('file', new Blob([plaintext], { type: 'text/plain' }), 'integrity.txt');

        const uploadRes = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: formData });
        assert.equal(uploadRes.status, 201);
        const uploadData = await uploadRes.json();
        const token = uploadData.file.shareToken;

        const record = await getFileByToken(token);
        assert.ok(record.integrity);
        assert.equal(record.integrity.algorithm, 'sha256');
        assert.equal(record.integrity.expectedDigest, expectedSha256);

        // Download succeeds and matches
        const dlRes = await fetch(`${baseUrl}/api/files/${token}/download`);
        assert.equal(dlRes.status, 200);
        const bodyText = await dlRes.text();
        assert.equal(bodyText, plaintext);
      });

      await t.test('D2. Modified expected digest triggers integrity check failure and rejects download', async () => {
        const plaintext = 'Plaintext with mutated expected hash';
        const formData = new FormData();
        formData.append('file', new Blob([plaintext], { type: 'text/plain' }), 'integrity_mismatch.txt');

        const uploadRes = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: formData });
        assert.equal(uploadRes.status, 201);
        const uploadData = await uploadRes.json();
        const token = uploadData.file.shareToken;

        const record = await getFileByToken(token);
        // Mutate expected digest to a different valid 64-char hex string
        const fakeDigest = crypto.createHash('sha256').update('different_data').digest('hex');
        await updateFileRecord(record.id, {
          integrity: {
            ...record.integrity,
            expectedDigest: fakeDigest
          }
        });

        // Download must fail closed with 500
        const dlRes = await fetch(`${baseUrl}/api/files/${token}/download`);
        assert.equal(dlRes.status, 500);
        const data = await dlRes.json();
        assert.ok(data.error.includes('integrity verification failed'));
      });

      await t.test('D3. verifySha256Digest rejects invalid lengths, non-hex strings, and mismatched digests', () => {
        const hash1 = 'a'.repeat(64);
        const hash2 = 'a'.repeat(63) + 'b';

        assert.equal(verifySha256Digest(hash1, hash1), true);
        assert.equal(verifySha256Digest(hash1, hash2), false);

        // Invalid lengths / formats
        assert.equal(verifySha256Digest('short', hash1), false);
        assert.equal(verifySha256Digest(hash1, null), false);
        assert.equal(verifySha256Digest(hash1, 'not-hex-at-all'.padEnd(64, 'z')), false);
        assert.equal(verifySha256Digest(12345, hash1), false);
      });
    });

  });
}
