import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

import {
  getFileByToken,
  getFileById,
  updateFileRecord,
  addFileRecord
} from '../services/metadataService.js';
import { getSafeFilePath, fileExists, TEMP_DIR } from '../services/fileService.js';
import { runCleanupCycle, auditStorageConsistency } from '../services/cleanupService.js';
import { getActiveDownloadCount, hasActiveDownloads } from '../services/operationCoordinator.js';
import { FILE_STATUS } from '../services/accessService.js';

/**
 * Resilience and Failure-Handling Tests
 *
 * Covers behaviour that the previous suites asserted only loosely:
 *   - cleanup must not claim a deletion that did not happen
 *   - an in-flight download must survive a concurrent cleanup cycle
 *   - each tampering scenario must fail in its own distinguishable way
 *   - a refused download must not leak its cleanup lease
 *
 * All operations run against the disposable directories from tests/setup.mjs.
 */
export function registerResilienceTests(urlOrGetter) {
  test('Suite: Resilience and Failure Handling', async (suite) => {
    const baseUrl = typeof urlOrGetter === 'function' ? urlOrGetter() : urlOrGetter;

    /** Uploads a buffer and returns the API's file object. */
    async function upload(buffer, filename = 'resilience.bin', extraFields = {}) {
      const formData = new FormData();
      formData.append('file', new Blob([buffer]), filename);
      for (const [key, value] of Object.entries(extraFields)) {
        formData.append(key, value);
      }
      const res = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: formData });
      assert.equal(res.status, 201, 'upload must succeed');
      return (await res.json()).file;
    }

    /** Lists leftover decrypted staging files. */
    async function listDecryptedTempFiles() {
      const entries = await fs.readdir(TEMP_DIR).catch(() => []);
      return entries.filter((name) => name.startsWith('dec_'));
    }

    await suite.test('Section 1: Cleanup deletion accounting', async (t) => {

      await t.test('R1. A failed physical deletion keeps the record retryable, not deleted', async () => {
        // Simulate an undeletable stored file by creating a NON-EMPTY DIRECTORY
        // at the stored path. unlink() fails on a directory on every platform,
        // which reproduces the locked/permission-denied case portably.
        const storedName = `undeletable_${crypto.randomBytes(4).toString('hex')}.dat`;
        const blockerDir = getSafeFilePath(storedName);
        await fs.mkdir(blockerDir, { recursive: true });
        await fs.writeFile(path.join(blockerDir, 'inner.txt'), 'blocker', 'utf-8');

        const recordId = crypto.randomUUID();
        await addFileRecord({
          id: recordId,
          shareToken: crypto.randomBytes(32).toString('base64url'),
          originalName: 'undeletable.txt',
          storedName,
          mimeType: 'text/plain',
          size: 7,
          passwordHash: null,
          passwordSalt: null,
          // Already expired, so it is eligible for cleanup.
          expiresAt: new Date(Date.now() - 60000).toISOString(),
          createdAt: new Date(Date.now() - 120000).toISOString(),
          status: FILE_STATUS.ACTIVE,
          scanStatus: 'not_scanned',
          downloadPolicy: 'unlimited',
          downloadLimit: null,
          downloadCount: 0,
          authorizedRecipients: [],
          storageFormat: 'encrypted-v2',
          encryption: { enabled: true, algorithm: 'aes-256-gcm' },
          integrity: { algorithm: 'sha256', expectedDigest: 'a'.repeat(64), version: 1 }
        });

        const cycle = await runCleanupCycle();
        assert.ok(cycle.failed >= 1, 'cycle must report at least one failed deletion');
        assert.ok(
          cycle.errors.some((e) => e.id === recordId && e.stage === 'unlink'),
          'the failure must be attributed to this record'
        );

        // The decisive assertion: status must NOT be 'deleted'.
        const record = await getFileById(recordId);
        assert.equal(
          record.status,
          FILE_STATUS.DELETING,
          'record must stay in DELETING so a later cycle retries it'
        );
        assert.notEqual(record.status, FILE_STATUS.DELETED);
        assert.ok(record.lastCleanupError, 'the failure reason must be recorded');
        assert.ok(record.lastCleanupError.code, 'error code must be captured');
        assert.equal(record.deletedAt, undefined, 'deletedAt must not be set on failure');

        // Now remove the blocker and confirm a later cycle completes the deletion.
        await fs.rm(blockerDir, { recursive: true, force: true });
        await fs.writeFile(blockerDir, 'real-ciphertext-now', 'utf-8');

        const retryCycle = await runCleanupCycle();
        assert.ok(retryCycle.deleted >= 1, 'retry cycle must delete the file');

        const retried = await getFileById(recordId);
        assert.equal(retried.status, FILE_STATUS.DELETED, 'record must now be DELETED');
        assert.equal(retried.lastCleanupError, null, 'stale error must be cleared');
        assert.equal(await fileExists(storedName), false, 'file must be gone from storage');
      });

      await t.test('R2. Consistency audit reports anomalies without deleting anything', async () => {
        // A stored file with no metadata record at all.
        const orphanName = `orphan_${crypto.randomBytes(4).toString('hex')}.dat`;
        await fs.writeFile(getSafeFilePath(orphanName), 'orphaned-bytes', 'utf-8');

        const report = await auditStorageConsistency();
        assert.ok(report.filesWithoutRecord.includes(orphanName), 'orphan must be reported');
        assert.ok(typeof report.totalRecords === 'number');

        // The audit is read-only: the orphan must still be present afterwards.
        assert.equal(
          await fileExists(orphanName),
          true,
          'audit must not delete files it cannot account for'
        );

        // Clean up our own fixture.
        await fs.unlink(getSafeFilePath(orphanName)).catch(() => {});
      });
    });

    await suite.test('Section 2: Streaming download versus cleanup', async (t) => {

      await t.test('R3. Cleanup skips a file whose download is mid-stream, and the download stays intact', async () => {
        // Large enough that the response cannot be fully buffered before the
        // client starts reading, so the stream is genuinely still open.
        const payloadSize = 24 * 1024 * 1024;
        const payload = crypto.randomBytes(payloadSize);
        const file = await upload(payload, 'streaming_race.bin');
        const record = await getFileByToken(file.shareToken);

        // Start the download while the link is still valid.
        const res = await fetch(`${baseUrl}/api/files/${file.shareToken}/download`);
        assert.equal(res.status, 200);

        const reader = res.body.getReader();
        const chunks = [];
        let received = 0;

        // Read exactly one chunk, then deliberately stall.
        const first = await reader.read();
        assert.equal(first.done, false, 'stream must still be open after one chunk');
        chunks.push(first.value);
        received += first.value.length;
        assert.ok(received < payloadSize, 'the whole body must not have arrived yet');

        // While the stream is open, the lease must be held.
        assert.equal(hasActiveDownloads(record.id), true, 'lease must be active mid-stream');
        assert.ok(getActiveDownloadCount(record.id) >= 1);

        // The link expires *during* the transfer, making the record eligible
        // for cleanup while its bytes are still being streamed.
        await updateFileRecord(record.id, {
          expiresAt: new Date(Date.now() - 1000).toISOString()
        });

        // Run cleanup against the now-expired record while streaming.
        const cycle = await runCleanupCycle();
        assert.ok(cycle.skippedBusy >= 1, 'cleanup must skip the busy record');
        assert.equal(
          await fileExists(record.storedName),
          true,
          'stored file must survive cleanup while being streamed'
        );

        // Drain the rest and verify the payload is byte-for-byte intact.
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
          received += value.length;
        }

        assert.equal(received, payloadSize, 'full payload must be delivered');
        const delivered = Buffer.concat(chunks.map((c) => Buffer.from(c)));
        assert.equal(
          Buffer.compare(delivered, payload),
          0,
          'delivered bytes must match the uploaded bytes exactly'
        );

        // After the response completes the lease is released, so a later cycle
        // may finish the deletion.
        const settle = async () => {
          for (let i = 0; i < 50; i++) {
            if (!hasActiveDownloads(record.id)) return true;
            await new Promise((r) => setTimeout(r, 20));
          }
          return !hasActiveDownloads(record.id);
        };
        assert.equal(await settle(), true, 'lease must be released after the response finishes');

        await runCleanupCycle();
        assert.equal(
          await fileExists(record.storedName),
          false,
          'expired file must be removed once no download is active'
        );
      });

      await t.test('R4. A refused download releases its lease so cleanup is not blocked', async () => {
        // Regression guard: an early failure path must not leak the read lease.
        const file = await upload(Buffer.from('lease-release-check'), 'lease_release.txt');
        const record = await getFileByToken(file.shareToken);

        // Force an integrity failure by corrupting the expected digest.
        await updateFileRecord(record.id, {
          integrity: { algorithm: 'sha256', expectedDigest: '0'.repeat(64), version: 1 }
        });

        const res = await fetch(`${baseUrl}/api/files/${file.shareToken}/download`);
        assert.equal(res.status, 500);
        await res.text();

        assert.equal(
          hasActiveDownloads(record.id),
          false,
          'lease must be released after a refused download'
        );

        // Cleanup must therefore be able to delete the expired record.
        await updateFileRecord(record.id, {
          expiresAt: new Date(Date.now() - 1000).toISOString()
        });
        await runCleanupCycle();
        assert.equal(await fileExists(record.storedName), false);
      });
    });

    await suite.test('Section 3: Tampering scenarios are individually verified', async (t) => {
      const MARKER = 'TAMPER-MATRIX-SECRET-PAYLOAD-7f3a9c';

      const INTEGRITY_MESSAGE = /integrity verification failed/i;
      const CRYPTO_MESSAGE = /could not be verified and was not delivered/i;

      /**
       * Asserts a download attempt fails without leaking plaintext, without
       * consuming an allowance, and without leaving staged plaintext behind.
       */
      async function assertRefused(token, recordId, { expectedStatus, expectedMessage }) {
        const before = await getFileByToken(token);
        const res = await fetch(`${baseUrl}/api/files/${token}/download`);
        const bodyText = await res.text();

        assert.equal(res.status, expectedStatus, `expected HTTP ${expectedStatus}`);
        assert.match(bodyText, expectedMessage, 'error message must identify the failure class');
        assert.ok(!bodyText.includes(MARKER), 'response must never contain plaintext');

        const after = await getFileByToken(token);
        assert.equal(
          after.downloadCount,
          before.downloadCount,
          'a refused download must not consume an allowance'
        );

        const leftovers = await listDecryptedTempFiles();
        assert.equal(leftovers.length, 0, 'no decrypted plaintext may remain staged');

        assert.equal(hasActiveDownloads(recordId), false, 'lease must be released');
      }

      await t.test('R5. Incorrect expected SHA-256 digest is reported as an integrity failure', async () => {
        const file = await upload(Buffer.from(MARKER), 'tamper_digest.txt');
        const record = await getFileByToken(file.shareToken);

        await updateFileRecord(record.id, {
          integrity: {
            algorithm: 'sha256',
            expectedDigest: crypto.createHash('sha256').update('something-else').digest('hex'),
            version: 1
          }
        });

        await assertRefused(file.shareToken, record.id, {
          expectedStatus: 500,
          expectedMessage: INTEGRITY_MESSAGE
        });
      });

      await t.test('R6. Modified ciphertext fails GCM authentication, distinctly from a digest mismatch', async () => {
        const file = await upload(Buffer.from(MARKER), 'tamper_ciphertext.txt');
        const record = await getFileByToken(file.shareToken);

        const diskPath = getSafeFilePath(record.storedName);
        const bytes = await fs.readFile(diskPath);
        bytes[0] ^= 0xff;
        await fs.writeFile(diskPath, bytes);

        // Must NOT be reported as a digest mismatch: authentication fails first.
        await assertRefused(file.shareToken, record.id, {
          expectedStatus: 500,
          expectedMessage: CRYPTO_MESSAGE
        });
      });

      await t.test('R7. Modified authentication tag is rejected', async () => {
        const file = await upload(Buffer.from(MARKER), 'tamper_tag.txt');
        const record = await getFileByToken(file.shareToken);

        const tag = Buffer.from(record.encryption.contentTag, 'hex');
        tag[0] ^= 0xff;
        await updateFileRecord(record.id, {
          encryption: { ...record.encryption, contentTag: tag.toString('hex') }
        });

        await assertRefused(file.shareToken, record.id, {
          expectedStatus: 500,
          expectedMessage: CRYPTO_MESSAGE
        });
      });

      await t.test('R8. Modified wrapped data key is rejected', async () => {
        const file = await upload(Buffer.from(MARKER), 'tamper_dek.txt');
        const record = await getFileByToken(file.shareToken);

        const wrapped = Buffer.from(record.encryption.wrappedDek, 'hex');
        wrapped[0] ^= 0xff;
        await updateFileRecord(record.id, {
          encryption: { ...record.encryption, wrappedDek: wrapped.toString('hex') }
        });

        await assertRefused(file.shareToken, record.id, {
          expectedStatus: 500,
          expectedMessage: CRYPTO_MESSAGE
        });
      });

      await t.test('R9. Truncated ciphertext is rejected', async () => {
        const file = await upload(Buffer.from(`${MARKER}-with-extra-length-for-truncation`), 'tamper_truncated.txt');
        const record = await getFileByToken(file.shareToken);

        const diskPath = getSafeFilePath(record.storedName);
        const bytes = await fs.readFile(diskPath);
        await fs.writeFile(diskPath, bytes.subarray(0, bytes.length - 5));

        await assertRefused(file.shareToken, record.id, {
          expectedStatus: 500,
          expectedMessage: CRYPTO_MESSAGE
        });
      });

      await t.test('R10. A missing encrypted file is reported as not found, not as tampering', async () => {
        const file = await upload(Buffer.from(MARKER), 'tamper_missing.txt');
        const record = await getFileByToken(file.shareToken);

        await fs.unlink(getSafeFilePath(record.storedName));

        await assertRefused(file.shareToken, record.id, {
          expectedStatus: 404,
          expectedMessage: /could not be found in storage/i
        });
      });
    });
  });
}
