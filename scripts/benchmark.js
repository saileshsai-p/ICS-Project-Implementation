/**
 * SecuShare Performance and Enforcement Benchmark
 *
 * Measures upload/download latency, real on-disk storage overhead, metadata
 * growth, expiry-cleanup timing and security-enforcement behaviour.
 *
 * SAFETY: runs entirely inside a disposable temporary installation with a
 * throwaway key, removes only what it created, and refuses to start if the
 * configured locations are not disposable - so it can never touch real data.
 *
 * Usage: npm run benchmark   |   BENCH_TRIALS=10 npm run benchmark
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import fsPromises from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

// Build the isolated installation BEFORE importing any application module:
// services resolve their paths at import time, so the imports below are dynamic.

const RUN_ID = `${process.pid}-${crypto.randomBytes(5).toString('hex')}`;
const BENCH_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), `secushare-bench-${RUN_ID}-`));

const BENCH_DATA_DIR = path.join(BENCH_ROOT, 'data');
const BENCH_STORAGE_DIR = path.join(BENCH_ROOT, 'storage');
const BENCH_ENV_FILE = path.join(BENCH_ROOT, '.env.bench');

fs.mkdirSync(BENCH_DATA_DIR, { recursive: true });
fs.mkdirSync(path.join(BENCH_STORAGE_DIR, 'files'), { recursive: true });
fs.mkdirSync(path.join(BENCH_STORAGE_DIR, 'quarantine'), { recursive: true });
fs.mkdirSync(path.join(BENCH_STORAGE_DIR, 'temp'), { recursive: true });

process.env.SECUSHARE_DATA_DIR = BENCH_DATA_DIR;
process.env.SECUSHARE_STORAGE_DIR = BENCH_STORAGE_DIR;
process.env.SECUSHARE_ENV_FILE = BENCH_ENV_FILE;
process.env.FILE_ENCRYPTION_MASTER_KEY = crypto.randomBytes(32).toString('hex');
// Keep the background worker from interfering with timed measurements.
process.env.CLEANUP_INTERVAL_MS = '3600000';

const { assertDisposableDataLocations, describeRuntimePaths } = await import('../services/config.js');
assertDisposableDataLocations('The benchmark script');

const { startServer, stopServer } = await import('../server.js');
const { getFileByToken, getFileById, updateFileRecord } = await import('../services/metadataService.js');
const { getSafeFilePath, fileExists } = await import('../services/fileService.js');
const { runCleanupCycle } = await import('../services/cleanupService.js');

const METADATA_FILE = path.join(BENCH_DATA_DIR, 'metadata.json');
const TRIALS = Math.max(1, parseInt(process.env.BENCH_TRIALS || '5', 10));

const FILE_SIZES = [
  { label: '10 KB', bytes: 10 * 1024 },
  { label: '100 KB', bytes: 100 * 1024 },
  { label: '1 MB', bytes: 1024 * 1024 },
  { label: '10 MB', bytes: 10 * 1024 * 1024 }
];

// --- Statistics helpers ---

function mean(values) {
  return values.reduce((sum, v) => sum + v, 0) / values.length;
}

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

/** Sample standard deviation (n-1). Returns 0 for a single observation. */
function stdDev(values) {
  if (values.length < 2) return 0;
  const m = mean(values);
  const variance = values.reduce((sum, v) => sum + (v - m) ** 2, 0) / (values.length - 1);
  return Math.sqrt(variance);
}

const fmt = (n, digits = 2) => Number(n).toFixed(digits);

// --- Benchmark body ---

async function runBenchmark() {
  const server = await startServer(0);
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  const paths = describeRuntimePaths();

  console.log('='.repeat(78));
  console.log('SecuShare Benchmark - isolated run');
  console.log('='.repeat(78));
  console.log('\n--- Test conditions (for reproducibility) ---');
  console.log(`Node.js version   : ${process.version}`);
  console.log(`Platform          : ${process.platform} ${process.arch} (${os.release()})`);
  console.log(`CPU               : ${os.cpus()[0]?.model ?? 'unknown'} x${os.cpus().length}`);
  console.log(`Total memory      : ${fmt(os.totalmem() / 1024 ** 3)} GiB`);
  console.log(`Trials per size   : ${TRIALS}`);
  console.log(`Payload sizes     : ${FILE_SIZES.map((f) => f.label).join(', ')}`);
  console.log(`Payload content   : cryptographically random bytes (incompressible)`);
  console.log(`Isolated data dir : ${paths.dataDir}`);
  console.log(`Isolated storage  : ${paths.storageRoot}`);
  console.log(`Client/server     : same Node process, loopback HTTP (127.0.0.1)`);
  console.log(
    '\nNOTE: latency figures include HTTP transfer over loopback, multipart parsing,\n' +
    '      SHA-256 hashing, AES-256-GCM encryption/decryption, JSON metadata I/O and\n' +
    '      response handling. They are end-to-end request timings on one machine, not\n' +
    '      isolated cryptographic throughput, and not a claim of consistent performance.'
  );

  /* -------------------------------------------------------------------------
   * A. Latency and REAL storage overhead
   *
   * Storage overhead is measured by locating the ciphertext for the exact
   * upload under test via its own metadata record, then stat()-ing that single
   * file. The previous implementation compared the downloaded plaintext with
   * the input, which is 0 by construction and measured nothing.
   * ----------------------------------------------------------------------- */
  console.log('\n--- A. Upload / download latency and on-disk storage overhead ---');

  const latencyRows = [];
  const overheadRows = [];

  for (const { label, bytes } of FILE_SIZES) {
    const uploadTimes = [];
    const downloadTimes = [];
    const storedSizes = [];

    for (let trial = 0; trial < TRIALS; trial++) {
      // Fresh random payload per trial so no result can come from a cached or
      // stale file, and so the exact input size is known.
      const payload = crypto.randomBytes(bytes);

      const formData = new FormData();
      formData.append('file', new Blob([payload], { type: 'application/octet-stream' }), `bench_${bytes}_${trial}.bin`);
      formData.append('downloadPolicy', 'unlimited');

      // Upload timing boundary: request dispatch -> response headers+body parsed.
      const uploadStart = performance.now();
      const uploadRes = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: formData });
      const uploadData = await uploadRes.json();
      uploadTimes.push(performance.now() - uploadStart);

      if (uploadRes.status !== 201) {
        throw new Error(`Upload failed for ${label}: HTTP ${uploadRes.status}`);
      }

      // Locate THIS upload's ciphertext through its own metadata record.
      const record = await getFileById(uploadData.file.id);
      const ciphertextPath = getSafeFilePath(record.storedName);
      const stat = await fsPromises.stat(ciphertextPath);
      storedSizes.push(stat.size);

      // Download timing boundary: request dispatch -> COMPLETE body received.
      const downloadStart = performance.now();
      const downloadRes = await fetch(`${baseUrl}/api/files/${uploadData.file.shareToken}/download`);
      const received = Buffer.from(await downloadRes.arrayBuffer());
      downloadTimes.push(performance.now() - downloadStart);

      // Correctness guard: a latency number is meaningless if the bytes are wrong.
      if (received.length !== bytes || Buffer.compare(received, payload) !== 0) {
        throw new Error(`Round-trip corruption detected for ${label} on trial ${trial}`);
      }
    }

    latencyRows.push({
      'File size': label,
      'Upload mean (ms)': fmt(mean(uploadTimes)),
      'Upload median (ms)': fmt(median(uploadTimes)),
      'Upload SD (ms)': fmt(stdDev(uploadTimes)),
      'Download mean (ms)': fmt(mean(downloadTimes)),
      'Download median (ms)': fmt(median(downloadTimes)),
      'Download SD (ms)': fmt(stdDev(downloadTimes))
    });

    const uniqueStored = [...new Set(storedSizes)];
    const storedSize = storedSizes[0];
    const overheadBytes = storedSize - bytes;

    overheadRows.push({
      'File size': label,
      'Original bytes': bytes,
      'Stored ciphertext bytes': uniqueStored.length === 1 ? storedSize : uniqueStored.join('/'),
      'Overhead bytes': overheadBytes,
      'Overhead %': fmt((overheadBytes / bytes) * 100, 4),
      'Consistent across trials': uniqueStored.length === 1 ? 'yes' : 'NO'
    });
  }

  console.log(`\nLatency (${TRIALS} trials per size):`);
  console.table(latencyRows);

  console.log('\nOn-disk storage overhead, measured per upload via its metadata record:');
  console.log('  Overhead % = ((stored ciphertext size - original size) / original size) * 100');
  console.table(overheadRows);
  console.log(
    'Interpretation: AES-256-GCM is a counter-based stream construction, so the\n' +
    'ciphertext is the same length as the plaintext. The 12-byte nonce and 16-byte\n' +
    'authentication tag are NOT stored in the file; they live in metadata.json and\n' +
    'are therefore accounted for under section B, not here.'
  );

  /* -------------------------------------------------------------------------
   * B. Metadata overhead - actually measured, before and after one upload.
   * ----------------------------------------------------------------------- */
  console.log('\n--- B. Metadata overhead per stored file (measured) ---');

  const metadataSizeBefore = (await fsPromises.stat(METADATA_FILE)).size;
  const probeFormData = new FormData();
  const probePayload = crypto.randomBytes(1024);
  probeFormData.append('file', new Blob([probePayload]), 'metadata_probe.bin');
  const probeRes = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: probeFormData });
  const probeData = await probeRes.json();
  const metadataSizeAfter = (await fsPromises.stat(METADATA_FILE)).size;

  const probeRecord = await getFileById(probeData.file.id);
  const cryptoBlocksBytes = Buffer.byteLength(
    JSON.stringify(
      {
        encryption: probeRecord.encryption,
        integrity: probeRecord.integrity,
        storageFormat: probeRecord.storageFormat
      },
      null,
      2
    )
  );
  const wholeRecordBytes = Buffer.byteLength(JSON.stringify(probeRecord, null, 2));

  console.table([
    {
      Measurement: 'metadata.json growth from one upload',
      'Bytes': metadataSizeAfter - metadataSizeBefore,
      'Definition': 'file size after minus before, one 1 KB upload, JSON.stringify indent 2'
    },
    {
      Measurement: 'whole record, serialized',
      'Bytes': wholeRecordBytes,
      'Definition': 'all fields of the new record, indent 2'
    },
    {
      Measurement: 'encryption + integrity + storageFormat blocks only',
      'Bytes': cryptoBlocksBytes,
      'Definition': 'the crypto-specific additions, indent 2'
    }
  ]);
  console.log(
    'Note: growth depends on the pretty-print indentation and on filename length,\n' +
    'so it is a measurement of this configuration rather than a universal constant.'
  );

  /* -------------------------------------------------------------------------
   * C. Enforcement: one-time link under concurrency
   * ----------------------------------------------------------------------- */
  console.log('\n--- C. One-time link enforcement under concurrent load ---');

  const otForm = new FormData();
  otForm.append('file', new Blob([crypto.randomBytes(256)]), 'one_time.bin');
  otForm.append('downloadPolicy', 'one_time');
  const otUpload = await (await fetch(`${baseUrl}/api/files`, { method: 'POST', body: otForm })).json();

  const CONCURRENCY = 10;
  const responses = await Promise.all(
    Array.from({ length: CONCURRENCY }, () =>
      fetch(`${baseUrl}/api/files/${otUpload.file.shareToken}/download`)
    )
  );
  // Drain bodies so the connections close cleanly.
  await Promise.all(responses.map((r) => r.arrayBuffer().catch(() => null)));

  const allowed = responses.filter((r) => r.status === 200).length;
  const refused = responses.filter((r) => r.status === 410).length;

  console.table([
    {
      Scenario: `${CONCURRENCY} simultaneous requests on a one-time link`,
      'Allowed (200)': allowed,
      'Refused (410)': refused,
      'Correct': allowed === 1 && refused === CONCURRENCY - 1 ? 'yes' : 'NO'
    }
  ]);
  console.log('Scope: single Node.js process. This result does not extend to multi-process deployments.');

  /* -------------------------------------------------------------------------
   * D. Tampering scenarios - each failure mode exercised and asserted
   *    separately, rather than treating any HTTP 500 as proof.
   * ----------------------------------------------------------------------- */
  console.log('\n--- D. Tampering and corruption scenarios ---');

  const MARKER = 'BENCH-PLAINTEXT-MARKER-5d1e7b';
  const INTEGRITY_RE = /integrity verification failed/i;
  const CRYPTO_RE = /could not be verified and was not delivered/i;
  const MISSING_RE = /could not be found in storage/i;

  async function uploadMarkerFile(name) {
    const form = new FormData();
    form.append('file', new Blob([Buffer.from(`${MARKER}-${name}-padding-padding`)]), `${name}.txt`);
    const res = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: form });
    return (await res.json()).file;
  }

  /**
   * Applies one tampering mutation, attempts a download, and checks the exact
   * expected outcome plus the invariants that matter: no plaintext leaks and no
   * download allowance is consumed.
   */
  async function tamperScenario({ name, expectedStatus, expectedPattern, mutate }) {
    const file = await uploadMarkerFile(name);
    const record = await getFileByToken(file.shareToken);
    await mutate(record);

    const before = await getFileByToken(file.shareToken);
    const res = await fetch(`${baseUrl}/api/files/${file.shareToken}/download`);
    const body = await res.text();
    const after = await getFileByToken(file.shareToken);

    const statusOk = res.status === expectedStatus;
    const messageOk = expectedPattern.test(body);
    const noPlaintext = !body.includes(MARKER);
    const noAllowanceSpent = after.downloadCount === before.downloadCount;

    return {
      Scenario: name,
      'Expected status': expectedStatus,
      'Actual status': res.status,
      'Correct failure class': messageOk ? 'yes' : 'NO',
      'No plaintext leaked': noPlaintext ? 'yes' : 'NO',
      'No allowance consumed': noAllowanceSpent ? 'yes' : 'NO',
      Result: statusOk && messageOk && noPlaintext && noAllowanceSpent ? 'PASS' : 'FAIL'
    };
  }

  const tamperResults = [];

  tamperResults.push(
    await tamperScenario({
      name: 'incorrect expected SHA-256 digest',
      expectedStatus: 500,
      expectedPattern: INTEGRITY_RE,
      mutate: async (record) => {
        await updateFileRecord(record.id, {
          integrity: {
            algorithm: 'sha256',
            expectedDigest: crypto.createHash('sha256').update('unrelated').digest('hex'),
            version: 1
          }
        });
      }
    })
  );

  tamperResults.push(
    await tamperScenario({
      name: 'modified ciphertext (1 byte flipped)',
      expectedStatus: 500,
      expectedPattern: CRYPTO_RE,
      mutate: async (record) => {
        const p = getSafeFilePath(record.storedName);
        const bytes = await fsPromises.readFile(p);
        bytes[0] ^= 0xff;
        await fsPromises.writeFile(p, bytes);
      }
    })
  );

  tamperResults.push(
    await tamperScenario({
      name: 'modified GCM authentication tag',
      expectedStatus: 500,
      expectedPattern: CRYPTO_RE,
      mutate: async (record) => {
        const tag = Buffer.from(record.encryption.contentTag, 'hex');
        tag[0] ^= 0xff;
        await updateFileRecord(record.id, {
          encryption: { ...record.encryption, contentTag: tag.toString('hex') }
        });
      }
    })
  );

  tamperResults.push(
    await tamperScenario({
      name: 'modified wrapped data key (DEK)',
      expectedStatus: 500,
      expectedPattern: CRYPTO_RE,
      mutate: async (record) => {
        const dek = Buffer.from(record.encryption.wrappedDek, 'hex');
        dek[0] ^= 0xff;
        await updateFileRecord(record.id, {
          encryption: { ...record.encryption, wrappedDek: dek.toString('hex') }
        });
      }
    })
  );

  tamperResults.push(
    await tamperScenario({
      name: 'truncated ciphertext (5 bytes removed)',
      expectedStatus: 500,
      expectedPattern: CRYPTO_RE,
      mutate: async (record) => {
        const p = getSafeFilePath(record.storedName);
        const bytes = await fsPromises.readFile(p);
        await fsPromises.writeFile(p, bytes.subarray(0, bytes.length - 5));
      }
    })
  );

  tamperResults.push(
    await tamperScenario({
      name: 'encrypted file missing from storage',
      expectedStatus: 404,
      expectedPattern: MISSING_RE,
      mutate: async (record) => {
        await fsPromises.unlink(getSafeFilePath(record.storedName));
      }
    })
  );

  console.table(tamperResults);
  const tamperPassCount = tamperResults.filter((r) => r.Result === 'PASS').length;
  console.log(`Scenarios behaving as specified: ${tamperPassCount}/${tamperResults.length}`);
  console.log(
    'These scenarios test cryptographic integrity and access control only.\n' +
    'They are NOT malware detection and say nothing about the safety of file content.'
  );

  /* -------------------------------------------------------------------------
   * E. Expiry cleanup timing, with a verified deletion.
   * ----------------------------------------------------------------------- */
  console.log('\n--- E. Expiry cleanup timing (own fixture, deletion verified) ---');

  const cleanupForm = new FormData();
  cleanupForm.append('file', new Blob([crypto.randomBytes(64 * 1024)]), 'cleanup_fixture.bin');
  const cleanupUpload = await (await fetch(`${baseUrl}/api/files`, { method: 'POST', body: cleanupForm })).json();
  const cleanupRecord = await getFileById(cleanupUpload.file.id);

  const existedBefore = await fileExists(cleanupRecord.storedName);
  await updateFileRecord(cleanupRecord.id, {
    expiresAt: new Date(Date.now() - 1000).toISOString()
  });

  const cleanupStart = performance.now();
  const cycleResult = await runCleanupCycle();
  const cleanupMs = performance.now() - cleanupStart;

  const existsAfter = await fileExists(cleanupRecord.storedName);
  const recordAfter = await getFileById(cleanupRecord.id);

  console.table([
    {
      'Cycle duration (ms)': fmt(cleanupMs),
      'Records scanned': cycleResult.scanned,
      'Files deleted': cycleResult.deleted,
      'Deletions failed': cycleResult.failed,
      'Fixture existed before': existedBefore ? 'yes' : 'no',
      'Fixture removed': existsAfter === false ? 'yes' : 'NO',
      'Record status after': recordAfter?.status ?? 'unknown',
      Verified: existedBefore && !existsAfter && recordAfter?.status === 'deleted' ? 'yes' : 'NO'
    }
  ]);
  console.log(
    `Scope: one full cycle over ${cycleResult.scanned} record(s) in this isolated store.\n` +
    'A cycle rescans and rewrites the whole JSON store, so the duration grows with the\n' +
    'number of records and is not a per-file deletion cost.'
  );

  await stopServer(server);

  console.log('\n' + '='.repeat(78));
  console.log('Benchmark complete. All measurements came from the isolated installation.');
  console.log('='.repeat(78));
}

// --- Teardown: remove only the directory this run created ---

function cleanupBenchRoot() {
  try {
    const resolved = path.resolve(BENCH_ROOT);
    const insideTmp = resolved.toLowerCase().startsWith(path.resolve(os.tmpdir()).toLowerCase());
    const looksLikeOurs = path.basename(resolved).startsWith(`secushare-bench-${RUN_ID}-`);
    if (insideTmp && looksLikeOurs) {
      fs.rmSync(resolved, { recursive: true, force: true });
    }
  } catch {
    // Non-fatal.
  }
}

try {
  await runBenchmark();
} catch (err) {
  console.error('\nBenchmark failed:', err.message);
  process.exitCode = 1;
} finally {
  cleanupBenchRoot();
}
