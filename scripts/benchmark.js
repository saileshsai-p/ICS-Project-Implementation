/**
 * SecuShare Version 2 Performance Benchmark Script
 * Collects actual empirical performance numbers on upload/download latency,
 * encryption overhead, and security enforcement rates.
 */

import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer, stopServer } from '../server.js';
import { calculateFileSha256 } from '../services/fileIntegrityService.js';
import { encryptFileToStorage, decryptStorageToTemp, cleanupTempDecryptedFile } from '../services/encryptionService.js';
import { runCleanupCycle } from '../services/cleanupService.js';
import { updateFileRecord } from '../services/metadataService.js';

process.env.FILE_ENCRYPTION_MASTER_KEY =
  process.env.FILE_ENCRYPTION_MASTER_KEY || crypto.randomBytes(32).toString('hex');

async function runBenchmark() {
  console.log('=== Running SecuShare Version 2 Empirical Benchmark ===\n');
  console.log(`Node.js Version: ${process.version}`);
  console.log(`OS: ${process.platform} ${process.arch}`);

  const server = await startServer(0);
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  const fileSizes = [
    { label: '10 KB', bytes: 10 * 1024 },
    { label: '100 KB', bytes: 100 * 1024 },
    { label: '1 MB', bytes: 1024 * 1024 },
    { label: '10 MB', bytes: 10 * 1024 * 1024 }
  ];

  const results = [];

  for (const { label, bytes } of fileSizes) {
    const buffer = crypto.randomBytes(bytes);
    const trials = 3;
    let totalUploadTime = 0;
    let totalDownloadTime = 0;
    let ciphertextOverhead = 0;

    for (let t = 0; t < trials; t++) {
      const formData = new FormData();
      formData.append('file', new Blob([buffer], { type: 'application/octet-stream' }), `bench_${bytes}.bin`);
      formData.append('downloadPolicy', 'unlimited');

      const startUpload = performance.now();
      const uploadRes = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: formData });
      const uploadDuration = performance.now() - startUpload;
      totalUploadTime += uploadDuration;

      const uploadData = await uploadRes.json();
      const token = uploadData.file.shareToken;

      const startDownload = performance.now();
      const downloadRes = await fetch(`${baseUrl}/api/files/${token}/download`);
      const dlBytes = await downloadRes.arrayBuffer();
      const downloadDuration = performance.now() - startDownload;
      totalDownloadTime += downloadDuration;

      ciphertextOverhead = dlBytes.byteLength - bytes; // byte diff
    }

    results.push({
      fileSize: label,
      avgUploadMs: (totalUploadTime / trials).toFixed(2),
      avgDownloadMs: (totalDownloadTime / trials).toFixed(2),
      storageByteDiff: ciphertextOverhead
    });
  }

  console.log('\n--- Latency & Storage Overhead Results ---');
  console.table(results);

  // Test one-time link race condition enforcement rate
  console.log('\n--- One-Time Download Enforcement Rate ---');
  const onetimeData = new FormData();
  onetimeData.append('file', new Blob(['test'], { type: 'text/plain' }), 'ot.txt');
  onetimeData.append('downloadPolicy', 'one_time');
  const otRes = await fetch(`${baseUrl}/api/files`, { method: 'POST', body: onetimeData });
  const otJson = await otRes.json();
  const otToken = otJson.file.shareToken;

  const concurrentRequests = 10;
  const promises = Array.from({ length: concurrentRequests }, () => fetch(`${baseUrl}/api/files/${otToken}/download`));
  const responses = await Promise.all(promises);
  const success200 = responses.filter((r) => r.status === 200).length;
  const rejected410 = responses.filter((r) => r.status === 410).length;
  console.log(`Concurrent requests: ${concurrentRequests}`);
  console.log(`Allowed downloads (200 OK): ${success200}`);
  console.log(`Rejected requests (410 Gone): ${rejected410}`);
  console.log(`One-time link enforcement accuracy: ${success200 === 1 ? '100%' : 'FAILED'}`);

  // Test integrity rejection rate
  console.log('\n--- Tamper Detection & Integrity Rejection Rate ---');
  let tamperedAttempts = 5;
  let rejectedTampered = 0;

  for (let i = 0; i < tamperedAttempts; i++) {
    const fData = new FormData();
    fData.append('file', new Blob([`tamper_content_${i}`], { type: 'text/plain' }), `t_${i}.txt`);
    const up = await (await fetch(`${baseUrl}/api/files`, { method: 'POST', body: fData })).json();
    // Tamper digest in metadata
    await updateFileRecord(up.file.id, {
      integrity: { algorithm: 'sha256', expectedDigest: '0'.repeat(64), version: 1 }
    });
    const dl = await fetch(`${baseUrl}/api/files/${up.file.shareToken}/download`);
    if (dl.status === 500) {
      rejectedTampered++;
    }
  }
  console.log(`Tampered files tested: ${tamperedAttempts}`);
  console.log(`Correctly rejected by integrity check: ${rejectedTampered}`);
  console.log(`Integrity detection accuracy: ${(rejectedTampered / tamperedAttempts * 100).toFixed(0)}%`);

  // Cleanup latency
  const cleanStart = performance.now();
  await runCleanupCycle();
  const cleanDuration = performance.now() - cleanStart;
  console.log(`\nCleanup cycle execution time: ${cleanDuration.toFixed(2)} ms`);

  await stopServer(server);
  console.log('\n=== Benchmark Finished Successfully ===');
}

runBenchmark().catch(console.error);
