import fs from 'node:fs';
import fsPromises from 'node:fs/promises';
import crypto from 'node:crypto';
import { pipeline } from 'node:stream/promises';

/**
 * File Integrity Verification Service
 *
 * Provides streaming SHA-256 digest computation and timing-safe verification
 * to detect unexpected changes or corruption between upload and download.
 *
 * NOTE: SHA-256 is a cryptographic hash function, not encryption.
 * It provides tamper and corruption detection provided that the stored digest
 * is kept trustworthy.
 */

const SHA256_HEX_REGEX = /^[a-f0-9]{64}$/i;

/**
 * Calculates SHA-256 digest of a file at the given path using streaming.
 * Avoids loading large files into memory.
 * 
 * @param {string} filePath - Absolute path to file on disk
 * @returns {Promise<string>} 64-character lowercase hexadecimal hash digest
 */
export async function calculateFileSha256(filePath) {
  if (!filePath || typeof filePath !== 'string') {
    throw new TypeError('File path must be a non-empty string');
  }

  // Ensure file exists and is accessible
  await fsPromises.access(filePath);

  const hashStream = crypto.createHash('sha256');
  const readStream = fs.createReadStream(filePath);

  try {
    await pipeline(readStream, hashStream);
    return hashStream.digest('hex');
  } catch (err) {
    throw new Error(`Failed to compute SHA-256 digest for ${filePath}: ${err.message}`);
  }
}

/**
 * Calculates SHA-256 digest from a readable stream.
 *
 * @param {import('node:stream').Readable} readableStream
 * @returns {Promise<string>} 64-character lowercase hexadecimal hash digest
 */
export async function calculateStreamSha256(readableStream) {
  const hashStream = crypto.createHash('sha256');
  await pipeline(readableStream, hashStream);
  return hashStream.digest('hex');
}

/**
 * Timing-safely compares an actual digest with an expected digest.
 * Validates format, character set, and byte length before comparison.
 *
 * @param {string} actualDigest - Computed hex digest
 * @param {string} expectedDigest - Stored hex digest from metadata
 * @returns {boolean} True if matching, false otherwise
 */
export function verifySha256Digest(actualDigest, expectedDigest) {
  if (
    typeof actualDigest !== 'string' ||
    typeof expectedDigest !== 'string' ||
    !SHA256_HEX_REGEX.test(actualDigest) ||
    !SHA256_HEX_REGEX.test(expectedDigest)
  ) {
    return false;
  }

  const actualBuf = Buffer.from(actualDigest.toLowerCase(), 'hex');
  const expectedBuf = Buffer.from(expectedDigest.toLowerCase(), 'hex');

  if (actualBuf.length !== 32 || expectedBuf.length !== 32) {
    return false;
  }

  return crypto.timingSafeEqual(actualBuf, expectedBuf);
}
