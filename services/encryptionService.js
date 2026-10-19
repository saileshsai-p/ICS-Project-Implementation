import fs from 'node:fs';
import fsPromises from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import { getSafeFilePath, TEMP_DIR } from './fileService.js';

/**
 * AES-256-GCM Encryption at Rest Service
 *
 * Implements authenticated envelope encryption for stored files:
 * - Each file is encrypted with a unique, randomly generated 32-byte Data Encryption Key (DEK).
 * - Each DEK is wrapped using AES-256-GCM with a server Master Key (KEK) configured via environment variables.
 * - Nonces (IVs) are fresh and unique for every single operation (12 bytes).
 * - Decryption authenticates ciphertext and DEK tags before any data is delivered.
 */

export const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
export const ENCRYPTION_VERSION = 2;
export const MASTER_KEY_VERSION = 'v1';

const NONCE_LENGTH_BYTES = 12; // 96 bits for AES-GCM
const TAG_LENGTH_BYTES = 16;   // 128 bits auth tag
const KEY_LENGTH_BYTES = 32;   // 256 bits

// Automatically load .env if available in Node.js runtime
try {
  if (typeof process.loadEnvFile === 'function') {
    process.loadEnvFile();
  }
} catch {}

/**
 * Validates and retrieves the server master key.
 * Automatically loads from environment or local .env file.
 * 
 * @returns {Buffer} 32-byte master key buffer
 */
export function getMasterKey() {
  let rawKey = process.env.FILE_ENCRYPTION_MASTER_KEY;

  if (!rawKey || typeof rawKey !== 'string' || !rawKey.trim()) {
    // Attempt to reload .env in case it was created after process startup
    try {
      if (typeof process.loadEnvFile === 'function') {
        process.loadEnvFile();
        rawKey = process.env.FILE_ENCRYPTION_MASTER_KEY;
      }
    } catch {}
  }

  // If still missing, check or auto-generate persistent master key for local workstation
  if (!rawKey || typeof rawKey !== 'string' || !rawKey.trim()) {
    const envPath = path.resolve(process.cwd(), '.env');
    try {
      if (fs.existsSync(envPath)) {
        const content = fs.readFileSync(envPath, 'utf-8');
        const match = content.match(/^FILE_ENCRYPTION_MASTER_KEY\s*=\s*([a-f0-9]{64})/im);
        if (match) {
          rawKey = match[1];
          process.env.FILE_ENCRYPTION_MASTER_KEY = rawKey;
        }
      }
    } catch {}
  }

  // If still not configured, generate a fresh 32-byte master key and persist to .env
  if (!rawKey || typeof rawKey !== 'string' || !rawKey.trim()) {
    const generatedKey = crypto.randomBytes(KEY_LENGTH_BYTES).toString('hex');
    rawKey = generatedKey;
    process.env.FILE_ENCRYPTION_MASTER_KEY = generatedKey;
    try {
      const envPath = path.resolve(process.cwd(), '.env');
      fs.appendFileSync(envPath, `\nFILE_ENCRYPTION_MASTER_KEY=${generatedKey}\n`, 'utf-8');
      console.log('[SecuShare] Auto-generated and persisted FILE_ENCRYPTION_MASTER_KEY to .env');
    } catch {}
  }

  const trimmed = rawKey.trim();
  let keyBuffer;

  // Support 64 hex characters (32 bytes)
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    keyBuffer = Buffer.from(trimmed, 'hex');
  } else if (/^[A-Za-z0-9+/]{43}=?$/.test(trimmed)) {
    // 32-byte Base64 representation
    keyBuffer = Buffer.from(trimmed, 'base64');
  } else {
    throw new Error(
      'Server configuration error: FILE_ENCRYPTION_MASTER_KEY has invalid format. ' +
      'It must be exactly 32 bytes (64 hexadecimal characters or 44 base64 characters).'
    );
  }

  if (keyBuffer.length !== KEY_LENGTH_BYTES) {
    throw new Error(
      `Server configuration error: FILE_ENCRYPTION_MASTER_KEY must be exactly 32 bytes (got ${keyBuffer.length} bytes).`
    );
  }

  return keyBuffer;
}

/**
 * Wraps a per-file DEK using AES-256-GCM under the master key.
 *
 * @param {Buffer} dek - 32-byte per-file data encryption key
 * @param {Buffer} masterKey - 32-byte master key
 * @returns {{ wrappedDekHex: string, dekWrappingNonceHex: string, dekWrappingTagHex: string }}
 */
export function wrapDek(dek, masterKey) {
  if (!Buffer.isBuffer(dek) || dek.length !== KEY_LENGTH_BYTES) {
    throw new TypeError(`DEK must be a 32-byte Buffer`);
  }
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== KEY_LENGTH_BYTES) {
    throw new TypeError(`Master key must be a 32-byte Buffer`);
  }

  const wrappingNonce = crypto.randomBytes(NONCE_LENGTH_BYTES);
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, masterKey, wrappingNonce);

  const wrapped = Buffer.concat([cipher.update(dek), cipher.final()]);
  const wrappingTag = cipher.getAuthTag();

  return {
    wrappedDekHex: wrapped.toString('hex'),
    dekWrappingNonceHex: wrappingNonce.toString('hex'),
    dekWrappingTagHex: wrappingTag.toString('hex')
  };
}

/**
 * Unwraps a per-file DEK using AES-256-GCM under the master key.
 *
 * @param {string} wrappedDekHex
 * @param {string} wrappingNonceHex
 * @param {string} wrappingTagHex
 * @param {Buffer} masterKey
 * @returns {Buffer} 32-byte unwrapped DEK
 */
export function unwrapDek(wrappedDekHex, wrappingNonceHex, wrappingTagHex, masterKey) {
  if (!wrappedDekHex || !wrappingNonceHex || !wrappingTagHex) {
    throw new Error('Incomplete wrapped DEK metadata');
  }

  const nonce = Buffer.from(wrappingNonceHex, 'hex');
  const tag = Buffer.from(wrappingTagHex, 'hex');
  const ciphertext = Buffer.from(wrappedDekHex, 'hex');

  if (nonce.length !== NONCE_LENGTH_BYTES || tag.length !== TAG_LENGTH_BYTES) {
    throw new Error('Invalid wrapped DEK nonce or tag length');
  }

  const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, masterKey, nonce);
  decipher.setAuthTag(tag);

  try {
    const dek = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (dek.length !== KEY_LENGTH_BYTES) {
      throw new Error('Recovered DEK has invalid length');
    }
    return dek;
  } catch (err) {
    throw new Error(`Master key verification failed or wrapped DEK was tampered with: ${err.message}`);
  }
}

/**
 * Encrypts a temporary plaintext file into permanent storage using AES-256-GCM.
 *
 * @param {string} sourceTempPath - Path to original uploaded plaintext in temp/
 * @param {string} destStoredName - Target filename in storage/files/
 * @param {Buffer} [masterKey] - Optional master key (defaults to getMasterKey())
 * @returns {Promise<{
 *   storedPath: string,
 *   encryptionMeta: {
 *     enabled: boolean,
 *     algorithm: string,
 *     version: number,
 *     contentNonce: string,
 *     contentTag: string,
 *     wrappedDek: string,
 *     dekWrappingNonce: string,
 *     dekWrappingTag: string,
 *     masterKeyId: string,
 *     originalPlaintextSize: number
 *   }
 * }>}
 */
export async function encryptFileToStorage(sourceTempPath, destStoredName, masterKey = getMasterKey()) {
  const destPath = getSafeFilePath(destStoredName);

  // Generate random 32-byte DEK and wrap it under Master Key
  const dek = crypto.randomBytes(KEY_LENGTH_BYTES);
  const wrapped = wrapDek(dek, masterKey);

  // Generate unique 12-byte nonce for content encryption
  const contentNonce = crypto.randomBytes(NONCE_LENGTH_BYTES);
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, dek, contentNonce);

  const readStream = fs.createReadStream(sourceTempPath);
  const writeStream = fs.createWriteStream(destPath);

  let plaintextSize = 0;
  readStream.on('data', (chunk) => {
    plaintextSize += chunk.length;
  });

  try {
    await pipeline(readStream, cipher, writeStream);
    const contentTag = cipher.getAuthTag();

    const encryptionMeta = {
      enabled: true,
      algorithm: ENCRYPTION_ALGORITHM,
      version: ENCRYPTION_VERSION,
      contentNonce: contentNonce.toString('hex'),
      contentTag: contentTag.toString('hex'),
      wrappedDek: wrapped.wrappedDekHex,
      dekWrappingNonce: wrapped.dekWrappingNonceHex,
      dekWrappingTag: wrapped.dekWrappingTagHex,
      masterKeyId: MASTER_KEY_VERSION,
      originalPlaintextSize: plaintextSize
    };

    return {
      storedPath: destPath,
      encryptionMeta
    };
  } catch (err) {
    // Clean up partial encrypted file on failure
    try {
      await fsPromises.unlink(destPath);
    } catch {}
    throw new Error(`Encryption failed: ${err.message}`);
  }
}

/**
 * Decrypts a stored ciphertext file into a private temporary file.
 * Verifies GCM authentication tag before returning the decrypted file path.
 *
 * @param {string} storedName - Stored filename in storage/files/
 * @param {Object} encryptionMeta - Metadata record containing encryption parameters
 * @param {Buffer} [masterKey] - Optional master key (defaults to getMasterKey())
 * @returns {Promise<string>} Path to verified temporary decrypted file
 */
export async function decryptStorageToTemp(storedName, encryptionMeta, masterKey = getMasterKey()) {
  if (!encryptionMeta || !encryptionMeta.enabled) {
    throw new Error('Encryption metadata missing or encryption not enabled');
  }

  const storedPath = getSafeFilePath(storedName);
  await fsPromises.access(storedPath);

  // 1. Unwrap DEK
  const dek = unwrapDek(
    encryptionMeta.wrappedDek,
    encryptionMeta.dekWrappingNonce,
    encryptionMeta.dekWrappingTag,
    masterKey
  );

  // 2. Prepare decipher
  const contentNonce = Buffer.from(encryptionMeta.contentNonce, 'hex');
  const contentTag = Buffer.from(encryptionMeta.contentTag, 'hex');

  if (contentNonce.length !== NONCE_LENGTH_BYTES || contentTag.length !== TAG_LENGTH_BYTES) {
    throw new Error('Invalid content nonce or authentication tag format');
  }

  const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, dek, contentNonce);
  decipher.setAuthTag(contentTag);

  // 3. Decrypt into private temporary file
  const tempDecryptedName = `dec_${Date.now()}_${crypto.randomBytes(8).toString('hex')}.tmp`;
  const tempDecryptedPath = path.join(TEMP_DIR, tempDecryptedName);

  const readStream = fs.createReadStream(storedPath);
  const writeStream = fs.createWriteStream(tempDecryptedPath);

  try {
    await pipeline(readStream, decipher, writeStream);
    return tempDecryptedPath;
  } catch (err) {
    // Clean up temporary file immediately if tag verification or stream fails
    try {
      await fsPromises.unlink(tempDecryptedPath);
    } catch {}
    throw new Error(`Decryption failed or ciphertext integrity compromised: ${err.message}`);
  }
}

/**
 * Validates that an encryption metadata object contains all required fields.
 * @param {Object} meta
 * @returns {boolean}
 */
export function isValidEncryptionMeta(meta) {
  if (!meta || typeof meta !== 'object') return false;
  return (
    meta.enabled === true &&
    meta.algorithm === ENCRYPTION_ALGORITHM &&
    typeof meta.contentNonce === 'string' &&
    typeof meta.contentTag === 'string' &&
    typeof meta.wrappedDek === 'string' &&
    typeof meta.dekWrappingNonce === 'string' &&
    typeof meta.dekWrappingTag === 'string'
  );
}

/**
 * Safely removes a temporary decrypted file.
 * @param {string} tempFilePath
 */
export async function cleanupTempDecryptedFile(tempFilePath) {
  if (!tempFilePath) return;
  try {
    await fsPromises.unlink(tempFilePath);
  } catch {}
}
