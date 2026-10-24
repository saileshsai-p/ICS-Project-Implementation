import fs from 'node:fs';
import fsPromises from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import { getSafeFilePath, TEMP_DIR, FILES_DIR } from './fileService.js';
import { DATA_DIR, ENV_FILE } from './config.js';

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

export const MASTER_KEY_ENV_VAR = 'FILE_ENCRYPTION_MASTER_KEY';

// Automatically load the configured .env if available in the Node.js runtime.
// Failures are non-fatal here: getMasterKey() parses the file directly as well.
try {
  if (typeof process.loadEnvFile === 'function' && fs.existsSync(ENV_FILE)) {
    process.loadEnvFile(ENV_FILE);
  }
} catch {}

// Resolved master key is cached so that repeated encrypt/decrypt calls do not
// re-read the filesystem, and so that key resolution cannot change mid-process.
let cachedMasterKey = null;

/** Encrypted data exists but its master key is unavailable. Carries no key material. */
export class MissingMasterKeyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'MissingMasterKeyError';
    this.code = 'MASTER_KEY_MISSING';
  }
}

/** A newly generated master key could not be persisted. Carries no key material. */
export class MasterKeyPersistenceError extends Error {
  constructor(message) {
    super(message);
    this.name = 'MasterKeyPersistenceError';
    this.code = 'MASTER_KEY_NOT_PERSISTED';
  }
}

/**
 * `.env` values are commonly quoted (KEY="abc"), and process.loadEnvFile()
 * strips quotes while a raw file read does not. Both forms must resolve to the
 * same key, or existing ciphertext becomes undecryptable.
 */
function stripSurroundingQuotes(value) {
  const trimmed = value.trim();
  if (trimmed.length >= 2) {
    const first = trimmed[0];
    const last = trimmed[trimmed.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return trimmed.slice(1, -1).trim();
    }
  }
  return trimmed;
}

/**
 * @param {string} rawValue - Hex (64 chars) or base64 (44 chars)
 * @returns {Buffer|null} 32-byte buffer, or null when the format is unusable
 */
function parseKeyMaterial(rawValue) {
  if (typeof rawValue !== 'string') return null;

  const value = stripSurroundingQuotes(rawValue);
  if (!value) return null;

  let keyBuffer = null;

  if (/^[0-9a-fA-F]{64}$/.test(value)) {
    keyBuffer = Buffer.from(value, 'hex');
  } else if (/^[A-Za-z0-9+/_-]{43}=?$/.test(value)) {
    keyBuffer = Buffer.from(value, 'base64');
  } else {
    return null;
  }

  return keyBuffer.length === KEY_LENGTH_BYTES ? keyBuffer : null;
}

/**
 * Reads the key from the configured .env without relying on
 * process.loadEnvFile(), which may be unavailable or already have run.
 *
 * @returns {{ present: boolean, value?: string }} Raw, unparsed value
 */
function readKeyFromEnvFile() {
  try {
    if (!fs.existsSync(ENV_FILE)) {
      return { present: false };
    }

    const content = fs.readFileSync(ENV_FILE, 'utf-8');
    const lines = content.split(/\r?\n/);
    let found = null;

    for (const line of lines) {
      const match = line.match(/^\s*(?:export\s+)?FILE_ENCRYPTION_MASTER_KEY\s*=\s*(.*)$/);
      if (match) {
        // Last assignment wins, mirroring dotenv-style precedence.
        found = match[1];
      }
    }

    return found === null ? { present: false } : { present: true, value: found };
  } catch {
    return { present: false };
  }
}

/**
 * Determines whether this installation already holds encrypted data.
 *
 * EXISTING when the metadata store references an encrypted record, or storage
 * holds any file. FRESH means neither holds, so there is nothing an
 * auto-generated key could render undecryptable.
 *
 * If undeterminable (unreadable or malformed metadata) it reports EXISTING:
 * the fail-safe direction, refusing to invent a key rather than risk orphaning
 * real ciphertext.
 *
 * @returns {{ existing: boolean, reason: string }}
 */
export function inspectEncryptedState() {
  // 1. Any physically stored file implies prior uploads.
  try {
    if (fs.existsSync(FILES_DIR)) {
      const entries = fs.readdirSync(FILES_DIR).filter((name) => name !== '.gitkeep');
      if (entries.length > 0) {
        return {
          existing: true,
          reason: `${entries.length} stored file(s) present in ${FILES_DIR}`
        };
      }
    }
  } catch (err) {
    return { existing: true, reason: `storage directory could not be inspected (${err.code || err.message})` };
  }

  // 2. Any metadata record with encryption enabled implies prior uploads,
  //    including records whose ciphertext has since been cleaned up.
  const metadataFile = path.join(DATA_DIR, 'metadata.json');
  try {
    if (fs.existsSync(metadataFile)) {
      const raw = fs.readFileSync(metadataFile, 'utf-8');
      if (raw.trim()) {
        const records = JSON.parse(raw);
        if (Array.isArray(records)) {
          const encryptedCount = records.filter((r) => r && r.encryption && r.encryption.enabled).length;
          if (encryptedCount > 0) {
            return {
              existing: true,
              reason: `${encryptedCount} metadata record(s) reference encrypted content`
            };
          }
        } else {
          return { existing: true, reason: 'metadata.json is not an array; treating installation as existing' };
        }
      }
    }
  } catch (err) {
    return { existing: true, reason: `metadata.json could not be parsed (${err.code || err.message})` };
  }

  return { existing: false, reason: 'no stored files and no encrypted metadata records' };
}

/**
 * Generates a new master key, persists it, then verifies the persisted copy is
 * readable and identical before returning it.
 *
 * Verifying the write BEFORE use guarantees files encrypted in this process are
 * still decryptable after a restart. If persistence fails, nothing is encrypted
 * with an ephemeral key.
 *
 * @throws {MasterKeyPersistenceError}
 */
function initializeNewMasterKey() {
  const generatedHex = crypto.randomBytes(KEY_LENGTH_BYTES).toString('hex');

  // 1. Persist first.
  try {
    const needsLeadingNewline =
      fs.existsSync(ENV_FILE) && fs.statSync(ENV_FILE).size > 0 &&
      !fs.readFileSync(ENV_FILE, 'utf-8').endsWith('\n');

    const entry = `${needsLeadingNewline ? '\n' : ''}${MASTER_KEY_ENV_VAR}=${generatedHex}\n`;
    fs.appendFileSync(ENV_FILE, entry, { encoding: 'utf-8', mode: 0o600 });
  } catch (err) {
    throw new MasterKeyPersistenceError(
      `Unable to persist a new ${MASTER_KEY_ENV_VAR} to ${ENV_FILE} (${err.code || 'write failed'}). ` +
      'Refusing to encrypt files with a key that would be lost on restart. ' +
      `Create the file manually or set ${MASTER_KEY_ENV_VAR} in the environment.`
    );
  }

  // 2. Read the persisted value back and confirm it matches.
  const readBack = readKeyFromEnvFile();
  const persistedKey = readBack.present ? parseKeyMaterial(readBack.value) : null;

  if (!persistedKey) {
    throw new MasterKeyPersistenceError(
      `A new ${MASTER_KEY_ENV_VAR} was written to ${ENV_FILE} but could not be read back and validated. ` +
      'Refusing to encrypt files with an unverified key.'
    );
  }

  const generatedKey = Buffer.from(generatedHex, 'hex');
  if (!crypto.timingSafeEqual(persistedKey, generatedKey)) {
    throw new MasterKeyPersistenceError(
      `The persisted ${MASTER_KEY_ENV_VAR} in ${ENV_FILE} does not match the key just generated ` +
      '(another value may already be present). Resolve the configuration manually.'
    );
  }

  process.env[MASTER_KEY_ENV_VAR] = generatedHex;
  console.log(
    `[SecuShare] Initialized a new encryption master key and persisted it to ${ENV_FILE}. ` +
    'Back this file up: losing it makes every stored file permanently unreadable.'
  );

  return generatedKey;
}

/**
 * Resolves the server master key (KEK) used to wrap per-file data keys.
 *
 * Resolution order:
 *   1. process.env.FILE_ENCRYPTION_MASTER_KEY
 *   2. the FILE_ENCRYPTION_MASTER_KEY entry in the configured .env file
 *   3. first-run initialization, but ONLY for a verifiably fresh installation
 *
 * A present-but-malformed key is always a hard error: it is never silently
 * replaced, because the correct key may simply be mistyped.
 *
 * @returns {Buffer} 32-byte master key buffer
 * @throws {MissingMasterKeyError|MasterKeyPersistenceError|Error}
 */
export function getMasterKey() {
  if (cachedMasterKey) {
    return cachedMasterKey;
  }

  const invalidFormatMessage =
    `Server configuration error: ${MASTER_KEY_ENV_VAR} is set but is not valid key material. ` +
    'It must be exactly 32 bytes, written as 64 hexadecimal characters or 44 base64 characters. ' +
    'The existing value has NOT been replaced, because files encrypted under the correct key ' +
    'would become unreadable.';

  // 1. Environment variable takes precedence.
  const fromEnvVar = process.env[MASTER_KEY_ENV_VAR];
  if (typeof fromEnvVar === 'string' && fromEnvVar.trim()) {
    const parsed = parseKeyMaterial(fromEnvVar);
    if (!parsed) {
      throw new Error(invalidFormatMessage);
    }
    cachedMasterKey = parsed;
    return cachedMasterKey;
  }

  // 2. Configured .env file.
  const fromFile = readKeyFromEnvFile();
  if (fromFile.present && stripSurroundingQuotes(fromFile.value)) {
    const parsed = parseKeyMaterial(fromFile.value);
    if (!parsed) {
      throw new Error(
        `${invalidFormatMessage} (source: ${ENV_FILE})`
      );
    }
    // Normalize into the environment so child processes and other readers agree.
    process.env[MASTER_KEY_ENV_VAR] = parsed.toString('hex');
    cachedMasterKey = parsed;
    return cachedMasterKey;
  }

  // 3. No key configured anywhere. Only a provably fresh installation may
  //    initialize one; an existing installation must fail closed.
  const state = inspectEncryptedState();
  if (state.existing) {
    throw new MissingMasterKeyError(
      `${MASTER_KEY_ENV_VAR} is not configured, but this installation already holds encrypted data ` +
      `(${state.reason}). A replacement key has NOT been generated, because it could not decrypt ` +
      'the existing files and would make them permanently unreadable. Restore the original key into ' +
      `${ENV_FILE} or the environment, then start the application again.`
    );
  }

  cachedMasterKey = initializeNewMasterKey();
  return cachedMasterKey;
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
