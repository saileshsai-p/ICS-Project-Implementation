import crypto from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(crypto.scrypt);

const KEY_LENGTH = 64; // 64 bytes hash
const SALT_LENGTH = 16; // 16 bytes salt

/**
 * Hashes a plaintext password using crypto.scrypt with a unique random salt.
 * @param {string} password - Plaintext password
 * @returns {Promise<{ hash: string, salt: string }>} Hex-encoded hash and salt
 */
export async function hashPassword(password) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new Error('Password must be a non-empty string');
  }

  const salt = crypto.randomBytes(SALT_LENGTH);
  const derivedKey = await scryptAsync(password, salt, KEY_LENGTH);

  return {
    hash: derivedKey.toString('hex'),
    salt: salt.toString('hex')
  };
}

/**
 * Timing-safe password verification.
 * @param {string} password - Plaintext password attempt
 * @param {string} storedHashHex - Stored hex-encoded hash
 * @param {string} storedSaltHex - Stored hex-encoded salt
 * @returns {Promise<boolean>} True if password matches, false otherwise
 */
export async function verifyPassword(password, storedHashHex, storedSaltHex) {
  if (!password || !storedHashHex || !storedSaltHex) {
    return false;
  }

  try {
    const salt = Buffer.from(storedSaltHex, 'hex');
    const storedHash = Buffer.from(storedHashHex, 'hex');

    const derivedKey = await scryptAsync(password, salt, storedHash.length);
    return crypto.timingSafeEqual(derivedKey, storedHash);
  } catch (err) {
    // If salt or hash format is malformed or invalid buffer, fail closed
    return false;
  }
}
