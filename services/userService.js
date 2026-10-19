import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { hashPassword, verifyPassword } from './passwordService.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.resolve(__dirname, '../data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const USERS_TMP_FILE = path.join(DATA_DIR, 'users.tmp.json');

// In-memory queue to serialize concurrent user store reads/writes
let userWriteQueue = Promise.resolve();

/**
 * Normalizes an email address: trims whitespace and converts to lowercase.
 * Single source of truth for email normalization across the entire application.
 * @param {string} email
 * @returns {string}
 */
export function normalizeEmail(email) {
  if (typeof email !== 'string') return '';
  return email.trim().toLowerCase();
}

/**
 * Validates basic email syntax.
 * @param {string} email
 * @returns {boolean}
 */
export function isValidEmail(email) {
  if (typeof email !== 'string') return false;
  const normalized = normalizeEmail(email);
  if (!normalized || normalized.length > 254) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized);
}

/**
 * Ensures data directory and users.json exist.
 */
export async function initUserStore() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    await fs.access(USERS_FILE);
  } catch {
    await fs.writeFile(USERS_FILE, JSON.stringify([], null, 2), 'utf-8');
  }
}

/**
 * Reads all user records safely from disk.
 * @returns {Promise<Array>} Array of user records.
 */
async function readUsers() {
  await initUserStore();
  try {
    const data = await fs.readFile(USERS_FILE, 'utf-8');
    if (!data.trim()) return [];
    return JSON.parse(data);
  } catch (err) {
    if (err.code === 'ENOENT') {
      return [];
    }
    console.error('Error reading users.json:', err.message);
    throw new Error('Failed to read user storage');
  }
}

/**
 * Atomically writes user records to disk with Windows retry fallback.
 * @param {Array} users
 */
async function writeUsers(users) {
  await initUserStore();
  const serialized = JSON.stringify(users, null, 2);
  await fs.writeFile(USERS_TMP_FILE, serialized, 'utf-8');

  let retries = 5;
  while (retries > 0) {
    try {
      await fs.rename(USERS_TMP_FILE, USERS_FILE);
      return;
    } catch (err) {
      if ((err.code === 'EPERM' || err.code === 'EBUSY') && retries > 1) {
        retries--;
        await new Promise((r) => setTimeout(r, 25));
      } else {
        await fs.writeFile(USERS_FILE, serialized, 'utf-8');
        await fs.unlink(USERS_TMP_FILE).catch(() => {});
        return;
      }
    }
  }
}

/**
 * Serializes user operations to prevent concurrent write collisions.
 * @param {Function} task
 */
function queueUserTask(task) {
  const result = userWriteQueue.then(task);
  userWriteQueue = result.catch(() => {});
  return result;
}

/**
 * Registers a new user account.
 * Enforces email syntax, email uniqueness (case/whitespace-insensitive), and minimum password length.
 *
 * @param {Object} params
 * @param {string} params.email
 * @param {string} params.password
 * @returns {Promise<{ id: string, email: string, createdAt: string }>}
 */
export async function registerUser({ email, password }) {
  const normalized = normalizeEmail(email);

  if (!isValidEmail(normalized)) {
    throw { status: 400, message: 'Invalid email address format.' };
  }

  if (typeof password !== 'string' || password.length < 8) {
    throw { status: 400, message: 'Password must be at least 8 characters long.' };
  }

  if (password.length > 128) {
    throw { status: 400, message: 'Password exceeds maximum length of 128 characters.' };
  }

  return queueUserTask(async () => {
    const users = await readUsers();

    // Enforce email uniqueness against normalized form
    const exists = users.some((u) => u.email === normalized);
    if (exists) {
      throw { status: 409, message: 'An account with this email address already exists.' };
    }

    // Securely hash password using scrypt with unique salt
    const { hash, salt } = await hashPassword(password);

    const userRecord = {
      id: crypto.randomUUID(),
      email: normalized,
      passwordHash: hash,
      passwordSalt: salt,
      createdAt: new Date().toISOString()
    };

    users.push(userRecord);
    await writeUsers(users);

    return {
      id: userRecord.id,
      email: userRecord.email,
      createdAt: userRecord.createdAt
    };
  });
}

/**
 * Verifies email and password credentials.
 * Timing-safe scrypt comparison.
 *
 * @param {string} email
 * @param {string} password
 * @returns {Promise<{ id: string, email: string }|null>} User object on success, null on failure
 */
export async function authenticateUser(email, password) {
  const normalized = normalizeEmail(email);
  if (!normalized || typeof password !== 'string' || !password) {
    return null;
  }

  return queueUserTask(async () => {
    const users = await readUsers();
    const user = users.find((u) => u.email === normalized);

    if (!user) {
      // To mitigate timing attacks, run a dummy verify when user is not found
      await verifyPassword(
        password,
        '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '00000000000000000000000000000000'
      );
      return null;
    }

    const isMatch = await verifyPassword(password, user.passwordHash, user.passwordSalt);
    if (!isMatch) {
      return null;
    }

    return {
      id: user.id,
      email: user.email
    };
  });
}

/**
 * Finds a user by ID.
 * @param {string} id
 * @returns {Promise<{ id: string, email: string }|null>}
 */
export async function findUserById(id) {
  if (!id) return null;
  return queueUserTask(async () => {
    const users = await readUsers();
    const user = users.find((u) => u.id === id);
    if (!user) return null;
    return {
      id: user.id,
      email: user.email
    };
  });
}

/**
 * Finds a user by email (normalized).
 * @param {string} email
 * @returns {Promise<{ id: string, email: string }|null>}
 */
export async function findUserByEmail(email) {
  const normalized = normalizeEmail(email);
  if (!normalized) return null;
  return queueUserTask(async () => {
    const users = await readUsers();
    const user = users.find((u) => u.email === normalized);
    if (!user) return null;
    return {
      id: user.id,
      email: user.email
    };
  });
}
