import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { DATA_DIR } from './config.js';

const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
const SESSIONS_TMP_FILE = path.join(DATA_DIR, 'sessions.tmp.json');

// Default session lifetime: 7 days in milliseconds
export const DEFAULT_SESSION_LIFETIME_DAYS = 7;
export const SESSION_LIFETIME_MS = parseInt(
  process.env.SESSION_LIFETIME_MS || String(DEFAULT_SESSION_LIFETIME_DAYS * 24 * 60 * 60 * 1000),
  10
);
export const SESSION_COOKIE_NAME = process.env.SESSION_COOKIE_NAME || 'secushare_session';

// In-memory queue to serialize concurrent session reads/writes
let sessionWriteQueue = Promise.resolve();

/**
 * Ensures data directory and sessions.json exist.
 */
export async function initSessionStore() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    await fs.access(SESSIONS_FILE);
  } catch {
    await fs.writeFile(SESSIONS_FILE, JSON.stringify([], null, 2), 'utf-8');
  }
}

/**
 * Reads all session records from disk.
 * @returns {Promise<Array>}
 */
async function readSessions() {
  await initSessionStore();
  try {
    const data = await fs.readFile(SESSIONS_FILE, 'utf-8');
    if (!data.trim()) return [];
    return JSON.parse(data);
  } catch (err) {
    if (err.code === 'ENOENT') {
      return [];
    }
    console.error('Error reading sessions.json:', err.message);
    throw new Error('Failed to read session storage');
  }
}

/**
 * Atomically writes session records to disk with Windows retry fallback.
 * @param {Array} sessions
 */
async function writeSessions(sessions) {
  await initSessionStore();
  const serialized = JSON.stringify(sessions, null, 2);
  await fs.writeFile(SESSIONS_TMP_FILE, serialized, 'utf-8');

  let retries = 5;
  while (retries > 0) {
    try {
      await fs.rename(SESSIONS_TMP_FILE, SESSIONS_FILE);
      return;
    } catch (err) {
      if ((err.code === 'EPERM' || err.code === 'EBUSY') && retries > 1) {
        retries--;
        await new Promise((r) => setTimeout(r, 25));
      } else {
        await fs.writeFile(SESSIONS_FILE, serialized, 'utf-8');
        await fs.unlink(SESSIONS_TMP_FILE).catch(() => {});
        return;
      }
    }
  }
}

/**
 * Serializes session operations to prevent concurrent write collisions.
 * @param {Function} task
 */
function queueSessionTask(task) {
  const result = sessionWriteQueue.then(task);
  sessionWriteQueue = result.catch(() => {});
  return result;
}

/**
 * Creates a new server-side persistent session for a user.
 * Generates an unguessable 256-bit cryptographically secure session ID.
 *
 * @param {string} userId - User ID
 * @returns {Promise<{ id: string, userId: string, expiresAt: string, maxAgeMs: number }>}
 */
export async function createSession(userId) {
  if (!userId) {
    throw new Error('userId is required to create a session');
  }

  const sessionId = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();
  const expiresAt = new Date(now + SESSION_LIFETIME_MS).toISOString();

  const sessionRecord = {
    id: sessionId,
    userId,
    createdAt: new Date(now).toISOString(),
    expiresAt
  };

  return queueSessionTask(async () => {
    const sessions = await readSessions();
    // Prune expired sessions opportunistically
    const active = sessions.filter((s) => new Date(s.expiresAt).getTime() > now);
    active.push(sessionRecord);
    await writeSessions(active);

    return {
      id: sessionRecord.id,
      userId: sessionRecord.userId,
      expiresAt: sessionRecord.expiresAt,
      maxAgeMs: SESSION_LIFETIME_MS
    };
  });
}

/**
 * Validates a session identifier server-side.
 * Enforces session expiration on the server.
 *
 * @param {string} sessionId
 * @returns {Promise<{ id: string, userId: string }|null>}
 */
export async function getSession(sessionId) {
  if (!sessionId || typeof sessionId !== 'string') {
    return null;
  }

  return queueSessionTask(async () => {
    const sessions = await readSessions();
    const session = sessions.find((s) => s.id === sessionId);

    if (!session) {
      return null;
    }

    const now = Date.now();
    const expiry = new Date(session.expiresAt).getTime();

    // Check expiration server-side
    if (isNaN(expiry) || now > expiry) {
      // Clean up expired session
      const filtered = sessions.filter((s) => s.id !== sessionId);
      await writeSessions(filtered);
      return null;
    }

    return {
      id: session.id,
      userId: session.userId,
      expiresAt: session.expiresAt
    };
  });
}

/**
 * Destroys a session on logout.
 * Ensures the session cannot be reused.
 *
 * @param {string} sessionId
 * @returns {Promise<boolean>}
 */
export async function destroySession(sessionId) {
  if (!sessionId || typeof sessionId !== 'string') {
    return false;
  }

  return queueSessionTask(async () => {
    const sessions = await readSessions();
    const filtered = sessions.filter((s) => s.id !== sessionId);
    await writeSessions(filtered);
    return true;
  });
}

/**
 * Destroys all sessions for a specific user (useful for security invalidation).
 * @param {string} userId
 */
export async function destroyUserSessions(userId) {
  if (!userId) return;
  return queueSessionTask(async () => {
    const sessions = await readSessions();
    const filtered = sessions.filter((s) => s.userId !== userId);
    await writeSessions(filtered);
  });
}
