import { getSession, SESSION_COOKIE_NAME, SESSION_LIFETIME_MS } from '../services/sessionService.js';
import { findUserById } from '../services/userService.js';

/**
 * Parses raw Cookie header string into a key-value object.
 * Pure Node.js implementation without external dependencies.
 *
 * @param {string|undefined} cookieHeader
 * @returns {Record<string, string>}
 */
export function parseCookies(cookieHeader) {
  if (!cookieHeader || typeof cookieHeader !== 'string') {
    return {};
  }

  const cookies = {};
  const pairs = cookieHeader.split(';');

  for (const pair of pairs) {
    const idx = pair.indexOf('=');
    if (idx === -1) continue;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    if (!cookies[key]) {
      try {
        cookies[key] = decodeURIComponent(val);
      } catch {
        cookies[key] = val;
      }
    }
  }

  return cookies;
}

/**
 * Middleware that parses cookies and resolves the authenticated user session (if any).
 * Attaches `req.user` and `req.session` to the request object.
 */
export async function authenticateSession(req, res, next) {
  try {
    // Parse cookies if not already parsed
    req.cookies = parseCookies(req.headers.cookie);
    const sessionId = req.cookies[SESSION_COOKIE_NAME];

    if (!sessionId) {
      req.user = null;
      req.session = null;
      return next();
    }

    const session = await getSession(sessionId);
    if (!session) {
      // Unknown or expired session: clear cookie
      clearSessionCookie(res);
      req.user = null;
      req.session = null;
      return next();
    }

    const user = await findUserById(session.userId);
    if (!user) {
      clearSessionCookie(res);
      req.user = null;
      req.session = null;
      return next();
    }

    // Attach validated identity
    req.user = {
      id: user.id,
      email: user.email
    };
    req.session = session;
    next();
  } catch (err) {
    req.user = null;
    req.session = null;
    next();
  }
}

/**
 * Middleware that strictly requires an authenticated user.
 */
export function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      error: 'Authentication required. Please log in.',
      authRequired: true
    });
  }
  next();
}

/**
 * Sets the secure session cookie on the response.
 *
 * @param {import('express').Response} res
 * @param {string} sessionId
 * @param {number} [maxAgeMs]
 */
export function setSessionCookie(res, sessionId, maxAgeMs = SESSION_LIFETIME_MS) {
  const isProd = process.env.NODE_ENV === 'production';
  res.cookie(SESSION_COOKIE_NAME, sessionId, {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd,
    path: '/',
    maxAge: maxAgeMs,
    expires: new Date(Date.now() + maxAgeMs)
  });
}

/**
 * Clears the session cookie on logout or invalid session.
 *
 * @param {import('express').Response} res
 */
export function clearSessionCookie(res) {
  const isProd = process.env.NODE_ENV === 'production';
  res.clearCookie(SESSION_COOKIE_NAME, {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd,
    path: '/'
  });
}
