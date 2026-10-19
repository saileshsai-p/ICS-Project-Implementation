import express from 'express';
import { registerUser, authenticateUser } from '../services/userService.js';
import { createSession, destroySession } from '../services/sessionService.js';
import { setSessionCookie, clearSessionCookie } from '../middleware/authMiddleware.js';
import { authRateLimiter } from '../middleware/rateLimiter.js';
import { validateRedirectUrl } from '../services/authService.js';

const router = express.Router();

/**
 * POST /api/auth/register
 * Registers a new user account and creates a persistent authenticated session.
 */
router.post('/register', authRateLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body || {};

    if (!email || typeof email !== 'string') {
      return res.status(400).json({ error: 'Email address is required.' });
    }

    if (!password || typeof password !== 'string') {
      return res.status(400).json({ error: 'Password is required.' });
    }

    // Register user record (enforces normalization, syntax, uniqueness, and min length 8)
    const user = await registerUser({ email, password });

    // Rotate/create session for the newly registered user
    if (req.session?.id) {
      await destroySession(req.session.id);
    }
    const session = await createSession(user.id);
    setSessionCookie(res, session.id, session.maxAgeMs);

    return res.status(201).json({
      success: true,
      user: {
        id: user.id,
        email: user.email
      }
    });
  } catch (err) {
    if (err.status) {
      return res.status(err.status).json({ error: err.message });
    }
    next(err);
  }
});

/**
 * POST /api/auth/login
 * Authenticates user credentials with timing-safe verification, rate limiting, and session rotation.
 */
router.post('/login', authRateLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
      if (req.recordLoginFailure) req.recordLoginFailure();
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const user = await authenticateUser(email, password);

    if (!user) {
      if (req.recordLoginFailure) req.recordLoginFailure();
      // Generic error message: avoid revealing whether email exists
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Clear rate limit failures upon successful authentication
    if (req.clearLoginFailures) {
      req.clearLoginFailures();
    }

    // Prevent session fixation: rotate session ID upon login
    if (req.session?.id) {
      await destroySession(req.session.id);
    }

    const session = await createSession(user.id);
    setSessionCookie(res, session.id, session.maxAgeMs);

    return res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email
      }
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/auth/logout
 * Destroys server-side session and clears the session cookie.
 */
router.post('/logout', async (req, res, next) => {
  try {
    if (req.session?.id) {
      await destroySession(req.session.id);
    }
    clearSessionCookie(res);
    return res.json({ success: true, message: 'Logged out successfully.' });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/auth/me
 * Returns current authenticated user state (never exposes hashes, salts, or session IDs).
 */
router.get('/me', (req, res) => {
  if (req.user) {
    return res.json({
      authenticated: true,
      user: {
        id: req.user.id,
        email: req.user.email
      }
    });
  }
  return res.json({
    authenticated: false,
    user: null
  });
});

export default router;
