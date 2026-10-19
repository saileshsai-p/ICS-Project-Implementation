/**
 * In-memory sliding rate limiters.
 * Prevents automated brute-force attacks against password verification and user authentication.
 */

const MAX_PASSWORD_ATTEMPTS = 5;
const PASSWORD_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

const MAX_AUTH_ATTEMPTS = 5;
const AUTH_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

// Map of key -> { count, resetTime }
const attemptsMap = new Map();
const authAttemptsMap = new Map();

// Periodic cleanup of expired entries
setInterval(() => {
  const now = Date.now();
  for (const [key, data] of attemptsMap.entries()) {
    if (now > data.resetTime) {
      attemptsMap.delete(key);
    }
  }
  for (const [key, data] of authAttemptsMap.entries()) {
    if (now > data.resetTime) {
      authAttemptsMap.delete(key);
    }
  }
}, 60 * 1000).unref(); // unref so it won't block server shutdown or tests

export function passwordRateLimiter(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const token = req.params.token || 'general';
  const key = `${ip}:${token}`;

  const now = Date.now();
  const record = attemptsMap.get(key);

  if (record && now < record.resetTime) {
    if (record.count >= MAX_PASSWORD_ATTEMPTS) {
      const waitSeconds = Math.ceil((record.resetTime - now) / 1000);
      return res.status(429).json({
        error: `Too many failed password attempts. Please wait ${waitSeconds} seconds before trying again.`
      });
    }
  }

  // Attach helper to record failure on wrong password
  req.recordPasswordFailure = () => {
    const current = attemptsMap.get(key);
    if (!current || now >= current.resetTime) {
      attemptsMap.set(key, { count: 1, resetTime: now + PASSWORD_WINDOW_MS });
    } else {
      current.count += 1;
    }
  };

  // Helper to clear failures on successful password verification
  req.clearPasswordFailures = () => {
    attemptsMap.delete(key);
  };

  next();
}

/**
 * Rate limiter for user login attempts.
 * Limits repeated failed attempts per IP and normalized email.
 */
export function authRateLimiter(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const email = (req.body?.email || '').trim().toLowerCase();
  const key = email ? `${ip}:${email}` : ip;

  const now = Date.now();
  const record = authAttemptsMap.get(key);

  if (record && now < record.resetTime) {
    if (record.count >= MAX_AUTH_ATTEMPTS) {
      const waitSeconds = Math.ceil((record.resetTime - now) / 1000);
      return res.status(429).json({
        error: `Too many failed login attempts. Please wait ${waitSeconds} seconds before trying again.`
      });
    }
  }

  req.recordLoginFailure = () => {
    const current = authAttemptsMap.get(key);
    if (!current || now >= current.resetTime) {
      authAttemptsMap.set(key, { count: 1, resetTime: now + AUTH_WINDOW_MS });
    } else {
      current.count += 1;
    }
  };

  req.clearLoginFailures = () => {
    authAttemptsMap.delete(key);
  };

  next();
}
