/**
 * In-memory sliding rate limiter for password verification attempts.
 * Prevents automated brute-force attacks against password-protected file links.
 */

const MAX_ATTEMPTS = 5;
const WINDOW_MS = 5 * 60 * 1000; // 5 minutes

// Map of key -> { count, resetTime }
const attemptsMap = new Map();

// Periodic cleanup of expired entries
setInterval(() => {
  const now = Date.now();
  for (const [key, data] of attemptsMap.entries()) {
    if (now > data.resetTime) {
      attemptsMap.delete(key);
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
    if (record.count >= MAX_ATTEMPTS) {
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
      attemptsMap.set(key, { count: 1, resetTime: now + WINDOW_MS });
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
