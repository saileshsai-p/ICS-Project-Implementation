/**
 * Custom lightweight security headers middleware.
 * Implements core OWASP security header recommendations without external dependencies.
 */
export function securityHeaders(req, res, next) {
  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Prevent framing to defend against clickjacking
  res.setHeader('X-Frame-Options', 'DENY');

  // Strict CSP allowing modern internal scripts and styles without external CDNs
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; form-action 'self';"
  );

  // Send the origin but not the path when navigating cross-origin, so share
  // tokens in the URL are never leaked through the Referer header.
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Restrict sensitive browser features
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

  // Remove Express footprint header
  res.removeHeader('X-Powered-By');

  next();
}
