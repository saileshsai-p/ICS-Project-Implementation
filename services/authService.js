/**
 * Validates a redirect target URL to prevent open redirect vulnerabilities.
 * Only accepts safe, same-origin relative application paths.
 *
 * @param {string|undefined|null} target
 * @returns {string} Safe relative path or default '/'
 */
export function validateRedirectUrl(target) {
  if (typeof target !== 'string' || !target.trim()) {
    return '/';
  }

  const clean = target.trim();

  // Must begin with a single slash '/'
  if (!clean.startsWith('/')) {
    return '/';
  }

  // Reject protocol-relative URLs (e.g., //evil.com or ///evil.com)
  if (clean.startsWith('//')) {
    return '/';
  }

  // Reject backslashes which browsers or parsers might treat as path separators (e.g., /\evil.com)
  if (clean.includes('\\')) {
    return '/';
  }

  // Reject explicit schemes (e.g., /https://evil.com or javascript:)
  if (clean.includes('://') || clean.toLowerCase().includes('javascript:') || clean.toLowerCase().includes('data:')) {
    return '/';
  }

  // Reject control characters and newlines (CRLF injection)
  if (/[\r\n\t\0]/.test(clean)) {
    return '/';
  }

  return clean;
}
