/**
 * SecuShare Client-Side Authentication Helper
 * Manages navbar auth state, login status checks, logout, and safe redirect resolution.
 */

(function () {
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function sanitizeRedirect(target) {
    if (!target || typeof target !== 'string') return '/';
    const clean = target.trim();
    if (!clean.startsWith('/') || clean.startsWith('//') || clean.includes('\\') || clean.includes('://')) {
      return '/';
    }
    return clean;
  }

  async function checkAuth() {
    try {
      const res = await fetch('/api/auth/me', { cache: 'no-store' });
      if (!res.ok) return { authenticated: false, user: null };
      return await res.json();
    } catch {
      return { authenticated: false, user: null };
    }
  }

  async function logout() {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } catch {}
    window.location.href = '/';
  }

  async function initNavAuth() {
    const navAuthContainer = document.getElementById('nav-auth-container');
    if (!navAuthContainer) return;

    const { authenticated, user } = await checkAuth();

    // Preserve current URL as redirect target if on a share page
    const currentPath = window.location.pathname;
    const redirectParam = currentPath.startsWith('/share/')
      ? `?redirect=${encodeURIComponent(currentPath)}`
      : '';

    if (authenticated && user) {
      navAuthContainer.innerHTML = `
        <span class="nav-user-email" title="${escapeHtml(user.email)}">👤 ${escapeHtml(user.email)}</span>
        <button type="button" class="btn-nav-logout" id="nav-logout-btn">Log Out</button>
      `;
      const logoutBtn = document.getElementById('nav-logout-btn');
      if (logoutBtn) {
        logoutBtn.addEventListener('click', logout);
      }
    } else {
      navAuthContainer.innerHTML = `
        <a href="/login${redirectParam}" class="nav-link" id="nav-login-link">Log In</a>
        <a href="/register${redirectParam}" class="btn btn-secondary" style="padding: 0.35rem 0.75rem; font-size: 0.8rem;" id="nav-register-link">Register</a>
      `;
    }
  }

  window.SecuShareAuth = {
    checkAuth,
    logout,
    sanitizeRedirect,
    escapeHtml
  };

  document.addEventListener('DOMContentLoaded', initNavAuth);
})();
