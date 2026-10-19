document.addEventListener('DOMContentLoaded', () => {
  const loginForm = document.getElementById('login-form');
  const emailInput = document.getElementById('login-email');
  const passwordInput = document.getElementById('login-password');
  const togglePwdBtn = document.getElementById('toggle-pwd-btn');
  const loginBtn = document.getElementById('login-btn');
  const loginBtnText = document.getElementById('login-btn-text');
  const errorAlert = document.getElementById('login-error-alert');
  const switchRegisterLink = document.getElementById('switch-register-link');

  // Preserve redirect parameter if present
  const params = new URLSearchParams(window.location.search);
  const redirectUrl = params.get('redirect');
  if (redirectUrl && switchRegisterLink) {
    switchRegisterLink.href = `/register?redirect=${encodeURIComponent(redirectUrl)}`;
  }

  // Password toggle
  if (togglePwdBtn && passwordInput) {
    togglePwdBtn.addEventListener('click', () => {
      const isPwd = passwordInput.getAttribute('type') === 'password';
      passwordInput.setAttribute('type', isPwd ? 'text' : 'password');
    });
  }

  if (!loginForm) return;

  // Submit handler
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (errorAlert) {
      errorAlert.classList.remove('visible');
      errorAlert.style.display = 'none';
      errorAlert.textContent = '';
    }

    const email = emailInput ? emailInput.value.trim() : '';
    const password = passwordInput ? passwordInput.value : '';

    if (!email || !password) {
      if (errorAlert) {
        errorAlert.textContent = 'Please enter both your email and password.';
        errorAlert.classList.add('visible');
        errorAlert.style.display = 'block';
      }
      return;
    }

    if (loginBtn) loginBtn.disabled = true;
    if (loginBtnText) loginBtnText.textContent = 'Authenticating...';

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const data = await res.json();

      if (!res.ok) {
        if (errorAlert) {
          errorAlert.textContent = data.error || 'Authentication failed.';
          errorAlert.classList.add('visible');
          errorAlert.style.display = 'block';
        }
        if (loginBtn) loginBtn.disabled = false;
        if (loginBtnText) loginBtnText.textContent = 'Log In';
        if (passwordInput) passwordInput.select();
        return;
      }

      // Successful authentication: redirect to intended destination (or home)
      const sanitize = window.SecuShareAuth ? window.SecuShareAuth.sanitizeRedirect : (u) => (u && u.startsWith('/') && !u.startsWith('//') ? u : '/');
      const target = sanitize(redirectUrl);
      window.location.href = target;
    } catch (err) {
      if (errorAlert) {
        errorAlert.textContent = 'Connection error. Please try again.';
        errorAlert.classList.add('visible');
        errorAlert.style.display = 'block';
      }
      if (loginBtn) loginBtn.disabled = false;
      if (loginBtnText) loginBtnText.textContent = 'Log In';
    }
  });
});
