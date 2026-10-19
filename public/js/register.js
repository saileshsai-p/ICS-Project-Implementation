document.addEventListener('DOMContentLoaded', () => {
  const registerForm = document.getElementById('register-form');
  const emailInput = document.getElementById('register-email');
  const passwordInput = document.getElementById('register-password');
  const confirmPasswordInput = document.getElementById('register-confirm-password');
  const togglePwdBtn = document.getElementById('toggle-pwd-btn');
  const registerBtn = document.getElementById('register-btn');
  const registerBtnText = document.getElementById('register-btn-text');
  const errorAlert = document.getElementById('register-error-alert');
  const switchLoginLink = document.getElementById('switch-login-link');

  // Preserve redirect parameter if present
  const params = new URLSearchParams(window.location.search);
  const redirectUrl = params.get('redirect');
  if (redirectUrl && switchLoginLink) {
    switchLoginLink.href = `/login?redirect=${encodeURIComponent(redirectUrl)}`;
  }

  // Password toggle
  if (togglePwdBtn && passwordInput) {
    togglePwdBtn.addEventListener('click', () => {
      const isPwd = passwordInput.getAttribute('type') === 'password';
      passwordInput.setAttribute('type', isPwd ? 'text' : 'password');
    });
  }

  if (!registerForm) return;

  // Submit handler
  registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (errorAlert) {
      errorAlert.classList.remove('visible');
      errorAlert.style.display = 'none';
      errorAlert.textContent = '';
    }

    const email = emailInput ? emailInput.value.trim() : '';
    const password = passwordInput ? passwordInput.value : '';
    const confirmPassword = confirmPasswordInput ? confirmPasswordInput.value : '';

    if (!email || !password) {
      if (errorAlert) {
        errorAlert.textContent = 'Please provide both your email address and a password.';
        errorAlert.classList.add('visible');
        errorAlert.style.display = 'block';
      }
      return;
    }

    if (password.length < 8) {
      if (errorAlert) {
        errorAlert.textContent = 'Password must be at least 8 characters in length.';
        errorAlert.classList.add('visible');
        errorAlert.style.display = 'block';
      }
      if (passwordInput) passwordInput.focus();
      return;
    }

    if (password !== confirmPassword) {
      if (errorAlert) {
        errorAlert.textContent = 'Passwords do not match. Please ensure both fields are identical.';
        errorAlert.classList.add('visible');
        errorAlert.style.display = 'block';
      }
      if (confirmPasswordInput) confirmPasswordInput.focus();
      return;
    }

    if (registerBtn) registerBtn.disabled = true;
    if (registerBtnText) registerBtnText.textContent = 'Creating Account...';

    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const data = await res.json();

      if (!res.ok) {
        if (errorAlert) {
          errorAlert.textContent = data.error || 'Registration failed.';
          errorAlert.classList.add('visible');
          errorAlert.style.display = 'block';
        }
        if (registerBtn) registerBtn.disabled = false;
        if (registerBtnText) registerBtnText.textContent = 'Create Account';
        return;
      }

      // Registration automatically established session, redirect to destination
      const sanitize = window.SecuShareAuth ? window.SecuShareAuth.sanitizeRedirect : (u) => (u && u.startsWith('/') && !u.startsWith('//') ? u : '/');
      const target = sanitize(redirectUrl);
      window.location.href = target;
    } catch (err) {
      if (errorAlert) {
        errorAlert.textContent = 'Connection error. Please try again.';
        errorAlert.classList.add('visible');
        errorAlert.style.display = 'block';
      }
      if (registerBtn) registerBtn.disabled = false;
      if (registerBtnText) registerBtnText.textContent = 'Create Account';
    }
  });
});
