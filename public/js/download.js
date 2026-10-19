document.addEventListener('DOMContentLoaded', async () => {
  const loadingCard = document.getElementById('loading-card');
  const errorCard = document.getElementById('error-card');
  const errorTitle = document.getElementById('error-title');
  const errorDescription = document.getElementById('error-description');
  const downloadCard = document.getElementById('download-card');
  const fileTitle = document.getElementById('file-title');
  const fileSizeSubtitle = document.getElementById('file-size-subtitle');
  const fileExpiry = document.getElementById('file-expiry');
  const fileSecurityBadge = document.getElementById('file-security-badge');
  const passwordGroup = document.getElementById('password-group');
  const downloadPwdInput = document.getElementById('download-pwd-input');
  const toggleDownloadPwd = document.getElementById('toggle-download-pwd');
  const downloadForm = document.getElementById('download-form');
  const downloadSubmitBtn = document.getElementById('download-submit-btn');
  const downloadBtnText = document.getElementById('download-btn-text');
  const downloadErrorAlert = document.getElementById('download-error-alert');

  // Extract share token from URL path: /share/:token
  const pathParts = window.location.pathname.split('/');
  const token = pathParts[pathParts.length - 1];

  let fileMetadata = null;

  function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function showErrorView(title, message) {
    loadingCard.style.display = 'none';
    downloadCard.style.display = 'none';
    errorCard.style.display = 'block';
    errorTitle.textContent = title;
    errorDescription.textContent = message;
  }

  function showInlineError(message) {
    downloadErrorAlert.textContent = message;
    downloadErrorAlert.classList.add('visible');
  }

  function hideInlineError() {
    downloadErrorAlert.textContent = '';
    downloadErrorAlert.classList.remove('visible');
  }

  if (!token || token === 'share') {
    showErrorView('Invalid Link', 'No sharing token was detected in the URL.');
    return;
  }

  // Toggle password visibility
  toggleDownloadPwd.addEventListener('click', () => {
    const isPassword = downloadPwdInput.getAttribute('type') === 'password';
    downloadPwdInput.setAttribute('type', isPassword ? 'text' : 'password');
  });

  // Step 1: Query backend for file metadata
  try {
    const res = await fetch(`/api/files/${encodeURIComponent(token)}`);
    const data = await res.json();

    if (res.status === 404) {
      showErrorView('File Not Found', 'This sharing link is invalid, corrupted, or does not exist.');
      return;
    }

    if (res.status === 410 || data.expired) {
      showErrorView('Link Expired', 'This sharing link has passed its expiration time and can no longer be downloaded.');
      return;
    }

    if (!res.ok) {
      showErrorView('Access Unavailable', data.error || 'Failed to retrieve file details.');
      return;
    }

    // Success: Populate download card
    fileMetadata = data;
    loadingCard.style.display = 'none';
    downloadCard.style.display = 'block';

    fileTitle.textContent = data.originalName;
    fileSizeSubtitle.textContent = formatBytes(data.size);

    const expiryDate = new Date(data.expiresAt);
    fileExpiry.textContent = expiryDate.toLocaleString();

    if (data.hasPassword) {
      fileSecurityBadge.textContent = 'Password Protected';
      passwordGroup.style.display = 'block';
      downloadPwdInput.focus();
    } else {
      fileSecurityBadge.textContent = 'Direct Download (Public)';
      passwordGroup.style.display = 'none';
    }
  } catch (err) {
    showErrorView('Connection Error', 'Could not communicate with the local server. Ensure the server is running.');
    return;
  }

  // Step 2: Handle file download submission
  downloadForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideInlineError();

    const pwd = downloadPwdInput.value.trim();

    if (fileMetadata.hasPassword && !pwd) {
      showInlineError('Please enter the password to download this file.');
      downloadPwdInput.focus();
      return;
    }

    downloadSubmitBtn.disabled = true;
    downloadBtnText.textContent = 'Authorizing & Downloading...';

    try {
      // Passwords are sent exclusively in POST request body (NEVER in URL or query params)
      const res = await fetch(`/api/files/${encodeURIComponent(token)}/download`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ password: pwd || null })
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({ error: 'Download failed.' }));
        showInlineError(errorData.error || 'Failed to download file.');
        downloadSubmitBtn.disabled = false;
        downloadBtnText.textContent = 'Download File';
        if (res.status === 401) {
          downloadPwdInput.select();
        }
        return;
      }

      // Successful authorization & download stream
      const blob = await res.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = fileMetadata.originalName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(downloadUrl);

      downloadBtnText.textContent = 'Download Completed!';
      setTimeout(() => {
        downloadSubmitBtn.disabled = false;
        downloadBtnText.textContent = 'Download Again';
      }, 3000);
    } catch (err) {
      showInlineError('Network error during file download. Please try again.');
      downloadSubmitBtn.disabled = false;
      downloadBtnText.textContent = 'Download File';
    }
  });
});
