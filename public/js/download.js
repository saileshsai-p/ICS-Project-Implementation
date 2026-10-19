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
  const filePolicyBadge = document.getElementById('file-policy-badge');
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

  function renderPolicyBadge(policy, remaining, limit) {
    if (!filePolicyBadge) return;
    if (policy === 'one_time') {
      if (remaining !== null && remaining <= 0) {
        filePolicyBadge.textContent = '0 remaining (Allowance Consumed)';
        filePolicyBadge.style.color = 'var(--accent-rose)';
      } else {
        filePolicyBadge.textContent = 'One-Time Link (Single Use)';
        filePolicyBadge.style.color = 'var(--accent-amber)';
      }
    } else if (policy === 'limited') {
      if (remaining !== null && remaining <= 0) {
        filePolicyBadge.textContent = `0 of ${limit} downloads remaining (Exhausted)`;
        filePolicyBadge.style.color = 'var(--accent-rose)';
      } else {
        filePolicyBadge.textContent = `${remaining} of ${limit} downloads remaining`;
        filePolicyBadge.style.color = 'var(--accent-cyan)';
      }
    } else {
      filePolicyBadge.textContent = 'Unlimited Downloads';
      filePolicyBadge.style.color = 'var(--text-secondary)';
    }
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

  // Step 1: Query backend for file metadata (prevent caching with cache: 'no-store')
  try {
    const res = await fetch(`/api/files/${encodeURIComponent(token)}`, {
      cache: 'no-store'
    });
    const data = await res.json();

    if (res.status === 404) {
      showErrorView('File Not Found', 'This sharing link is invalid, corrupted, or does not exist.');
      return;
    }

    if (res.status === 410 || data.expired || data.limitExhausted || data.unavailable) {
      if (data.limitExhausted) {
        showErrorView('Download Limit Reached', 'This link has reached its maximum authorized download limit and is no longer available.');
      } else if (data.expired) {
        showErrorView('Link Expired', 'This sharing link has passed its expiration time and can no longer be downloaded.');
      } else {
        showErrorView('File Unavailable', data.error || 'This file has expired or is no longer available.');
      }
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

    // Initialize download policy badge
    renderPolicyBadge(data.downloadPolicy, data.remainingDownloads, data.downloadLimit);
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
    downloadBtnText.textContent = 'Verifying & Decrypting...';

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
        } else if (res.status === 410 && errorData.error?.includes('limit')) {
          showErrorView('Download Limit Reached', errorData.error);
        }
        return;
      }

      // Check response headers for updated allowance values
      const remainingHeader = res.headers.get('X-Download-Remaining');
      if (remainingHeader !== null && remainingHeader !== undefined) {
        fileMetadata.remainingDownloads = parseInt(remainingHeader, 10);
      } else if (fileMetadata.remainingDownloads !== null && fileMetadata.remainingDownloads !== undefined) {
        fileMetadata.remainingDownloads = Math.max(0, fileMetadata.remainingDownloads - 1);
      }

      if (typeof fileMetadata.downloadCount === 'number') {
        fileMetadata.downloadCount += 1;
      }

      // Update badge live on the download page
      renderPolicyBadge(
        fileMetadata.downloadPolicy,
        fileMetadata.remainingDownloads,
        fileMetadata.downloadLimit
      );

      // Successful authorization, GCM decryption & SHA-256 integrity check passed!
      const blob = await res.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = fileMetadata.originalName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(downloadUrl);

      // Handle allowance exhaustion or re-enabling download
      const isExhausted = fileMetadata.downloadPolicy === 'one_time' ||
        (fileMetadata.remainingDownloads !== null && fileMetadata.remainingDownloads <= 0);

      if (isExhausted) {
        downloadSubmitBtn.disabled = true;
        downloadBtnText.textContent = fileMetadata.downloadPolicy === 'one_time'
          ? 'One-Time Allowance Consumed'
          : 'Download Limit Exhausted';
      } else {
        downloadBtnText.textContent = 'Download Completed!';
        setTimeout(() => {
          downloadSubmitBtn.disabled = false;
          downloadBtnText.textContent = 'Download Again';
        }, 2000);
      }

      // Synchronize metadata from server in background
      fetch(`/api/files/${encodeURIComponent(token)}`, { cache: 'no-store' })
        .then((r) => r.json())
        .then((fresh) => {
          if (fresh && !fresh.error) {
            fileMetadata = fresh;
            renderPolicyBadge(fresh.downloadPolicy, fresh.remainingDownloads, fresh.downloadLimit);
            if (fresh.limitExhausted || (fresh.remainingDownloads !== null && fresh.remainingDownloads <= 0)) {
              downloadSubmitBtn.disabled = true;
              downloadBtnText.textContent = 'Download Limit Exhausted';
            }
          }
        })
        .catch(() => {});

    } catch (err) {
      showInlineError('Network error during file download. Please try again.');
      downloadSubmitBtn.disabled = false;
      downloadBtnText.textContent = 'Download File';
    }
  });
});
