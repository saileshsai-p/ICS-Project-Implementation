document.addEventListener('DOMContentLoaded', () => {
  // Elements
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('file-input');
  const browseBtn = document.getElementById('browse-btn');
  const selectedFileBox = document.getElementById('selected-file-box');
  const fileNameDisplay = document.getElementById('file-name-display');
  const fileSizeDisplay = document.getElementById('file-size-display');
  const removeFileBtn = document.getElementById('remove-file-btn');
  const uploadBtn = document.getElementById('upload-btn');
  const uploadBtnText = document.getElementById('upload-btn-text');
  const uploadForm = document.getElementById('upload-form');
  const passwordInput = document.getElementById('password-input');
  const toggleUploadPwd = document.getElementById('toggle-upload-pwd');
  const expirySelect = document.getElementById('expiry-select');
  const customExpiryContainer = document.getElementById('custom-expiry-container');
  const customExpiryValue = document.getElementById('custom-expiry-value');
  const customExpiryUnit = document.getElementById('custom-expiry-unit');
  const expiryLiveHint = document.getElementById('expiry-live-hint');
  const progressContainer = document.getElementById('progress-container');
  const progressBar = document.getElementById('progress-bar');
  const progressText = document.getElementById('progress-text');
  const uploadErrorAlert = document.getElementById('upload-error-alert');

  // Result card elements
  const uploadCard = document.getElementById('upload-card');
  const resultCard = document.getElementById('result-card');
  const shareUrlInput = document.getElementById('share-url-input');
  const copyBtn = document.getElementById('copy-btn');
  const copyBtnText = document.getElementById('copy-btn-text');
  const resultFilename = document.getElementById('result-filename');
  const resultSize = document.getElementById('result-size');
  const resultExpiry = document.getElementById('result-expiry');
  const resultPasswordStatus = document.getElementById('result-password-status');
  const openDownloadBtn = document.getElementById('open-download-btn');
  const uploadAnotherBtn = document.getElementById('upload-another-btn');

  let currentFile = null;
  const MAX_SIZE_BYTES = 50 * 1024 * 1024; // 50MB

  function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function showError(msg) {
    uploadErrorAlert.textContent = msg;
    uploadErrorAlert.classList.add('visible');
  }

  function hideError() {
    uploadErrorAlert.textContent = '';
    uploadErrorAlert.classList.remove('visible');
  }

  function handleFileSelect(file) {
    hideError();
    if (!file) return;

    if (file.size > MAX_SIZE_BYTES) {
      showError(`File exceeds maximum permitted size of 50 MB (Selected: ${formatBytes(file.size)}).`);
      return;
    }

    currentFile = file;
    fileNameDisplay.textContent = file.name;
    fileSizeDisplay.textContent = formatBytes(file.size);
    selectedFileBox.style.display = 'flex';
    dropzone.style.display = 'none';
    uploadBtn.disabled = false;
  }

  function clearSelectedFile() {
    currentFile = null;
    fileInput.value = '';
    selectedFileBox.style.display = 'none';
    dropzone.style.display = 'block';
    uploadBtn.disabled = true;
    hideError();
  }

  // Browse files click
  browseBtn.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files[0]) {
      handleFileSelect(e.target.files[0]);
    }
  });

  // Drag and drop handlers
  ['dragenter', 'dragover'].forEach((eventName) => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach((eventName) => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove('dragover');
    });
  });

  dropzone.addEventListener('drop', (e) => {
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  });

  // Remove file
  removeFileBtn.addEventListener('click', clearSelectedFile);

  // Toggle password visibility
  toggleUploadPwd.addEventListener('click', () => {
    const isPassword = passwordInput.getAttribute('type') === 'password';
    passwordInput.setAttribute('type', isPassword ? 'text' : 'password');
  });

  // Calculate and display live expiry preview
  function updateExpiryLivePreview() {
    const now = Date.now();
    let ms = 24 * 60 * 60 * 1000;
    if (expirySelect.value === 'custom') {
      const val = Math.max(1, parseInt(customExpiryValue.value, 10) || 1);
      const unit = customExpiryUnit.value;
      if (unit === 'minutes') ms = val * 60 * 1000;
      else if (unit === 'hours') ms = val * 60 * 60 * 1000;
      else if (unit === 'days') ms = val * 24 * 60 * 60 * 1000;
    } else {
      const presets = {
        '1m': 1 * 60 * 1000,
        '5m': 5 * 60 * 1000,
        '15m': 15 * 60 * 1000,
        '1h': 1 * 60 * 60 * 1000,
        '6h': 6 * 60 * 60 * 1000,
        '24h': 24 * 60 * 60 * 1000,
        '7d': 7 * 24 * 60 * 60 * 1000,
        '30d': 30 * 24 * 60 * 60 * 1000
      };
      ms = presets[expirySelect.value] || ms;
    }
    const expiresAtDate = new Date(now + ms);
    expiryLiveHint.textContent = `Will expire on: ${expiresAtDate.toLocaleString()}`;
  }

  expirySelect.addEventListener('change', () => {
    if (expirySelect.value === 'custom') {
      customExpiryContainer.style.display = 'flex';
    } else {
      customExpiryContainer.style.display = 'none';
    }
    updateExpiryLivePreview();
  });

  customExpiryValue.addEventListener('input', updateExpiryLivePreview);
  customExpiryUnit.addEventListener('change', updateExpiryLivePreview);

  // Initialize live preview
  updateExpiryLivePreview();

  // Form submission via XMLHttpRequest for progress reporting
  uploadForm.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!currentFile) return;

    hideError();
    uploadBtn.disabled = true;
    uploadBtnText.textContent = 'Uploading...';
    progressContainer.style.display = 'block';
    progressBar.style.width = '0%';
    progressText.textContent = '0%';

    const formData = new FormData();
    formData.append('file', currentFile);
    
    // Pass either custom amount + unit or the selected preset
    if (expirySelect.value === 'custom') {
      const val = Math.max(1, parseInt(customExpiryValue.value, 10) || 1);
      formData.append('expiryValue', val);
      formData.append('expiryUnit', customExpiryUnit.value || 'days');
    } else {
      formData.append('expiry', expirySelect.value);
    }

    const pwd = passwordInput.value.trim();
    if (pwd) {
      formData.append('password', pwd);
    }

    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/files', true);

    xhr.upload.onprogress = (evt) => {
      if (evt.lengthComputable) {
        const percentComplete = Math.round((evt.loaded / evt.total) * 100);
        progressBar.style.width = percentComplete + '%';
        progressText.textContent = percentComplete + '%';
      }
    };

    xhr.onload = () => {
      uploadBtn.disabled = false;
      uploadBtnText.textContent = 'Upload and Generate Link';
      progressContainer.style.display = 'none';

      let response;
      try {
        response = JSON.parse(xhr.responseText);
      } catch {
        showError('Unexpected server response format.');
        return;
      }

      if (xhr.status >= 200 && xhr.status < 300 && response.success) {
        showSuccessView(response.file);
      } else {
        showError(response.error || 'Failed to upload file.');
      }
    };

    xhr.onerror = () => {
      uploadBtn.disabled = false;
      uploadBtnText.textContent = 'Upload and Generate Link';
      progressContainer.style.display = 'none';
      showError('Network error occurred during upload. Please check your connection.');
    };

    xhr.send(formData);
  });

  function showSuccessView(fileData) {
    uploadCard.style.display = 'none';
    resultCard.style.display = 'block';

    const fullShareUrl = window.location.origin + fileData.shareUrl;
    shareUrlInput.value = fullShareUrl;
    resultFilename.textContent = fileData.originalName;
    resultSize.textContent = formatBytes(fileData.size);

    const expiryDate = new Date(fileData.expiresAt);
    resultExpiry.textContent = expiryDate.toLocaleString();
    resultPasswordStatus.textContent = fileData.hasPassword ? 'Enabled (Password Required)' : 'None (Direct Access)';
    resultPasswordStatus.style.color = fileData.hasPassword ? 'var(--accent-cyan)' : 'var(--text-secondary)';

    openDownloadBtn.href = fileData.shareUrl;
  }

  // Copy link to clipboard
  copyBtn.addEventListener('click', () => {
    shareUrlInput.select();
    navigator.clipboard.writeText(shareUrlInput.value).then(() => {
      copyBtnText.textContent = 'Copied!';
      copyBtn.classList.remove('btn-secondary');
      copyBtn.classList.add('btn-primary');
      setTimeout(() => {
        copyBtnText.textContent = 'Copy Link';
        copyBtn.classList.remove('btn-primary');
        copyBtn.classList.add('btn-secondary');
      }, 2500);
    }).catch(() => {
      // Fallback
      document.execCommand('copy');
      copyBtnText.textContent = 'Copied!';
      setTimeout(() => { copyBtnText.textContent = 'Copy Link'; }, 2000);
    });
  });

  // Upload another file
  uploadAnotherBtn.addEventListener('click', () => {
    clearSelectedFile();
    passwordInput.value = '';
    resultCard.style.display = 'none';
    uploadCard.style.display = 'block';
  });
});
