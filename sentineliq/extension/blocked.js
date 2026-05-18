(function () {
  // ── Parse URL params ────────────────────────────────────────────────────────
  const params      = new URLSearchParams(location.search);
  const destUrl     = decodeURIComponent(params.get('url') || '');
  const risk        = parseInt(params.get('risk') || '0', 10);
  const explanation = decodeURIComponent(params.get('explanation') || 'This destination has been classified as malicious by SentinelIQ threat engines.');
  const action      = decodeURIComponent(params.get('action') || 'Do not proceed. Return to a safe page and report this URL to your IT team.');

  let signals = [];
  try { signals = JSON.parse(decodeURIComponent(params.get('signals') || '[]')); } catch {}

  // ── Populate static content ─────────────────────────────────────────────────
  document.getElementById('risk-num').textContent   = risk;
  document.getElementById('url-display').textContent = destUrl || 'Unknown destination';
  document.getElementById('url-display').title       = destUrl;
  document.getElementById('explanation').textContent  = explanation;
  document.getElementById('action-text').textContent  = action;
  document.getElementById('timestamp').textContent    = new Date().toLocaleTimeString();

  // Animate risk bar in after a short delay
  setTimeout(() => {
    document.getElementById('risk-bar').style.width = Math.min(risk, 100) + '%';
  }, 200);

  // ── Signals ─────────────────────────────────────────────────────────────────
  const SIGNAL_ICONS = {
    'Account Threat':       '👤',
    'Urgency Deadline':     '⏳',
    'Language Manipulation':'🧠',
    'Credential Harvest':   '🔑',
    'Brand Spoof':          '🎭',
    'Malicious URL pattern':'🔗',
  };

  const sigContainer = document.getElementById('signals-container');
  const sigList = signals.length ? signals : ['Malicious URL pattern'];
  sigContainer.innerHTML = sigList.map(s => {
    const icon = SIGNAL_ICONS[s] || '⚡';
    return `<span class="sig-chip"><span class="sig-icon">${icon}</span>${s}</span>`;
  }).join('');

  // ── Custom checkbox ──────────────────────────────────────────────────────────
  let consented = false;
  let countdownTimer = null;
  let countdownSec = 5;

  const consentBox    = document.getElementById('consent-box');
  const consentRow    = document.getElementById('consent-row');
  const proceedBtn    = document.getElementById('proceed-btn');
  const proceedZone   = document.getElementById('proceed-zone');
  const countdownEl   = document.getElementById('countdown-badge');

  function toggleConsent() {
    consented = !consented;
    consentBox.classList.toggle('checked', consented);
    proceedZone.classList.toggle('active', consented);

    if (consented) {
      startCountdown();
    } else {
      stopCountdown();
      proceedBtn.classList.remove('ready');
      proceedBtn.disabled = true;
    }
  }

  consentBox.addEventListener('click', toggleConsent);
  consentRow.addEventListener('click', (e) => {
    if (e.target === consentBox) return; // already handled
    toggleConsent();
  });

  // ── Countdown before enable ──────────────────────────────────────────────────
  function startCountdown() {
    countdownSec = 5;
    countdownEl.textContent = countdownSec + 's';
    proceedBtn.disabled = true;
    proceedBtn.classList.remove('ready');

    countdownTimer = setInterval(() => {
      countdownSec--;
      countdownEl.textContent = countdownSec + 's';
      if (countdownSec <= 0) {
        stopCountdown();
        if (consented) enableProceed();
      }
    }, 1000);
  }

  function stopCountdown() {
    if (countdownTimer) { clearInterval(countdownTimer); countdownTimer = null; }
  }

  function enableProceed() {
    proceedBtn.disabled = false;
    proceedBtn.classList.add('ready');
    countdownEl.textContent = 'GO';
  }

  // ── Proceed button ───────────────────────────────────────────────────────────
  proceedBtn.addEventListener('click', () => {
    if (proceedBtn.disabled || !consented) return;

    // Show overlay immediately so user gets instant feedback
    const overlay = document.getElementById('redirect-overlay');
    const msg     = document.getElementById('redirect-msg');
    overlay.classList.add('visible');
    msg.textContent = 'Bypassing protection…';

    // Fire the whitelist message — don't wait for response
    if (destUrl && typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({ type: 'WHITELIST_URL', url: destUrl }).catch(() => {});
    }

    // Navigate immediately on the next frame
    requestAnimationFrame(() => {
      msg.textContent = 'Navigating to destination…';

      if (!destUrl) {
        overlay.classList.remove('visible');
        return;
      }

      if (destUrl.toLowerCase().startsWith('file://')) {
        // Chrome blocks chrome-extension:// → file:// navigation; go back in history
        history.back();
      } else {
        // For web URLs use background worker which has full tab privileges
        if (typeof chrome !== 'undefined' && chrome.runtime) {
          chrome.runtime.sendMessage({ type: 'FORCE_NAVIGATE', url: destUrl });
        } else {
          window.location.href = destUrl;
        }
      }
    });
  });

  // ── Return to Safety ─────────────────────────────────────────────────────────
  document.getElementById('safe-btn').addEventListener('click', () => {
    // If there's a previous page that isn't the malicious site, go back
    // Otherwise, fall back to Google
    try {
      if (history.length > 1) {
        history.back();
      } else {
        window.location.replace('https://www.google.com');
      }
    } catch {
      window.location.replace('https://www.google.com');
    }
  });
})();
