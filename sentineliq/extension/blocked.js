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
  document.getElementById('risk-num').textContent    = risk;
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
    'Account Threat':        '👤',
    'Urgency Deadline':      '⏳',
    'Language Manipulation': '🧠',
    'Credential Harvest':    '🔑',
    'Brand Spoof':           '🎭',
    'Malicious URL pattern': '🔗',
  };

  const sigContainer = document.getElementById('signals-container');
  const sigList = signals.length ? signals : ['Malicious URL pattern'];
  sigContainer.innerHTML = sigList.map(s => {
    const icon = SIGNAL_ICONS[s] || '⚡';
    return `<span class="sig-chip"><span class="sig-icon">${icon}</span>${s}</span>`;
  }).join('');

  // ── Custom checkbox ──────────────────────────────────────────────────────────
  let consented      = false;
  let countdownTimer = null;
  let countdownSec   = 5;
  let navigating     = false;   // guard against double clicks

  const consentBox  = document.getElementById('consent-box');
  const consentRow  = document.getElementById('consent-row');
  const proceedBtn  = document.getElementById('proceed-btn');
  const proceedZone = document.getElementById('proceed-zone');
  const countdownEl = document.getElementById('countdown-badge');

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
    if (e.target === consentBox) return;
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

  // ── Core navigation ──────────────────────────────────────────────────────────
  // We use chrome.tabs.getCurrent() to get OUR OWN tab ID directly.
  // This is more reliable than relying on the background worker's sender.tab,
  // which is undefined for extension pages.
  function doNavigateNow() {
    if (!destUrl) return;

    // Whitelist first (fire-and-forget — don't await)
    try {
      chrome.runtime.sendMessage({ type: 'WHITELIST_URL', url: destUrl });
    } catch (_) {}

    // Get our own tab ID and navigate directly
    chrome.tabs.getCurrent(function (tab) {
      if (tab && tab.id) {
        chrome.tabs.update(tab.id, { url: destUrl });
      } else {
        // Fallback for http/https if tab lookup fails
        if (!destUrl.startsWith('file://')) {
          window.location.href = destUrl;
        }
      }
    });
  }

  // ── Proceed button ───────────────────────────────────────────────────────────
  proceedBtn.addEventListener('click', () => {
    if (proceedBtn.disabled || !consented || navigating) return;
    navigating = true;

    const overlay = document.getElementById('redirect-overlay');
    const msg     = document.getElementById('redirect-msg');
    overlay.classList.add('visible');
    msg.textContent = 'Navigating to destination…';

    doNavigateNow();

    // Safety valve: if chrome.tabs.update triggered a tab URL change,
    // this page will unload. If it hasn't after 4s, hide the overlay.
    setTimeout(() => {
      navigating = false;
      overlay.classList.remove('visible');
    }, 4000);
  });

  // ── Return to Safety ─────────────────────────────────────────────────────────
  document.getElementById('safe-btn').addEventListener('click', () => {
    // Navigate the current tab to Google instead of using history.back()
    // (history.back() would return to the malicious page and trigger the loop again)
    chrome.tabs.getCurrent(function (tab) {
      if (tab && tab.id) {
        chrome.tabs.update(tab.id, { url: 'https://www.google.com' });
      } else {
        window.location.replace('https://www.google.com');
      }
    });
  });
})();
