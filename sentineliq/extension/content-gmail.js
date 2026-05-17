/**
 * SentinelIQ - Gmail Content Script
 * Scopes to mail.google.com to extract and analyze email body contents.
 */

let _lastTitle = document.title;
let _bannerInjected = false;
let _scanInProgress = false;
let _navDebounce = null;

// Observe SPA navigation
const _navObserver = new MutationObserver(() => {
  if (document.title !== _lastTitle) {
    _lastTitle = document.title;
    _onEmailNavigation();
  }
});

const titleEl = document.querySelector('title');
if (titleEl) {
  _navObserver.observe(titleEl, { childList: true });
}
_navObserver.observe(document.body, { childList: true, subtree: false });

function _onEmailNavigation() {
  clearTimeout(_navDebounce);
  _navDebounce = setTimeout(() => {
    _bannerInjected = false;
    _scanInProgress = false;
    document.getElementById('siq-email-banner')?.remove();
    setTimeout(_triggerEmailScan, 800);
  }, 300);
}

// ── DOM Helpers ──
function _safeQuery(selector, context = document) {
  try { return context.querySelector(selector); } catch { return null; }
}

function _safeQueryAll(selector, context = document) {
  try { return [...context.querySelectorAll(selector)]; } catch { return []; }
}

function _getExpandedEmailBody() {
  const wrappers = _safeQueryAll('.h7');
  if (!wrappers.length) return _safeQuery('.a3s.aiL') || _safeQuery('.ii.gt div[dir="ltr"]') || _safeQuery('.a3s');
  
  for (let i = wrappers.length - 1; i >= 0; i--) {
    const body = wrappers[i].querySelector('.a3s.aiL') || wrappers[i].querySelector('.ii.gt div[dir="ltr"]') || wrappers[i].querySelector('.a3s');
    if (body && body.offsetParent !== null) return body;
  }
  return null;
}

function _isViewingEmail() {
  const composeWindow = _safeQuery('.AD');
  if (composeWindow && composeWindow.offsetParent !== null) return false; // Composing
  const body = _getExpandedEmailBody();
  return body !== null && body.offsetParent !== null;
}

// ── Extraction ──
function _extractEmailData() {
  const bodyEl = _getExpandedEmailBody();
  if (!bodyEl) return null;

  const subject = _safeQuery('h2.hP')?.innerText?.trim() || '';

  const senderEl    = _safeQuery('.go .gD[email]') || _safeQuery('.from span[email]') || _safeQuery('span[email]');
  const senderName  = senderEl?.innerText?.trim() || '';
  const senderEmail = senderEl?.getAttribute('email')?.trim() || '';

  const replyEl    = _safeQuery('.ajv .g2');
  const replyTo    = replyEl?.getAttribute('email')?.trim() || replyEl?.innerText?.trim() || '';

  const attachmentEls = _safeQueryAll('.aQA .aV3');
  const attachments   = attachmentEls.map(el => el.innerText.trim());

  const SKIP_PROTOCOLS = ['mailto:', 'tel:', 'javascript:', 'data:', '#'];
  const TRUSTED_DOMAINS = new Set([
    'google.com', 'googleapis.com', 'gstatic.com',
    'googleusercontent.com', 'youtube.com', 'accounts.google.com',
    'support.google.com', 'mail.google.com',
  ]);

  function isTrustedDomain(url) {
    try {
      const hostname = new URL(url).hostname.replace(/^www\./, '');
      return TRUSTED_DOMAINS.has(hostname) || [...TRUSTED_DOMAINS].some(d => hostname.endsWith('.' + d));
    } catch { return false; }
  }

  const rawLinks = _safeQueryAll('a[href]', bodyEl)
    .map(a => { try { return new URL(a.href).href; } catch { return null; } })
    .filter(href => href && !SKIP_PROTOCOLS.some(p => href.startsWith(p)) && !isTrustedDomain(href));

  const URL_REGEX = /https?:\/\/[^\s\])"'>]{10,}/gi;
  const rawTextMatches = (bodyEl.innerText.match(URL_REGEX) || [])
    .map(u => { try { return new URL(u).href; } catch { return null; } })
    .filter(href => href && !SKIP_PROTOCOLS.some(p => href.startsWith(p)) && !isTrustedDomain(href));

  const links = [...new Set([...rawLinks, ...rawTextMatches])].slice(0, 10);

  const bodyText = bodyEl.innerText
    .replace(/\S+@\S+\.\S+/g, '[email]')
    .substring(0, 3000);

  return {
    subject, senderName, senderEmail, replyTo, attachments, links, bodyText, url: location.href
  };
}

function _hashEmail(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = Math.imul(31, h) + str.charCodeAt(i) | 0;
  }
  return 'email_' + Math.abs(h).toString(36);
}

// ── Trigger Scan ──
async function _triggerEmailScan() {
  if (_scanInProgress) return;
  if (!location.href.includes('#')) return;
  if (!_isViewingEmail()) return;

  const data = _extractEmailData();
  if (!data) return;

  const emailHash = _hashEmail(data.subject + data.senderEmail);
  const { siq_dismissed_banners = {} } = await chrome.storage.session.get('siq_dismissed_banners');
  if (siq_dismissed_banners[emailHash]) return;

  _scanInProgress = true;
  _injectScanningIndicator();

  chrome.runtime.sendMessage({
    type:        'SCAN_EMAIL_FULL',
    bodyText:    data.bodyText,
    subject:     data.subject,
    senderName:  data.senderName,
    senderEmail: data.senderEmail,
    replyTo:     data.replyTo,
    attachments: data.attachments,
    links:       data.links,
    url:         data.url,
  });
}

function _injectScanningIndicator() {
  chrome.runtime.sendMessage({ type: 'EMAIL_SCANNING' });
}

// ── Handle Results ──
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'EMAIL_SCAN_RESULT') {
    _scanInProgress = false;
    _handleScanResult(msg);
  }
});

function _handleScanResult(msg) {
  if (msg.verdict === 'MALICIOUS' || msg.verdict === 'SUSPICIOUS') {
    if (!_bannerInjected) {
      _injectWarningBanner(msg);
      _bannerInjected = true;
    }
    _highlightDangerousLinks(msg.linkVerdictMap);
  }
}

// ── UI Injection ──
function _injectWarningBanner(msg) {
  const bodyEl = _getExpandedEmailBody();
  if (!bodyEl) return;

  const isMalicious = msg.verdict === 'MALICIOUS';
  const color       = isMalicious ? '#ef4444' : '#f59e0b';
  const bgColor     = isMalicious ? '#fef2f2' : '#fffbeb';
  const borderColor = isMalicious ? '#fca5a5' : '#fde68a';
  const icon        = isMalicious ? '🚨' : '⚠️';
  const title       = isMalicious
    ? 'SentinelIQ: Malicious Email Detected'
    : 'SentinelIQ: Suspicious Email Detected';

  const signals = (msg.shap_features || [])
    .slice(0, 4)
    .map(f => `<li style="margin:2px 0;color:#374151;font-size:12px">${f.feature}</li>`)
    .join('');

  const badUrls = (msg.urlResults || [])
    .filter(r => r && (r.verdict === 'MALICIOUS' || r.verdict === 'SUSPICIOUS'))
    .slice(0, 3)
    .map((r, i) => {
      const urlShort = (msg.links[i] || '').substring(0, 60);
      return `<li style="margin:2px 0;color:#ef4444;font-size:12px;font-family:monospace">${urlShort}</li>`;
    })
    .join('');

  const banner = document.createElement('div');
  banner.id = 'siq-email-banner';
  banner.style.cssText = `
    all: initial;
    display: block;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: ${bgColor};
    border: 1px solid ${borderColor};
    border-left: 4px solid ${color};
    border-radius: 8px;
    padding: 12px 16px;
    margin: 0 0 12px 0;
    position: relative;
    z-index: 1000;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
  `;
  banner.innerHTML = `
    <div style="display:flex;align-items:flex-start;gap:10px">
      <span style="font-size:18px;line-height:1">${icon}</span>
      <div style="flex:1">
        <div style="font-weight:700;color:${color};font-size:13px;margin-bottom:6px">${title}</div>
        ${signals ? `<ul style="margin:0 0 6px 16px;padding:0">${signals}</ul>` : ''}
        ${badUrls ? `
          <div style="font-weight:600;color:#374151;font-size:12px;margin-bottom:4px">Dangerous links detected:</div>
          <ul style="margin:0 0 0 16px;padding:0">${badUrls}</ul>
        ` : ''}
        <div style="margin-top:8px;display:flex;gap:8px">
          <button id="siq-banner-details" style="
            background:${color};color:white;border:none;border-radius:4px;
            padding:4px 10px;font-size:11px;cursor:pointer;font-weight:600">
            View in SentinelIQ
          </button>
          <button id="siq-banner-safe" style="
            background:transparent;color:#6b7280;border:1px solid #d1d5db;
            border-radius:4px;padding:4px 10px;font-size:11px;cursor:pointer">
            Mark as Safe
          </button>
        </div>
      </div>
      <button id="siq-banner-close" style="
        background:none;border:none;color:#9ca3af;cursor:pointer;
        font-size:18px;line-height:1;padding:0;margin:-2px -4px 0 0">×</button>
    </div>
  `;

  bodyEl.parentElement?.insertBefore(banner, bodyEl);

  document.getElementById('siq-banner-close')?.addEventListener('click', () => {
    banner.remove();
    _bannerInjected = false;
  });

  document.getElementById('siq-banner-safe')?.addEventListener('click', async () => {
    banner.remove();
    _bannerInjected = false;
    const emailData = _extractEmailData();
    if (emailData) {
      const hash = _hashEmail(emailData.subject + emailData.senderEmail);
      const { siq_dismissed_banners = {} } = await chrome.storage.session.get('siq_dismissed_banners');
      siq_dismissed_banners[hash] = true;
      await chrome.storage.session.set({ siq_dismissed_banners });
    }
  });

  document.getElementById('siq-banner-details')?.addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'OPEN_POPUP_EMAIL_TAB' });
  });
}

function _highlightDangerousLinks(linkVerdictMapEntries) {
  if (!linkVerdictMapEntries || linkVerdictMapEntries.length === 0) return;

  const bodyEl = _getExpandedEmailBody();
  if (!bodyEl) return;

  const verdictMap = new Map(linkVerdictMapEntries);

  _safeQueryAll('a[href]', bodyEl).forEach(linkEl => {
    let href;
    try { href = new URL(linkEl.href).href; } catch { return; }
    
    const result = verdictMap.get(href);
    if (!result) return;
    if (result.verdict !== 'MALICIOUS' && result.verdict !== 'SUSPICIOUS') return;

    if (linkEl.parentElement?.classList?.contains('siq-link-wrapper')) return;

    const isMalicious = result.verdict === 'MALICIOUS';
    const wrapColor   = isMalicious ? '#ef4444' : '#f59e0b';

    const wrapper = document.createElement('span');
    wrapper.className = 'siq-link-wrapper';
    wrapper.style.cssText = `
      display: inline;
      outline: 2px solid ${wrapColor};
      outline-offset: 1px;
      border-radius: 2px;
      position: relative;
    `;

    const tooltip = document.createElement('span');
    tooltip.className = 'siq-link-tooltip';
    tooltip.style.cssText = `
      display: none;
      position: absolute;
      bottom: 100%;
      left: 0;
      background: #1f2937;
      color: white;
      font-size: 11px;
      padding: 4px 8px;
      border-radius: 4px;
      white-space: nowrap;
      z-index: 9999;
      pointer-events: none;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    `;
    tooltip.textContent = isMalicious
      ? \`⚠ SentinelIQ: Malicious URL (\${Math.round((result.confidence||0)*100)}% confidence)\`
      : \`⚠ SentinelIQ: Suspicious URL (\${Math.round((result.confidence||0)*100)}% confidence)\`;

    wrapper.appendChild(tooltip);
    linkEl.parentNode?.insertBefore(wrapper, linkEl);
    wrapper.appendChild(linkEl);

    wrapper.addEventListener('mouseenter', () => { tooltip.style.display = 'block'; });
    wrapper.addEventListener('mouseleave', () => { tooltip.style.display = 'none'; });
  });
}

// Initial trigger
setTimeout(_triggerEmailScan, 1200);
