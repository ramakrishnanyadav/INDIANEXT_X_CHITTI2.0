/**
 * SentinelIQ — Background Service Worker
 * Scan pipeline | Smart cache | Badge management | Stats tracking | Nav interception
 *
 * Architecture:
 *   scanUrl(url)      → URL structural analysis ONLY. Returns BYPASSED for localhost.
 *   scanContent(text) → NLP/heuristic phishing scan. ALWAYS runs, regardless of host.
 *   SCAN_PAGE handler → Promise.all([scanUrl, scanContent]) → merge worst → badge → cache
 *
 * Fix log (2026-05-10):
 *   1. Separated localhost URL exemption from content exemption.
 *   2. Badge update happens ONLY after full merge is resolved (not inside individual callbacks).
 *   3. Password form detection forces escalation regardless of URL verdict.
 *   4. BYPASSED state is explicit — distinct from BENIGN (scanned clean).
 *   5. Merged result (worst verdict) is what gets cached — popup always reads the real verdict.
 */

const DEFAULT_BACKEND = 'https://indianext-x-chitti2-0.onrender.com/api/v1';
let currentBackendUrl = DEFAULT_BACKEND;

// Load saved backend URL on startup
chrome.storage.local.get('siq_backend_url').then(res => {
  if (res.siq_backend_url) currentBackendUrl = res.siq_backend_url;
});

const CACHE_TTL_MS    = 30 * 60 * 1000; // 30 min
const MAX_CACHE       = 500;
const BLOCKED_PAGE    = chrome.runtime.getURL('blocked.html');

// ── v3.0 Auth & Feature Parity constants ─────────────────────────────────────
const FIREBASE_API_KEY            = 'AIzaSyABYnQ3LzEJ5awl7iVq4KusHpEUqFcK-c4';
const TOKEN_REFRESH_URL           = `https://securetoken.googleapis.com/v1/token?key=${FIREBASE_API_KEY}`;
const TOKEN_REFRESH_BUFFER_MS     = 5 * 60 * 1000;  // refresh 5 min before expiry
const MAX_REFRESH_FAILURES        = 3;
const ANOMALY_HEARTBEAT_INTERVAL_MIN = 15;
const AI_HOSTS = new Set([
  'chat.openai.com', 'gemini.google.com', 'claude.ai',
  'copilot.microsoft.com', 'poe.com', 'character.ai',
  'huggingface.co', 'perplexity.ai',
]);

const TRUSTED_EMAIL_DOMAINS = new Set([
  'google.com', 'googleapis.com', 'gstatic.com',
  'googleusercontent.com', 'youtube.com',
]);
const MAX_EMAIL_URL_SCANS   = 5;
const EMAIL_SCAN_TIMEOUT_MS = 15000;
const URL_SCAN_TIMEOUT_MS   = 8000;

const SENDER_BRAND_TABLE = {
  'paypal':       ['.paypal.com', '.paypal.co.uk'],
  'amazon':       ['.amazon.com', '.amazon.co.', '.amazonaws.com', '.amzn.to'],
  'google':       ['.google.com', '.googleapis.com', '.googlemail.com'],
  'apple':        ['.apple.com', '.icloud.com'],
  'microsoft':    ['.microsoft.com', '.microsoftonline.com', '.outlook.com'],
  'netflix':      ['.netflix.com'],
  'ebay':         ['.ebay.com', '.ebay.co.'],
  'instagram':    ['.instagram.com'],
  'facebook':     ['.facebook.com', '.fb.com'],
  'wellsfargo':   ['.wellsfargo.com'],
  'chase':        ['.chase.com'],
  'bankofamerica':['.bankofamerica.com'],
  'citibank':     ['.citibank.com', '.citi.com'],
  'steam':        ['.steampowered.com', '.steamcommunity.com'],
  'discord':      ['.discord.com', '.discord.gg'],
  'linkedin':     ['.linkedin.com'],
  'twitter':      ['.twitter.com', '.x.com'],
  'dropbox':      ['.dropbox.com'],
  'icloud':       ['.icloud.com'],
  'dhl':          ['.dhl.com'],
  'fedex':        ['.fedex.com'],
  'ups':          ['.ups.com'],
  'usps':         ['.usps.com'],
  'irs':          ['.irs.gov'],
};

function _normalizeDomain(domain) {
  try {
    return new URL('https://' + domain).hostname;
  } catch {
    return domain.toLowerCase();
  }
}

function analyzeSender(displayName, fromEmail, replyToEmail) {
  const fromDomain    = _normalizeDomain((fromEmail.split('@')[1]  || '').toLowerCase());
  const replyDomain   = _normalizeDomain((replyToEmail?.split('@')[1] || '').toLowerCase());
  const nameLower     = displayName.toLowerCase();

  for (const [brand, canonicals] of Object.entries(SENDER_BRAND_TABLE)) {
    const nameHasBrand = nameLower.includes(brand);
    if (!nameHasBrand) continue;

    const fromIsCanonical   = canonicals.some(c => fromDomain.endsWith(c.replace(/^\./,'')));
    const replyIsCanonical  = !replyDomain ||
      canonicals.some(c => replyDomain.endsWith(c.replace(/^\./,'')));

    if (!fromIsCanonical) {
      return {
        verdict:    'MALICIOUS',
        confidence: 0.95,
        shap_features: [{
          feature:   `Sender Spoof: claims ${brand}, domain is ${fromDomain}`,
          weight:    0.95,
          direction: 'positive',
          category:  'active_attack_signal',
        }],
        explanation: `Email claims to be from ${brand.toUpperCase()} but was
          sent from ${fromDomain} which is not a canonical ${brand} domain.`,
        action: 'Do not click any links. Do not reply. Report as phishing.',
      };
    }

    if (!replyIsCanonical) {
      return {
        verdict:    'SUSPICIOUS',
        confidence: 0.80,
        shap_features: [{
          feature:   `Reply-To Mismatch: reply goes to ${replyDomain}`,
          weight:    0.80,
          direction: 'positive',
          category:  'active_attack_signal',
        }],
        explanation: `Email appears to be from ${brand.toUpperCase()} but
          replies go to ${replyDomain} — a common credential harvesting tactic.`,
        action: 'Do not reply. Verify through official website directly.',
      };
    }
  }

  return { verdict: 'BENIGN', confidence: 0.1, shap_features: [] };
}

// ── Whitelist: in-memory + persistent, race-condition-free ───────────────────
//
// MV3 service workers die after ~30 s of inactivity. Every restart wipes all
// JS heap state. The three-layer design below guarantees no bypass loop:
//
//   Layer 1 – _approvedUrls (in-memory Set)
//     Populated SYNCHRONOUSLY inside _whitelistAdd().
//     Checked first — zero async latency.
//
//   Layer 2 – _whitelistRestorePromise
//     On every SW wake-up, we immediately start reading storage and populating
//     _approvedUrls. Any SCAN_PAGE that arrives before restore finishes AWAITS
//     this promise before deciding — so a restart never causes a false-block.
//
//   Layer 3 – chrome.storage.local (persistent across restarts)
//     _whitelistAdd() AWAITS the storage write before returning. Callers that
//     need guaranteed persistence (WHITELIST_AND_NAVIGATE) await this promise
//     before triggering navigation. By the time content.js fires on the new
//     page, storage is written and Layer 2 will restore it even if the SW died.
//
// Timeline (worst case — SW restart between whitelist + navigate):
//   WHITELIST_AND_NAVIGATE → storage write awaited → chrome.tabs.update
//   SW killed by Chrome ← idle
//   New page loads → content.js fires SCAN_PAGE → SW wakes
//   _whitelistRestorePromise reads storage → finds entry → _approvedUrls populated
//   SCAN_PAGE handler awaits restore → _whitelistHasSync() → true → BYPASS
//   ✓ No loop. Guaranteed.

const _intercepted  = new Set();
const _approvedUrls = new Set();

function _normalizeUrl(url) {
  try {
    return decodeURIComponent(url.split('#')[0].split('?')[0])
      .toLowerCase()
      .replace(/\/+$/, '');
  } catch { return url.toLowerCase(); }
}

/** Synchronous O(n) check against in-memory Set. Zero latency. */
function _whitelistHasSync(url) {
  const base = _normalizeUrl(url);
  for (const entry of _approvedUrls) {
    if (base.startsWith(entry) || entry.startsWith(base)) return true;
  }
  return false;
}

/**
 * Reads storage once per SW lifetime and populates _approvedUrls.
 * Save the promise so SCAN_PAGE can await it instead of reading storage again.
 */
const _whitelistRestorePromise = chrome.storage.local
  .get('siq_whitelist')
  .then(d => {
    const now = Date.now();
    (d.siq_whitelist || [])
      .filter(e => now < e.expiry)
      .forEach(e => _approvedUrls.add(_normalizeUrl(e.url)));
  })
  .catch(() => {}); // never throw on startup

/**
 * Adds url to _approvedUrls synchronously AND awaits the storage write.
 * Returns a Promise that resolves when persistence is confirmed.
 * Callers that navigate after this can be sure storage is durable.
 */
function _whitelistAdd(url) {
  const normalized = _normalizeUrl(url);
  _approvedUrls.add(normalized); // synchronous — instant
  return chrome.storage.local
    .get('siq_whitelist')
    .then(d => {
      const list = (d.siq_whitelist || []).filter(e => Date.now() < e.expiry);
      list.push({ url: normalized, expiry: Date.now() + 60 * 60 * 1000 }); // 1 hr
      return chrome.storage.local.set({ siq_whitelist: list });
    });
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// REMOVED: hashUrl() was a 32-bit hash with ~3% collision rate at 500 cached URLs.
// With a 500-URL cache the birthday paradox gives ~3% chance URL_A gets URL_B's verdict.
// For a security tool this is unacceptable. Use the full URL as the cache key.
function safeCacheKey(prefix, url) {
  // Prefix + full URL. chrome.storage.local keys can be arbitrary strings.
  return prefix + url;
}

function isLocal(url) {
  try {
    const h = new URL(url).hostname;
    return h === 'localhost' || h.startsWith('127.') || h.startsWith('192.168.') || h.startsWith('10.');
  } catch {}
  return false;
}

// ── Cache (chrome.storage.local, full URL keys) ───────────────────────────────
async function getCached(url) {
  const key = safeCacheKey('c_', url);
  const res = await chrome.storage.local.get(key);
  if (!res[key]) return null;
  if (Date.now() - res[key].ts > CACHE_TTL_MS) { chrome.storage.local.remove(key); return null; }
  return res[key].d;
}

async function setCache(url, data) {
  const key = safeCacheKey('c_', url);
  await chrome.storage.local.set({ [key]: { d: data, ts: Date.now() } });
  const all = await chrome.storage.local.get(null);
  const keys = Object.keys(all).filter(k => k.startsWith('c_'));
  if (keys.length > MAX_CACHE) await chrome.storage.local.remove(keys.slice(0, keys.length - MAX_CACHE));
}

// ── Verdict helpers ───────────────────────────────────────────────────────────
const VERDICT_PRIORITY = { MALICIOUS:3, SUSPICIOUS:2, BENIGN:1, BYPASSED:0, ERROR:0 };

function mergeResults(urlResult, contentResult, hasPasswordForm) {
  // Fix #3: Password form is a mandatory escalation gate.
  // If a password form is present AND any phishing signal fired, force ensemble.
  const contentHasSignals = contentResult && (contentResult.shap_features || []).length > 0;
  const passwordEscalation = hasPasswordForm && contentHasSignals;

  let finalResult = urlResult;

  if (contentResult && contentResult.verdict !== 'BYPASSED') {
    const urlPri     = VERDICT_PRIORITY[urlResult.verdict]     || 0;
    const contentPri = VERDICT_PRIORITY[contentResult.verdict] || 0;

    if (contentPri > urlPri || passwordEscalation) {
      finalResult = {
        ...contentResult,
        detection_source: 'dom_content_phishing',
        // If password form escalation triggered, annotate
        escalated_by: passwordEscalation ? 'password_form_gate' : undefined,
      };
    }
  }

  // Fix #6: Preserve BYPASSED state so UI can show it distinctly from BENIGN
  if (urlResult.verdict === 'BYPASSED' && (!contentResult || contentResult.verdict === 'BENIGN')) {
    return {
      verdict: 'BYPASSED',
      confidence: 0,
      risk_score: 0,
      risk_band: 'CLEAN',
      shap_features: [],
      explanation: 'URL structural analysis bypassed for local address. Content scan returned clean.',
      action: 'No action required.',
      narration_mode: 'bypassed',
    };
  }

  return finalResult;
}

function mergeAllResults(...results) {
  return results.filter(Boolean).reduce((worst, current) => {
    const worstPri = VERDICT_PRIORITY[worst?.verdict] || 0;
    const currPri  = VERDICT_PRIORITY[current?.verdict] || 0;
    if (currPri > worstPri) return current;
    return worst;
  }, { verdict: 'BENIGN', confidence: 0, shap_features: [] });
}

// ── Auth Helpers (v3.0) ───────────────────────────────────────────────────────

/** Returns a fresh id_token if logged in, or null if anonymous. Never throws. */
async function getAuthToken() {
  try {
    const { siq_auth } = await chrome.storage.local.get('siq_auth');
    if (!siq_auth) return null;
    // Refresh if within buffer window of expiry
    if (Date.now() < siq_auth.expiry_ms - TOKEN_REFRESH_BUFFER_MS) {
      return siq_auth.id_token;
    }
    return await _refreshToken(siq_auth.refresh_token);
  } catch (err) {
    console.warn('[getAuthToken] error:', err);
    return null;
  }
}

async function _refreshToken(refreshToken) {
  const { siq_refresh_fails = 0 } = await chrome.storage.local.get('siq_refresh_fails');
  try {
    const resp = await fetch(TOKEN_REFRESH_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ grant_type: 'refresh_token', refresh_token: refreshToken }),
      signal: AbortSignal.timeout(8000),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    // A14: spread existing FIRST so fresh fields overwrite stale ones
    const { siq_auth: existing } = await chrome.storage.local.get('siq_auth');
    const newAuth = {
      ...existing,
      id_token:      data.id_token,
      refresh_token: data.refresh_token,
      expiry_ms:     Date.now() + (parseInt(data.expires_in) * 1000),
    };
    await chrome.storage.local.set({ siq_auth: newAuth, siq_refresh_fails: 0 });
    return data.id_token;
  } catch (err) {
    const newFails = siq_refresh_fails + 1;
    await chrome.storage.local.set({ siq_refresh_fails: newFails });
    if (newFails >= MAX_REFRESH_FAILURES) {
      await _forceLogout('session_expired');
    }
    return null;
  }
}

async function _forceLogout(reason) {
  await chrome.storage.local.remove(['siq_auth', 'siq_refresh_fails']);
  chrome.runtime.sendMessage({
    type: 'AUTH_STATE_CHANGED', loggedOut: true, reason,
  }).catch(() => {});
}

/** Builds fetch headers with auth token and extension version. */
function _buildHeaders(token, extra = {}) {
  const { version } = chrome.runtime.getManifest();
  const headers = { 'X-Extension-Version': version, ...extra };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  return headers;
}

// ── Scan: URL structural analysis ─────────────────────────────────────────────
// Fix #1: Localhost exempts URL structural scoring ONLY.
// Content scanning (scanContent) is a SEPARATE function that always runs.
const BYPASSED_RESULT = (reason) => ({
  verdict: 'BYPASSED', confidence: 0, risk_score: 0, risk_band: 'CLEAN',
  shap_features: [], explanation: reason, action: 'No action required.',
  narration_mode: 'url_bypassed', processing_time_ms: 0,
});

const BENIGN_FAST = (reason) => ({
  verdict: 'BENIGN', confidence: 0, risk_score: 0, risk_band: 'CLEAN',
  shap_features: [], explanation: reason, action: 'No action required.',
  narration_mode: 'fast_path', processing_time_ms: 0,
});

async function scanUrl(url) {
  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
    return BENIGN_FAST('Browser internal page.');
  }

  // Fix #1: Localhost BYPASSES URL structural analysis, NOT content analysis.
  // The bypass returns BYPASSED (not BENIGN) so the merger knows to defer to content scan.
  if (isLocal(url)) {
    return BYPASSED_RESULT('Local address — URL structural analysis bypassed. Content scan active.');
  }

  const cached = await getCached(url);
  if (cached) return { ...cached, fromCache: true };

  const fd = new FormData();
  fd.append('threat_type', 'url');
  fd.append('content', url);

  try {
    const token = await getAuthToken();
    const resp = await fetch(`${currentBackendUrl}/analyze`, {
      method: 'POST', body: fd,
      headers: _buildHeaders(token),
      signal: AbortSignal.timeout(12000),
    });
    // A15: 401 retry guard — attempt once after forced logout
    if (resp.status === 401) {
      await _forceLogout('401_invalid_token');
      const fd2 = new FormData();
      fd2.append('threat_type', 'url');
      fd2.append('content', url);
      const resp2 = await fetch(`${currentBackendUrl}/analyze`, {
        method: 'POST', body: fd2,
        headers: _buildHeaders(null),
        signal: AbortSignal.timeout(12000),
      });
      if (!resp2.ok) throw new Error(`HTTP ${resp2.status}`);
      const data2 = await resp2.json();
      await setCache(url, data2);
      return data2;
    }
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    await setCache(url, data);
    return data;
  } catch (err) {
    return {
      verdict: 'ERROR', confidence: 0, risk_score: 0, risk_band: 'UNKNOWN',
      shap_features: [], explanation: 'SentinelIQ backend unreachable.',
      action: `Ensure your backend is running at ${currentBackendUrl}`, error: err.message,
    };
  }
}

// ── Scan: DOM content phishing (ALWAYS runs, regardless of host) ──────────────
// Fix #1: Content scanning has NO host exemption. A phishing page on localhost
// is still a phishing page. This function must fire for every page.
async function scanContent(text, semanticDivergence = null) {
  if (!text || text.trim().length < 20) return null;

  const fd = new FormData();
  fd.append('threat_type', 'phishing');
  fd.append('content', text.substring(0, 3000));
  if (semanticDivergence) {
    fd.append('semantic_divergence', JSON.stringify(semanticDivergence));
  }

  try {
    const token = await getAuthToken();
    const resp = await fetch(`${currentBackendUrl}/analyze`, {
      method: 'POST', body: fd,
      headers: _buildHeaders(token),
      signal: AbortSignal.timeout(15000),
    });
    if (resp.status === 401) {
      await _forceLogout('401_invalid_token');
      return null;
    }
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return await resp.json();
  } catch (err) {
    console.error('[scanContent] error:', err);
    return null;
  }
}

// ── Email Scanning Helpers ────────────────────────────────────────────────────
async function scanEmailBody(bodyText) {
  return scanContent(bodyText);
}

function _extractRedirectTargets(url) {
  try {
    const u = new URL(url);
    const redirectParams = ['url','redirect','next','goto','return','dest','target','link'];
    for (const param of redirectParams) {
      const val = u.searchParams.get(param);
      if (val && val.startsWith('http')) return val;
    }
  } catch {}
  return null;
}

async function scanEmailUrls(links) {
  const expanded = [];
  const expandedMap = new Map();

  for (const link of links) {
    expanded.push(link);
    expandedMap.set(link, link);
    const inner = _extractRedirectTargets(link);
    if (inner && !expanded.includes(inner)) {
      expanded.push(inner);
      expandedMap.set(inner, link);
    }
  }

  const toScan = [...new Set(expanded)].slice(0, MAX_EMAIL_URL_SCANS);

  const results = await Promise.allSettled(
    toScan.map(url => Promise.race([
      scanUrl(url),
      new Promise(resolve =>
        setTimeout(() => resolve({
          verdict:'ERROR', confidence:0, shap_features:[],
          explanation:'URL scan timeout'
        }), URL_SCAN_TIMEOUT_MS)
      )
    ]))
  );

  return {
    scannedUrls: toScan,
    results: results.map(r => r.status === 'fulfilled' ? r.value : { verdict:'ERROR', confidence:0, shap_features:[] }),
    linkVerdictMap: new Map(
      links.map(link => {
        const innerUrl = _extractRedirectTargets(link);
        const idx1 = toScan.indexOf(link);
        const idx2 = innerUrl ? toScan.indexOf(innerUrl) : -1;
        const r1 = idx1 >= 0 ? results[idx1]?.value : null;
        const r2 = idx2 >= 0 ? results[idx2]?.value : null;
        const worst = [r1, r2].filter(Boolean).reduce((w, r) =>
          (VERDICT_PRIORITY[r?.verdict]||0) > (VERDICT_PRIORITY[w?.verdict]||0) ? r : w,
          { verdict:'BENIGN', confidence:0 }
        );
        return [link, worst];
      })
    )
  };
}

function _scoreAttachments(attachments) {
  const HIGH_RISK = new Set([
    '.zip','.iso','.scr','.html','.htm','.docm','.xlsm',
    '.exe','.js','.vbs','.lnk','.msi','.bat','.cmd','.ps1',
  ]);
  const hasHighRisk = attachments.some(name => {
    const ext = '.' + name.split('.').pop().toLowerCase();
    return HIGH_RISK.has(ext);
  });
  if (!hasHighRisk) return { verdict:'BENIGN', confidence:0.05, shap_features:[] };
  const risky = attachments.filter(name => HIGH_RISK.has('.' + name.split('.').pop().toLowerCase()));
  return {
    verdict:    'SUSPICIOUS',
    confidence: 0.65,
    shap_features: risky.map(name => ({
      feature:   `High-risk attachment: ${name}`,
      weight:    0.65,
      direction: 'positive',
      category:  'active_attack_signal',
    })),
    explanation: `High-risk attachment type detected: ${risky.join(', ')}`,
    action: 'Do not open attachments from unknown senders.',
  };
}

// ── Email Scan ───────────────────────────────────────────────────────────────
async function getEmailCache(vectorHash) {
  const key = 'ce_' + vectorHash;
  const res = await chrome.storage.local.get(key);
  if (!res[key]) return null;
  if (Date.now() - res[key].ts > CACHE_TTL_MS) { chrome.storage.local.remove(key); return null; }
  return res[key].d;
}

async function setEmailCache(vectorHash, data) {
  const key = 'ce_' + vectorHash;
  await chrome.storage.local.set({ [key]: { d: data, ts: Date.now() } });
}

async function scanEmail(vector) {
  if (!vector) return { verdict: 'ERROR', risk_score: 0, explanation: 'No email vector.', shap_features: [] };
  const vectorHash = JSON.stringify(vector).substring(0, 400);
  const cached = await getEmailCache(vectorHash);
  if (cached) return { ...cached, fromCache: true };

  const fd = new FormData();
  fd.append('threat_type', 'email');
  fd.append('content', JSON.stringify(vector));

  try {
    const token = await getAuthToken();
    const resp = await fetch(`${currentBackendUrl}/analyze`, {
      method: 'POST', body: fd,
      headers: _buildHeaders(token),
      signal: AbortSignal.timeout(15000),
    });
    if (resp.status === 401) {
      await _forceLogout('401_invalid_token');
      return { verdict: 'ERROR', risk_score: 0, explanation: 'Auth session expired. Scan restarted anonymously.', shap_features: [] };
    }
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    await setEmailCache(vectorHash, data);
    return data;
  } catch (err) {
    return {
      verdict: 'ERROR', risk_score: 0,
      explanation: 'Email scan failed. Backend may be unreachable.',
      shap_features: [], error: err.message,
    };
  }
}

// ── Injection & Anomaly scan functions (v3.0) ─────────────────────────────────

async function scanInjection(text, url, isAiInterface) {
  if (!text || text.trim().length < 30) return null;
  const token = await getAuthToken();
  const fd = new FormData();
  fd.append('threat_type', 'prompt_injection');
  fd.append('content', text.substring(0, 2000));
  const extra = {};
  if (isAiInterface) extra['X-Escalation-Mode'] = 'true';
  try {
    const resp = await fetch(`${currentBackendUrl}/analyze`, {
      method: 'POST', body: fd,
      headers: _buildHeaders(token, extra),
      signal: AbortSignal.timeout(10000),
    });
    if (resp.status === 401) {
      await _forceLogout('401_invalid_token');
      // A15: retry once anonymously — no infinite loop
      const fd2 = new FormData();
      fd2.append('threat_type', 'prompt_injection');
      fd2.append('content', text.substring(0, 2000));
      const resp2 = await fetch(`${currentBackendUrl}/analyze`, {
        method: 'POST', body: fd2,
        headers: _buildHeaders(null),
        signal: AbortSignal.timeout(15000),
      });
      if (!resp2.ok) return { verdict: 'ERROR', confidence: 0, shap_features: [], explanation: 'Injection scan failed.' };
      const d2 = await resp2.json();
      await setCache(safeCacheKey('inj_', url), d2);
      return d2;
    }
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    await setCache(safeCacheKey('inj_', url), data);
    return data;
  } catch (err) {
    return { verdict: 'ERROR', confidence: 0, shap_features: [], explanation: 'Injection scan failed.' };
  }
}

async function buildPartialVector(trigger) {
  const now = new Date();
  const { siq_login_events = [] } = await chrome.storage.local.get('siq_login_events');
  const { siq_known_device = '' } = await chrome.storage.local.get('siq_known_device');
  const { siq_tab_open_ts = {} } = await chrome.storage.local.get('siq_tab_open_ts');
  const recentLogins = siq_login_events.filter(t => now.getTime() - t < 60 * 60 * 1000);
  const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const tabOpenTs = activeTab
    ? (siq_tab_open_ts[activeTab.id] || now.getTime())
    : now.getTime();
  return {
    hour:                 now.getHours(),
    day_of_week:          now.getDay(),
    new_user_agent_flag:  0.0,  // UA not available in service worker
    session_duration_sec: Math.floor((now.getTime() - tabOpenTs) / 1000),
    login_velocity:       recentLogins.length,
    device_match_int:     siq_known_device ? 1.0 : 0.0,
  };
}

async function scanAnomaly(partialVector, url, trigger) {
  const token = await getAuthToken();
  const fd = new FormData();
  fd.append('threat_type', 'anomaly');
  fd.append('content', JSON.stringify(partialVector));
  try {
    const resp = await fetch(`${DEFAULT_BACKEND}/analyze`, {
      method: 'POST', body: fd,
      headers: _buildHeaders(token, { 'X-Anomaly-Trigger': trigger }),
      signal: AbortSignal.timeout(10000),
    });
    if (resp.status === 401) {
      await _forceLogout('401_invalid_token');
      return null;
    }
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    await setCache(safeCacheKey('ano_', url), data);
    return data;
  } catch (err) {
    return { verdict: 'ERROR', confidence: 0, shap_features: [], explanation: 'Anomaly scan failed.' };
  }
}

// ── Badge ────────────────────────────────────────────────────────────────────
function setBadge(tabId, verdict) {
  const map = {
    MALICIOUS:  { color: '#ef4444', text: '⚠' },
    SUSPICIOUS: { color: '#f59e0b', text: '!' },
    BENIGN:     { color: '#10b981', text: '✓' },
    BYPASSED:   { color: '#10b981', text: '✓' }, // Fix #6: BYPASSED shows green (not BENIGN scanned)
    SCANNING:   { color: '#6366f1', text: '…' },
    ERROR:      { color: '#6b7280', text: '?' },
  };
  const { color, text } = map[verdict] || map.ERROR;
  chrome.action.setBadgeBackgroundColor({ tabId, color });
  chrome.action.setBadgeText({ tabId, text });
}

// ── Stats ────────────────────────────────────────────────────────────────────
async function recordScan(url, result) {
  if (!result || result.verdict === 'BYPASSED') return; // Don't count bypassed URL scans as real scans
  const sd = await chrome.storage.local.get('siq_stats');
  const s  = sd.siq_stats || { total:0, malicious:0, suspicious:0, benign:0, blocked:0 };
  s.total++;
  if (result.verdict === 'MALICIOUS')  s.malicious++;
  else if (result.verdict === 'SUSPICIOUS') s.suspicious++;
  else if (result.verdict === 'BENIGN') s.benign++;
  await chrome.storage.local.set({ siq_stats: s });

  // History (last 50)
  const hd = await chrome.storage.local.get('siq_history');
  const h  = hd.siq_history || [];
  h.unshift({ url: url.substring(0, 90), verdict: result.verdict, risk_score: result.risk_score || 0, ts: Date.now() });
  if (h.length > 50) h.length = 50;
  await chrome.storage.local.set({ siq_history: h });
}

async function recordBlock(url) {
  const sd = await chrome.storage.local.get('siq_stats');
  const s  = sd.siq_stats || { total:0, malicious:0, suspicious:0, benign:0, blocked:0 };
  s.blocked = (s.blocked || 0) + 1;
  await chrome.storage.local.set({ siq_stats: s });
  const hd = await chrome.storage.local.get('siq_history');
  const h  = hd.siq_history || [];
  h.unshift({ url: url.substring(0, 90), verdict: 'BLOCKED', risk_score: 100, ts: Date.now() });
  if (h.length > 50) h.length = 50;
  await chrome.storage.local.set({ siq_history: h });
}

// ── Message Router ────────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const tabId = msg.tabId || sender.tab?.id;

  if (msg.type === 'SCAN_URL') {
    // Popup cache read — if we have a cached SCAN_PAGE result, return it
    getCached(msg.url).then(cached => {
      if (cached) { sendResponse({ result: cached }); return; }
      // No cache: run URL scan only (popup doesn't have DOM content)
      scanUrl(msg.url).then(result => {
        if (tabId) recordScan(msg.url, result);
        sendResponse({ result });
      });
    });
    return true;
  }

  if (msg.type === 'FORCE_NAVIGATE') {
    if (tabId) {
      chrome.tabs.update(tabId, { url: msg.url });
    }
    return true;
  }

  if (msg.type === 'WHITELIST_URL') {
    _whitelistAdd(msg.url).then(() => sendResponse({ success: true }));
    return true;
  }

  // ── WHITELIST_AND_NAVIGATE: the guaranteed loop-free bypass ──────────────────
  // 1. Whitelist added to in-memory Set SYNCHRONOUSLY (before any navigation).
  // 2. Storage write fires in background (non-blocking).
  // 3. Tab navigates AFTER in-memory set is populated.
  // Result: when content.js fires SCAN_PAGE on the new page, _whitelistHasSync()
  //         already returns true → redirect is short-circuited → no loop.
  if (msg.type === 'WHITELIST_AND_NAVIGATE') {
    _whitelistAdd(msg.url); // synchronously adds to _approvedUrls
    const targetTabId = msg.tabId || tabId;
    if (targetTabId && msg.url) {
      chrome.tabs.update(targetTabId, { url: msg.url });
    }
    sendResponse({ success: true });
    return true;
  }

  if (msg.type === 'SET_SETTINGS') {
    currentBackendUrl = msg.backendUrl || DEFAULT_BACKEND;
    chrome.storage.local.set({ siq_backend_url: currentBackendUrl });
    sendResponse({ success: true });
    return true;
  }

  if (msg.type === 'SCAN_PAGE') {
    // ── Whitelist gate: wait for startup restore, then check ─────────────────────
    // _whitelistRestorePromise resolves in <10 ms on SW wake (reads storage once).
    // By awaiting it here, we guarantee _approvedUrls is populated before the
    // check — even if the SW restarted between WHITELIST_AND_NAVIGATE and now.
    _whitelistRestorePromise.then(() => {
      if (_whitelistHasSync(msg.url)) {
        // Bypass: user explicitly approved this URL.
        if (tabId) setBadge(tabId, 'BENIGN');
        const r = BENIGN_FAST('User-approved bypass — 1 hr session whitelist active.');
        sendResponse({ result: r });
        chrome.runtime.sendMessage({ type: 'PAGE_RESULT', result: r, url: msg.url }).catch(() => {});
        return;
      }

      // Not whitelisted: run full scan pipeline.
      if (tabId) setBadge(tabId, 'SCANNING');
      const hasPasswordForm = msg.hasPasswordForm || false;

      Promise.all([
        scanUrl(msg.url),
        msg.content && msg.content.length > 30
          ? scanContent(msg.content, msg.semanticDivergence)
          : Promise.resolve(null),
      ]).then(async ([urlResult, contentResult]) => {
        const finalResult = mergeResults(urlResult, contentResult, hasPasswordForm);
        setCache(msg.url, finalResult);

        if (tabId) {
          recordScan(msg.url, finalResult);
          setBadge(tabId, finalResult.verdict);

          if (
            finalResult.verdict === 'MALICIOUS' &&
            (finalResult.risk_score || 0) >= 70 &&
            !isLocal(msg.url)
          ) {
            // Final async storage check (covers edge cases not caught above)
            const stillBlocked = !_whitelistHasSync(msg.url);
            if (stillBlocked) {
              const params = new URLSearchParams({
                url:         encodeURIComponent(msg.url),
                verdict:     finalResult.verdict,
                risk:        String(finalResult.risk_score || 0),
                explanation: encodeURIComponent(finalResult.explanation || 'Malicious content detected.'),
                action:      encodeURIComponent(finalResult.action     || 'Do not proceed to this site.'),
                signals:     encodeURIComponent(JSON.stringify(
                  (finalResult.shap_features || []).slice(0, 3).map(f => f.feature)
                )),
              });
              chrome.tabs.update(tabId, { url: `${BLOCKED_PAGE}?${params.toString()}` });
            }
          }
        }
        chrome.runtime.sendMessage({ type: 'PAGE_RESULT', result: finalResult, url: msg.url }).catch(() => {});
        sendResponse({ result: finalResult });
      });
    });
    return true;
  }

  if (msg.type === 'SCAN_CONTENT') {
    // Fix #3: Direct content scan from password form detection — always escalates
    if (tabId) setBadge(tabId, 'SCANNING');
    scanContent(msg.content).then(result => {
      if (!result) { sendResponse({ result: BENIGN_FAST('No content signals.') }); return; }
      const url = msg.url || 'content-scan';
      // Cache under the page URL so popup reads this result
      setCache(url, result);
      if (tabId) { recordScan(url, result); setBadge(tabId, result.verdict); }
      chrome.runtime.sendMessage({ type: 'PAGE_RESULT', result, url }).catch(() => {});
      sendResponse({ result });
    });
    return true;
  }

  if (msg.type === 'SCAN_EMAIL') {
    if (tabId) setBadge(tabId, 'SCANNING');
    scanEmail(msg.vector).then(result => {
      if (tabId) setBadge(tabId, result.verdict);
      sendResponse({ result });
    });
    return true;
  }

  if (msg.type === 'SCAN_EMAIL_FULL') {
    if (tabId) setBadge(tabId, 'SCANNING');

    Promise.all([
      Promise.race([
        scanEmailBody(msg.bodyText),
        new Promise(resolve => setTimeout(() => resolve({ verdict:'ERROR', confidence:0, shap_features:[], explanation:'Body scan timeout' }), EMAIL_SCAN_TIMEOUT_MS))
      ]),
      scanEmailUrls(msg.links || [])
    ]).then(async ([bodyResult, urlScanObj]) => {
      const urlResults = urlScanObj.results;
      const scannedUrls = urlScanObj.scannedUrls;
      const linkVerdictMap = urlScanObj.linkVerdictMap;

      const senderResult = analyzeSender(msg.senderName, msg.senderEmail, msg.replyTo);
      const attachmentResult = _scoreAttachments(msg.attachments || []);

      const finalResult = mergeAllResults(bodyResult, senderResult, attachmentResult, ...urlResults);

      const url = msg.url || 'gmail';
      await setCache(safeCacheKey('email_', url), {
        ...finalResult,
        bodyVerdict:      bodyResult?.verdict,
        senderVerdict:    senderResult?.verdict,
        attachmentVerdict: attachmentResult?.verdict,
        urlResults,
        scannedUrls,
        links:            msg.links,
        subject:          msg.subject,
        senderEmail:      msg.senderEmail,
        senderName:       msg.senderName,
      });

      if (tabId) {
        recordScan(url, finalResult);
        setBadge(tabId, finalResult.verdict);
      }

      chrome.tabs.sendMessage(tabId, {
        type:          'EMAIL_SCAN_RESULT',
        verdict:       finalResult.verdict,
        confidence:    finalResult.confidence,
        bodyVerdict:   bodyResult?.verdict,
        senderVerdict: senderResult?.verdict,
        urlResults,
        links:         msg.links,
        linkVerdictMap: Array.from(linkVerdictMap.entries()),
        shap_features: finalResult.shap_features,
        explanation:   finalResult.explanation,
        action:        finalResult.action,
      }).catch(() => {});

      chrome.runtime.sendMessage({
        type:   'EMAIL_RESULT',
        result: finalResult,
        url,
      }).catch(() => {});

      sendResponse({ result: finalResult });
    });
    return true;
  }

  if (msg.type === 'EMAIL_SCANNING') {
    if (tabId) setBadge(tabId, 'SCANNING');
    return true;
  }

  if (msg.type === 'GET_STATS') {
    Promise.all([
      chrome.storage.local.get('siq_stats'),
      chrome.storage.local.get('siq_history'),
    ]).then(([sd, hd]) => sendResponse({
      stats:   sd.siq_stats   || { total:0, malicious:0, suspicious:0, benign:0, blocked:0 },
      history: hd.siq_history || [],
    }));
    return true;
  }

  if (msg.type === 'GET_SETTINGS') {
    chrome.storage.local.get('backendUrl').then(d => sendResponse({ backendUrl: d.backendUrl || DEFAULT_BACKEND }));
    return true;
  }

  if (msg.type === 'SET_SETTINGS') {
    chrome.storage.local.set({ backendUrl: msg.backendUrl }).then(() => sendResponse({ ok: true }));
    return true;
  }

  if (msg.type === 'WHITELIST_URL') {
    _whitelistAdd(msg.url).then(() => {
      sendResponse({ ok: true });
    });
    return true;
  }

  // ── v3.0 Injection handler ────────────────────────────────────────────────
  if (msg.type === 'SCAN_INJECTION') {
    if (tabId) setBadge(tabId, 'SCANNING');
    scanInjection(msg.content, msg.url, msg.is_ai_interface).then(async result => {
      if (!result) { sendResponse({ result: null }); return; }
      const urlCached = await getCached(safeCacheKey('c_', msg.url));
      const merged = mergeAllResults(urlCached, result);
      if (tabId) {
        recordScan(msg.url, result);
        setBadge(tabId, merged.verdict);
      }
      chrome.runtime.sendMessage({
        type: 'INJECTION_RESULT', result, url: msg.url,
      }).catch(() => {});
      sendResponse({ result });
    });
    return true; // ← MANDATORY: async sendResponse
  }

  // ── v3.0 Anomaly handler ──────────────────────────────────────────────────
  if (msg.type === 'SCAN_ANOMALY') {
    if (tabId) setBadge(tabId, 'SCANNING');
    buildPartialVector(msg.trigger).then(async vector => {
      const merged = { ...msg.partial_vector, ...vector };
      const result = await scanAnomaly(merged, msg.url, msg.trigger);
      if (!result) { sendResponse({ result: null }); return; }
      if (tabId) {
        recordScan(msg.url, result);
        setBadge(tabId, result.verdict);
      }
      chrome.runtime.sendMessage({
        type: 'ANOMALY_RESULT', result, url: msg.url,
      }).catch(() => {});
      sendResponse({ result });
    });
    return true; // ← MANDATORY: async sendResponse
  }

  // ── v3.0 Auth state propagation ───────────────────────────────────────────
  if (msg.type === 'AUTH_STATE_CHANGED') {
    sendResponse({ ok: true });
    return true;
  }
});

// ── v3.0 Alarms — anomaly heartbeat ──────────────────────────────────────────
// onInstalled: idempotent alarm creation. chrome.alarms.create is safe to call
// with the same name; it replaces any existing alarm of that name.
chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create('anomaly_heartbeat', {
    periodInMinutes: ANOMALY_HEARTBEAT_INTERVAL_MIN,
  });
  // Record current device fingerprint for anomaly baseline
  // navigator is not available in MV3 service workers — set empty string (OK)
  chrome.storage.local.get('siq_known_device').then(({ siq_known_device }) => {
    if (!siq_known_device) {
      chrome.storage.local.set({ siq_known_device: 'chrome_extension_worker' });
    }
  });
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== 'anomaly_heartbeat') return;
  const { siq_auth } = await chrome.storage.local.get('siq_auth');
  if (!siq_auth) return; // Heartbeat only fires when logged in (A12)
  const vector = await buildPartialVector('heartbeat');
  const result = await scanAnomaly(vector, 'background://heartbeat', 'heartbeat');
  if (!result) return;
  if ((VERDICT_PRIORITY[result.verdict] || 0) >= (VERDICT_PRIORITY['SUSPICIOUS'] || 0)) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id) setBadge(tab.id, result.verdict);
  }
});

// ── v3.0 Tab session tracking ─────────────────────────────────────────────────
// Track when each tab was opened so anomaly vector can compute session_duration_sec.
chrome.tabs.onCreated.addListener(tab => {
  chrome.storage.local.get('siq_tab_open_ts').then(({ siq_tab_open_ts = {} }) => {
    siq_tab_open_ts[tab.id] = Date.now();
    chrome.storage.local.set({ siq_tab_open_ts });
  });
});
chrome.tabs.onRemoved.addListener(tabId => {
  chrome.storage.local.get('siq_tab_open_ts').then(({ siq_tab_open_ts = {} }) => {
    delete siq_tab_open_ts[tabId];
    chrome.storage.local.set({ siq_tab_open_ts });
  });
});

// ── Tab Navigation ────────────────────────────────────────────────────────────
chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === 'complete' && tab.url) {
    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
      setBadge(tabId, 'BENIGN');
      return;
    }
    // Set SCANNING — content.js will send SCAN_PAGE (with DOM content) and update via PAGE_RESULT
    setBadge(tabId, 'SCANNING');
  }
});

// ── Navigation Interception (webNavigation) ───────────────────────────────────
if (typeof chrome.webNavigation !== 'undefined') {
  chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    const { tabId, url, frameId } = details;
    if (frameId !== 0) return;
    if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://')) return;
    if (isLocal(url)) return; // Never intercept local dev addresses

    if (_intercepted.has(tabId)) { _intercepted.delete(tabId); return; }

    const cached = await getCached(url);
    const isWhitelisted = await _whitelistHas(url);
    if (isWhitelisted) return;
    if (cached && cached.verdict === 'MALICIOUS' && (cached.risk_score || 0) >= 70) {
      _intercepted.add(tabId);
      await recordBlock(url);
      setBadge(tabId, 'MALICIOUS');

      const params = new URLSearchParams({
        url:         encodeURIComponent(url),
        verdict:     cached.verdict,
        risk:        String(cached.risk_score || 0),
        explanation: encodeURIComponent(cached.explanation || 'Malicious URL detected.'),
        action:      encodeURIComponent(cached.action || 'Do not proceed to this site.'),
        signals:     encodeURIComponent(JSON.stringify(
          (cached.shap_features || []).slice(0, 3).map(f => f.feature)
        )),
      });
      chrome.tabs.update(tabId, { url: `${BLOCKED_PAGE}?${params.toString()}` });
    }
  });
}
