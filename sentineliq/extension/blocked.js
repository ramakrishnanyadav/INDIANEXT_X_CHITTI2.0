(function() {
  const params = new URLSearchParams(location.search);
  const destUrl     = decodeURIComponent(params.get('url') || '');
  const risk        = params.get('risk') || '0';
  const explanation = decodeURIComponent(params.get('explanation') || 'This destination has been classified as malicious.');
  const action      = decodeURIComponent(params.get('action') || 'Do not proceed. Close this tab.');

  let signals = [];
  try { signals = JSON.parse(decodeURIComponent(params.get('signals') || '[]')); } catch {}

  // Populate
  document.getElementById('risk-chip').textContent     = `Risk ${risk}/100`;
  document.getElementById('url-display').textContent   = destUrl || 'Unknown destination';
  document.getElementById('url-display').title         = destUrl;
  document.getElementById('explanation').textContent   = explanation;
  document.getElementById('action-text').textContent   = action;
  document.getElementById('timestamp').textContent     = new Date().toLocaleTimeString();

  const sigContainer = document.getElementById('signals-container');
  if (signals.length) {
    sigContainer.innerHTML = signals.map(s =>
      `<span class="signal-chip">${s}</span>`
    ).join('');
  } else {
    sigContainer.innerHTML = '<span class="signal-chip">Malicious URL pattern</span>';
  }

  // Handle the proceed button click
  document.getElementById('proceed-btn').addEventListener('click', () => {
    if (!document.getElementById('proceed-check').checked) return;
    // Send message to background to whitelist this URL
    chrome.runtime.sendMessage({ type: 'WHITELIST_URL', url: destUrl }, (response) => {
      // Chrome fundamentally blocks forward navigation from chrome-extension:// to file:///
      // The only way to bypass this security boundary is to use the native history stack.
      if (destUrl.toLowerCase().startsWith('file://')) {
        history.back();
      } else {
        // For normal web URLs, force navigate via background worker privileges
        chrome.runtime.sendMessage({ type: 'FORCE_NAVIGATE', url: destUrl });
      }
    });
  });

  // Handle safe exit
  document.getElementById('safe-btn').addEventListener('click', () => {
    // We cannot use history.back() if the previous page was the malicious page itself,
    // as it will simply trigger the block again in an infinite loop.
    try {
      window.close(); // Attempt to close the tab
    } catch {}
    // If closing fails (because it's the last tab or opened manually), redirect to a safe page
    window.location.replace("https://google.com");
  });

  // Enable/disable proceed button based on checkbox
  document.getElementById('proceed-check').addEventListener('change', (e) => {
    document.getElementById('proceed-btn').disabled = !e.target.checked;
  });
})();
