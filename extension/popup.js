// LinkShield Popup — Quick status and controls

const SERVER = 'http://127.0.0.1:3847';

// ═══════════════════════════════════════════════════════════════
// LOAD STATUS
// ═══════════════════════════════════════════════════════════════

// Server status
chrome.runtime.sendMessage({ type: 'serverStatus' }, (response) => {
  const el = document.getElementById('serverStatus');
  if (response?.online) {
    el.textContent = 'Online';
    el.className = 'status-value online';
  } else {
    el.textContent = 'Offline';
    el.className = 'status-value offline';
  }
});

// Stats
chrome.runtime.sendMessage({ type: 'getStats' }, (response) => {
  if (response) {
    document.getElementById('statChecked').textContent = response.checked || 0;
    document.getElementById('statBlocked').textContent = response.blocked || 0;
  }
});

// Current site info
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tab = tabs[0];
  if (!tab?.url) return;

  try {
    const url = new URL(tab.url);
    const hostname = url.hostname;
    const siteEl = document.getElementById('currentSite');

    // Check if trusted
    chrome.runtime.sendMessage({ type: 'getTrusted' }, (response) => {
      if (!response) return;
      const trusted = new Set(response.trusted || []);
      const whitelist = new Set(response.whitelist || []);

      const parts = hostname.split('.');
      const domain = parts.length > 2 ? parts.slice(-2).join('.') : hostname;

      const isTrusted = trusted.has(domain) || whitelist.has(domain);
      const badge = isTrusted
        ? '<span class="badge trusted">Trusted</span>'
        : '<span class="badge unknown">Unknown</span>';

      siteEl.innerHTML = `<span class="domain">${escapeHtml(hostname)}</span>${badge}`;

      // Update button text
      const btn = document.getElementById('btnWhitelist');
      if (isTrusted) {
        btn.textContent = 'Already trusted';
        btn.disabled = true;
        btn.style.opacity = '0.5';
      }
    });
  } catch { /* not a regular page */ }
});

// ═══════════════════════════════════════════════════════════════
// ACTIONS
// ═══════════════════════════════════════════════════════════════

document.getElementById('btnWhitelist').addEventListener('click', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab?.url) return;

    try {
      const hostname = new URL(tab.url).hostname;
      const parts = hostname.split('.');
      const domain = parts.length > 2 ? parts.slice(-2).join('.') : hostname;

      chrome.runtime.sendMessage({ type: 'whitelistDomain', domain }, () => {
        const btn = document.getElementById('btnWhitelist');
        btn.textContent = 'Trusted!';
        btn.disabled = true;
        btn.style.opacity = '0.5';

        const siteEl = document.getElementById('currentSite');
        siteEl.innerHTML = `<span class="domain">${escapeHtml(hostname)}</span><span class="badge trusted">Trusted</span>`;
      });
    } catch { /* ignore */ }
  });
});

document.getElementById('btnScan').addEventListener('click', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab?.url) return;

    const checkUrl = chrome.runtime.getURL('check.html') +
      '?url=' + encodeURIComponent(tab.url);
    chrome.tabs.update(tab.id, { url: checkUrl });
    window.close();
  });
});

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
