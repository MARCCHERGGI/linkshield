// LinkShield Service Worker — Chrome Extension background script
// Manages URL checking, caching, icon updates, and content script communication.

const SERVER = 'http://127.0.0.1:3847';
const CACHE_MAX = 2000;

// ═══════════════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════════════

const urlCache = new Map();
let trustedDomains = new Set();
let userWhitelist = new Set();
let userContentDomains = new Set();
let serverOnline = false;

let stats = { checked: 0, blocked: 0, today: new Date().toDateString() };

// ═══════════════════════════════════════════════════════════════
// INITIALIZE — Load lists from server
// ═══════════════════════════════════════════════════════════════

async function loadLists() {
  try {
    const res = await fetch(`${SERVER}/api/lists`);
    const data = await res.json();
    trustedDomains = new Set(data.trusted || []);
    userWhitelist = new Set(data.whitelist || []);
    userContentDomains = new Set(data.userContentDomains || []);
    serverOnline = true;
  } catch {
    serverOnline = false;
    // Fallback: hardcoded top domains
    trustedDomains = new Set([
      'google.com', 'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
      'linkedin.com', 'reddit.com', 'wikipedia.org', 'amazon.com', 'apple.com', 'microsoft.com',
      'github.com', 'stackoverflow.com', 'netflix.com', 'spotify.com', 'discord.com',
      'paypal.com', 'stripe.com', 'ebay.com', 'yahoo.com', 'bing.com', 'outlook.com',
      'zoom.us', 'slack.com', 'notion.so', 'dropbox.com', 'whatsapp.com', 'telegram.org',
      'anthropic.com', 'openai.com', 'news.ycombinator.com', 'medium.com',
    ]);
  }

  // Also load persisted stats
  try {
    const stored = await chrome.storage.local.get(['stats']);
    if (stored.stats) {
      stats = stored.stats;
      if (stats.today !== new Date().toDateString()) {
        stats = { checked: 0, blocked: 0, today: new Date().toDateString() };
      }
    }
  } catch { /* fresh stats */ }
}

loadLists();
// Refresh lists every 30 minutes
setInterval(loadLists, 1800_000);

// ═══════════════════════════════════════════════════════════════
// DOMAIN HELPERS
// ═══════════════════════════════════════════════════════════════

function extractDomain(hostname) {
  const multiTlds = ['.co.uk', '.com.au', '.co.nz', '.co.jp', '.com.br'];
  const lower = hostname.toLowerCase();
  for (const mt of multiTlds) {
    if (lower.endsWith(mt)) {
      const base = lower.slice(0, -mt.length);
      const lastDot = base.lastIndexOf('.');
      return lastDot >= 0 ? lower.slice(lastDot + 1) : lower;
    }
  }
  const parts = lower.split('.');
  if (parts.length <= 2) return lower;
  return parts.slice(-2).join('.');
}

function isDomainTrusted(hostname) {
  const domain = extractDomain(hostname);
  if (trustedDomains.has(domain)) return true;
  if (userWhitelist.has(domain)) return true;
  return false;
}

function isUserContent(hostname) {
  for (const ucd of userContentDomains) {
    if (hostname.endsWith(ucd)) return true;
  }
  return false;
}

// ═══════════════════════════════════════════════════════════════
// URL CHECKING
// ═══════════════════════════════════════════════════════════════

async function checkUrl(url) {
  // Parse
  let parsed;
  try { parsed = new URL(url); } catch { return { action: 'check', reason: 'invalid' }; }

  const hostname = parsed.hostname;

  // Skip non-HTTP
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { action: 'allow' };
  }

  // Trusted domain (and not user-content host)
  if (isDomainTrusted(hostname) && !isUserContent(hostname)) {
    return { action: 'allow', reason: 'trusted' };
  }

  // Check cache
  const cached = urlCache.get(url);
  if (cached && Date.now() < cached.expires) {
    if (cached.verdict === 'safe') return { action: 'allow', reason: 'cached' };
    return { action: 'check', reason: 'cached-unsafe' };
  }

  // Try server for quick check
  if (serverOnline) {
    try {
      const res = await fetch(`${SERVER}/api/quick?url=${encodeURIComponent(url)}`);
      const data = await res.json();

      urlCache.set(url, {
        verdict: data.verdict,
        score: data.score,
        expires: Date.now() + (data.verdict === 'safe' ? 3600_000 : 1800_000),
      });

      // Prune cache
      if (urlCache.size > CACHE_MAX) {
        const oldest = urlCache.keys().next().value;
        urlCache.delete(oldest);
      }

      if (data.verdict === 'safe' && data.score <= 15) {
        return { action: 'allow', reason: 'server-safe' };
      }

      return { action: 'check', reason: 'server-flagged' };
    } catch {
      serverOnline = false;
    }
  }

  // Fallback: basic pattern check
  return basicCheck(url, hostname);
}

function basicCheck(url, hostname) {
  // @ symbol
  if (url.includes('@') && url.indexOf('@') < url.indexOf(hostname)) {
    return { action: 'check', reason: 'at-symbol' };
  }

  // IP address
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    return { action: 'check', reason: 'ip-address' };
  }

  // Suspicious TLDs
  const tld = '.' + hostname.split('.').pop().toLowerCase();
  const badTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click', '.loan', '.download', '.racing', '.win', '.bid'];
  if (badTlds.includes(tld)) {
    return { action: 'check', reason: 'suspicious-tld' };
  }

  // If domain is totally unknown and server is down, still let them through
  // but mark as unverified
  return { action: 'allow', reason: 'unverified' };
}

// ═══════════════════════════════════════════════════════════════
// MESSAGE HANDLING
// ═══════════════════════════════════════════════════════════════

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'checkUrl') {
    checkUrl(msg.url).then(result => {
      stats.checked++;
      if (result.action === 'check') stats.blocked++;
      chrome.storage.local.set({ stats });
      sendResponse(result);
    }).catch(() => {
      sendResponse({ action: 'allow', reason: 'error' });
    });
    return true; // Keep channel open for async response
  }

  if (msg.type === 'getTrusted') {
    sendResponse({
      trusted: [...trustedDomains],
      whitelist: [...userWhitelist],
      userContent: [...userContentDomains],
    });
    return false;
  }

  if (msg.type === 'getStats') {
    if (stats.today !== new Date().toDateString()) {
      stats = { checked: 0, blocked: 0, today: new Date().toDateString() };
    }
    sendResponse({ ...stats, serverOnline, cacheSize: urlCache.size });
    return false;
  }

  if (msg.type === 'whitelistDomain') {
    const domain = msg.domain;
    userWhitelist.add(domain);
    // Tell server
    fetch(`${SERVER}/api/whitelist`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    }).catch(() => {});
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === 'serverStatus') {
    fetch(`${SERVER}/api/status`)
      .then(r => r.json())
      .then(data => { serverOnline = true; sendResponse({ online: true, ...data }); })
      .catch(() => { serverOnline = false; sendResponse({ online: false }); });
    return true;
  }
});

// ═══════════════════════════════════════════════════════════════
// ICON MANAGEMENT — Dynamic icon based on page safety
// ═══════════════════════════════════════════════════════════════

function drawShieldIcon(color, size) {
  const canvas = new OffscreenCanvas(size, size);
  const ctx = canvas.getContext('2d');
  const s = size;
  const cx = s / 2;

  // Shield shape
  ctx.beginPath();
  ctx.moveTo(cx, s * 0.06);
  ctx.bezierCurveTo(cx - s * 0.35, s * 0.08, cx - s * 0.42, s * 0.12, cx - s * 0.42, s * 0.12);
  ctx.lineTo(cx - s * 0.42, s * 0.45);
  ctx.bezierCurveTo(cx - s * 0.42, s * 0.7, cx - s * 0.1, s * 0.88, cx, s * 0.94);
  ctx.bezierCurveTo(cx + s * 0.1, s * 0.88, cx + s * 0.42, s * 0.7, cx + s * 0.42, s * 0.45);
  ctx.lineTo(cx + s * 0.42, s * 0.12);
  ctx.bezierCurveTo(cx + s * 0.42, s * 0.12, cx + s * 0.35, s * 0.08, cx, s * 0.06);
  ctx.closePath();

  // Fill with gradient
  const grad = ctx.createLinearGradient(0, 0, 0, s);
  if (color === 'green') {
    grad.addColorStop(0, '#22c55e');
    grad.addColorStop(1, '#16a34a');
  } else if (color === 'yellow') {
    grad.addColorStop(0, '#f59e0b');
    grad.addColorStop(1, '#d97706');
  } else if (color === 'red') {
    grad.addColorStop(0, '#ef4444');
    grad.addColorStop(1, '#dc2626');
  } else {
    grad.addColorStop(0, '#6366f1');
    grad.addColorStop(1, '#4f46e5');
  }
  ctx.fillStyle = grad;
  ctx.fill();

  // Checkmark / X
  ctx.strokeStyle = '#fff';
  ctx.lineWidth = Math.max(1.5, s * 0.08);
  ctx.lineCap = 'round';
  ctx.lineJoin = 'round';

  if (color === 'green' || color === 'default') {
    // Checkmark
    ctx.beginPath();
    ctx.moveTo(cx - s * 0.15, cx + s * 0.02);
    ctx.lineTo(cx - s * 0.03, cx + s * 0.14);
    ctx.lineTo(cx + s * 0.17, cx - s * 0.1);
    ctx.stroke();
  } else if (color === 'red') {
    // X mark
    ctx.beginPath();
    ctx.moveTo(cx - s * 0.12, cx - s * 0.08);
    ctx.lineTo(cx + s * 0.12, cx + s * 0.12);
    ctx.moveTo(cx + s * 0.12, cx - s * 0.08);
    ctx.lineTo(cx - s * 0.12, cx + s * 0.12);
    ctx.stroke();
  } else if (color === 'yellow') {
    // ! mark
    ctx.beginPath();
    ctx.moveTo(cx, cx - s * 0.12);
    ctx.lineTo(cx, cx + s * 0.04);
    ctx.stroke();
    ctx.beginPath();
    ctx.arc(cx, cx + s * 0.13, s * 0.03, 0, Math.PI * 2);
    ctx.fillStyle = '#fff';
    ctx.fill();
  }

  return ctx.getImageData(0, 0, s, s);
}

// Set default icon on install
chrome.runtime.onInstalled.addListener(() => {
  try {
    const icon = {
      16: drawShieldIcon('default', 16),
      32: drawShieldIcon('default', 32),
      48: drawShieldIcon('default', 48),
    };
    chrome.action.setIcon({ imageData: icon });
  } catch { /* OffscreenCanvas may not be available */ }
});

// Update icon for active tab
chrome.tabs.onActivated.addListener(async (info) => {
  try {
    const tab = await chrome.tabs.get(info.tabId);
    if (!tab.url) return;
    const parsed = new URL(tab.url);
    const trusted = isDomainTrusted(parsed.hostname);
    const color = trusted ? 'green' : 'default';
    const icon = {
      16: drawShieldIcon(color, 16),
      32: drawShieldIcon(color, 32),
    };
    chrome.action.setIcon({ tabId: info.tabId, imageData: icon });
  } catch { /* ignore */ }
});

// ═══════════════════════════════════════════════════════════════
// WEB NAVIGATION SAFETY NET
// Catches navigations that bypass the content script
// (typed URLs, right-click open in new tab, bookmarks)
// ═══════════════════════════════════════════════════════════════

chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only main frame
  if (!details.url.startsWith('http')) return;

  try {
    const parsed = new URL(details.url);
    if (isDomainTrusted(parsed.hostname) && !isUserContent(parsed.hostname)) return;

    // Check with server if available
    const result = await checkUrl(details.url);
    if (result.action === 'check') {
      // Inject warning banner on the page
      chrome.scripting.executeScript({
        target: { tabId: details.tabId },
        func: showWarningBanner,
        args: [details.url, result.reason],
      }).catch(() => {});
    }
  } catch { /* ignore errors on restricted pages */ }
});

// Injected function for warning banner
function showWarningBanner(url, reason) {
  if (document.getElementById('linkshield-banner')) return;

  const banner = document.createElement('div');
  banner.id = 'linkshield-banner';
  banner.innerHTML = `
    <div style="position:fixed;top:0;left:0;right:0;z-index:2147483647;
      background:linear-gradient(135deg,#1a1a2e,#16213e);
      border-bottom:3px solid #f59e0b;padding:12px 20px;
      font-family:-apple-system,BlinkMacSystemFont,sans-serif;
      display:flex;align-items:center;gap:12px;color:#e0e0e0;font-size:14px;
      box-shadow:0 4px 20px rgba(0,0,0,0.5);">
      <span style="font-size:20px">&#x1f6e1;</span>
      <span><strong>LinkShield:</strong> This site hasn't been verified.
        <a href="${chrome.runtime.getURL('check.html')}?url=${encodeURIComponent(url)}"
           style="color:#818cf8;text-decoration:underline;margin-left:4px;">Run full scan</a></span>
      <button id="linkshield-dismiss" style="margin-left:auto;background:none;border:1px solid #4a4a6a;
        color:#e0e0e0;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:13px;">Dismiss</button>
    </div>`;
  document.body.prepend(banner);
  document.getElementById('linkshield-dismiss').onclick = () => banner.remove();
}
