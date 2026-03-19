// LinkShield Content Script — Intercepts link clicks on all pages
// Runs at document_start on all HTTP/HTTPS pages.

(() => {
  // Skip extension pages
  if (location.protocol === 'chrome-extension:' || location.protocol === 'chrome:') return;

  // ═══════════════════════════════════════════════════════════
  // LOCAL TRUSTED LIST (loaded from service worker)
  // ═══════════════════════════════════════════════════════════

  let trustedDomains = new Set();
  let userWhitelist = new Set();
  let userContentDomains = new Set();

  // Load trusted list
  try {
    chrome.runtime.sendMessage({ type: 'getTrusted' }, (response) => {
      if (chrome.runtime.lastError) return;
      if (response) {
        trustedDomains = new Set(response.trusted || []);
        userWhitelist = new Set(response.whitelist || []);
        userContentDomains = new Set(response.userContent || []);
      }
    });
  } catch { /* extension context may be invalidated */ }

  // ═══════════════════════════════════════════════════════════
  // DOMAIN HELPERS
  // ═══════════════════════════════════════════════════════════

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

  function isTrusted(hostname) {
    const domain = extractDomain(hostname);
    return trustedDomains.has(domain) || userWhitelist.has(domain);
  }

  function isUserContent(hostname) {
    for (const ucd of userContentDomains) {
      if (hostname.endsWith(ucd)) return true;
    }
    return false;
  }

  // ═══════════════════════════════════════════════════════════
  // CLICK INTERCEPTION
  // ═══════════════════════════════════════════════════════════

  document.addEventListener('click', (e) => {
    // Find the closest anchor
    const link = e.target.closest('a[href]');
    if (!link) return;

    const href = link.href;
    if (!href) return;

    // Skip non-navigatable protocols
    if (href.startsWith('javascript:') || href.startsWith('mailto:') ||
        href.startsWith('tel:') || href.startsWith('#') ||
        href.startsWith('chrome') || href.startsWith('about:') ||
        href.startsWith('blob:') || href.startsWith('data:text/')) return;

    // Parse target URL
    let targetUrl;
    try {
      targetUrl = new URL(href);
    } catch {
      return; // Can't parse — let browser handle it
    }

    // Skip same-origin navigation (internal links)
    if (targetUrl.origin === location.origin) return;

    // Skip non-HTTP(S)
    if (!['http:', 'https:'].includes(targetUrl.protocol)) return;

    // Trusted domain — allow immediately (no delay)
    if (isTrusted(targetUrl.hostname) && !isUserContent(targetUrl.hostname)) return;

    // ─── INTERCEPT ────────────────────────────────────────
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();

    // Determine if should open in new tab
    const newTab = link.target === '_blank' || e.ctrlKey || e.metaKey || e.button === 1;

    // Navigate to check page
    const checkPageUrl = chrome.runtime.getURL('check.html') +
      '?url=' + encodeURIComponent(href) +
      (newTab ? '&newtab=1' : '');

    if (newTab) {
      window.open(checkPageUrl);
    } else {
      location.href = checkPageUrl;
    }
  }, true); // Capture phase — fires before any other click handlers

  // Also intercept middle-click (button 1)
  document.addEventListener('auxclick', (e) => {
    if (e.button !== 1) return; // Only middle-click
    const link = e.target.closest('a[href]');
    if (!link) return;

    const href = link.href;
    if (!href) return;

    let targetUrl;
    try { targetUrl = new URL(href); } catch { return; }

    if (targetUrl.origin === location.origin) return;
    if (!['http:', 'https:'].includes(targetUrl.protocol)) return;
    if (isTrusted(targetUrl.hostname) && !isUserContent(targetUrl.hostname)) return;

    e.preventDefault();
    e.stopPropagation();

    const checkPageUrl = chrome.runtime.getURL('check.html') +
      '?url=' + encodeURIComponent(href) + '&newtab=1';
    window.open(checkPageUrl);
  }, true);

  // ═══════════════════════════════════════════════════════════
  // INTERCEPT window.open CALLS
  // ═══════════════════════════════════════════════════════════

  const originalOpen = window.open;
  window.open = function(url, ...args) {
    if (!url || typeof url !== 'string') return originalOpen.call(this, url, ...args);

    try {
      const parsed = new URL(url, location.href);
      if (!['http:', 'https:'].includes(parsed.protocol)) return originalOpen.call(this, url, ...args);
      if (parsed.origin === location.origin) return originalOpen.call(this, url, ...args);
      if (isTrusted(parsed.hostname) && !isUserContent(parsed.hostname)) return originalOpen.call(this, url, ...args);

      // Redirect to check page
      const checkUrl = chrome.runtime.getURL('check.html') +
        '?url=' + encodeURIComponent(parsed.href) + '&newtab=1';
      return originalOpen.call(this, checkUrl, ...args);
    } catch {
      return originalOpen.call(this, url, ...args);
    }
  };
})();
