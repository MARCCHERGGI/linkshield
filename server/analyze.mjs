// LinkShield Analysis Engine — Zero dependencies, pure Node.js
// Multi-layer threat detection: URL syntax, domain reputation, homograph attacks,
// typosquatting, redirect chains, SSL verification, and optional API checks.

import https from 'node:https';
import http from 'node:http';
import { URL } from 'node:url';
import tls from 'node:tls';
import dns from 'node:dns/promises';

// ═══════════════════════════════════════════════════════════════
// CONFUSABLE UNICODE CHARACTERS (homograph attack detection)
// ═══════════════════════════════════════════════════════════════
const CONFUSABLES = new Map([
  [0x0430, 'a'], // Cyrillic а
  [0x0435, 'e'], // Cyrillic е
  [0x043E, 'o'], // Cyrillic о
  [0x0440, 'p'], // Cyrillic р
  [0x0441, 'c'], // Cyrillic с
  [0x0443, 'y'], // Cyrillic у
  [0x0445, 'x'], // Cyrillic х
  [0x0456, 'i'], // Cyrillic і
  [0x0455, 's'], // Cyrillic ѕ
  [0x04BB, 'h'], // Cyrillic һ
  [0x0501, 'd'], // Cyrillic ԁ
  [0x051B, 'q'], // Cyrillic ԛ
  [0x051D, 'w'], // Cyrillic ԝ
  [0x03B1, 'a'], // Greek α
  [0x03B5, 'e'], // Greek ε
  [0x03BF, 'o'], // Greek ο
  [0x03C1, 'p'], // Greek ρ
  [0x03BA, 'k'], // Greek κ
  [0x03BD, 'v'], // Greek ν
  [0x0131, 'i'], // Turkish ı
  [0x0261, 'g'], // Latin ɡ
  [0x026A, 'i'], // Latin ɪ
  [0x1D00, 'a'], // Small cap A
  [0x1D04, 'c'], // Small cap C
  [0x1D07, 'e'], // Small cap E
  [0x1D0F, 'o'], // Small cap O
  [0xFF41, 'a'], // Fullwidth a
  [0xFF42, 'b'], // Fullwidth b
  [0xFF43, 'c'], // Fullwidth c
  [0xFF44, 'd'], // Fullwidth d
  [0xFF45, 'e'], // Fullwidth e
  [0x2010, '-'], // Hyphen
  [0x2011, '-'], // Non-breaking hyphen
  [0x2012, '-'], // Figure dash
  [0x2013, '-'], // En dash
  [0x2014, '-'], // Em dash
  [0x2212, '-'], // Minus
  [0xFF0D, '-'], // Fullwidth minus
]);

// ═══════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════

function extractRegisteredDomain(hostname) {
  // Handle known multi-part TLDs
  const multiTlds = ['.co.uk', '.com.au', '.co.nz', '.co.jp', '.com.br', '.co.kr', '.org.uk', '.ac.uk'];
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

function extractBaseName(hostname) {
  const domain = extractRegisteredDomain(hostname);
  return domain.split('.')[0];
}

function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

function levenshtein(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const matrix = Array.from({ length: a.length + 1 }, (_, i) =>
    Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost
      );
    }
  }
  return matrix[a.length][b.length];
}

function isCharSwap(a, b) {
  if (a.length !== b.length) return false;
  let diffs = [];
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) diffs.push(i);
  }
  if (diffs.length !== 2) return false;
  const [i, j] = diffs;
  return a[i] === b[j] && a[j] === b[i];
}

function isCharDoubled(input, brand) {
  if (input.length !== brand.length + 1) return false;
  let skipped = false;
  let bi = 0;
  for (let ii = 0; ii < input.length; ii++) {
    if (bi >= brand.length) {
      if (!skipped) { skipped = true; continue; }
      return false;
    }
    if (input[ii] === brand[bi]) { bi++; continue; }
    if (!skipped && ii > 0 && input[ii] === input[ii - 1]) {
      skipped = true;
      continue;
    }
    return false;
  }
  return bi === brand.length;
}

function isCharMissing(input, brand) {
  if (input.length !== brand.length - 1) return false;
  let skipped = false;
  let ii = 0;
  for (let bi = 0; bi < brand.length; bi++) {
    if (ii >= input.length) {
      if (!skipped) return true;
      return false;
    }
    if (input[ii] === brand[bi]) { ii++; continue; }
    if (!skipped) { skipped = true; continue; }
    return false;
  }
  return ii === input.length;
}

function normalizeHomoglyphs(str) {
  let result = '';
  for (const ch of str) {
    const code = ch.codePointAt(0);
    result += CONFUSABLES.get(code) || ch.toLowerCase();
  }
  return result;
}

function detectScripts(str) {
  const scripts = new Set();
  for (const ch of str) {
    const code = ch.codePointAt(0);
    if (code >= 0x0041 && code <= 0x024F) scripts.add('Latin');
    else if (code >= 0x0400 && code <= 0x04FF) scripts.add('Cyrillic');
    else if (code >= 0x0370 && code <= 0x03FF) scripts.add('Greek');
    else if (code >= 0x0600 && code <= 0x06FF) scripts.add('Arabic');
    else if (code >= 0x4E00 && code <= 0x9FFF) scripts.add('CJK');
    else if (code >= 0x0030 && code <= 0x0039) { /* digits are neutral */ }
    else if (code === 0x002D || code === 0x002E) { /* hyphens/dots are neutral */ }
    else if (code >= 0x0080) scripts.add('Other');
  }
  return scripts;
}

function httpGet(urlStr, options = {}) {
  return new Promise((resolve, reject) => {
    const timeout = options.timeout || 5000;
    const proto = urlStr.startsWith('https') ? https : http;
    const req = proto.get(urlStr, {
      timeout,
      headers: { 'User-Agent': 'LinkShield/1.0' },
      rejectUnauthorized: false,
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, data }));
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
  });
}

function httpPost(urlStr, body, options = {}) {
  return new Promise((resolve, reject) => {
    const timeout = options.timeout || 5000;
    const url = new URL(urlStr);
    const proto = url.protocol === 'https:' ? https : http;
    const payload = typeof body === 'string' ? body : JSON.stringify(body);
    const req = proto.request({
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: 'POST',
      timeout,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        ...(options.headers || {}),
      },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, data }));
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

// ═══════════════════════════════════════════════════════════════
// ANALYZER 1: URL SYNTAX
// ═══════════════════════════════════════════════════════════════

function analyzeUrlSyntax(urlStr) {
  const flags = [];

  try {
    const url = new URL(urlStr);

    // @ symbol — URL hijacking: http://trusted.com@evil.com
    if (url.username || url.password || (url.href.indexOf('@') > -1 && url.href.indexOf('@') < url.href.indexOf(url.hostname))) {
      flags.push({ id: 'url_at_symbol', severity: 90, detail: 'Contains @ — may redirect to a different domain than displayed' });
    }

    // IP address as hostname
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(url.hostname)) {
      flags.push({ id: 'ip_address', severity: 50, detail: `Raw IP address: ${url.hostname} — legitimate sites use domain names` });
    }

    // Hex/octal/decimal encoded IP
    if (/^(0x[\da-f]+|0\d+|\d{8,})$/i.test(url.hostname)) {
      flags.push({ id: 'obfuscated_ip', severity: 80, detail: 'Obfuscated IP address — used to evade detection' });
    }

    // data: URI
    if (url.protocol === 'data:') {
      flags.push({ id: 'data_uri', severity: 85, detail: 'Data URI can contain hidden malicious content' });
    }

    // javascript: URI
    if (url.protocol === 'javascript:') {
      flags.push({ id: 'javascript_uri', severity: 95, detail: 'JavaScript URI — can execute code in your browser' });
    }

    // blob: URI
    if (url.protocol === 'blob:') {
      flags.push({ id: 'blob_uri', severity: 70, detail: 'Blob URI — may contain dynamically generated malicious content' });
    }

    // HTTP (not HTTPS)
    if (url.protocol === 'http:') {
      flags.push({ id: 'no_https', severity: 20, detail: 'No encryption — data sent in plain text' });
    }

    // Unusual port
    const port = parseInt(url.port);
    if (port && ![80, 443, 8080, 8443].includes(port)) {
      flags.push({ id: 'unusual_port', severity: 30, detail: `Non-standard port ${port}` });
    }

    // Excessive subdomains
    const hostParts = url.hostname.split('.');
    if (hostParts.length > 4) {
      flags.push({ id: 'excessive_subdomains', severity: 40, detail: `${hostParts.length} subdomain levels — may hide real domain` });
    }

    // Very long URL
    if (urlStr.length > 300) {
      flags.push({ id: 'very_long_url', severity: 20, detail: `${urlStr.length} characters — unusually long` });
    }

    // URL-encoded hostname
    if (/%[0-9a-f]{2}/i.test(url.hostname)) {
      flags.push({ id: 'encoded_hostname', severity: 70, detail: 'Encoded characters in hostname — hides real domain' });
    }

    // Embedded URL in path (open redirect / tracking)
    const pathAndQuery = url.pathname + url.search;
    if (/https?%3A%2F%2F/i.test(pathAndQuery) || /https?:\/\//i.test(pathAndQuery)) {
      flags.push({ id: 'embedded_url', severity: 40, detail: 'Contains another URL — possible redirect to unknown destination' });
    }

    // Suspicious path keywords (only matters for non-trusted domains)
    if (/(login|signin|sign-in|verify|confirm|account|secure|update|banking|password|credential|wallet|recover|suspend)/i.test(url.pathname)) {
      flags.push({ id: 'suspicious_path', severity: 25, detail: 'Path contains sensitive keywords (login/verify/account)' });
    }

    // Double extension in path (e.g., file.pdf.exe)
    if (/\.\w{2,4}\.\w{2,4}$/.test(url.pathname) && /\.(exe|scr|bat|cmd|msi|vbs|js|ps1|jar|apk|dmg|pkg|deb|rpm)$/i.test(url.pathname)) {
      flags.push({ id: 'double_extension', severity: 75, detail: 'Double file extension — may disguise executable as document' });
    }

  } catch {
    flags.push({ id: 'invalid_url', severity: 60, detail: 'Could not parse URL — malformed' });
  }

  return flags;
}

// ═══════════════════════════════════════════════════════════════
// ANALYZER 2: DOMAIN REPUTATION
// ═══════════════════════════════════════════════════════════════

function analyzeDomainReputation(hostname, lists) {
  const flags = [];
  const domain = extractRegisteredDomain(hostname);

  // Trusted domain — big negative score (safe signal)
  if (lists.trusted.includes(domain)) {
    flags.push({ id: 'trusted_domain', severity: -80, detail: `${domain} is a known trusted domain` });
    return flags;
  }

  // User content hosting — trusted platform but untrusted content
  for (const ucd of lists.userContentDomains) {
    if (hostname.endsWith(ucd) || hostname === ucd) {
      flags.push({ id: 'user_content', severity: 30, detail: `Hosted on ${ucd} — anyone can publish here` });
      break;
    }
  }

  // TLD risk
  const tld = '.' + hostname.split('.').pop().toLowerCase();
  if (lists.suspiciousTlds.high.includes(tld)) {
    flags.push({ id: 'high_risk_tld', severity: 55, detail: `${tld} is a high-risk TLD — commonly used for scams` });
  } else if (lists.suspiciousTlds.medium.includes(tld)) {
    flags.push({ id: 'medium_risk_tld', severity: 25, detail: `${tld} is a medium-risk TLD` });
  }

  // Domain entropy (random-looking = suspicious)
  const baseName = extractBaseName(hostname);
  const entropy = calculateEntropy(baseName);
  if (entropy > 3.8 && baseName.length > 8) {
    flags.push({ id: 'high_entropy', severity: 35, detail: `Domain looks randomly generated (entropy ${entropy.toFixed(1)})` });
  }

  // Very long domain name
  if (domain.length > 30) {
    flags.push({ id: 'long_domain', severity: 20, detail: 'Unusually long domain name' });
  }

  // Suspicious keywords in domain (brand impersonation)
  const suspiciousWords = ['secure', 'login', 'verify', 'account', 'update', 'confirm', 'banking', 'support', 'helpdesk', 'recover', 'suspend', 'wallet', 'crypto'];
  for (const word of suspiciousWords) {
    if (baseName.includes(word)) {
      flags.push({ id: 'suspicious_keyword', severity: 35, detail: `Domain contains "${word}" — possible impersonation` });
      break;
    }
  }

  // URL shortener — destination is hidden
  if (lists.shorteners.includes(domain)) {
    flags.push({ id: 'url_shortener', severity: 30, detail: 'URL shortener — real destination is hidden' });
  }

  // Free hosting
  for (const fh of lists.freeHosting) {
    if (hostname.endsWith(fh)) {
      flags.push({ id: 'free_hosting', severity: 35, detail: 'Free hosting — commonly used for throwaway phishing sites' });
      break;
    }
  }

  // Dash-heavy domain (secure-login-paypal-verify.com)
  const dashCount = (baseName.match(/-/g) || []).length;
  if (dashCount >= 3) {
    flags.push({ id: 'dash_heavy', severity: 40, detail: `${dashCount} hyphens in domain — common in phishing URLs` });
  }

  // Digits mixed with brand-like words
  if (/\d/.test(baseName) && /[a-z]{3,}/i.test(baseName) && baseName.length > 10) {
    flags.push({ id: 'digits_and_words', severity: 15, detail: 'Mix of numbers and words in domain' });
  }

  return flags;
}

// ═══════════════════════════════════════════════════════════════
// ANALYZER 3: HOMOGRAPH ATTACK DETECTION
// ═══════════════════════════════════════════════════════════════

function analyzeHomograph(hostname, lists) {
  const flags = [];

  // Punycode detection (xn-- prefix)
  if (hostname.includes('xn--')) {
    flags.push({ id: 'punycode', severity: 55, detail: 'Internationalized domain (Punycode) — may look like a different site' });
  }

  // Mixed script detection
  const scripts = detectScripts(hostname.replace(/\./g, ''));
  if (scripts.size > 1 && !scripts.has('CJK')) {
    const scriptList = [...scripts].join(' + ');
    flags.push({ id: 'mixed_scripts', severity: 80, detail: `Mixed character sets: ${scriptList} — strong indicator of impersonation` });
  }

  // Visual similarity to brands after normalizing homoglyphs
  const normalized = normalizeHomoglyphs(hostname);
  for (const brand of lists.brands) {
    const brandBase = brand.domain.split('.')[0];
    const normalizedBase = normalizeHomoglyphs(extractBaseName(hostname));

    // The normalized form matches a brand but the original doesn't
    if (normalizedBase === brandBase && extractBaseName(hostname) !== brandBase) {
      flags.push({
        id: 'homograph_brand',
        severity: 95,
        detail: `Visually mimics ${brand.name} (${brand.domain}) using look-alike characters`
      });
      break;
    }

    // Check if normalized hostname contains brand
    if (normalized.includes(brandBase) && !hostname.includes(brandBase) && hostname !== brand.domain) {
      flags.push({
        id: 'homograph_contains',
        severity: 85,
        detail: `Contains characters that look like "${brand.name}" but aren't`
      });
      break;
    }
  }

  return flags;
}

// ═══════════════════════════════════════════════════════════════
// ANALYZER 4: TYPOSQUATTING DETECTION
// ═══════════════════════════════════════════════════════════════

function analyzeTyposquat(hostname, lists) {
  const flags = [];
  const inputBase = extractBaseName(hostname);
  if (inputBase.length < 3) return flags;

  for (const brand of lists.brands) {
    const brandBase = brand.domain.split('.')[0];
    if (inputBase === brandBase) continue; // Exact match = not a typosquat

    // Levenshtein distance
    const dist = levenshtein(inputBase, brandBase);
    const maxLen = Math.max(inputBase.length, brandBase.length);

    if (dist === 1) {
      const sim = ((maxLen - dist) / maxLen * 100).toFixed(0);
      flags.push({
        id: 'typosquat_close',
        severity: 75,
        detail: `${sim}% similar to ${brand.name} (${brand.domain}) — likely typosquatting`
      });
      return flags;
    }

    if (dist === 2 && maxLen >= 6) {
      const sim = ((maxLen - dist) / maxLen * 100).toFixed(0);
      flags.push({
        id: 'typosquat_similar',
        severity: 55,
        detail: `${sim}% similar to ${brand.name} (${brand.domain})`
      });
      return flags;
    }

    // Character swap (e.g., gogle → google)
    if (isCharSwap(inputBase, brandBase)) {
      flags.push({ id: 'char_swap', severity: 70, detail: `Swapped characters — looks like ${brand.name} (${brand.domain})` });
      return flags;
    }

    // Character doubled (e.g., gooogle → google)
    if (isCharDoubled(inputBase, brandBase)) {
      flags.push({ id: 'char_doubled', severity: 60, detail: `Doubled character — looks like ${brand.name} (${brand.domain})` });
      return flags;
    }

    // Character missing (e.g., gogle → google)
    if (isCharMissing(inputBase, brandBase)) {
      flags.push({ id: 'char_missing', severity: 65, detail: `Missing character — looks like ${brand.name} (${brand.domain})` });
      return flags;
    }

    // Brand keyword in a compound domain (e.g., paypal-secure-login.com)
    for (const kw of brand.keywords) {
      if (inputBase.includes(kw) && inputBase !== kw && inputBase.length > kw.length + 3) {
        flags.push({
          id: 'brand_compound',
          severity: 50,
          detail: `Contains "${kw}" — may be impersonating ${brand.name}`
        });
        return flags;
      }
    }
  }

  return flags;
}

// ═══════════════════════════════════════════════════════════════
// ANALYZER 5: REDIRECT CHAIN (async)
// ═══════════════════════════════════════════════════════════════

async function analyzeRedirects(urlStr) {
  const flags = [];

  try {
    const visited = [];
    let current = urlStr;
    const maxHops = 10;

    for (let i = 0; i < maxHops; i++) {
      const res = await new Promise((resolve, reject) => {
        const proto = current.startsWith('https') ? https : http;
        const req = proto.get(current, {
          timeout: 3000,
          headers: { 'User-Agent': 'LinkShield/1.0' },
          rejectUnauthorized: false,
        }, (res) => resolve(res));
        req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
        req.on('error', reject);
      });

      res.destroy(); // Don't download body

      visited.push({ url: current, status: res.statusCode });

      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        const next = new URL(res.headers.location, current).href;
        current = next;
        continue;
      }
      break;
    }

    const hops = visited.length - 1;
    if (hops > 0) {
      const firstDomain = extractRegisteredDomain(new URL(visited[0].url).hostname);
      const lastDomain = extractRegisteredDomain(new URL(visited[visited.length - 1].url).hostname);
      const crossDomain = firstDomain !== lastDomain;

      if (hops >= 4) {
        flags.push({ id: 'many_redirects', severity: 45, detail: `${hops} redirects — excessive redirect chain` });
      } else if (hops >= 2) {
        flags.push({ id: 'some_redirects', severity: 20, detail: `${hops} redirects` });
      }

      if (crossDomain) {
        flags.push({
          id: 'cross_domain_redirect',
          severity: 40,
          detail: `Redirects from ${firstDomain} to ${lastDomain}`
        });
      }
    }

    // Return final URL for display
    flags._finalUrl = visited.length > 0 ? visited[visited.length - 1].url : urlStr;

  } catch (err) {
    flags.push({ id: 'redirect_error', severity: 10, detail: `Could not follow redirects: ${err.message}` });
  }

  return flags;
}

// ═══════════════════════════════════════════════════════════════
// ANALYZER 6: SSL CERTIFICATE CHECK (async)
// ═══════════════════════════════════════════════════════════════

async function analyzeSsl(hostname) {
  const flags = [];

  try {
    const cert = await new Promise((resolve, reject) => {
      const socket = tls.connect(443, hostname, {
        timeout: 4000,
        servername: hostname,
        rejectUnauthorized: false,
      }, () => {
        const peerCert = socket.getPeerCertificate();
        const authorized = socket.authorized;
        socket.destroy();
        resolve({ cert: peerCert, authorized });
      });
      socket.on('timeout', () => { socket.destroy(); reject(new Error('timeout')); });
      socket.on('error', reject);
    });

    if (!cert.authorized) {
      flags.push({ id: 'ssl_invalid', severity: 50, detail: 'SSL certificate is not trusted by your system' });
    }

    if (cert.cert && cert.cert.subject) {
      // Check if cert is for this domain
      const cn = cert.cert.subject.CN || '';
      const altNames = (cert.cert.subjectaltname || '').split(',').map(s => s.trim().replace('DNS:', ''));
      const allNames = [cn, ...altNames];
      const matches = allNames.some(name => {
        if (name.startsWith('*.')) return hostname.endsWith(name.slice(1));
        return hostname === name;
      });
      if (!matches && allNames.length > 0 && allNames[0] !== '') {
        flags.push({ id: 'ssl_mismatch', severity: 60, detail: 'Certificate does not match this domain' });
      }
    }

    // Check expiry
    if (cert.cert && cert.cert.valid_to) {
      const expiry = new Date(cert.cert.valid_to);
      if (expiry < new Date()) {
        flags.push({ id: 'ssl_expired', severity: 55, detail: `Certificate expired ${expiry.toLocaleDateString()}` });
      } else {
        const daysLeft = Math.floor((expiry - new Date()) / 86400000);
        if (daysLeft < 7) {
          flags.push({ id: 'ssl_expiring', severity: 20, detail: `Certificate expires in ${daysLeft} days` });
        }
      }
    }

  } catch (err) {
    if (err.message === 'timeout') {
      flags.push({ id: 'ssl_timeout', severity: 15, detail: 'Could not verify SSL certificate (timeout)' });
    } else {
      flags.push({ id: 'ssl_error', severity: 25, detail: 'No SSL/TLS available' });
    }
  }

  return flags;
}

// ═══════════════════════════════════════════════════════════════
// ANALYZER 7: DNS CHECK (async)
// ═══════════════════════════════════════════════════════════════

async function analyzeDns(hostname) {
  const flags = [];

  try {
    const addresses = await dns.resolve4(hostname).catch(() => []);
    if (addresses.length === 0) {
      flags.push({ id: 'dns_no_records', severity: 40, detail: 'Domain has no DNS records — may not exist' });
      return flags;
    }

    // Check for private/reserved IPs (DNS rebinding attack)
    for (const ip of addresses) {
      if (ip.startsWith('127.') || ip.startsWith('10.') || ip.startsWith('192.168.') ||
          ip.startsWith('172.16.') || ip.startsWith('172.17.') || ip.startsWith('172.18.') ||
          ip.startsWith('172.19.') || ip.startsWith('172.2') || ip.startsWith('172.3') ||
          ip === '0.0.0.0') {
        flags.push({ id: 'dns_private_ip', severity: 60, detail: `Resolves to private IP ${ip} — possible DNS rebinding attack` });
        break;
      }
    }
  } catch {
    flags.push({ id: 'dns_error', severity: 10, detail: 'DNS lookup failed' });
  }

  return flags;
}

// ═══════════════════════════════════════════════════════════════
// ANALYZER 8: GOOGLE SAFE BROWSING (optional)
// ═══════════════════════════════════════════════════════════════

async function checkSafeBrowsing(urlStr, apiKey) {
  if (!apiKey) return [];
  const flags = [];

  try {
    const body = {
      client: { clientId: 'linkshield', clientVersion: '1.0.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url: urlStr }],
      },
    };

    const res = await httpPost(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      body,
      { timeout: 5000 }
    );

    const data = JSON.parse(res.data);
    if (data.matches && data.matches.length > 0) {
      const threats = data.matches.map(m => m.threatType).join(', ');
      flags.push({
        id: 'safe_browsing_hit',
        severity: 95,
        detail: `Google Safe Browsing: ${threats.toLowerCase().replace(/_/g, ' ')}`
      });
    }
  } catch {
    // API error — don't penalize the URL
  }

  return flags;
}

// ═══════════════════════════════════════════════════════════════
// ANALYZER 9: VIRUSTOTAL (optional)
// ═══════════════════════════════════════════════════════════════

async function checkVirusTotal(urlStr, apiKey) {
  if (!apiKey) return [];
  const flags = [];

  try {
    // URL ID for VT is base64(url)
    const urlId = Buffer.from(urlStr).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const res = await httpGet(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      timeout: 5000,
      headers: { 'x-apikey': apiKey },
    });

    if (res.status === 200) {
      const data = JSON.parse(res.data);
      const stats = data.data?.attributes?.last_analysis_stats;
      if (stats) {
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const total = Object.values(stats).reduce((a, b) => a + b, 0);

        if (malicious >= 5) {
          flags.push({ id: 'vt_malicious', severity: 95, detail: `VirusTotal: ${malicious}/${total} vendors flag as malicious` });
        } else if (malicious >= 2) {
          flags.push({ id: 'vt_some_flags', severity: 60, detail: `VirusTotal: ${malicious}/${total} vendors flag as malicious` });
        } else if (malicious === 1 || suspicious >= 2) {
          flags.push({ id: 'vt_minor_flags', severity: 30, detail: `VirusTotal: ${malicious} malicious, ${suspicious} suspicious out of ${total}` });
        }
      }
    }
  } catch {
    // API error — don't penalize
  }

  return flags;
}

// ═══════════════════════════════════════════════════════════════
// MAIN ANALYSIS ORCHESTRATOR
// ═══════════════════════════════════════════════════════════════

export async function analyzeUrl(urlStr, lists, options = {}) {
  const startTime = Date.now();

  let url;
  try {
    url = new URL(urlStr);
  } catch {
    return {
      url: urlStr,
      verdict: 'danger',
      score: 80,
      checks: [{ name: 'URL Syntax', status: 'fail', severity: 80, detail: 'Invalid URL — could not parse' }],
      summary: 'This URL is malformed and cannot be safely loaded.',
      ms: Date.now() - startTime,
    };
  }

  const hostname = url.hostname;

  // Phase 1: Instant local checks
  const syntaxFlags = analyzeUrlSyntax(urlStr);
  const reputationFlags = analyzeDomainReputation(hostname, lists);
  const homographFlags = analyzeHomograph(hostname, lists);
  const typosquatFlags = analyzeTyposquat(hostname, lists);

  // Quick exit for trusted domains with no syntax issues
  const isTrusted = reputationFlags.some(f => f.id === 'trusted_domain');
  const hasCriticalSyntax = syntaxFlags.some(f => f.severity >= 70);

  if (isTrusted && !hasCriticalSyntax && homographFlags.length === 0) {
    return {
      url: urlStr,
      verdict: 'safe',
      score: 0,
      checks: [
        { name: 'URL Syntax', status: 'pass', severity: 0, detail: 'Clean' },
        { name: 'Domain', status: 'pass', severity: 0, detail: `Trusted domain (${extractRegisteredDomain(hostname)})` },
        { name: 'Homograph', status: 'pass', severity: 0, detail: 'No attacks detected' },
        { name: 'Typosquatting', status: 'pass', severity: 0, detail: 'Not mimicking any known brand' },
      ],
      summary: `${extractRegisteredDomain(hostname)} is a trusted domain. Safe to visit.`,
      ms: Date.now() - startTime,
      trusted: true,
    };
  }

  // Phase 2: Async network checks (run in parallel)
  const asyncChecks = await Promise.allSettled([
    analyzeRedirects(urlStr),
    url.protocol === 'https:' ? analyzeSsl(hostname) : Promise.resolve([{ id: 'no_ssl', severity: 20, detail: 'Site does not use HTTPS' }]),
    analyzeDns(hostname),
    checkSafeBrowsing(urlStr, options.safeBrowsingKey),
    checkVirusTotal(urlStr, options.virusTotalKey),
  ]);

  const [redirectResult, sslResult, dnsResult, sbResult, vtResult] = asyncChecks.map(r =>
    r.status === 'fulfilled' ? r.value : []
  );

  // Collect all flags
  const allFlags = [
    ...syntaxFlags,
    ...reputationFlags,
    ...homographFlags,
    ...typosquatFlags,
    ...redirectResult,
    ...sslResult,
    ...dnsResult,
    ...sbResult,
    ...vtResult,
  ];

  // Calculate score
  let totalSeverity = 0;
  let maxSeverity = 0;
  let hasCritical = false;

  for (const flag of allFlags) {
    if (flag.id && flag.id.startsWith('_')) continue; // Skip metadata
    totalSeverity += flag.severity;
    if (flag.severity > 0) maxSeverity = Math.max(maxSeverity, flag.severity);
    if (flag.severity >= 80) hasCritical = true;
  }

  // Normalize score to 0-100
  const rawScore = Math.max(0, totalSeverity);
  const score = Math.min(100, Math.round(rawScore));

  // Determine verdict
  let verdict;
  if (hasCritical) {
    verdict = 'danger';
  } else if (score <= 20) {
    verdict = 'safe';
  } else if (score <= 50) {
    verdict = 'caution';
  } else {
    verdict = 'danger';
  }

  // Build check summary for each category
  const makeCheck = (name, flags) => {
    if (flags.length === 0) return { name, status: 'pass', severity: 0, detail: 'Clean' };
    const worst = flags.reduce((a, b) => (a.severity > b.severity ? a : b));
    const status = worst.severity >= 50 ? 'fail' : worst.severity >= 20 ? 'warn' : 'pass';
    return { name, status, severity: worst.severity, detail: worst.detail, flags };
  };

  const checks = [
    makeCheck('URL Syntax', syntaxFlags.filter(f => f.severity > 0)),
    makeCheck('Domain Reputation', reputationFlags.filter(f => f.severity > 0)),
    makeCheck('Homograph Check', homographFlags),
    makeCheck('Typosquatting', typosquatFlags),
    makeCheck('Redirect Chain', (redirectResult || []).filter(f => !f.id?.startsWith('_'))),
    makeCheck('SSL Certificate', sslResult || []),
    makeCheck('DNS', (dnsResult || []).filter(f => f.severity > 0)),
  ];

  // Add API checks if they ran
  if (options.safeBrowsingKey) {
    checks.push(makeCheck('Google Safe Browsing', sbResult || []));
  }
  if (options.virusTotalKey) {
    checks.push(makeCheck('VirusTotal', vtResult || []));
  }

  // Generate summary
  const failedChecks = checks.filter(c => c.status === 'fail');
  const warnChecks = checks.filter(c => c.status === 'warn');
  let summary;

  if (verdict === 'safe') {
    summary = 'All checks passed. This link appears safe.';
  } else if (verdict === 'caution') {
    const issues = [...warnChecks, ...failedChecks].map(c => c.detail).join('; ');
    summary = `Some concerns detected: ${issues}. Proceed with caution.`;
  } else {
    const issues = failedChecks.map(c => c.detail).join('; ');
    summary = `Threat detected: ${issues}. Strongly recommend NOT visiting this link.`;
  }

  return {
    url: urlStr,
    finalUrl: redirectResult?._finalUrl || urlStr,
    verdict,
    score,
    checks,
    summary,
    ms: Date.now() - startTime,
  };
}

// Quick analysis (no network calls) for extension fallback
export function analyzeUrlQuick(urlStr, lists) {
  let url;
  try { url = new URL(urlStr); } catch { return { verdict: 'caution', score: 50 }; }

  const hostname = url.hostname;
  const syntaxFlags = analyzeUrlSyntax(urlStr);
  const reputationFlags = analyzeDomainReputation(hostname, lists);
  const homographFlags = analyzeHomograph(hostname, lists);
  const typosquatFlags = analyzeTyposquat(hostname, lists);

  const isTrusted = reputationFlags.some(f => f.id === 'trusted_domain');
  if (isTrusted && homographFlags.length === 0) return { verdict: 'safe', score: 0 };

  const allFlags = [...syntaxFlags, ...reputationFlags, ...homographFlags, ...typosquatFlags];
  const totalSeverity = allFlags.reduce((s, f) => s + Math.max(0, f.severity), 0);
  const hasCritical = allFlags.some(f => f.severity >= 80);

  const score = Math.min(100, totalSeverity);
  let verdict = hasCritical ? 'danger' : score <= 20 ? 'safe' : score <= 50 ? 'caution' : 'danger';
  return { verdict, score };
}
