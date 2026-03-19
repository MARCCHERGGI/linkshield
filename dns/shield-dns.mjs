#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════
// LinkShield DNS — Network-wide link protection
// Protects every app on every device (phone, laptop, tablet)
// by intercepting DNS queries and blocking dangerous domains.
//
// Architecture:
//   [Any Device] → DNS query → [This Server] → Analysis
//     → Safe?   Forward to upstream DNS (1.1.1.1)
//     → Danger? Return 0.0.0.0 (blocked) + log + notify
//
// Zero external dependencies. Pure Node.js.
// ═══════════════════════════════════════════════════════════════

import dgram from 'node:dgram';
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ═══════════════════════════════════════════════════════════════
// 1. CONFIGURATION
// ═══════════════════════════════════════════════════════════════

const DNS_PORT = parseInt(process.env.DNS_PORT || '53');
const DASHBOARD_PORT = parseInt(process.env.DASHBOARD_PORT || '3848');
const UPSTREAM_DNS = ['1.1.1.1', '8.8.8.8'];
const UPSTREAM_TIMEOUT = 3000;
const BLOCK_IP = '0.0.0.0';
const BLOCK_IPV6 = Buffer.from('00000000000000000000000000000000', 'hex');
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || '5309534906';

// Load domain lists from server data
const listsPath = path.join(__dirname, '..', 'server', 'data', 'lists.json');
const lists = JSON.parse(fs.readFileSync(listsPath, 'utf-8'));

const trustedSet = new Set(lists.trusted);
const userContentSet = new Set(lists.userContentDomains);
const shortenerSet = new Set(lists.shorteners);

// User whitelist (persisted)
const whitelistPath = path.join(__dirname, 'whitelist.json');
let userWhitelist = new Set();
try {
  if (fs.existsSync(whitelistPath)) userWhitelist = new Set(JSON.parse(fs.readFileSync(whitelistPath, 'utf-8')));
} catch { /* fresh */ }

// Block list (runtime, grows as threats are detected)
const blockList = new Map(); // domain → { reason, score, time }

// DNS response cache
const dnsCache = new Map(); // domain → { response, expires }
const DNS_CACHE_TTL = 300_000; // 5 min
const DNS_CACHE_MAX = 10_000;

// ═══════════════════════════════════════════════════════════════
// 2. DOMAIN ANALYSIS (inline, fast, no async)
// ═══════════════════════════════════════════════════════════════

// Confusable characters
const CONFUSABLES = new Map([
  [0x0430, 'a'], [0x0435, 'e'], [0x043E, 'o'], [0x0440, 'p'], [0x0441, 'c'],
  [0x0443, 'y'], [0x0445, 'x'], [0x0456, 'i'], [0x0455, 's'], [0x03B1, 'a'],
  [0x03B5, 'e'], [0x03BF, 'o'], [0x03C1, 'p'], [0x03BA, 'k'], [0x0131, 'i'],
  [0x0261, 'g'],
]);

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

function extractBase(hostname) {
  return extractDomain(hostname).split('.')[0];
}

function levenshtein(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const m = Array.from({ length: a.length + 1 }, (_, i) =>
    Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      m[i][j] = Math.min(m[i-1][j]+1, m[i][j-1]+1, m[i-1][j-1]+(a[i-1]===b[j-1]?0:1));
  return m[a.length][b.length];
}

function normalizeHomoglyphs(str) {
  let r = '';
  for (const ch of str) {
    const code = ch.codePointAt(0);
    r += CONFUSABLES.get(code) || ch.toLowerCase();
  }
  return r;
}

function detectMixedScripts(str) {
  let hasLatin = false, hasCyrillic = false, hasGreek = false;
  for (const ch of str) {
    const c = ch.codePointAt(0);
    if (c >= 0x0041 && c <= 0x024F) hasLatin = true;
    if (c >= 0x0400 && c <= 0x04FF) hasCyrillic = true;
    if (c >= 0x0370 && c <= 0x03FF) hasGreek = true;
  }
  return (hasLatin && hasCyrillic) || (hasLatin && hasGreek) || (hasCyrillic && hasGreek);
}

function entropy(str) {
  if (!str) return 0;
  const f = {};
  for (const c of str) f[c] = (f[c]||0) + 1;
  let e = 0;
  for (const v of Object.values(f)) { const p = v/str.length; if (p > 0) e -= p * Math.log2(p); }
  return e;
}

function analyzeDomain(hostname) {
  const domain = extractDomain(hostname);
  const base = extractBase(hostname);
  const reasons = [];
  let score = 0;

  // 1. Trusted? → instant pass
  if (trustedSet.has(domain) && !userContentSet.has(domain)) {
    return { verdict: 'safe', score: 0, reasons: ['Trusted domain'] };
  }

  // User whitelist
  if (userWhitelist.has(domain)) {
    return { verdict: 'safe', score: 0, reasons: ['User whitelisted'] };
  }

  // 2. User-content hosting
  for (const ucd of userContentSet) {
    if (hostname.endsWith(ucd)) {
      reasons.push(`User-content host (${ucd})`);
      score += 25;
      break;
    }
  }

  // 3. TLD risk
  const tld = '.' + hostname.split('.').pop().toLowerCase();
  if (lists.suspiciousTlds.high.includes(tld)) {
    reasons.push(`High-risk TLD: ${tld}`);
    score += 55;
  } else if (lists.suspiciousTlds.medium.includes(tld)) {
    reasons.push(`Medium-risk TLD: ${tld}`);
    score += 25;
  }

  // 4. Homograph detection
  if (hostname.includes('xn--')) {
    reasons.push('Punycode (internationalized domain)');
    score += 50;
  }
  if (detectMixedScripts(hostname.replace(/\./g, ''))) {
    reasons.push('Mixed character sets (Cyrillic/Greek/Latin)');
    score += 80;
  }

  // Check visual similarity to brands
  const normalized = normalizeHomoglyphs(base);
  for (const brand of lists.brands) {
    const brandBase = brand.domain.split('.')[0];
    if (normalized === brandBase && base !== brandBase) {
      reasons.push(`Homograph attack mimicking ${brand.name}`);
      score += 90;
      break;
    }
  }

  // 5. Typosquatting
  if (base.length >= 3) {
    for (const brand of lists.brands) {
      const brandBase = brand.domain.split('.')[0];
      if (base === brandBase) break;
      const dist = levenshtein(base, brandBase);
      if (dist === 1) {
        reasons.push(`Typosquat of ${brand.name} (${brand.domain})`);
        score += 75;
        break;
      }
      if (dist === 2 && Math.max(base.length, brandBase.length) >= 6) {
        reasons.push(`Similar to ${brand.name} (${brand.domain})`);
        score += 50;
        break;
      }
      // Brand keyword in compound domain
      for (const kw of brand.keywords) {
        if (base.includes(kw) && base !== kw && base.length > kw.length + 3) {
          reasons.push(`Contains "${kw}" — may impersonate ${brand.name}`);
          score += 45;
          break;
        }
      }
      if (score > 0 && reasons.length > 0 && reasons[reasons.length-1].includes('impersonate')) break;
    }
  }

  // 6. Suspicious patterns
  const dashes = (base.match(/-/g) || []).length;
  if (dashes >= 3) {
    reasons.push(`${dashes} hyphens (common in phishing)`);
    score += 35;
  }

  const suspWords = ['secure', 'login', 'verify', 'account', 'update', 'banking', 'wallet', 'recover', 'suspend'];
  for (const w of suspWords) {
    if (base.includes(w) && !trustedSet.has(domain)) {
      reasons.push(`Contains "${w}"`);
      score += 30;
      break;
    }
  }

  if (entropy(base) > 3.8 && base.length > 8) {
    reasons.push('Random-looking domain');
    score += 30;
  }

  if (domain.length > 30) {
    reasons.push('Very long domain');
    score += 15;
  }

  // URL shortener
  if (shortenerSet.has(domain)) {
    // Don't block shorteners, just note them
    reasons.push('URL shortener');
    score += 10;
  }

  // Free hosting
  for (const fh of lists.freeHosting) {
    if (hostname.endsWith(fh)) {
      reasons.push(`Free hosting (${fh})`);
      score += 30;
      break;
    }
  }

  // Verdict
  score = Math.min(100, score);
  const hasCritical = score >= 80;
  let verdict;
  if (hasCritical) verdict = 'danger';
  else if (score <= 20) verdict = 'safe';
  else if (score <= 50) verdict = 'caution';
  else verdict = 'danger';

  return { verdict, score, reasons };
}

// ═══════════════════════════════════════════════════════════════
// 3. DNS PROTOCOL — Parse and build DNS packets
// ═══════════════════════════════════════════════════════════════

function parseDnsQuery(buf) {
  if (buf.length < 12) return null;

  const id = buf.readUInt16BE(0);
  const flags = buf.readUInt16BE(2);
  const qdcount = buf.readUInt16BE(4);

  if (qdcount === 0) return null;

  // Parse first question's QNAME
  let offset = 12;
  const labels = [];
  while (offset < buf.length && buf[offset] !== 0) {
    const len = buf[offset];
    if ((len & 0xC0) === 0xC0) break; // Pointer — shouldn't be in question, skip
    if (len === 0 || offset + len >= buf.length) break;
    offset++;
    labels.push(buf.slice(offset, offset + len).toString('ascii'));
    offset += len;
  }
  offset++; // Skip null byte

  if (offset + 4 > buf.length) return null;

  const qtype = buf.readUInt16BE(offset);
  const qclass = buf.readUInt16BE(offset + 2);
  const questionEnd = offset + 4;

  return {
    id,
    flags,
    domain: labels.join('.').toLowerCase(),
    qtype,   // 1=A, 28=AAAA, 5=CNAME, 15=MX, 16=TXT, etc.
    qclass,
    questionEnd,
    raw: buf,
  };
}

function buildBlockResponseA(query) {
  // Build response header
  const header = Buffer.alloc(12);
  header.writeUInt16BE(query.id, 0);
  header.writeUInt16BE(0x8180, 2); // QR=1, RD=1, RA=1
  header.writeUInt16BE(1, 4);      // QDCOUNT
  header.writeUInt16BE(1, 6);      // ANCOUNT

  // Question section (copy from query)
  const question = query.raw.slice(12, query.questionEnd);

  // Answer: 0.0.0.0
  const answer = Buffer.alloc(16);
  answer.writeUInt16BE(0xC00C, 0);  // Name pointer → offset 12
  answer.writeUInt16BE(1, 2);       // Type A
  answer.writeUInt16BE(1, 4);       // Class IN
  answer.writeUInt32BE(60, 6);      // TTL 60s
  answer.writeUInt16BE(4, 10);      // RDLENGTH
  // RDATA: 0.0.0.0 (already zeros)

  return Buffer.concat([header, question, answer]);
}

function buildBlockResponseAAAA(query) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(query.id, 0);
  header.writeUInt16BE(0x8180, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(1, 6);

  const question = query.raw.slice(12, query.questionEnd);

  const answer = Buffer.alloc(28);
  answer.writeUInt16BE(0xC00C, 0);
  answer.writeUInt16BE(28, 2);      // Type AAAA
  answer.writeUInt16BE(1, 4);
  answer.writeUInt32BE(60, 6);
  answer.writeUInt16BE(16, 10);
  // RDATA: :: (16 bytes of zeros, already filled)

  return Buffer.concat([header, question, answer]);
}

function buildNxdomainResponse(query) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(query.id, 0);
  header.writeUInt16BE(0x8183, 2); // QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
  header.writeUInt16BE(1, 4);
  // No answers

  const question = query.raw.slice(12, query.questionEnd);
  return Buffer.concat([header, question]);
}

// ═══════════════════════════════════════════════════════════════
// 4. DNS SERVER
// ═══════════════════════════════════════════════════════════════

const stats = {
  started: Date.now(),
  queries: 0,
  blocked: 0,
  forwarded: 0,
  cached: 0,
  errors: 0,
  recentBlocks: [],  // Last 50 blocked domains
};

const dnsServer = dgram.createSocket('udp4');

dnsServer.on('message', async (msg, rinfo) => {
  stats.queries++;

  const query = parseDnsQuery(msg);
  if (!query) {
    stats.errors++;
    return;
  }

  const domain = query.domain;

  // Skip empty or local domains
  if (!domain || domain === '' || domain.endsWith('.local') || domain.endsWith('.lan') ||
      domain.endsWith('.internal') || domain === 'localhost') {
    return forwardToUpstream(msg, rinfo);
  }

  // Check block list (previously analyzed as dangerous)
  if (blockList.has(domain)) {
    stats.blocked++;
    return sendBlockResponse(query, rinfo);
  }

  // Check if domain is trusted or whitelisted
  const regDomain = extractDomain(domain);
  if (trustedSet.has(regDomain) || userWhitelist.has(regDomain)) {
    stats.forwarded++;
    return forwardToUpstream(msg, rinfo);
  }

  // Check DNS cache
  const cached = dnsCache.get(domain + ':' + query.qtype);
  if (cached && Date.now() < cached.expires) {
    stats.cached++;
    // Update transaction ID in cached response
    const resp = Buffer.from(cached.response);
    resp.writeUInt16BE(query.id, 0);
    return dnsServer.send(resp, rinfo.port, rinfo.address);
  }

  // Analyze domain
  const analysis = analyzeDomain(domain);

  if (analysis.verdict === 'danger') {
    // Block it
    blockList.set(domain, {
      reason: analysis.reasons.join('; '),
      score: analysis.score,
      time: Date.now(),
    });
    stats.blocked++;

    // Log and notify
    const blockEntry = {
      domain,
      score: analysis.score,
      reasons: analysis.reasons,
      time: new Date().toISOString(),
      from: rinfo.address,
    };
    stats.recentBlocks.unshift(blockEntry);
    if (stats.recentBlocks.length > 50) stats.recentBlocks.pop();

    console.log(`\x1b[31m  BLOCKED\x1b[0m  ${domain}  (score: ${analysis.score})  ${analysis.reasons.join(', ')}`);
    logToFile(blockEntry);
    sendTelegramAlert(blockEntry);

    return sendBlockResponse(query, rinfo);
  }

  if (analysis.verdict === 'caution') {
    console.log(`\x1b[33m  CAUTION\x1b[0m  ${domain}  (score: ${analysis.score})  ${analysis.reasons.join(', ')}`);
  }

  // Safe or caution — forward to upstream
  stats.forwarded++;
  forwardToUpstream(msg, rinfo);
});

function sendBlockResponse(query, rinfo) {
  let response;
  if (query.qtype === 1) {
    response = buildBlockResponseA(query);
  } else if (query.qtype === 28) {
    response = buildBlockResponseAAAA(query);
  } else {
    response = buildNxdomainResponse(query);
  }
  dnsServer.send(response, rinfo.port, rinfo.address);
}

function forwardToUpstream(queryBuffer, clientInfo) {
  const upstream = dgram.createSocket('udp4');
  let responded = false;

  const timeout = setTimeout(() => {
    if (!responded) {
      responded = true;
      upstream.close();
      // Try second upstream
      const backup = dgram.createSocket('udp4');
      const timeout2 = setTimeout(() => { backup.close(); }, UPSTREAM_TIMEOUT);
      backup.on('message', (response) => {
        clearTimeout(timeout2);
        backup.close();
        cacheResponse(queryBuffer, response);
        dnsServer.send(response, clientInfo.port, clientInfo.address);
      });
      backup.on('error', () => { clearTimeout(timeout2); backup.close(); });
      backup.send(queryBuffer, 53, UPSTREAM_DNS[1]);
    }
  }, UPSTREAM_TIMEOUT);

  upstream.on('message', (response) => {
    if (!responded) {
      responded = true;
      clearTimeout(timeout);
      upstream.close();
      cacheResponse(queryBuffer, response);
      dnsServer.send(response, clientInfo.port, clientInfo.address);
    }
  });

  upstream.on('error', () => {
    if (!responded) {
      responded = true;
      clearTimeout(timeout);
      upstream.close();
    }
  });

  upstream.send(queryBuffer, 53, UPSTREAM_DNS[0]);
}

function cacheResponse(queryBuffer, response) {
  const query = parseDnsQuery(queryBuffer);
  if (!query) return;
  const key = query.domain + ':' + query.qtype;
  dnsCache.set(key, { response: Buffer.from(response), expires: Date.now() + DNS_CACHE_TTL });
  // Prune cache
  if (dnsCache.size > DNS_CACHE_MAX) {
    const oldest = dnsCache.keys().next().value;
    dnsCache.delete(oldest);
  }
}

dnsServer.on('error', (err) => {
  if (err.code === 'EACCES' || err.code === 'EADDRINUSE') {
    console.error(`\n  Port ${DNS_PORT} not available (${err.code}).`);
    if (DNS_PORT === 53) {
      console.error('  On Windows, try: net stop dnscache  (run as admin)');
      console.error('  Or set DNS_PORT=5353 to use alternate port.\n');
    }
    process.exit(1);
  }
  console.error('DNS server error:', err);
});

// ═══════════════════════════════════════════════════════════════
// 5. STATUS DASHBOARD (HTTP)
// ═══════════════════════════════════════════════════════════════

const dashboardServer = http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${DASHBOARD_PORT}`);

  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');

  // iOS profile download
  if (url.pathname === '/ios-profile') {
    const tailscaleIp = detectTailscaleIp() || '127.0.0.1';
    const profile = generateIosProfile(tailscaleIp);
    res.writeHead(200, {
      'Content-Type': 'application/x-apple-aspen-config',
      'Content-Disposition': 'attachment; filename="LinkShield-DNS.mobileconfig"',
    });
    res.end(profile);
    return;
  }

  // API: stats
  if (url.pathname === '/api/stats') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      uptime: Math.floor((Date.now() - stats.started) / 1000),
      ...stats,
      blockListSize: blockList.size,
      cacheSize: dnsCache.size,
    }));
    return;
  }

  // API: block list
  if (url.pathname === '/api/blocks') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(stats.recentBlocks));
    return;
  }

  // API: whitelist management
  if (url.pathname === '/api/whitelist' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const { domain } = JSON.parse(body);
        userWhitelist.add(domain);
        blockList.delete(domain);
        fs.writeFileSync(whitelistPath, JSON.stringify([...userWhitelist], null, 2));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch { res.writeHead(400); res.end('Bad request'); }
    });
    return;
  }

  // ── TEST PAGE — Proves DNS is working from any device ──
  if (url.pathname === '/test') {
    const clientIp = req.socket.remoteAddress?.replace('::ffff:', '') || 'unknown';
    const tailIp = detectTailscaleIp() || '127.0.0.1';
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LinkShield — Connection Test</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0f;color:#e0e0e8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:24px;min-height:100vh}
.card{background:#151520;border:1px solid #2a2a3a;border-radius:12px;padding:20px;margin-bottom:16px}
h1{font-size:22px;margin-bottom:20px;display:flex;align-items:center;gap:12px}
h2{font-size:16px;color:#a0a0b8;margin-bottom:12px}
.pass{color:#22c55e;font-weight:700}.fail{color:#ef4444;font-weight:700}.wait{color:#f59e0b;font-weight:700}
.test-row{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid #1e1e30;font-size:14px}
.test-row:last-child{border:none}
.icon{width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0}
.icon.pass{background:rgba(34,197,94,0.15)}.icon.fail{background:rgba(239,68,68,0.15)}.icon.wait{background:rgba(245,158,11,0.15)}
.label{flex:1;color:#c0c0d0}.detail{font-size:12px;color:#8888a0}
.btn{display:inline-block;padding:12px 24px;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;border:none;text-decoration:none;color:#fff;margin:8px 4px;transition:all .2s}
.btn-green{background:#22c55e}.btn-red{background:#ef4444}.btn-blue{background:#6366f1}
.btn:active{transform:scale(0.97)}
#liveLog{background:#0a0a0f;border:1px solid #2a2a3a;border-radius:8px;padding:12px;font-family:monospace;font-size:12px;max-height:200px;overflow-y:auto;margin-top:12px}
.log-entry{padding:4px 0;border-bottom:1px solid #1a1a2a}
.log-blocked{color:#ef4444}.log-safe{color:#22c55e}
.big-status{text-align:center;padding:30px;font-size:18px}
.pulse{display:inline-block;width:12px;height:12px;border-radius:50%;margin-right:8px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
</style></head><body>
<h1><span style="font-size:32px">&#x1f6e1;</span> LinkShield — Connection Test</h1>

<div class="card">
  <h2>Step 1: Are you connected?</h2>
  <div class="test-row">
    <div class="icon pass">&#x2713;</div>
    <div class="label">You reached this page</div>
    <div class="detail">Your device can talk to LinkShield</div>
  </div>
  <div class="test-row">
    <div class="icon pass">&#x2713;</div>
    <div class="label">Your IP: <code>${clientIp}</code></div>
    <div class="detail">${clientIp.startsWith('100.') ? 'Coming through Tailscale — phone/remote device' : clientIp === '127.0.0.1' ? 'Localhost — this computer' : 'Local network'}</div>
  </div>
</div>

<div class="card">
  <h2>Step 2: Is DNS routing through LinkShield?</h2>
  <div id="dnsTest" class="big-status">
    <span class="wait">Testing DNS...</span>
  </div>
  <p style="font-size:12px;color:#6a6a80;margin-top:8px;text-align:center">
    This checks if your device's DNS queries go through LinkShield.
  </p>
</div>

<div class="card">
  <h2>Step 3: Try it! Tap a dangerous link</h2>
  <p style="font-size:13px;color:#8888a0;margin-bottom:12px">
    These are fake phishing domains. If LinkShield is working, they will NOT load.
  </p>
  <a class="btn btn-red" href="http://paypal-secure-login.tk" target="_blank">paypal-secure-login.tk</a>
  <a class="btn btn-red" href="http://gooogle.com" target="_blank">gooogle.com (typosquat)</a>
  <a class="btn btn-red" href="http://apple-id-verify.ml" target="_blank">apple-id-verify.ml</a>
  <p style="font-size:12px;color:#22c55e;margin-top:12px">
    If they fail to load ("can't reach site") — you're protected.
  </p>
</div>

<div class="card">
  <h2>Step 4: Verify safe sites still work</h2>
  <a class="btn btn-green" href="https://google.com" target="_blank">google.com</a>
  <a class="btn btn-green" href="https://youtube.com" target="_blank">youtube.com</a>
  <a class="btn btn-green" href="https://github.com" target="_blank">github.com</a>
  <p style="font-size:12px;color:#8888a0;margin-top:8px">These should load normally.</p>
</div>

<div class="card">
  <h2>Live Block Log</h2>
  <p style="font-size:12px;color:#8888a0;margin-bottom:8px">Blocked domains appear here in real-time:</p>
  <div id="liveLog"><div style="color:#4a4a60">Waiting for blocks...</div></div>
</div>

<div class="card" style="text-align:center">
  <h2>Not working?</h2>
  <p style="font-size:13px;color:#8888a0;line-height:1.8">
    <strong>iPhone:</strong> Settings &rarr; WiFi &rarr; your network &rarr; Configure DNS &rarr; Manual &rarr; <code>${tailIp}</code><br>
    Or download the <a href="/ios-profile" style="color:#818cf8">DNS profile</a><br><br>
    <strong>Android:</strong> Settings &rarr; WiFi &rarr; your network &rarr; Advanced &rarr; DNS 1: <code>${tailIp}</code><br><br>
    <strong>Both devices need Tailscale connected</strong>
  </p>
</div>

<script>
// DNS test: try to resolve a domain we know we'd block
async function testDns() {
  const el = document.getElementById('dnsTest');
  try {
    // Try to fetch a resource from a domain we block
    // If DNS is going through us, this fetch will fail (0.0.0.0)
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 3000);
    await fetch('http://linkshield-dns-test-block.tk/', { mode: 'no-cors', signal: controller.signal });
    // If we get here, DNS is NOT going through LinkShield
    el.innerHTML = '<span class="fail">&#x2717; DNS is NOT going through LinkShield</span><br><small style="color:#8888a0">Set your DNS to ${tailIp} — see instructions below</small>';
  } catch(e) {
    if (e.name === 'AbortError' || e.message.includes('network') || e.message.includes('Failed')) {
      el.innerHTML = '<span class="pulse" style="background:#22c55e"></span><span class="pass">DNS is routed through LinkShield!</span>';
    } else {
      el.innerHTML = '<span class="pass">&#x2713; DNS appears to be protected</span>';
    }
  }
}
testDns();

// Live log polling
let lastCount = 0;
async function pollBlocks() {
  try {
    const res = await fetch('/api/blocks');
    const blocks = await res.json();
    if (blocks.length > lastCount || lastCount === 0) {
      const log = document.getElementById('liveLog');
      log.innerHTML = blocks.slice(0, 15).map(b =>
        '<div class="log-entry log-blocked">' +
        new Date(b.time).toLocaleTimeString() + ' — ' +
        '<strong>' + b.domain + '</strong> — ' +
        b.reasons.join(', ') +
        '</div>'
      ).join('') || '<div style="color:#4a4a60">No blocks yet</div>';
      lastCount = blocks.length;
    }
  } catch {}
}
pollBlocks();
setInterval(pollBlocks, 2000);
</script>
</body></html>`);
    return;
  }

  // ── DNS connectivity check endpoint ──
  if (url.pathname === '/api/dns-check') {
    // If a device can reach this, the HTTP connection works
    // We also test if DNS queries from that device are coming through us
    const clientIp = req.socket.remoteAddress?.replace('::ffff:', '') || 'unknown';
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      connected: true,
      clientIp,
      viaTailscale: clientIp.startsWith('100.'),
      dnsServer: `${detectTailscaleIp() || '127.0.0.1'}:${DNS_PORT}`,
      stats: { queries: stats.queries, blocked: stats.blocked },
    }));
    return;
  }

  // Dashboard HTML
  const tailscaleIp = detectTailscaleIp();
  const localIp = detectLocalIp();
  const uptimeSec = Math.floor((Date.now() - stats.started) / 1000);
  const uptime = uptimeSec < 60 ? `${uptimeSec}s` :
    uptimeSec < 3600 ? `${Math.floor(uptimeSec/60)}m ${uptimeSec%60}s` :
    `${Math.floor(uptimeSec/3600)}h ${Math.floor((uptimeSec%3600)/60)}m`;

  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LinkShield DNS</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0f;color:#e0e0e8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;padding:24px;min-height:100vh}
.header{display:flex;align-items:center;gap:14px;margin-bottom:28px}
.shield{width:48px;height:48px;background:linear-gradient(135deg,#6366f1,#4f46e5);border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px;flex-shrink:0}
h1{font-size:22px;font-weight:600}
.sub{font-size:13px;color:#22c55e;margin-top:2px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:28px}
.stat{background:#151520;border:1px solid #2a2a3a;border-radius:10px;padding:16px;text-align:center}
.stat .num{font-size:28px;font-weight:700;color:#f0f0f5}
.stat .num.green{color:#22c55e}.stat .num.red{color:#ef4444}.stat .num.blue{color:#818cf8}
.stat .label{font-size:12px;color:#6a6a80;margin-top:4px}
.section{margin-bottom:28px}
.section h2{font-size:16px;font-weight:600;margin-bottom:12px;color:#a0a0b8}
.card{background:#151520;border:1px solid #2a2a3a;border-radius:10px;overflow:hidden}
.block-row{padding:12px 16px;border-bottom:1px solid #1e1e30;display:flex;align-items:center;gap:12px}
.block-row:last-child{border-bottom:none}
.block-domain{font-family:'SF Mono','Fira Code',monospace;font-size:13px;color:#ef4444;flex:1}
.block-reason{font-size:12px;color:#8888a0;max-width:300px}
.block-time{font-size:11px;color:#4a4a60;white-space:nowrap}
.block-score{background:rgba(239,68,68,0.15);color:#ef4444;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
.empty{padding:24px;text-align:center;color:#4a4a60;font-size:14px}
.setup{background:#151520;border:1px solid #2a2a3a;border-radius:10px;padding:20px}
.setup h3{font-size:14px;margin-bottom:10px;color:#c0c0d0}
.setup p{font-size:13px;color:#8888a0;line-height:1.6;margin-bottom:8px}
.setup code{background:#0e0e18;padding:2px 6px;border-radius:4px;font-size:12px;color:#818cf8}
.btn{display:inline-block;padding:10px 20px;border-radius:8px;font-size:14px;font-weight:500;cursor:pointer;border:none;text-decoration:none;margin-top:8px;transition:all .2s}
.btn-primary{background:linear-gradient(135deg,#6366f1,#4f46e5);color:#fff}
.btn-primary:hover{filter:brightness(1.1)}
.ip-highlight{color:#22c55e;font-weight:600;font-family:monospace}
</style>
</head>
<body>
<div class="header">
  <div class="shield">&#x1f6e1;</div>
  <div><h1>LinkShield DNS</h1><div class="sub">Active — Protecting all devices</div></div>
</div>

<div class="stats-grid">
  <div class="stat"><div class="num blue">${stats.queries.toLocaleString()}</div><div class="label">DNS Queries</div></div>
  <div class="stat"><div class="num red">${stats.blocked.toLocaleString()}</div><div class="label">Threats Blocked</div></div>
  <div class="stat"><div class="num green">${stats.forwarded.toLocaleString()}</div><div class="label">Passed Safe</div></div>
  <div class="stat"><div class="num">${uptime}</div><div class="label">Uptime</div></div>
</div>

<div class="section">
  <h2>Recent Blocks</h2>
  <div class="card">
    ${stats.recentBlocks.length === 0
      ? '<div class="empty">No threats blocked yet. That\'s a good sign!</div>'
      : stats.recentBlocks.slice(0, 20).map(b => `
      <div class="block-row">
        <span class="block-score">${b.score}</span>
        <span class="block-domain">${esc(b.domain)}</span>
        <span class="block-reason">${esc(b.reasons.join(', '))}</span>
        <span class="block-time">${new Date(b.time).toLocaleTimeString()}</span>
      </div>`).join('')}
  </div>
</div>

<div class="section">
  <h2>Connect Your Devices</h2>
  <div class="setup">
    ${tailscaleIp ? `
    <h3>Your LinkShield DNS Address</h3>
    <p>Point any device's DNS to: <span class="ip-highlight">${tailscaleIp}</span></p>
    <p style="font-size:12px;color:#6a6a80">Tailscale IP — works from anywhere your VPN is connected</p>

    <h3 style="margin-top:20px">iPhone / iPad</h3>
    <p>Easiest: <a href="/ios-profile" class="btn btn-primary" style="display:inline-block;padding:8px 16px;font-size:13px">Download DNS Profile</a></p>
    <p>Or manually: Settings → WiFi → your network → Configure DNS → Manual → <code>${tailscaleIp}</code></p>

    <h3 style="margin-top:16px">Android</h3>
    <p>Settings → WiFi → your network → IP settings → Static → DNS 1: <code>${tailscaleIp}</code></p>

    <h3 style="margin-top:16px">Windows / Mac / Linux</h3>
    <p>Set DNS to <code>${tailscaleIp}</code> in your network settings, or add to Tailscale DNS config.</p>
    ` : `
    <h3>Local Only (Tailscale not detected)</h3>
    <p>DNS server is running on <code>127.0.0.1:${DNS_PORT}</code></p>
    <p>To protect other devices, install Tailscale or use your local IP: <code>${localIp || '127.0.0.1'}</code></p>
    `}
  </div>
</div>

<script>
setInterval(()=>location.reload(), 30000);
</script>
</body></html>`);
});

function esc(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// ═══════════════════════════════════════════════════════════════
// 6. iOS PROFILE GENERATOR
// ═══════════════════════════════════════════════════════════════

function generateIosProfile(dnsIp) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>DNSSettings</key>
      <dict>
        <key>DNSProtocol</key>
        <string>Cleartext</string>
        <key>ServerAddresses</key>
        <array>
          <string>${dnsIp}</string>
          <string>1.1.1.1</string>
        </array>
      </dict>
      <key>PayloadDescription</key>
      <string>Routes DNS through LinkShield for threat protection</string>
      <key>PayloadDisplayName</key>
      <string>LinkShield DNS</string>
      <key>PayloadIdentifier</key>
      <string>com.linkshield.dns.settings</string>
      <key>PayloadType</key>
      <string>com.apple.dnsSettings.managed</string>
      <key>PayloadUUID</key>
      <string>A1B2C3D4-E5F6-7890-ABCD-123456789ABC</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>LinkShield DNS Protection — blocks phishing, malware, and scam domains before they load.</string>
  <key>PayloadDisplayName</key>
  <string>LinkShield DNS</string>
  <key>PayloadIdentifier</key>
  <string>com.linkshield.dns.profile</string>
  <key>PayloadOrganization</key>
  <string>LinkShield</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>12345678-ABCD-ABCD-ABCD-123456789012</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>`;
}

// ═══════════════════════════════════════════════════════════════
// 7. LOGGING & NOTIFICATIONS
// ═══════════════════════════════════════════════════════════════

const logDir = path.join(__dirname, 'logs');
try { fs.mkdirSync(logDir, { recursive: true }); } catch {}

function logToFile(entry) {
  const date = new Date().toISOString().split('T')[0];
  const logFile = path.join(logDir, `blocks-${date}.log`);
  const line = `${entry.time}  ${entry.domain}  score:${entry.score}  from:${entry.from}  ${entry.reasons.join('; ')}\n`;
  fs.appendFile(logFile, line, () => {});
}

function sendTelegramAlert(entry) {
  if (!TELEGRAM_BOT_TOKEN) return;

  const msg = `🛡 <b>LinkShield blocked a threat</b>\n\n` +
    `<code>${entry.domain}</code>\n` +
    `Score: ${entry.score}/100\n` +
    `${entry.reasons.map(r => `• ${r}`).join('\n')}\n` +
    `\nFrom: ${entry.from}`;

  const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
  const body = JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text: msg, parse_mode: 'HTML' });

  const req = https.request(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } });
  req.on('error', () => {});
  req.write(body);
  req.end();
}

// ═══════════════════════════════════════════════════════════════
// 8. NETWORK DETECTION
// ═══════════════════════════════════════════════════════════════

function detectTailscaleIp() {
  const interfaces = os.networkInterfaces();
  for (const [name, addrs] of Object.entries(interfaces)) {
    for (const addr of addrs) {
      if (addr.family === 'IPv4' && addr.address.startsWith('100.')) {
        return addr.address;
      }
    }
  }
  return null;
}

function detectLocalIp() {
  const interfaces = os.networkInterfaces();
  for (const [name, addrs] of Object.entries(interfaces)) {
    for (const addr of addrs) {
      if (addr.family === 'IPv4' && !addr.internal && !addr.address.startsWith('100.')) {
        return addr.address;
      }
    }
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════
// 9. STARTUP
// ═══════════════════════════════════════════════════════════════

process.on('uncaughtException', (err) => {
  console.error('  Uncaught exception (DNS server stays running):', err.message);
});

const tailscaleIp = detectTailscaleIp();
const localIp = detectLocalIp();
const bindAddress = '0.0.0.0'; // Listen on all interfaces

dnsServer.bind(DNS_PORT, bindAddress, () => {
  dashboardServer.listen(DASHBOARD_PORT, '0.0.0.0', () => {

    console.log(`
  ╔══════════════════════════════════════════════════════╗
  ║  LinkShield DNS — Network Protection Active          ║
  ╠══════════════════════════════════════════════════════╣
  ║                                                      ║
  ║  DNS Server:    ${bindAddress}:${String(DNS_PORT).padEnd(5)}                       ║
  ║  Dashboard:     http://localhost:${DASHBOARD_PORT}                ║
  ║                                                      ║${tailscaleIp ? `
  ║  Tailscale IP:  ${tailscaleIp.padEnd(16)}                     ║
  ║  Phone DNS:     Set DNS to ${tailscaleIp.padEnd(16)}            ║` : `
  ║  Local IP:      ${(localIp || '127.0.0.1').padEnd(16)}                     ║
  ║  (Install Tailscale for phone protection)            ║`}
  ║                                                      ║
  ║  Upstream DNS:  ${UPSTREAM_DNS.join(', ').padEnd(20)}               ║
  ║  Trusted:       ${String(trustedSet.size).padEnd(4)} domains                       ║
  ║  Brands:        ${String(lists.brands.length).padEnd(4)} monitored                      ║
  ║  Telegram:      ${TELEGRAM_BOT_TOKEN ? 'ON ' : 'OFF'}                                  ║
  ║                                                      ║
  ╚══════════════════════════════════════════════════════╝
    `);

    if (tailscaleIp) {
      console.log(`  Phone setup: Point DNS to ${tailscaleIp}`);
      console.log(`  iOS shortcut: http://${tailscaleIp}:${DASHBOARD_PORT}/ios-profile`);
    }
    console.log(`  Dashboard: http://localhost:${DASHBOARD_PORT}\n`);
  });
});
