// LinkShield Server — Local analysis API
// Zero external dependencies. Runs on Node.js built-ins.

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeUrl, analyzeUrlQuick } from './analyze.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ═══════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════

const PORT = parseInt(process.env.LINKSHIELD_PORT || '3847');
const SAFE_BROWSING_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY || '';
const VIRUSTOTAL_KEY = process.env.VIRUSTOTAL_KEY || '';

// Load domain lists
const listsPath = path.join(__dirname, 'data', 'lists.json');
const lists = JSON.parse(fs.readFileSync(listsPath, 'utf-8'));

// ═══════════════════════════════════════════════════════════════
// CACHE (LRU with TTL)
// ═══════════════════════════════════════════════════════════════

class LRUCache {
  constructor(maxSize = 5000) {
    this.max = maxSize;
    this.cache = new Map();
  }

  get(key) {
    const entry = this.cache.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expires) {
      this.cache.delete(key);
      return null;
    }
    // Move to end (most recently used)
    this.cache.delete(key);
    this.cache.set(key, entry);
    return entry.value;
  }

  set(key, value, ttlMs) {
    if (this.cache.size >= this.max) {
      // Delete oldest
      const oldest = this.cache.keys().next().value;
      this.cache.delete(oldest);
    }
    this.cache.set(key, { value, expires: Date.now() + ttlMs });
  }

  get size() { return this.cache.size; }
}

const cache = new LRUCache(5000);

// TTLs by verdict
const TTL = {
  safe: 3600_000,     // 1 hour
  caution: 1800_000,  // 30 min
  danger: 86400_000,  // 24 hours
  trusted: 86400_000, // 24 hours
};

// ═══════════════════════════════════════════════════════════════
// STATS
// ═══════════════════════════════════════════════════════════════

const stats = {
  started: new Date().toISOString(),
  totalChecks: 0,
  verdicts: { safe: 0, caution: 0, danger: 0 },
  cacheHits: 0,
  lastCheck: null,
};

// ═══════════════════════════════════════════════════════════════
// USER WHITELIST (persisted to disk)
// ═══════════════════════════════════════════════════════════════

const whitelistPath = path.join(__dirname, 'data', 'whitelist.json');
let whitelist = new Set();

try {
  if (fs.existsSync(whitelistPath)) {
    whitelist = new Set(JSON.parse(fs.readFileSync(whitelistPath, 'utf-8')));
  }
} catch { /* fresh start */ }

function saveWhitelist() {
  fs.writeFileSync(whitelistPath, JSON.stringify([...whitelist], null, 2));
}

// ═══════════════════════════════════════════════════════════════
// HTTP SERVER
// ═══════════════════════════════════════════════════════════════

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

function json(res, data, status = 200) {
  cors(res);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (data.length > 100_000) { req.destroy(); reject(new Error('Body too large')); }
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const route = url.pathname;

  // CORS preflight
  if (req.method === 'OPTIONS') {
    cors(res);
    res.writeHead(204);
    res.end();
    return;
  }

  try {
    // ── POST /api/check ────────────────────────────────────
    if (route === '/api/check' && req.method === 'POST') {
      const body = JSON.parse(await readBody(req));
      const targetUrl = body.url;

      if (!targetUrl || typeof targetUrl !== 'string') {
        return json(res, { error: 'Missing url field' }, 400);
      }

      // Check whitelist
      try {
        const domain = new URL(targetUrl).hostname;
        const reg = domain.split('.').slice(-2).join('.');
        if (whitelist.has(reg)) {
          stats.totalChecks++;
          stats.verdicts.safe++;
          stats.lastCheck = { url: targetUrl, verdict: 'safe', time: new Date().toISOString() };
          return json(res, {
            url: targetUrl,
            verdict: 'safe',
            score: 0,
            checks: [{ name: 'User Whitelist', status: 'pass', severity: 0, detail: `${reg} is whitelisted by you` }],
            summary: `${reg} is in your trusted whitelist.`,
            ms: 0,
            whitelisted: true,
          });
        }
      } catch { /* invalid URL, let analyzer handle it */ }

      // Check cache
      const cached = cache.get(targetUrl);
      if (cached) {
        stats.cacheHits++;
        stats.totalChecks++;
        stats.verdicts[cached.verdict]++;
        stats.lastCheck = { url: targetUrl, verdict: cached.verdict, time: new Date().toISOString() };
        return json(res, { ...cached, cached: true });
      }

      // Full analysis
      const result = await analyzeUrl(targetUrl, lists, {
        safeBrowsingKey: SAFE_BROWSING_KEY,
        virusTotalKey: VIRUSTOTAL_KEY,
      });

      // Cache it
      const ttl = result.trusted ? TTL.trusted : TTL[result.verdict] || TTL.caution;
      cache.set(targetUrl, result, ttl);

      stats.totalChecks++;
      stats.verdicts[result.verdict]++;
      stats.lastCheck = { url: targetUrl, verdict: result.verdict, time: new Date().toISOString() };

      return json(res, result);
    }

    // ── POST /api/whitelist ────────────────────────────────
    if (route === '/api/whitelist' && req.method === 'POST') {
      const body = JSON.parse(await readBody(req));
      const domain = body.domain;
      if (!domain) return json(res, { error: 'Missing domain' }, 400);
      whitelist.add(domain);
      saveWhitelist();
      return json(res, { ok: true, whitelisted: [...whitelist] });
    }

    // ── DELETE /api/whitelist ──────────────────────────────
    if (route === '/api/whitelist' && req.method === 'DELETE') {
      const body = JSON.parse(await readBody(req));
      const domain = body.domain;
      if (!domain) return json(res, { error: 'Missing domain' }, 400);
      whitelist.delete(domain);
      saveWhitelist();
      return json(res, { ok: true, whitelisted: [...whitelist] });
    }

    // ── GET /api/whitelist ─────────────────────────────────
    if (route === '/api/whitelist' && req.method === 'GET') {
      return json(res, { whitelisted: [...whitelist] });
    }

    // ── GET /api/lists ─────────────────────────────────────
    if (route === '/api/lists' && req.method === 'GET') {
      return json(res, {
        trusted: lists.trusted,
        userContentDomains: lists.userContentDomains,
        whitelist: [...whitelist],
      });
    }

    // ── GET /api/status ────────────────────────────────────
    if (route === '/api/status' && req.method === 'GET') {
      return json(res, {
        status: 'running',
        version: '1.0.0',
        port: PORT,
        cache: cache.size,
        apis: {
          safeBrowsing: !!SAFE_BROWSING_KEY,
          virusTotal: !!VIRUSTOTAL_KEY,
        },
        stats,
      });
    }

    // ── GET /api/quick?url=... ─────────────────────────────
    if (route === '/api/quick' && req.method === 'GET') {
      const targetUrl = url.searchParams.get('url');
      if (!targetUrl) return json(res, { error: 'Missing url param' }, 400);
      const result = analyzeUrlQuick(targetUrl, lists);
      return json(res, result);
    }

    // ── 404 ────────────────────────────────────────────────
    json(res, { error: 'Not found' }, 404);

  } catch (err) {
    console.error('Request error:', err.message);
    json(res, { error: 'Internal server error' }, 500);
  }
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.log(`  Port ${PORT} in use — another instance may be running. Exiting gracefully.`);
    process.exit(0);
  }
  console.error('Server error:', err);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`
  ╔══════════════════════════════════════════════╗
  ║  LinkShield Analysis Server                  ║
  ║  http://127.0.0.1:${String(PORT).padEnd(5)}                    ║
  ║                                              ║
  ║  Trusted domains: ${String(lists.trusted.length).padEnd(4)}                     ║
  ║  Brand profiles:  ${String(lists.brands.length).padEnd(4)}                     ║
  ║  Safe Browsing:   ${SAFE_BROWSING_KEY ? 'ON ' : 'OFF'}                      ║
  ║  VirusTotal:      ${VIRUSTOTAL_KEY ? 'ON ' : 'OFF'}                      ║
  ╚══════════════════════════════════════════════╝
  `);
});
