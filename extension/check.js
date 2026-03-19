// LinkShield Check Page — Full URL analysis UI

const SERVER = 'http://127.0.0.1:3847';

// ═══════════════════════════════════════════════════════════════
// PARSE URL FROM QUERY PARAMS
// ═══════════════════════════════════════════════════════════════

const params = new URLSearchParams(location.search);
const targetUrl = params.get('url');
const isNewTab = params.get('newtab') === '1';

if (!targetUrl) {
  document.getElementById('urlBox').textContent = 'No URL provided.';
  throw new Error('No URL');
}

// Display URL with highlighted domain
try {
  const parsed = new URL(targetUrl);
  const domainHtml = `<span class="domain">${escapeHtml(parsed.hostname)}</span>`;
  const rest = escapeHtml(parsed.pathname + parsed.search + parsed.hash);
  document.getElementById('urlBox').innerHTML =
    `${escapeHtml(parsed.protocol)}//${domainHtml}${rest}`;
} catch {
  document.getElementById('urlBox').textContent = targetUrl;
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ═══════════════════════════════════════════════════════════════
// CHECK DEFINITIONS
// ═══════════════════════════════════════════════════════════════

const CHECK_NAMES = [
  'URL Syntax',
  'Domain Reputation',
  'Homograph Check',
  'Typosquatting',
  'Redirect Chain',
  'SSL Certificate',
  'DNS',
];

// Render initial pending state
const checksList = document.getElementById('checksList');
for (const name of CHECK_NAMES) {
  const row = document.createElement('div');
  row.className = 'check-row';
  row.id = `check-${name.replace(/\s+/g, '-').toLowerCase()}`;
  row.innerHTML = `
    <div class="check-icon pending"></div>
    <div class="check-name">${name}</div>
    <div class="check-detail">Checking...</div>
  `;
  checksList.appendChild(row);
}

// ═══════════════════════════════════════════════════════════════
// RUN ANALYSIS
// ═══════════════════════════════════════════════════════════════

const progress = document.getElementById('progressFill');
progress.style.width = '15%';

async function runAnalysis() {
  let result;
  let serverOnline = true;

  try {
    const res = await fetch(`${SERVER}/api/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: targetUrl }),
    });
    result = await res.json();
  } catch {
    serverOnline = false;
    document.getElementById('offlineNotice').style.display = 'block';
    // Fallback: basic analysis in service worker
    result = await new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: 'checkUrl', url: targetUrl }, (response) => {
        resolve({
          url: targetUrl,
          verdict: response?.action === 'allow' ? 'safe' : 'caution',
          score: response?.action === 'allow' ? 10 : 40,
          checks: CHECK_NAMES.map(name => ({
            name,
            status: response?.action === 'allow' ? 'pass' : 'warn',
            detail: serverOnline ? 'Clean' : 'Server offline — limited analysis',
          })),
          summary: response?.action === 'allow'
            ? 'Basic checks passed. Start the server for deeper analysis.'
            : 'Could not fully verify this link. Proceed with caution.',
        });
      });
    });
  }

  progress.style.width = '100%';

  // Animate checks appearing
  const checks = result.checks || [];
  for (let i = 0; i < checks.length; i++) {
    await delay(80);
    updateCheck(checks[i]);
  }

  // Update any check names from server that we didn't pre-render
  for (const check of checks) {
    const id = `check-${check.name.replace(/\s+/g, '-').toLowerCase()}`;
    if (!document.getElementById(id)) {
      const row = document.createElement('div');
      row.className = 'check-row';
      row.id = id;
      const iconClass = check.status === 'pass' ? 'pass' : check.status === 'warn' ? 'warn' : 'fail';
      const icon = check.status === 'pass' ? '&#x2713;' : check.status === 'warn' ? '!' : '&#x2717;';
      row.innerHTML = `
        <div class="check-icon ${iconClass}">${icon}</div>
        <div class="check-name">${escapeHtml(check.name)}</div>
        <div class="check-detail ${check.status === 'warn' ? 'warn' : check.status === 'fail' ? 'fail' : ''}">${escapeHtml(check.detail)}</div>
      `;
      checksList.appendChild(row);
    }
  }

  // Set progress bar color
  progress.className = `progress-fill ${result.verdict}`;

  // Show verdict
  await delay(200);
  showVerdict(result);
}

function updateCheck(check) {
  const id = `check-${check.name.replace(/\s+/g, '-').toLowerCase()}`;
  const row = document.getElementById(id);
  if (!row) return;

  const iconEl = row.querySelector('.check-icon');
  const detailEl = row.querySelector('.check-detail');

  iconEl.classList.remove('pending');

  if (check.status === 'pass') {
    iconEl.classList.add('pass');
    iconEl.innerHTML = '&#x2713;';
  } else if (check.status === 'warn') {
    iconEl.classList.add('warn');
    iconEl.innerHTML = '!';
    detailEl.classList.add('warn');
  } else {
    iconEl.classList.add('fail');
    iconEl.innerHTML = '&#x2717;';
    detailEl.classList.add('fail');
  }

  detailEl.textContent = check.detail || 'Clean';
}

function showVerdict(result) {
  const el = document.getElementById('verdict');
  const actions = document.getElementById('actions');

  el.className = `verdict ${result.verdict} visible`;

  const score = result.score || 0;
  const scoreBadge = `<span class="score-badge ${result.verdict}">${score}/100</span>`;

  if (result.verdict === 'safe') {
    el.innerHTML = `
      <h2>SAFE ${scoreBadge}</h2>
      <p>${escapeHtml(result.summary)}</p>
      <div class="countdown" id="countdown">Proceeding in 2 seconds...</div>
      <div class="auto-progress"><div class="auto-progress-fill" id="autoProgress"></div></div>
    `;

    // Auto-proceed countdown
    const autoBar = document.getElementById('autoProgress');
    autoBar.style.transition = 'width 2s linear';
    requestAnimationFrame(() => { autoBar.style.width = '100%'; });

    const timer = setTimeout(() => navigate(), 2000);

    actions.style.display = 'flex';
    actions.innerHTML = `
      <button class="btn btn-safe" id="btnProceed">Proceed now &#x2192;</button>
      <button class="btn btn-secondary" id="btnBack">&#x2190; Go back</button>
      <button class="btn btn-ghost" id="btnTrust">Trust this domain</button>
    `;

    document.getElementById('btnProceed').onclick = () => { clearTimeout(timer); navigate(); };
    document.getElementById('btnBack').onclick = () => goBack();
    document.getElementById('btnTrust').onclick = () => { clearTimeout(timer); trustAndNavigate(); };

  } else if (result.verdict === 'caution') {
    el.innerHTML = `
      <h2>CAUTION ${scoreBadge}</h2>
      <p>${escapeHtml(result.summary)}</p>
    `;

    actions.style.display = 'flex';
    actions.innerHTML = `
      <button class="btn btn-secondary" id="btnBack">&#x2190; Go back</button>
      <button class="btn btn-primary" id="btnProceed">Proceed anyway &#x2192;</button>
      <button class="btn btn-ghost" id="btnTrust">Trust this domain</button>
    `;

    document.getElementById('btnProceed').onclick = () => navigate();
    document.getElementById('btnBack').onclick = () => goBack();
    document.getElementById('btnTrust').onclick = () => trustAndNavigate();

  } else {
    // DANGER
    el.innerHTML = `
      <h2>&#x26A0; DANGER ${scoreBadge}</h2>
      <p>${escapeHtml(result.summary)}</p>
      <p style="margin-top:10px;font-size:13px;color:#ef4444;">
        This link shows strong indicators of being malicious. Going here could compromise your accounts, steal your data, or infect your device.
      </p>
    `;

    actions.style.display = 'flex';
    actions.innerHTML = `
      <button class="btn btn-safe" id="btnBack">&#x2190; Go back to safety</button>
      <button class="btn btn-danger" id="btnProceed">I understand the risk &#x2192;</button>
    `;

    document.getElementById('btnProceed').onclick = () => {
      if (confirm('Are you sure? This link has been flagged as dangerous.')) {
        navigate();
      }
    };
    document.getElementById('btnBack').onclick = () => goBack();
  }

  // Update page title
  const titles = { safe: 'SAFE', caution: 'CAUTION', danger: 'DANGER' };
  document.title = `LinkShield — ${titles[result.verdict]}`;
}

// ═══════════════════════════════════════════════════════════════
// NAVIGATION
// ═══════════════════════════════════════════════════════════════

function navigate() {
  // Remove from check flow — navigate to actual URL
  location.href = targetUrl;
}

function goBack() {
  if (history.length > 1) {
    history.back();
  } else {
    window.close();
  }
}

function trustAndNavigate() {
  try {
    const domain = new URL(targetUrl).hostname;
    const parts = domain.split('.');
    const regDomain = parts.length > 2 ? parts.slice(-2).join('.') : domain;
    chrome.runtime.sendMessage({ type: 'whitelistDomain', domain: regDomain });
  } catch { /* ignore */ }
  navigate();
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ═══════════════════════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════════════════════

runAnalysis().catch(err => {
  console.error('LinkShield analysis error:', err);
  document.getElementById('verdict').className = 'verdict caution visible';
  document.getElementById('verdict').innerHTML = `
    <h2>ANALYSIS ERROR</h2>
    <p>Could not complete analysis. Proceed with caution.</p>
  `;
  document.getElementById('actions').style.display = 'flex';
  document.getElementById('actions').innerHTML = `
    <button class="btn btn-secondary" id="btnBack">&#x2190; Go back</button>
    <button class="btn btn-primary" id="btnProceed">Proceed &#x2192;</button>
  `;
  document.getElementById('btnProceed').onclick = () => navigate();
  document.getElementById('btnBack').onclick = () => goBack();
});
