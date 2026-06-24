/**
 * script.js — securA: Website Security Score Checker (Frontend Logic)
 *
 * Responsibilities:
 *  1. Listen for the form submit event.
 *  2. POST the URL to our backend at /check-security.
 *  3. Show a loading state while waiting for the response.
 *  4. Render the score gauge, risk badge, issues, suggestions, and detailed analysis tabs.
 *  5. Handle all errors gracefully.
 */

// ─────────────────────────────────────────────────────────────────────────────
// 1.  GRAB DOM ELEMENTS
// ─────────────────────────────────────────────────────────────────────────────
const form            = document.getElementById('scan-form');
const urlInput        = document.getElementById('url-input');
const scanBtn         = document.getElementById('scan-btn');
const loadingArea     = document.getElementById('loading-area');
const loadingText     = document.getElementById('loading-text');
const errorArea       = document.getElementById('error-area');
const errorMessage    = document.getElementById('error-message');
const resultsSection  = document.getElementById('results-section');

// Score gauge elements
const gaugeProgress   = document.getElementById('gauge-progress');
const scoreNumber     = document.getElementById('score-number');
const statusBadge     = document.getElementById('status-badge');
const scannedUrl      = document.getElementById('scanned-url');

// Lists
const issuesList      = document.getElementById('issues-list');
const suggestionsList = document.getElementById('suggestions-list');

// Details section
const detailsSection  = document.getElementById('details-section');

// The SVG circle's radius (matches the r="64" in index.html).
const GAUGE_RADIUS        = 64;
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * GAUGE_RADIUS; // ≈ 402.12

// Loading messages that cycle during the longer Puppeteer scan
const LOADING_MESSAGES = [
  'Launching headless browser…',
  'Navigating to the website…',
  'Monitoring network traffic…',
  'Analysing DOM structure…',
  'Checking security headers…',
  'Inspecting cookies…',
  'Evaluating TLS configuration…',
  'Calculating security score…'
];
let loadingMsgInterval = null;

// ─────────────────────────────────────────────────────────────────────────────
// 2.  FORM SUBMIT HANDLER
// ─────────────────────────────────────────────────────────────────────────────
form.addEventListener('submit', async (event) => {
  event.preventDefault();

  const url = urlInput.value.trim();

  if (!url) {
    showError('Please enter a URL before scanning.');
    return;
  }

  setLoadingState(true);
  hideError();
  hideResults();

  try {
    const response = await fetch('/check-security', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url })
    });

    const data = await response.json();
    renderResults(data, url);

  } catch (err) {
    console.error('Fetch error:', err);
    showError(
      'Could not reach the server. Make sure the backend is running ' +
      '(npm start) and try again.'
    );
  } finally {
    setLoadingState(false);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 3.  RENDER RESULTS
// ─────────────────────────────────────────────────────────────────────────────
function renderResults(data, url) {
  const { score, status, issues, suggestions, details } = data;

  // ── 3a. Score gauge ────────────────────────────────────────────────────────
  const fraction = Math.max(0, Math.min(1, score / 100));
  const offset   = GAUGE_CIRCUMFERENCE * (1 - fraction);
  gaugeProgress.style.strokeDashoffset = offset;
  scoreNumber.textContent = score;

  // ── 3b. Risk-level CSS classes ─────────────────────────────────────────────
  const riskClass = statusToClass(status);
  setRiskClass(statusBadge,   riskClass);
  setRiskClass(gaugeProgress, riskClass);
  setRiskClass(scoreNumber,   riskClass);

  const riskEmoji = { 'low-risk': '✅', 'medium-risk': '⚠️', 'high-risk': '🔴' };
  statusBadge.textContent = `${riskEmoji[riskClass] || ''} ${status}`;
  scannedUrl.textContent  = url;

  // ── 3c. Issues & Suggestions ───────────────────────────────────────────────
  populateList(issuesList,      issues,      'issues-list');
  populateList(suggestionsList, suggestions, 'suggestions-list');

  // ── 3d. Detailed Analysis Panel ────────────────────────────────────────────
  if (details && detailsSection) {
    renderDetails(details);
  }

  showResults();
}

// ─────────────────────────────────────────────────────────────────────────────
// 4.  RENDER DETAILED ANALYSIS PANEL
// ─────────────────────────────────────────────────────────────────────────────
function renderDetails(details) {
  detailsSection.innerHTML = '';

  // Build sections for networking, headers, dom, cookies, tls
  const sections = [
    buildNetworkingSection(details.networking || {}),
    buildHeadersSection(details.headers     || {}),
    buildDomSection(details.dom             || {}),
    buildCookiesSection(details.cookies     || {}),
    buildTlsSection(details.tls             || {}),
  ];

  sections.forEach(el => detailsSection.appendChild(el));
  detailsSection.hidden = false;
}

function buildNetworkingSection(net) {
  const rows = [
    { label: 'HTTPS Active',      value: net.https ? '✅ Yes' : '❌ No',     good: net.https },
    { label: 'Mixed Content URLs', value: net.mixedContentCount != null
        ? (net.mixedContentCount === 0 ? '✅ None detected' : `❌ ${net.mixedContentCount} found`)
        : 'N/A',
      good: (net.mixedContentCount === 0) }
  ];
  if (net.mixedContentUrls && net.mixedContentUrls.length > 0) {
    rows.push({ label: 'First Mixed URL', value: net.mixedContentUrls[0], good: false });
  }
  return buildDetailCard('🌐 Networking', rows);
}

function buildHeadersSection(headers) {
  const HEADER_LABELS = {
    'content-security-policy':    'Content-Security-Policy',
    'x-frame-options':            'X-Frame-Options',
    'strict-transport-security':  'Strict-Transport-Security',
    'x-content-type-options':     'X-Content-Type-Options'
  };

  const rows = Object.entries(HEADER_LABELS).map(([key, label]) => {
    const val = headers[key];
    return {
      label: label,
      value: val ? `✅ ${val.length > 60 ? val.slice(0, 60) + '…' : val}` : '❌ Missing',
      good:  !!val
    };
  });
  return buildDetailCard('🔒 Security Headers', rows);
}

function buildDomSection(dom) {
  const rows = [
    {
      label: 'External Scripts',
      value: dom.totalExternalScripts != null ? dom.totalExternalScripts : 'N/A',
      good: true
    },
    {
      label: 'Scripts Missing SRI',
      value: dom.scriptsMissingSri
        ? (dom.scriptsMissingSri.length === 0 ? '✅ None' : `❌ ${dom.scriptsMissingSri.length}`)
        : 'N/A',
      good: (dom.scriptsMissingSri && dom.scriptsMissingSri.length === 0)
    },
    {
      label: 'Insecure Form Actions',
      value: dom.insecureForms
        ? (dom.insecureForms.length === 0 ? '✅ None' : `❌ ${dom.insecureForms.length} form(s)`)
        : 'N/A',
      good: (dom.insecureForms && dom.insecureForms.length === 0)
    }
  ];
  return buildDetailCard('🧩 DOM Analysis', rows);
}

function buildCookiesSection(cookies) {
  const rows = [
    {
      label: 'Total Cookies',
      value: cookies.total != null ? cookies.total : 'N/A',
      good: true
    },
    {
      label: 'Insecure Cookies',
      value: cookies.insecureCount != null
        ? (cookies.insecureCount === 0 ? '✅ None' : `❌ ${cookies.insecureCount} insecure`)
        : 'N/A',
      good: cookies.insecureCount === 0
    }
  ];
  if (cookies.insecureNames && cookies.insecureNames.length > 0) {
    rows.push({ label: 'Insecure Cookie Names', value: cookies.insecureNames.join(', '), good: false });
  }
  if (cookies.note) {
    rows.push({ label: 'Note', value: cookies.note, good: true });
  }
  return buildDetailCard('🍪 Cookie Security', rows);
}

function buildTlsSection(tls) {
  const rows = [
    {
      label: 'TLS Status',
      value: tls.securityState || 'unknown',
      good: tls.securityState !== 'none' && tls.securityState !== 'unknown'
    }
  ];
  if (tls.note) {
    rows.push({ label: 'Note', value: tls.note, good: tls.securityState !== 'none' });
  }
  return buildDetailCard('🛡️ TLS / SSL', rows);
}

function buildDetailCard(title, rows) {
  const card = document.createElement('div');
  card.className = 'card detail-analysis-card';

  const h3 = document.createElement('h3');
  h3.className = 'detail-analysis-title';
  h3.textContent = title;
  card.appendChild(h3);

  const table = document.createElement('table');
  table.className = 'detail-table';

  rows.forEach(({ label, value, good }) => {
    const tr = document.createElement('tr');
    tr.className = good === false ? 'detail-row-bad' : (good === true ? 'detail-row-good' : '');

    const tdLabel = document.createElement('td');
    tdLabel.className = 'detail-label';
    tdLabel.textContent = label;

    const tdValue = document.createElement('td');
    tdValue.className = 'detail-value';
    tdValue.textContent = value;

    tr.appendChild(tdLabel);
    tr.appendChild(tdValue);
    table.appendChild(tr);
  });

  card.appendChild(table);
  return card;
}

// ─────────────────────────────────────────────────────────────────────────────
// 5.  HELPER FUNCTIONS
// ─────────────────────────────────────────────────────────────────────────────
function statusToClass(status) {
  if (!status) return 'high-risk';
  return status.toLowerCase().replace(/\s+/g, '-');
}

function setRiskClass(el, riskClass) {
  el.classList.remove('low-risk', 'medium-risk', 'high-risk');
  el.classList.add(riskClass);
}

function populateList(listEl, items) {
  listEl.innerHTML = '';
  if (!Array.isArray(items) || items.length === 0) {
    const li = document.createElement('li');
    li.textContent = 'No items to display.';
    listEl.appendChild(li);
    return;
  }
  items.forEach((text) => {
    const li = document.createElement('li');
    li.textContent = text;
    listEl.appendChild(li);
  });
}

function setLoadingState(isLoading) {
  if (isLoading) {
    scanBtn.disabled = true;
    scanBtn.classList.add('loading');
    loadingArea.hidden = false;

    // Cycle through informative loading messages
    let msgIdx = 0;
    if (loadingText) loadingText.textContent = LOADING_MESSAGES[0];
    loadingMsgInterval = setInterval(() => {
      msgIdx = (msgIdx + 1) % LOADING_MESSAGES.length;
      if (loadingText) loadingText.textContent = LOADING_MESSAGES[msgIdx];
    }, 2000);

  } else {
    scanBtn.disabled = false;
    scanBtn.classList.remove('loading');
    loadingArea.hidden = true;
    if (loadingMsgInterval) {
      clearInterval(loadingMsgInterval);
      loadingMsgInterval = null;
    }
    if (loadingText) loadingText.textContent = LOADING_MESSAGES[0];
  }
}

function showError(message) {
  errorMessage.textContent = message;
  errorArea.hidden = false;
}

function hideError() {
  errorArea.hidden = true;
}

function showResults() {
  resultsSection.hidden = false;
  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function hideResults() {
  resultsSection.hidden = true;
  if (detailsSection) detailsSection.hidden = true;
}
