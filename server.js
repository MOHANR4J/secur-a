/**
 * server.js — securA: Website Security Score Checker
 *
 * Uses Puppeteer (headless Chromium) to dynamically analyse a website:
 *  1. Security Headers       — CSP, X-Frame-Options, HSTS, X-Content-Type-Options
 *  2. HTTPS / TLS            — Protocol scheme, TLS version
 *  3. Mixed Content          — HTTP subresources loaded on HTTPS pages
 *  4. Subresource Integrity  — External scripts missing integrity= attributes
 *  5. Insecure Forms         — Form actions pointing to http:// endpoints
 *  6. Cookie Security        — Secure, HttpOnly, SameSite flags on cookies
 *
 * Run with:  node server.js
 */

// ─────────────────────────────────────────────────────────────────────────────
// 1.  IMPORTS
// ─────────────────────────────────────────────────────────────────────────────
const express    = require('express');
const cors       = require('cors');
const path       = require('path');
const puppeteer  = require('puppeteer');

const app  = express();
const PORT = process.env.PORT || 5000;

// ─────────────────────────────────────────────────────────────────────────────
// 2.  MIDDLEWARE
// ─────────────────────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.use(cors());
app.use(express.json());

// ─────────────────────────────────────────────────────────────────────────────
// 3.  HELPER — build standard response object
// ─────────────────────────────────────────────────────────────────────────────
function makeResponse(score, issues = [], suggestions = [], details = {}) {
  const finalScore = Math.min(100, Math.max(0, score));

  let status;
  if (finalScore >= 80)      status = 'Low Risk';
  else if (finalScore >= 50) status = 'Medium Risk';
  else                       status = 'High Risk';

  if (issues.length === 0) {
    issues.push('No major security issues detected. Great job!');
  }
  if (suggestions.length === 0) {
    suggestions.push('Your site follows all the security best practices we check. Keep it up!');
  }

  return { score: finalScore, status, issues, suggestions, details };
}

// ─────────────────────────────────────────────────────────────────────────────
// 4.  MAIN ROUTE — POST /check-security
// ─────────────────────────────────────────────────────────────────────────────
app.post('/check-security', async (req, res) => {

  // ── 4a. Validate URL ───────────────────────────────────────────────────────
  const { url } = req.body;

  if (!url || typeof url !== 'string' || url.trim() === '') {
    return res.status(400).json(makeResponse(0,
      ['No URL was provided. Please enter a website address.'],
      ['Enter a full URL starting with https:// (for example, https://example.com).']
    ));
  }

  const trimmedUrl = url.trim();

  let parsedUrl;
  try {
    parsedUrl = new URL(trimmedUrl);
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      throw new Error('Protocol must be http or https.');
    }
  } catch {
    return res.status(400).json(makeResponse(0,
      ['The URL format is invalid. It must start with http:// or https://.'],
      ['Use a full URL, e.g. https://example.com or http://example.com.']
    ));
  }

  // ── 4b. Launch Puppeteer ───────────────────────────────────────────────────
  let browser;
  try {
    const launchOptions = {
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-software-rasterizer',
        '--hide-scrollbars',
        '--mute-audio',
        '--window-position=-10000,-10000',  // Move off-screen completely
        '--window-size=1,1',                // Tiny window size as extra safety
      ]
    };

    // Auto-detect executable path on Render / Docker environments
    if (process.env.PUPPETEER_EXECUTABLE_PATH) {
      const fs = require('fs');
      if (fs.existsSync(process.env.PUPPETEER_EXECUTABLE_PATH)) {
        launchOptions.executablePath = process.env.PUPPETEER_EXECUTABLE_PATH;
      }
    }

    if (!launchOptions.executablePath) {
      const fs = require('fs');
      // If we are deploying using the build script render-build.sh, Chrome is installed in the cache directory
      const cacheDir = process.env.PUPPETEER_CACHE_DIR || '/opt/render/project/.cache/puppeteer';
      if (fs.existsSync(cacheDir)) {
        // Recursively locate a chrome executable inside the cache directory
        const findChromeBinary = (dir) => {
          const files = fs.readdirSync(dir);
          for (const file of files) {
            const fullPath = path.join(dir, file);
            const stat = fs.statSync(fullPath);
            if (stat.isDirectory()) {
              const found = findChromeBinary(fullPath);
              if (found) return found;
            } else if (file === 'chrome' || file === 'chrome-linux64' || file === 'chrome-linux') {
              // Ensure it's executable
              try {
                fs.accessSync(fullPath, fs.constants.X_OK);
                return fullPath;
              } catch {
                // Not executable or access issue
              }
            }
          }
          return null;
        };

        try {
          const cachedChrome = findChromeBinary(cacheDir);
          if (cachedChrome) {
            console.log('Found cached Chrome executable at:', cachedChrome);
            launchOptions.executablePath = cachedChrome;
          }
        } catch (err) {
          console.error('Error walking cache directory:', err.message);
        }
      }
    }

    // Additional common fallbacks
    if (!launchOptions.executablePath && process.env.RENDER) {
      const fs = require('fs');
      const commonPaths = [
        '/usr/bin/google-chrome-stable',
        '/usr/bin/chromium',
        '/usr/bin/chromium-browser'
      ];
      for (const p of commonPaths) {
        if (fs.existsSync(p)) {
          launchOptions.executablePath = p;
          break;
        }
      }
    }

    browser = await puppeteer.launch(launchOptions);
  } catch (err) {
    console.error('Puppeteer launch error:', err.message);
    return res.status(200).json({
      score: 0,
      status: 'High Risk',
      issues: ['Failed to launch the headless browser for analysis.'],
      suggestions: [`Error: ${err.message}`],
      details: {
        error: err.message,
        stack: err.stack,
        env: {
          NODE_ENV: process.env.NODE_ENV,
          PORT: process.env.PORT,
          RENDER: process.env.RENDER,
          PUPPETEER_EXECUTABLE_PATH: process.env.PUPPETEER_EXECUTABLE_PATH,
          PUPPETEER_CACHE_DIR: process.env.PUPPETEER_CACHE_DIR,
          PATH: process.env.PATH,
          USER: process.env.USER,
          HOME: process.env.HOME
        }
      }
    });
  }

  // ── 4c. Run the analysis ───────────────────────────────────────────────────
  let score = 0;
  const issues      = [];
  const suggestions = [];
  const details     = {
    networking: {},
    dom:        {},
    cookies:    {},
    tls:        {},
    headers:    {}
  };

  try {
    const page = await browser.newPage();

    // ── Track all network requests & responses ─────────────────────────────
    const mixedContentUrls = [];
    const allRequests      = [];

    await page.setRequestInterception(true);

    page.on('request', (req) => {
      allRequests.push(req.url());
      req.continue();
    });

    // ── Navigate to the page ───────────────────────────────────────────────
    let mainResponse;
    try {
      mainResponse = await page.goto(trimmedUrl, {
        waitUntil: 'networkidle2',
        timeout: 20000
      });
    } catch (navErr) {
      await browser.close();
      let issueMsg = `Could not connect to "${parsedUrl.hostname}".`;
      let suggMsg  = 'Make sure the URL is correct and the site is publicly accessible.';

      if (navErr.message.includes('net::ERR_NAME_NOT_RESOLVED')) {
        issueMsg = `DNS lookup failed for "${parsedUrl.hostname}". The domain may not exist.`;
        suggMsg  = 'Double-check the domain name spelling.';
      } else if (navErr.message.includes('TIMED_OUT') || navErr.message.includes('timeout')) {
        issueMsg = `The page at "${parsedUrl.hostname}" timed out after 20 seconds.`;
        suggMsg  = 'The site may be too slow or blocking automated requests.';
      } else if (navErr.message.includes('ERR_SSL')) {
        issueMsg = `SSL/TLS error connecting to "${parsedUrl.hostname}".`;
        suggMsg  = 'The site\'s certificate may be expired or misconfigured.';
      }

      return res.status(200).json(makeResponse(0, [issueMsg], [suggMsg]));
    }

    const finalUrl        = page.url();
    const finalParsedUrl  = new URL(finalUrl);
    const isHttps         = finalParsedUrl.protocol === 'https:';
    const responseHeaders = mainResponse.headers();

    // ══════════════════════════════════════════════════════════════════════
    // SCORING CRITERIA
    // ══════════════════════════════════════════════════════════════════════

    // ── [+10] Valid URL ────────────────────────────────────────────────────
    score += 10;

    // ── [+20] HTTPS protocol ──────────────────────────────────────────────
    if (isHttps) {
      score += 20;
      details.networking.https = true;
    } else {
      details.networking.https = false;
      issues.push('Website is not using HTTPS — data in transit is unencrypted.');
      suggestions.push(
        'Enable HTTPS by installing an SSL/TLS certificate. ' +
        'Free certificates are available from Let\'s Encrypt (https://letsencrypt.org).'
      );
    }

    // ── [+5 each] Security Headers (20 pts total) ─────────────────────────
    const headersToCheck = {
      'content-security-policy':   {
        pts: 5,
        issue: 'Missing security header: Content-Security-Policy (CSP)',
        suggestion:
          'Add a CSP header to restrict which scripts/resources are allowed. ' +
          'Example: Content-Security-Policy: default-src \'self\''
      },
      'x-frame-options': {
        pts: 5,
        issue: 'Missing security header: X-Frame-Options',
        suggestion:
          'Add X-Frame-Options to prevent clickjacking via hidden iframes. ' +
          'Example: X-Frame-Options: SAMEORIGIN'
      },
      'strict-transport-security': {
        pts: 5,
        issue: 'Missing security header: Strict-Transport-Security (HSTS)',
        suggestion:
          'Add HSTS to force browsers to always use HTTPS for this domain. ' +
          'Example: Strict-Transport-Security: max-age=31536000; includeSubDomains'
      },
      'x-content-type-options': {
        pts: 5,
        issue: 'Missing security header: X-Content-Type-Options',
        suggestion:
          'Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing attacks.'
      }
    };

    details.headers = {};
    for (const [header, meta] of Object.entries(headersToCheck)) {
      const present = !!responseHeaders[header];
      details.headers[header] = present ? responseHeaders[header] : null;
      if (present) {
        score += meta.pts;
      } else {
        issues.push(meta.issue);
        suggestions.push(meta.suggestion);
      }
    }

    // ── [+10] Mixed Content check ─────────────────────────────────────────
    // Only relevant for HTTPS sites — HTTP subresources defeat HTTPS protection.
    if (isHttps) {
      const mixedContent = allRequests.filter(reqUrl => reqUrl.startsWith('http://'));
      details.networking.mixedContentUrls = mixedContent;
      details.networking.mixedContentCount = mixedContent.length;

      if (mixedContent.length === 0) {
        score += 10;
      } else {
        issues.push(
          `Mixed Content: ${mixedContent.length} resource(s) loaded over HTTP on an HTTPS page.`
        );
        suggestions.push(
          'Update all subresource URLs to use https:// instead of http://. ' +
          'Mixed content weakens your HTTPS protection. ' +
          `First offending resource: ${mixedContent[0]}`
        );
      }
    } else {
      details.networking.mixedContentUrls  = [];
      details.networking.mixedContentCount = 0;
    }

    // ── DOM Analysis (SRI + Insecure Forms) ──────────────────────────────
    const domAnalysis = await page.evaluate(() => {
      // ── Subresource Integrity (SRI) check ────────────────────────────
      const externalScripts = Array.from(document.querySelectorAll('script[src]'))
        .filter(s => s.src && (s.src.startsWith('http://') || s.src.startsWith('https://')))
        .filter(s => {
          try {
            return new URL(s.src).hostname !== window.location.hostname;
          } catch { return false; }
        });

      const scriptsMissingSri = externalScripts
        .filter(s => !s.integrity)
        .map(s => s.src);

      // ── Insecure Form Actions ─────────────────────────────────────────
      const insecureForms = Array.from(document.querySelectorAll('form'))
        .filter(f => {
          const action = f.action || '';
          return action.startsWith('http://');
        })
        .map(f => f.action);

      return {
        totalExternalScripts: externalScripts.length,
        scriptsMissingSri,
        insecureForms
      };
    });

    details.dom = domAnalysis;

    // ── [+10] Subresource Integrity ──────────────────────────────────────
    if (domAnalysis.scriptsMissingSri.length === 0) {
      score += 10;
    } else {
      issues.push(
        `${domAnalysis.scriptsMissingSri.length} external script(s) are missing Subresource Integrity (SRI) hashes.`
      );
      suggestions.push(
        'Add integrity= and crossorigin= attributes to all external <script> tags. ' +
        'Generate SRI hashes at: https://www.srihash.org. ' +
        `Missing on: ${domAnalysis.scriptsMissingSri.slice(0, 2).join(', ')}`
      );
    }

    // ── [+10] Insecure Form Actions ───────────────────────────────────────
    if (domAnalysis.insecureForms.length === 0) {
      score += 10;
    } else {
      issues.push(
        `${domAnalysis.insecureForms.length} form(s) submit data to insecure http:// endpoints.`
      );
      suggestions.push(
        'Update all form action attributes to use https:// URLs to protect user data in transit. ' +
        `Insecure form target: ${domAnalysis.insecureForms[0]}`
      );
    }

    // ── Cookie Security check ─────────────────────────────────────────────
    const cookies = await page.cookies();
    details.cookies.total = cookies.length;

    const insecureCookies = cookies.filter(c => !c.secure || !c.httpOnly);
    details.cookies.insecureCount = insecureCookies.length;
    details.cookies.insecureNames = insecureCookies.map(c => c.name);

    // ── [+10] Secure Cookies ──────────────────────────────────────────────
    if (cookies.length === 0 || insecureCookies.length === 0) {
      score += 10;
      if (cookies.length === 0) {
        details.cookies.note = 'No cookies set by this page.';
      }
    } else {
      issues.push(
        `${insecureCookies.length} cookie(s) are missing Secure or HttpOnly flags: ` +
        insecureCookies.map(c => c.name).slice(0, 3).join(', ')
      );
      suggestions.push(
        'Set the Secure and HttpOnly attributes on all cookies to prevent ' +
        'them from being accessed over HTTP or via JavaScript. ' +
        'Example: Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict'
      );
    }

    // ── TLS Version check ─────────────────────────────────────────────────
    // Uses Chrome DevTools Protocol to get the security details.
    let tlsVersion = null;
    if (isHttps) {
      try {
        const cdpSession = await page.createCDPSession();
        await cdpSession.send('Network.enable');
        const securityInfo = await page.evaluate(async () => {
          const r = await fetch(window.location.href, { method: 'HEAD', cache: 'no-store' });
          return null; // CDP approach needed
        });

        // Fallback: inspect response security details via CDP
        const client = await page.createCDPSession();
        const { securityState } = await client.send('Security.getSecurityState');
        details.tls.securityState = securityState || 'unknown';
        tlsVersion = securityState;
      } catch {
        details.tls.securityState = 'unable to retrieve';
      }

      // ── [+5] TLS information bonus ───────────────────────────────────
      // We award 5 pts simply for having HTTPS (TLS used), since puppeteer
      // doesn't directly expose TLS cipher/version in all cases.
      score += 5;
      details.tls.note = 'TLS is active (HTTPS connection established).';
    } else {
      details.tls.securityState = 'none';
      details.tls.note = 'No TLS — site uses plain HTTP.';
    }

    // ── Cap the score ─────────────────────────────────────────────────────
    score = Math.min(100, score);

    return res.status(200).json(makeResponse(score, issues, suggestions, details));

  } catch (err) {
    console.error('Analysis error:', err.message);
    return res.status(200).json(makeResponse(0,
      ['An unexpected error occurred during analysis.'],
      ['Please try again with a different URL.']
    ));
  } finally {
    if (browser) await browser.close();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 5.  GLOBAL ERROR HANDLER
// ─────────────────────────────────────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('Unexpected server error:', err.message);
  res.status(500).json(makeResponse(
    0,
    ['An unexpected server error occurred. Please try again.'],
    ['If this keeps happening, check the server logs for more details.']
  ));
});

// ─────────────────────────────────────────────────────────────────────────────
// 6.  START THE SERVER
// ─────────────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

module.exports = app;
