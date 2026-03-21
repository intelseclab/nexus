/**
 * Service Worker - background script.
 * Handles: header analysis, JS file scanning, path probing, storage, badge.
 */

importScripts("scanner/patterns.js", "scanner/finding.js", "scanner/path-list.js");

// ── State ──
function createEmptyTabFindings(url = "", status = "idle") {
  return {
    content: [], network: [], jsFiles: [], paths: [],
    url, status, pendingScans: 0,
    scanSummary: { headersAnalyzed: false, jsFilesScanned: 0, pathsProbed: 0, totalPaths: SENSITIVE_PATHS.length }
  };
}

// ── Atomic Storage Queue ──
// Prevents race conditions from concurrent read-modify-write cycles
const storageQueue = new Map();

function withTabLock(tabId, fn) {
  const key = `tab_${tabId}`;
  const prev = storageQueue.get(key) || Promise.resolve();
  const next = prev.then(() => fn()).catch(e => console.warn("[Nexus] Storage error:", e));
  storageQueue.set(key, next);
  return next;
}

async function getTabFindings(tabId) {
  const key = `tab_${tabId}`;
  const data = await chrome.storage.session.get(key);
  return data[key] || createEmptyTabFindings();
}

async function saveTabFindings(tabId, findings) {
  const key = `tab_${tabId}`;
  await chrome.storage.session.set({ [key]: findings });
  updateBadge(tabId, findings);
}

async function mergeFindings(tabId, category, newFindings, url) {
  return withTabLock(tabId, async () => {
    const existing = await getTabFindings(tabId);
    existing[category] = newFindings;
    if (url) existing.url = url;
    if (existing.pendingScans > 0) existing.pendingScans--;
    if (existing.pendingScans <= 0 && existing.status === "scanning") {
      existing.status = "complete";
    }
    await saveTabFindings(tabId, existing);
  });
}

async function updateScanSummary(tabId, updates) {
  return withTabLock(tabId, async () => {
    const existing = await getTabFindings(tabId);
    Object.assign(existing.scanSummary, updates);
    await saveTabFindings(tabId, existing);
  });
}

function getAllFindings(tabData) {
  return [
    ...(tabData.content || []),
    ...(tabData.network || []),
    ...(tabData.jsFiles || []),
    ...(tabData.paths || [])
  ];
}

// ── AbortController Tracking ──
// Allows scan cancellation on navigation or tab close
const activeScanControllers = new Map();

function createScanAbort(tabId) {
  cancelScan(tabId);
  const controller = new AbortController();
  activeScanControllers.set(tabId, controller);
  return controller.signal;
}

function cancelScan(tabId) {
  const existing = activeScanControllers.get(tabId);
  if (existing) {
    existing.abort();
    activeScanControllers.delete(tabId);
  }
}

// ── Badge ──

function updateBadge(tabId, tabData) {
  const all = getAllFindings(tabData);
  const count = all.length;

  if (count === 0) {
    chrome.action.setBadgeText({ text: "", tabId });
    return;
  }

  chrome.action.setBadgeText({ text: count > 999 ? "999+" : String(count), tabId });

  const severities = new Set(all.map(f => f.severity));
  let color = "#78909C";
  if (severities.has("critical")) color = "#FF1744";
  else if (severities.has("high")) color = "#FF9100";
  else if (severities.has("medium")) color = "#FFC400";
  else if (severities.has("low")) color = "#2979FF";

  chrome.action.setBadgeBackgroundColor({ color, tabId });
  chrome.action.setBadgeTextColor({ color: "#FFFFFF", tabId });
}

// ── Header Cache ──
const cachedHeaders = new Map();

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type === "main_frame") {
      cachedHeaders.set(details.tabId, {
        headers: details.responseHeaders || [],
        url: details.url
      });
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders", "extraHeaders"]
);

function scanHeaders(tabId, headers, url) {
  const findings = [];
  const headerMap = {};
  const headerList = [];
  headers.forEach(h => {
    const name = h.name.toLowerCase();
    headerMap[name] = h.value;
    headerList.push({ name, value: h.value });
  });

  // Missing security headers
  const required = [
    { name: "content-security-policy", severity: "high", title: "Missing Content-Security-Policy", description: "No CSP header. Vulnerable to XSS and data injection." },
    { name: "strict-transport-security", severity: "high", title: "Missing Strict-Transport-Security", description: "No HSTS. Site doesn't enforce HTTPS." },
    { name: "x-frame-options", severity: "medium", title: "Missing X-Frame-Options", description: "No clickjacking protection." },
    { name: "x-content-type-options", severity: "low", title: "Missing X-Content-Type-Options", description: "No MIME sniffing protection." },
    { name: "permissions-policy", severity: "medium", title: "Missing Permissions-Policy", description: "No browser feature restrictions." },
    { name: "referrer-policy", severity: "low", title: "Missing Referrer-Policy", description: "No referrer policy set." }
  ];

  for (const sh of required) {
    if (!headerMap[sh.name]) {
      findings.push(createFinding({
        severity: sh.severity, category: "security-header",
        title: sh.title, description: sh.description,
        match: `Header "${sh.name}" is not set`, location: url
      }));
    }
  }

  // CSP analysis (if present)
  if (headerMap["content-security-policy"]) {
    const csp = headerMap["content-security-policy"];
    if (csp.includes("'unsafe-inline'")) {
      findings.push(createFinding({
        severity: "medium", category: "security-header",
        title: "CSP Allows unsafe-inline",
        description: "CSP contains 'unsafe-inline' which weakens XSS protection.",
        match: "unsafe-inline in CSP", location: url
      }));
    }
    if (csp.includes("'unsafe-eval'")) {
      findings.push(createFinding({
        severity: "medium", category: "security-header",
        title: "CSP Allows unsafe-eval",
        description: "CSP contains 'unsafe-eval' which allows eval() execution.",
        match: "unsafe-eval in CSP", location: url
      }));
    }
    if (/default-src[^;]*\*/.test(csp)) {
      findings.push(createFinding({
        severity: "high", category: "security-header",
        title: "CSP Has Wildcard default-src",
        description: "CSP default-src allows resources from any origin.",
        match: "default-src contains *", location: url
      }));
    }
    if (!csp.includes("script-src") && !csp.includes("default-src")) {
      findings.push(createFinding({
        severity: "high", category: "security-header",
        title: "CSP Missing script-src",
        description: "CSP has no script-src or default-src directive. All scripts are allowed.",
        match: "No script-src in CSP", location: url
      }));
    }
    if (/script-src[^;]*data:/i.test(csp)) {
      findings.push(createFinding({
        severity: "high", category: "security-header",
        title: "CSP script-src Allows data: URI",
        description: "CSP script-src permits data: URIs which can be used for XSS.",
        match: "data: in script-src", location: url
      }));
    }
    if (/script-src[^;]*\bhttp:/i.test(csp)) {
      findings.push(createFinding({
        severity: "medium", category: "security-header",
        title: "CSP script-src Allows HTTP",
        description: "CSP script-src permits loading scripts over HTTP (MitM risk).",
        match: "http: in script-src", location: url
      }));
    }
  }

  // HSTS deep analysis
  if (headerMap["strict-transport-security"]) {
    const hsts = headerMap["strict-transport-security"];
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0;
    if (maxAge < 31536000) {
      findings.push(createFinding({
        severity: "medium", category: "security-header",
        title: "HSTS max-age Below 1 Year",
        description: `HSTS max-age is ${maxAge}s (${Math.round(maxAge/86400)} days). Should be at least 31536000 (1 year).`,
        match: `max-age=${maxAge}`, location: url
      }));
    }
    if (!/includeSubDomains/i.test(hsts)) {
      findings.push(createFinding({
        severity: "low", category: "security-header",
        title: "HSTS Missing includeSubDomains",
        description: "HSTS does not include subdomains. Subdomains can be accessed over HTTP.",
        match: hsts.substring(0, 200), location: url
      }));
    }
  }

  // Server version disclosure
  const disclosureHeaders = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache", "x-varnish", "x-framework"];
  for (const h of disclosureHeaders) {
    if (headerMap[h]) {
      findings.push(createFinding({
        severity: "medium", category: "server-info",
        title: `Server Disclosure: ${h}`,
        description: `"${h}" header reveals technology/version.`,
        match: `${h}: ${headerMap[h]}`, location: url
      }));
    }
  }

  // CORS
  const acao = headerMap["access-control-allow-origin"];
  if (acao) {
    const acac = headerMap["access-control-allow-credentials"];
    if (acao === "*" && acac === "true") {
      findings.push(createFinding({
        severity: "critical", category: "cors",
        title: "CORS: Wildcard + Credentials",
        description: "Wildcard origin with credentials allowed. Critical misconfiguration.",
        match: "ACAO: * + ACAC: true", location: url
      }));
    } else if (acao === "*") {
      findings.push(createFinding({
        severity: "medium", category: "cors",
        title: "CORS: Wildcard Origin",
        description: "Access-Control-Allow-Origin set to wildcard (*).",
        match: "ACAO: *", location: url
      }));
    } else if (acao === "null") {
      findings.push(createFinding({
        severity: "high", category: "cors",
        title: "CORS: null Origin Allowed",
        description: "Access-Control-Allow-Origin allows 'null' which is exploitable.",
        match: "ACAO: null", location: url
      }));
    }
  }

  // Cookies
  headerList.filter(h => h.name === "set-cookie").forEach(h => {
    const cookie = h.value;
    const cookieName = cookie.split("=")[0].trim();
    const flags = cookie.toLowerCase();
    const issues = [];

    if (!flags.includes("secure")) issues.push("Secure");
    if (!flags.includes("httponly")) issues.push("HttpOnly");
    if (!flags.includes("samesite")) issues.push("SameSite");

    if (issues.length > 0) {
      const isSession = /(?:session|sess|sid|auth|token|jwt|login|identity|connect\.sid)/i.test(cookieName);
      findings.push(createFinding({
        severity: isSession ? "high" : "medium",
        category: "cookie",
        title: `Insecure Cookie: ${cookieName}`,
        description: `Missing ${issues.join(", ")} flag(s).${isSession ? " Appears to be a session cookie." : ""}`,
        match: cookie.substring(0, 200), location: url
      }));
    }

    if (cookieName.startsWith("__Secure-") && !flags.includes("secure")) {
      findings.push(createFinding({
        severity: "high", category: "cookie",
        title: "__Secure- Cookie Without Secure",
        description: `${cookieName} uses __Secure- prefix but lacks Secure flag.`,
        match: cookieName, location: url
      }));
    }

    if (cookieName.startsWith("__Host-")) {
      const hostIssues = [];
      if (!flags.includes("secure")) hostIssues.push("Secure");
      if (!flags.includes("path=/")) hostIssues.push("Path=/");
      if (/;\s*domain\s*=/i.test(cookie)) hostIssues.push("must not have Domain");
      if (hostIssues.length > 0) {
        findings.push(createFinding({
          severity: "high", category: "cookie",
          title: "__Host- Cookie Violation",
          description: `${cookieName} uses __Host- prefix but violates requirements: ${hostIssues.join(", ")}.`,
          match: cookieName, location: url
        }));
      }
    }
  });

  // ── Header-based Technology Fingerprinting ──
  const techFingerprints = [
    { check: () => headerMap["server"]?.toLowerCase().includes("github.com") || headerMap["x-github-request-id"], name: "GitHub Pages", description: "GitHub Pages hosting detected via headers." },
    { check: () => headerMap["x-vercel-id"] || headerMap["server"]?.toLowerCase() === "vercel", name: "Vercel", description: "Vercel hosting detected via headers." },
    { check: () => headerMap["x-netlify-request-id"] || headerMap["server"]?.toLowerCase() === "netlify", name: "Netlify", description: "Netlify hosting detected via headers." },
    { check: () => headerMap["x-amz-cf-id"] || headerMap["x-amz-cf-pop"], name: "Amazon CloudFront", description: "AWS CloudFront CDN detected via headers." },
    { check: () => headerMap["x-azure-ref"], name: "Azure", description: "Azure hosting detected via headers." },
    { check: () => headerMap["x-goog-generation"] || headerMap["x-guploader-uploadid"], name: "Google Cloud Storage", description: "Google Cloud Storage detected via headers." },
    { check: () => /fly-request-id|fly\.io/i.test(headerMap["server"] || ""), name: "Fly.io", description: "Fly.io hosting detected via headers." },
    { check: () => headerMap["x-render-origin-server"], name: "Render", description: "Render hosting detected via headers." },
    { check: () => headerMap["x-fastly-request-id"] || headerMap["x-served-by"]?.includes("cache-"), name: "Fastly", description: "Fastly CDN detected via headers." },
    { check: () => headerMap["cf-ray"] || headerMap["cf-cache-status"], name: "Cloudflare", description: "Cloudflare CDN detected via headers." },
    { check: () => headerMap["x-cdn"]?.toLowerCase().includes("akamai") || headerMap["x-akamai-transformed"], name: "Akamai", description: "Akamai CDN detected via headers." },
    { check: () => headerMap["x-sucuri-id"] || headerMap["x-sucuri-cache"], name: "Sucuri", description: "Sucuri WAF/CDN detected via headers." },
    { check: () => headerMap["x-varnish"] || (headerMap["via"] && /varnish/i.test(headerMap["via"])), name: "Varnish", description: "Varnish caching proxy detected via headers.", extra: () => { const via = headerMap["via"] || ""; const m = via.match(/varnish[\/\s]*([0-9.]+)/i) || headerMap["x-varnish"]?.match(/([0-9.]+)/); return m ? m[1] : null; } },
    { check: () => /^nginx/i.test(headerMap["server"] || ""), name: "Nginx", description: "Nginx web server detected.", extra: () => { const m = (headerMap["server"] || "").match(/nginx[\/\s]*([0-9.]+)/i); return m ? m[1] : null; } },
    { check: () => /^apache/i.test(headerMap["server"] || ""), name: "Apache", description: "Apache web server detected.", extra: () => { const m = (headerMap["server"] || "").match(/apache[\/\s]*([0-9.]+)/i); return m ? m[1] : null; } },
    { check: () => /^LiteSpeed/i.test(headerMap["server"] || ""), name: "LiteSpeed", description: "LiteSpeed web server detected." },
    { check: () => /^openresty/i.test(headerMap["server"] || ""), name: "OpenResty", description: "OpenResty (Nginx+Lua) detected." },
    { check: () => /Microsoft-IIS/i.test(headerMap["server"] || ""), name: "IIS", description: "Microsoft IIS detected.", extra: () => { const m = (headerMap["server"] || "").match(/IIS[\/\s]*([0-9.]+)/i); return m ? m[1] : null; } },
    { check: () => /^PHP/i.test(headerMap["x-powered-by"] || ""), name: "PHP", description: "PHP detected via X-Powered-By header.", extra: () => { const m = (headerMap["x-powered-by"] || "").match(/PHP[\/\s]*([0-9.]+)/i); return m ? m[1] : null; } },
    { check: () => /express/i.test(headerMap["x-powered-by"] || ""), name: "Express", description: "Express.js framework detected via headers." },
    { check: () => /^next\.js/i.test(headerMap["x-powered-by"] || ""), name: "Next.js", description: "Next.js detected via X-Powered-By header." },
    { check: () => headerMap["x-drupal-cache"] || headerMap["x-drupal-dynamic-cache"], name: "Drupal", description: "Drupal CMS detected via headers." },
    { check: () => headerMap["strict-transport-security"], name: "HSTS", description: "HTTP Strict Transport Security enabled." },
  ];

  for (const fp of techFingerprints) {
    try {
      if (fp.check()) {
        let name = fp.name;
        if (fp.extra) {
          const version = fp.extra();
          if (version) name += ` ${version}`;
        }
        findings.push(createFinding({
          severity: "info", category: "technology",
          title: name,
          description: fp.description,
          match: name, location: url
        }));
      }
    } catch (e) { /* skip */ }
  }

  // Deprecated/informational headers
  if (headerMap["x-xss-protection"]) {
    findings.push(createFinding({
      severity: "info", category: "security-header",
      title: "Deprecated X-XSS-Protection",
      description: "X-XSS-Protection is deprecated. Use CSP instead.",
      match: `X-XSS-Protection: ${headerMap["x-xss-protection"]}`, location: url
    }));
  }

  // Cache-Control for sensitive pages
  if (headerMap["set-cookie"] && !headerMap["cache-control"]?.includes("no-store")) {
    findings.push(createFinding({
      severity: "low", category: "security-header",
      title: "Missing Cache-Control: no-store",
      description: "Page sets cookies but doesn't prevent caching. Sensitive data may be cached.",
      match: `Cache-Control: ${headerMap["cache-control"] || "(not set)"}`, location: url
    }));
  }

  updateScanSummary(tabId, { headersAnalyzed: true });
  mergeFindings(tabId, "network", findings, url);
}

// ── JS File Scanner ──

async function scanJsFiles(tabId, urls, signal) {
  const findings = [];
  const maxFiles = 60;
  const maxSize = 2 * 1024 * 1024;
  const filesToScan = urls.slice(0, maxFiles);

  const scanGroups = [
    SCAN_PATTERNS.apiKeys,
    SCAN_PATTERNS.credentials,
    SCAN_PATTERNS.endpoints,
    SCAN_PATTERNS.envVars,
    SCAN_PATTERNS.sourceMaps,
    SCAN_PATTERNS.domSecurity,
    SCAN_PATTERNS.media
  ];

  let scannedCount = 0;
  for (const url of filesToScan) {
    if (signal.aborted) break;
    let onAbort = null;
    let timeoutId = null;
    try {
      const controller = new AbortController();
      timeoutId = setTimeout(() => controller.abort(), 8000);

      // Chain with parent signal so navigation cancels in-flight fetches
      onAbort = () => controller.abort();
      signal.addEventListener("abort", onAbort, { once: true });

      const response = await fetch(url, { credentials: "omit", signal: controller.signal });

      if (!response.ok) continue;

      let text = await response.text();
      if (text.length > maxSize) text = text.substring(0, maxSize);
      scannedCount++;

      for (const patterns of scanGroups) {
        for (const p of patterns) {
          if (p.requiresContext) continue;
          const regex = new RegExp(p.pattern.source, p.pattern.flags);
          let match;
          let matchCount = 0;
          while ((match = regex.exec(text)) !== null && matchCount < 30) {
            matchCount++;
            if (match[0].length === 0) { regex.lastIndex++; continue; }
            const matchedText = match[1] || match[0];
            if (p.falsePositiveFilter && p.falsePositiveFilter.test(matchedText)) continue;

            const start = Math.max(0, match.index - 50);
            const end = Math.min(text.length, match.index + match[0].length + 50);
            const context = text.substring(start, end).replace(/[\n\r]+/g, " ").trim();
            findings.push(createFinding({
              severity: p.severity, category: p.category,
              title: `${p.name} (in JS)`,
              description: p.description,
              match: matchedText, location: url, context
            }));
          }
        }
      }
    } catch (err) {
      if (signal.aborted) break;
    } finally {
      clearTimeout(timeoutId);
      if (onAbort) signal.removeEventListener("abort", onAbort);
    }
  }

  updateScanSummary(tabId, { jsFilesScanned: scannedCount });
  mergeFindings(tabId, "jsFiles", deduplicateFindings(findings));
}

// ── Path Checker (Concurrent) ──

async function probePaths(tabId, origin, signal) {
  const findings = [];
  const CONCURRENCY = 5;
  const delay = ms => new Promise(r => setTimeout(r, ms));

  // Detect if the site is an SPA (returns 200 for everything)
  let isSpa = false;
  try {
    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), 5000);
    const onAbort = () => controller.abort();
    signal.addEventListener("abort", onAbort, { once: true });

    const testResp = await fetch(origin + "/__nexus_spa_test_" + Date.now(), {
      method: "GET", credentials: "omit", redirect: "manual", signal: controller.signal
    });
    clearTimeout(tid);
    signal.removeEventListener("abort", onAbort);

    if (testResp.status === 200) {
      const body = await testResp.text();
      if (body.includes("<!doctype") || body.includes("<!DOCTYPE") || body.includes("<html")) {
        isSpa = true;
      }
    }
  } catch (e) { /* proceed without SPA detection */ }

  if (signal.aborted) {
    mergeFindings(tabId, "paths", []);
    return;
  }

  let nextIdx = 0;
  // Shared counter object — increment is always synchronous before the next await
  const stats = { probed: 0 };

  async function worker() {
    while (!signal.aborted) {
      const i = nextIdx++;
      if (i >= SENSITIVE_PATHS.length) break;

      const entry = SENSITIVE_PATHS[i];
      let retries = 0;
      const MAX_RETRIES = 3;

      while (retries <= MAX_RETRIES && !signal.aborted) {
        let onAbort = null;
        let timeoutId = null;
        try {
          const url = origin + entry.path;
          const controller = new AbortController();
          timeoutId = setTimeout(() => controller.abort(), 5000);
          onAbort = () => controller.abort();
          signal.addEventListener("abort", onAbort, { once: true });

          const response = await fetch(url, {
            method: "GET", credentials: "omit", redirect: "manual",
            signal: controller.signal
          });
          stats.probed++;

          if (response.status === 429 && retries < MAX_RETRIES) {
            retries++;
            await delay(Math.min(200 * Math.pow(2, retries), 5000));
            continue;
          }

          if (response.status === 200) {
            const contentType = response.headers.get("content-type") || "";
            const body = await response.text();
            const bodyPreview = body.substring(0, 1000);

            const expectsHtml = entry.path.endsWith(".html") || entry.path.endsWith(".php") || entry.path.endsWith("/");
            if (isSpa && !expectsHtml && contentType.includes("text/html")) break;

            const isErrorPage =
              (bodyPreview.includes("<title>404") || bodyPreview.includes("<title>Not Found") ||
               bodyPreview.includes("Page not found") || bodyPreview.includes("page not found") ||
               bodyPreview.includes("does not exist") || bodyPreview.includes("cannot be found"));
            if (isErrorPage) break;

            if (body.length < 5) break;

            if (entry.category === "config-file" || entry.category === "vcs" || entry.category === "backup") {
              if (contentType.includes("text/html") && !expectsHtml) break;
            }

            findings.push(createFinding({
              severity: entry.severity, category: entry.category,
              title: entry.title, description: entry.description,
              match: `${url} (HTTP 200, ${contentType || "unknown"})`,
              location: url,
              context: bodyPreview.substring(0, 200)
            }));
          }
          break; // success or non-429 response, move on
        } catch (err) {
          if (signal.aborted) return;
          break;
        } finally {
          clearTimeout(timeoutId);
          if (onAbort) signal.removeEventListener("abort", onAbort);
        }
      }

      // Small delay between requests per worker to avoid hammering
      await delay(100);
    }
  }

  await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()));

  updateScanSummary(tabId, { pathsProbed: stats.probed });
  mergeFindings(tabId, "paths", deduplicateFindings(findings));
}

// ── Message Handling ──

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab?.id || message.tabId;

  if (message.type === "CONTENT_FINDINGS") {
    if (tabId) {
      const hasJsFiles = message.jsFileUrls && message.jsFileUrls.length > 0;
      // +1 for paths (always probed), +1 for jsFiles if present
      // Note: content's decrement is already allocated in REQUEST_SCAN's pendingScans=2
      const extraPending = 1 + (hasJsFiles ? 1 : 0);

      // Retrieve or create the scan signal for this tab
      let signal = activeScanControllers.get(tabId)?.signal;
      if (!signal || signal.aborted) {
        signal = createScanAbort(tabId);
      }

      // Validate jsFileUrls: only allow http(s) URLs matching the tab's origin
      // to prevent a malicious page from injecting arbitrary fetch targets
      let safeJsUrls = null;
      if (hasJsFiles && sender.tab?.url) {
        try {
          const tabOrigin = new URL(sender.tab.url).origin;
          safeJsUrls = message.jsFileUrls.filter(u => {
            try { return u.startsWith("https://") || u.startsWith("http://"); }
            catch (e) { return false; }
          });
        } catch (e) { safeJsUrls = null; }
      }
      const hasValidJsFiles = safeJsUrls && safeJsUrls.length > 0;

      withTabLock(tabId, async () => {
        const existing = await getTabFindings(tabId);
        existing.pendingScans = (existing.pendingScans || 0) + extraPending;
        await saveTabFindings(tabId, existing);
      }).then(() => {
        mergeFindings(tabId, "content", message.findings, message.url).then(() => {
          if (hasValidJsFiles) {
            scanJsFiles(tabId, safeJsUrls, signal);
          } else if (hasJsFiles) {
            // jsFileUrls provided but none valid — still decrement pending
            mergeFindings(tabId, "jsFiles", []);
          }
          if (sender.tab?.url) {
            try {
              const origin = new URL(sender.tab.url).origin;
              probePaths(tabId, origin, signal);
            } catch (e) {
              mergeFindings(tabId, "paths", []);
            }
          } else {
            mergeFindings(tabId, "paths", []);
          }
        });
      });
    }
    sendResponse({ status: "ok" });
    return false;
  }

  if (message.type === "GET_FINDINGS") {
    if (message.tabId) {
      getTabFindings(message.tabId).then(tabData => {
        const all = deduplicateFindings(getAllFindings(tabData));
        sendResponse({
          findings: sortFindings(all),
          summary: getSeverityCounts(all),
          url: tabData.url,
          status: tabData.status || "idle",
          scanSummary: tabData.scanSummary || {}
        });
      }).catch(() => {
        sendResponse({ findings: [], summary: {}, url: "", status: "idle", scanSummary: {} });
      });
      return true;
    }
    sendResponse({ findings: [], summary: {}, url: "", status: "idle", scanSummary: {} });
    return false;
  }

  if (message.type === "REQUEST_SCAN") {
    if (message.tabId) {
      const tabId = message.tabId;
      const signal = createScanAbort(tabId);

      const initial = createEmptyTabFindings("", "scanning");
      initial.pendingScans = 2;
      saveTabFindings(tabId, initial).then(() => {
        const cached = cachedHeaders.get(tabId);
        if (cached) {
          scanHeaders(tabId, cached.headers, cached.url);
        } else {
          mergeFindings(tabId, "network", []);
        }

        const triggerRescan = () => chrome.tabs.sendMessage(tabId, { type: "REQUEST_RESCAN" });

        triggerRescan().catch(() => {
          chrome.scripting.executeScript({
            target: { tabId },
            files: ["scanner/patterns.js", "scanner/finding.js", "content.js"]
          }).then(() => triggerRescan()).catch((err) => {
            console.warn("[Nexus] Unable to start scan for tab:", tabId, err);
            saveTabFindings(tabId, createEmptyTabFindings("", "idle"));
          });
        });
      });
    }
    sendResponse({ status: "ok" });
    return false;
  }

  return false;
});

// ── Cleanup ──

chrome.tabs.onRemoved.addListener((tabId) => {
  cancelScan(tabId);
  chrome.storage.session.remove(`tab_${tabId}`);
  cachedHeaders.delete(tabId);
  storageQueue.delete(`tab_${tabId}`);
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    cancelScan(tabId);

    chrome.tabs.get(tabId, (tab) => {
      if (chrome.runtime.lastError || !tab) return;

      getTabFindings(tabId).then(data => {
        const currentUrl = tab.url;
        const storedUrl = data.url;

        if (currentUrl && storedUrl && currentUrl !== storedUrl) {
          saveTabFindings(tabId, createEmptyTabFindings(currentUrl, "idle"));
        }
      });
    });
  }
});
