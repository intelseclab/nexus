/**
 * Content script - runs on every page at document_idle.
 * Scans DOM, inline scripts, comments, meta tags, forms, links, and more.
 */
(function () {
  "use strict";

  const MAX_SOURCE_LENGTH = 5 * 1024 * 1024;
  const pageUrl = window.location.href;
  const pageOrigin = window.location.origin;
  const isHttps = window.location.protocol === "https:";

  // ── Collectors ──

  function getInlineScriptContents() {
    const scripts = [];
    document.querySelectorAll("script:not([src])").forEach(el => {
      const text = el.textContent.trim();
      if (text.length > 10) scripts.push(text);
    });
    return scripts;
  }

  function getExternalScriptUrls() {
    const urls = new Set();
    // Collect script[src] tags
    document.querySelectorAll("script[src]").forEach(el => {
      if (el.src && el.src.startsWith("http")) urls.add(el.src);
    });
    // Collect preloaded scripts (Next.js, webpack chunk preloads)
    document.querySelectorAll('link[rel="preload"][as="script"], link[rel="modulepreload"]').forEach(el => {
      const href = el.href || "";
      if (href.startsWith("http")) urls.add(href);
    });
    return [...urls];
  }

  function getHtmlComments() {
    const comments = [];
    const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT);
    let node;
    while ((node = walker.nextNode())) {
      const text = node.textContent.trim();
      if (text.length > 3) comments.push(text);
    }
    return comments;
  }

  function getMetaTags() {
    const metas = [];
    document.querySelectorAll("meta").forEach(el => {
      const name = el.getAttribute("name") || el.getAttribute("property") || el.getAttribute("http-equiv") || "";
      const content = el.getAttribute("content") || "";
      if (content) metas.push({ name: name.toLowerCase(), content });
    });
    return metas;
  }

  function getHiddenInputs() {
    const inputs = [];
    document.querySelectorAll('input[type="hidden"]').forEach(el => {
      const name = el.getAttribute("name") || "";
      const value = el.getAttribute("value") || "";
      if (value && value.length > 2) inputs.push({ name, value });
    });
    return inputs;
  }

  function getForms() {
    const forms = [];
    document.querySelectorAll("form").forEach(el => {
      forms.push({
        action: el.getAttribute("action") || "",
        method: (el.getAttribute("method") || "GET").toUpperCase(),
        id: el.id || "",
        hasPasswordField: !!el.querySelector('input[type="password"]'),
        isHttpAction: (el.getAttribute("action") || "").startsWith("http://")
      });
    });
    return forms;
  }

  function getExternalLinks() {
    const links = new Set();
    document.querySelectorAll("a[href]").forEach(el => {
      const href = el.href;
      if (href && href.startsWith("http") && !href.startsWith(pageOrigin)) {
        try { links.add(new URL(href).origin); } catch (e) { /* skip */ }
      }
    });
    return [...links];
  }

  function getExternalResources() {
    const resources = [];
    document.querySelectorAll("link[href], img[src], iframe[src], object[data], embed[src]").forEach(el => {
      const url = el.href || el.src || el.getAttribute("data") || "";
      if (url.startsWith("http://") && isHttps) {
        resources.push({ tag: el.tagName.toLowerCase(), url });
      }
    });
    return resources;
  }

  function getDataAttributes() {
    const findings = [];
    const sensitivePatterns = /(?:api|key|token|secret|auth|endpoint|url|host|base)/i;
    document.querySelectorAll("*").forEach(el => {
      for (const attr of el.attributes) {
        if (attr.name.startsWith("data-") && sensitivePatterns.test(attr.name) && attr.value.length > 5) {
          findings.push({ attr: attr.name, value: attr.value, tag: el.tagName.toLowerCase() });
        }
      }
    });
    return findings;
  }

  // ── Scanners ──

  function scanWithPatterns(text, patternGroup, sourceLabel) {
    const findings = [];
    if (!text || text.length < 3) return findings;

    for (const p of patternGroup) {
      if (p.requiresContext) continue;
      const regex = new RegExp(p.pattern.source, p.pattern.flags);
      let match;
      let matchCount = 0;
      while ((match = regex.exec(text)) !== null && matchCount < 50) {
        matchCount++;
        if (match[0].length === 0) { regex.lastIndex++; continue; }
        const matchedText = match[1] || match[0];
        if (p.falsePositiveFilter && p.falsePositiveFilter.test(matchedText)) continue;
        const start = Math.max(0, match.index - 50);
        const end = Math.min(text.length, match.index + match[0].length + 50);
        const context = text.substring(start, end).replace(/[\n\r]+/g, " ").trim();
        findings.push(createFinding({
          severity: p.severity,
          category: p.category,
          title: p.name,
          description: p.description,
          match: matchedText,
          location: sourceLabel,
          context
        }));
      }
    }
    return findings;
  }

  function scanComments(comments) {
    const findings = [];
    const sensitiveKeywords = /\b(password|secret|token|api[_-]?key|credential|private|internal|fixme|hack|xxx|admin|root|config|database|mysql|connection|auth|session)\b/i;
    const severityKeywords = /\b(password|secret|token|credential|database|mysql|auth)\b/i;

    for (let i = 0; i < comments.length; i++) {
      const comment = comments[i];
      if (sensitiveKeywords.test(comment)) {
        findings.push(createFinding({
          severity: severityKeywords.test(comment) ? "medium" : "low",
          category: "comment",
          title: "Sensitive HTML Comment",
          description: "HTML comment contains potentially sensitive keywords.",
          match: comment.substring(0, 200),
          location: `HTML Comment #${i + 1}`,
          context: comment.substring(0, 300)
        }));
      }
    }
    return findings;
  }

  function scanHiddenInputs(inputs) {
    const findings = [];
    const sensitiveNames = /(?:token|key|secret|csrf|session|auth|password|hash|nonce|api)/i;

    for (const input of inputs) {
      if (sensitiveNames.test(input.name)) {
        findings.push(createFinding({
          severity: "medium",
          category: "hidden-input",
          title: `Hidden Input: ${input.name}`,
          description: "Hidden form input with security-related name.",
          match: `${input.name}=${input.value.substring(0, 100)}`,
          location: pageUrl,
          context: `<input type="hidden" name="${input.name}" value="${input.value.substring(0, 80)}">`
        }));
      }
    }
    return findings;
  }

  function scanMetaTags(metas) {
    const findings = [];
    for (const meta of metas) {
      if (meta.name === "generator") {
        findings.push(createFinding({
          severity: "info", category: "technology",
          title: `CMS/Framework: ${meta.content}`,
          description: "Generator meta tag reveals technology.",
          match: meta.content, location: pageUrl,
          context: `<meta name="generator" content="${meta.content}">`
        }));
      }
      if (meta.name === "author") {
        findings.push(createFinding({
          severity: "info", category: "info-leak",
          title: `Author: ${meta.content}`,
          description: "Author meta tag reveals developer/company info.",
          match: meta.content, location: pageUrl
        }));
      }
      if (/^(api|key|token|secret|csrf)/.test(meta.name) && meta.content.length > 5) {
        findings.push(createFinding({
          severity: "medium", category: "meta-info",
          title: `Sensitive Meta: ${meta.name}`,
          description: "Meta tag may contain sensitive information.",
          match: `${meta.name}=${meta.content}`, location: pageUrl
        }));
      }
      // CSP via meta tag
      if (meta.name === "content-security-policy" || meta.name === "content-security-policy-report-only") {
        findings.push(createFinding({
          severity: "info", category: "security-header",
          title: "CSP via Meta Tag",
          description: "Content-Security-Policy set via meta tag (weaker than HTTP header).",
          match: meta.content.substring(0, 200), location: pageUrl
        }));
      }
    }
    return findings;
  }

  function scanForms(forms) {
    const findings = [];
    for (const form of forms) {
      if (form.isHttpAction && form.hasPasswordField) {
        findings.push(createFinding({
          severity: "critical", category: "transport",
          title: "Password Form over HTTP",
          description: "Form with password field submits to HTTP (unencrypted).",
          match: `action="${form.action}" method="${form.method}"`,
          location: pageUrl
        }));
      } else if (form.isHttpAction) {
        findings.push(createFinding({
          severity: "high", category: "transport",
          title: "Form Submits over HTTP",
          description: "Form action uses HTTP instead of HTTPS.",
          match: `action="${form.action}"`,
          location: pageUrl
        }));
      }
      if (form.action && /^https?:\/\//.test(form.action) && !form.action.startsWith(pageOrigin)) {
        findings.push(createFinding({
          severity: "info", category: "endpoint",
          title: "External Form Action",
          description: "Form submits to external domain.",
          match: form.action,
          location: pageUrl
        }));
      }
    }
    return findings;
  }

  function scanMixedContent(resources) {
    const findings = [];
    for (const res of resources) {
      findings.push(createFinding({
        severity: "medium", category: "transport",
        title: `Mixed Content: <${res.tag}>`,
        description: `HTTP resource loaded on HTTPS page via <${res.tag}>.`,
        match: res.url,
        location: pageUrl
      }));
    }
    return findings;
  }

  function scanDataAttributes(dataAttrs) {
    const findings = [];
    for (const d of dataAttrs) {
      findings.push(createFinding({
        severity: "low", category: "info-leak",
        title: `Sensitive data-attribute: ${d.attr}`,
        description: `Data attribute on <${d.tag}> may expose configuration.`,
        match: `${d.attr}="${d.value.substring(0, 100)}"`,
        location: pageUrl
      }));
    }
    return findings;
  }

  function scanNextData() {
    const findings = [];
    const nextDataEl = document.getElementById("__NEXT_DATA__");
    if (!nextDataEl) return findings;
    try {
      const data = JSON.parse(nextDataEl.textContent);
      const fullStr = nextDataEl.textContent;

      // Scan full JSON blob for secrets and env vars
      findings.push(...scanWithPatterns(fullStr, SCAN_PATTERNS.apiKeys, "__NEXT_DATA__"));
      findings.push(...scanWithPatterns(fullStr, SCAN_PATTERNS.credentials, "__NEXT_DATA__"));
      findings.push(...scanWithPatterns(fullStr, SCAN_PATTERNS.envVars, "__NEXT_DATA__"));

      // Extract buildId
      if (data.buildId && data.buildId !== "development") {
        findings.push(createFinding({
          severity: "info", category: "info-leak",
          title: "Next.js Build ID",
          description: "Use /_next/data/" + data.buildId + "/<page>.json to access SSR props for any route.",
          match: data.buildId, location: pageUrl
        }));
      }

      // Extract current page route
      if (data.page) {
        findings.push(createFinding({
          severity: "info", category: "endpoint",
          title: "Next.js Route: " + data.page,
          description: "Current page route from __NEXT_DATA__.",
          match: data.page, location: pageUrl
        }));
      }

      // Deep URL extraction from entire JSON — catches all embedded URLs and API paths
      const urlRe = /(?:https?:\/\/[^\s"\\,}{[\]]+|\/api\/[^\s"\\,}{[\]]+|\/v[1-9]\d?\/[^\s"\\,}{[\]]+)/g;
      const foundUrls = new Set();
      let um;
      while ((um = urlRe.exec(fullStr)) !== null) {
        const u = um[0].replace(/[")}\]\\]+$/, "");
        if (u.length > 4 && !u.includes("_next/static")) foundUrls.add(u);
      }
      for (const u of foundUrls) {
        findings.push(createFinding({
          severity: "info", category: "endpoint",
          title: u.startsWith("http") ? "URL in __NEXT_DATA__" : "API Path in __NEXT_DATA__",
          description: "Endpoint found in Next.js server-side data.",
          match: u.substring(0, 200), location: "__NEXT_DATA__"
        }));
      }

      // RuntimeConfig
      const rc = data.runtimeConfig || data.props?.pageProps?.runtimeConfig;
      if (rc) {
        const rcStr = JSON.stringify(rc);
        findings.push(createFinding({
          severity: "medium", category: "env-var",
          title: "Next.js Runtime Config Exposed",
          description: "Runtime configuration in __NEXT_DATA__ may contain server-side values.",
          match: rcStr.substring(0, 200), location: pageUrl
        }));
        findings.push(...scanWithPatterns(rcStr, SCAN_PATTERNS.apiKeys, "runtimeConfig"));
        findings.push(...scanWithPatterns(rcStr, SCAN_PATTERNS.credentials, "runtimeConfig"));
      }

      // pageProps env/config
      const envConfig = data.props?.pageProps?.env || data.props?.pageProps?.config;
      if (envConfig) {
        const eStr = JSON.stringify(envConfig);
        findings.push(...scanWithPatterns(eStr, SCAN_PATTERNS.apiKeys, "__NEXT_DATA__ env"));
        findings.push(...scanWithPatterns(eStr, SCAN_PATTERNS.credentials, "__NEXT_DATA__ env"));
      }
    } catch (e) { /* not valid JSON */ }
    return findings;
  }

  // ── Next.js Build Manifest Route Extraction ──
  function scanNextBuildManifest() {
    const findings = [];

    // Check window.__BUILD_MANIFEST (Next.js always exposes this)
    try {
      const bm = window.__BUILD_MANIFEST;
      if (bm && typeof bm === "object") {
        const pages = Object.keys(bm).filter(k => k.startsWith("/"));
        const apiRoutes = pages.filter(p => p.startsWith("/api/"));
        const pageRoutes = pages.filter(p => !p.startsWith("/api/"));

        for (const route of apiRoutes) {
          findings.push(createFinding({
            severity: "info", category: "endpoint",
            title: "Next.js API Route: " + route,
            description: "API route from build manifest. Test for auth bypass and IDOR.",
            match: route, location: "__BUILD_MANIFEST"
          }));
        }
        if (pageRoutes.length > 0) {
          findings.push(createFinding({
            severity: "info", category: "endpoint",
            title: pageRoutes.length + " Next.js Page Route(s)",
            description: "All page routes from build manifest.",
            match: pageRoutes.slice(0, 30).join(", "),
            location: "__BUILD_MANIFEST",
            context: pageRoutes.join("\n")
          }));
        }
      }
    } catch (e) {}

    // Also parse inline scripts for __BUILD_MANIFEST_CB / sortedPages
    const scripts = document.querySelectorAll("script:not([src])");
    for (const script of scripts) {
      const text = script.textContent;
      if (!text.includes("BUILD_MANIFEST")) continue;

      const routeRe = /["'](\/(?:api\/)?[a-zA-Z0-9\[\]._\-/]+)["']/g;
      const routes = new Set();
      let rm;
      while ((rm = routeRe.exec(text)) !== null) {
        const route = rm[1];
        if (route.startsWith("/_next/") || route.startsWith("/static/")) continue;
        if (/\.(js|css|map|woff|png|jpg|svg)$/.test(route)) continue;
        routes.add(route);
      }
      const apiRoutes = [...routes].filter(r => r.includes("/api/"));
      for (const route of apiRoutes) {
        findings.push(createFinding({
          severity: "info", category: "endpoint",
          title: "Next.js API Route: " + route,
          description: "API route from inline build manifest.",
          match: route, location: "buildManifest (inline)"
        }));
      }
      break;
    }

    return findings;
  }

  // ── localStorage / sessionStorage scanner ──
  function scanWebStorage() {
    const findings = [];
    const stores = [
      { name: "localStorage", obj: window.localStorage },
      { name: "sessionStorage", obj: window.sessionStorage }
    ];
    for (const { name, obj } of stores) {
      try {
        for (let i = 0; i < obj.length; i++) {
          const key = obj.key(i);
          const value = obj.getItem(key) || "";
          if (value.length < 5) continue;
          const combined = `${key}=${value}`;
          const label = `${name}.${key}`;

          // Scan value through secret patterns
          const keyFindings = scanWithPatterns(combined, SCAN_PATTERNS.apiKeys, label);
          const credFindings = scanWithPatterns(combined, SCAN_PATTERNS.credentials, label);
          findings.push(...keyFindings, ...credFindings);

          // Check key names for sensitive patterns
          if (/(?:token|jwt|auth|session|secret|key|password|credential|access_token|refresh_token|id_token)/i.test(key) && value.length > 10) {
            findings.push(createFinding({
              severity: "high", category: "web-storage",
              title: `Sensitive ${name} Key: ${key}`,
              description: `Sensitive data stored in ${name}. Accessible to any JS on this origin (XSS-reachable).`,
              match: `${key}=${value.substring(0, 120)}`,
              location: pageUrl,
              context: `${name}.getItem("${key}") = "${value.substring(0, 200)}"`
            }));
          }
        }
      } catch (e) { /* cross-origin or access error */ }
    }
    return findings;
  }

  // ── SRI absence on external scripts/styles ──
  function scanMissingSRI() {
    const findings = [];
    const crossOriginCDNs = /(?:cdnjs|unpkg|jsdelivr|cdn\.jsdelivr|ajax\.googleapis|stackpath|cloudflare|maxcdn|bootstrapcdn)/i;
    document.querySelectorAll('script[src], link[rel="stylesheet"][href]').forEach(el => {
      const url = el.src || el.href || "";
      if (!url.startsWith("http")) return;
      try {
        const urlOrigin = new URL(url).origin;
        if (urlOrigin === pageOrigin) return; // same-origin, SRI not needed
        if (!el.integrity && crossOriginCDNs.test(url)) {
          findings.push(createFinding({
            severity: "low", category: "sri",
            title: `Missing SRI: ${el.tagName.toLowerCase()}`,
            description: "Cross-origin resource loaded without Subresource Integrity hash. Supply-chain risk.",
            match: url.substring(0, 200),
            location: pageUrl
          }));
        }
      } catch (e) { /* invalid URL */ }
    });
    return findings;
  }

  // ── Subdomain / domain collector ──
  function collectSubdomains() {
    const findings = [];
    const domains = new Set();
    const baseDomain = extractBaseDomain(window.location.hostname);
    if (!baseDomain) return findings;

    // Collect from all src, href, action attributes
    document.querySelectorAll("[src], [href], [action], [data-url], [data-src]").forEach(el => {
      const url = el.src || el.href || el.getAttribute("action") || el.getAttribute("data-url") || el.getAttribute("data-src") || "";
      try {
        if (!url.startsWith("http")) return;
        const host = new URL(url).hostname;
        if (host !== window.location.hostname && host.endsWith("." + baseDomain)) {
          domains.add(host);
        }
      } catch (e) {}
    });

    if (domains.size > 0) {
      const sorted = [...domains].sort();
      findings.push(createFinding({
        severity: "info", category: "subdomain",
        title: `${sorted.length} Subdomain(s) Discovered`,
        description: "Subdomains referenced on this page. Useful for expanding attack surface.",
        match: sorted.join(", "),
        location: pageUrl,
        context: sorted.join("\n")
      }));
    }
    return findings;
  }

  function extractBaseDomain(hostname) {
    const parts = hostname.split(".");
    if (parts.length < 2) return null;
    // Handle TLDs like .co.uk, .com.br
    const knownTwoPartTLDs = /^(?:co|com|org|net|ac|gov|edu)\.\w{2}$/;
    if (parts.length >= 3 && knownTwoPartTLDs.test(parts.slice(-2).join("."))) {
      return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
  }

  // ── dns-prefetch / preconnect ──
  function scanLinkHints() {
    const findings = [];
    const hints = [];
    document.querySelectorAll('link[rel="dns-prefetch"], link[rel="preconnect"]').forEach(el => {
      const href = el.href || el.getAttribute("href") || "";
      if (href && href.startsWith("http")) {
        try { hints.push(new URL(href).hostname); } catch (e) {}
      }
    });
    if (hints.length > 0) {
      const unique = [...new Set(hints)];
      findings.push(createFinding({
        severity: "info", category: "infrastructure",
        title: `${unique.length} Prefetch/Preconnect Hint(s)`,
        description: "DNS prefetch and preconnect hints reveal backend services and infrastructure.",
        match: unique.join(", "),
        location: pageUrl
      }));
    }
    return findings;
  }

  // ── Sensitive file links ──
  function scanSensitiveLinks() {
    const findings = [];
    const sensitiveExts = /\.(?:sql|bak|backup|old|orig|save|swp|sav|conf|config|ini|log|env|key|pem|pfx|p12|jks|kdb|db|sqlite|sqlite3|mdb|dump|tar|tar\.gz|tgz|zip|rar|7z)$/i;
    document.querySelectorAll("a[href]").forEach(el => {
      const href = el.getAttribute("href") || "";
      if (sensitiveExts.test(href)) {
        findings.push(createFinding({
          severity: "medium", category: "sensitive-link",
          title: `Sensitive File Link: ${href.split("/").pop()}`,
          description: "Link to a potentially sensitive file type found on the page.",
          match: href.substring(0, 200),
          location: pageUrl
        }));
      }
    });
    return findings;
  }

  function scanWindowGlobals() {
    const findings = [];
    const sensitiveGlobals = ["__APP_CONFIG__", "__CONFIG__", "__ENV__", "__RUNTIME_CONFIG__",
      "APP_CONFIG", "CONFIG", "__INITIAL_STATE__", "__PRELOADED_STATE__",
      "__APP_INITIAL_STATE__", "GLOBAL_CONFIG", "__config"];
    for (const name of sensitiveGlobals) {
      try {
        const val = window[name];
        if (val && typeof val === "object") {
          const str = JSON.stringify(val);
          if (str.length > 10) {
            findings.push(createFinding({
              severity: "medium", category: "env-var",
              title: `Global Config: window.${name}`,
              description: "Global config object may expose server-side configuration.",
              match: str.substring(0, 200),
              location: pageUrl
            }));
            findings.push(...scanWithPatterns(str, SCAN_PATTERNS.apiKeys, `window.${name}`));
            findings.push(...scanWithPatterns(str, SCAN_PATTERNS.credentials, `window.${name}`));
            findings.push(...scanWithPatterns(str, SCAN_PATTERNS.endpoints, `window.${name}`));
            findings.push(...scanWithPatterns(str, SCAN_PATTERNS.envVars, `window.${name}`));
          }
        }
      } catch (e) { /* cross-origin or access error */ }
    }
    return findings;
  }

  // ── Main Scan ──

  function runScan() {
    const allFindings = [];

    // Collect data
    const inlineScripts = getInlineScriptContents();
    const comments = getHtmlComments();
    const metas = getMetaTags();
    const hiddenInputs = getHiddenInputs();
    const externalScriptUrls = getExternalScriptUrls();
    const forms = getForms();
    const externalResources = getExternalResources();
    const dataAttrs = getDataAttributes();

    // All pattern groups to scan
    const allPatternGroups = [
      SCAN_PATTERNS.apiKeys,
      SCAN_PATTERNS.credentials,
      SCAN_PATTERNS.infoLeaks,
      SCAN_PATTERNS.debug,
      SCAN_PATTERNS.envVars,
      SCAN_PATTERNS.endpoints,
      SCAN_PATTERNS.sourceMaps,
      SCAN_PATTERNS.domSecurity,
      SCAN_PATTERNS.technology,
      SCAN_PATTERNS.transport,
      SCAN_PATTERNS.media
    ];

    // Scan inline scripts only (not full page source - avoids duplicates)
    for (let i = 0; i < inlineScripts.length; i++) {
      const label = `Inline Script #${i + 1}`;
      for (const group of allPatternGroups) {
        allFindings.push(...scanWithPatterns(inlineScripts[i], group, label));
      }
    }

    // Scan page HTML for non-script patterns (comments, meta, hidden inputs are separate)
    // Scan body for info-leaks, technology, transport, and endpoints (e.g. data-attributes, inline URLs)
    const bodyHtml = document.body ? document.body.innerHTML : "";
    const htmlOnlyGroups = [SCAN_PATTERNS.infoLeaks, SCAN_PATTERNS.technology, SCAN_PATTERNS.transport, SCAN_PATTERNS.endpoints, SCAN_PATTERNS.media];
    for (const group of htmlOnlyGroups) {
      allFindings.push(...scanWithPatterns(bodyHtml.substring(0, MAX_SOURCE_LENGTH), group, `Page HTML: ${pageUrl}`));
    }

    // Structured scanners
    allFindings.push(...scanComments(comments));
    allFindings.push(...scanMetaTags(metas));
    allFindings.push(...scanHiddenInputs(hiddenInputs));
    allFindings.push(...scanForms(forms));
    allFindings.push(...scanMixedContent(externalResources));
    allFindings.push(...scanDataAttributes(dataAttrs));
    allFindings.push(...scanNextData());
    allFindings.push(...scanNextBuildManifest());
    allFindings.push(...scanWindowGlobals());
    allFindings.push(...scanWebStorage());
    allFindings.push(...scanMissingSRI());
    allFindings.push(...collectSubdomains());
    allFindings.push(...scanLinkHints());
    allFindings.push(...scanSensitiveLinks());

    // Deduplicate & send
    const uniqueFindings = deduplicateFindings(allFindings);

    try {
      chrome.runtime.sendMessage({
        type: "CONTENT_FINDINGS",
        findings: uniqueFindings,
        url: pageUrl,
        jsFileUrls: externalScriptUrls.length > 0 ? externalScriptUrls : null
      });
    } catch (e) { /* extension context invalidated */ }
  }

  // Listen for re-scan requests
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "REQUEST_RESCAN") {
      runScan();
      sendResponse({ status: "ok" });
    }
    return false;
  });

  // Run scan
  // Auto-scan disabled to prevent performance issues
  // Scan must be triggered manually via popup
  /*
  try {
    runScan();
  } catch (err) {
    console.error("[Nexus] Content scan error:", err);
  }
  */
})();
