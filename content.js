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
    document.querySelectorAll("script[src]").forEach(el => {
      if (el.src && el.src.startsWith("http")) urls.add(el.src);
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
    if (nextDataEl) {
      try {
        const data = JSON.parse(nextDataEl.textContent);
        const propsStr = JSON.stringify(data.props || {});
        // Scan the props for secrets
        findings.push(...scanWithPatterns(propsStr, SCAN_PATTERNS.apiKeys, "__NEXT_DATA__ props"));
        findings.push(...scanWithPatterns(propsStr, SCAN_PATTERNS.credentials, "__NEXT_DATA__ props"));
        // Check for runtimeConfig
        if (data.runtimeConfig || data.props?.pageProps?.runtimeConfig) {
          findings.push(createFinding({
            severity: "medium", category: "env-var",
            title: "Next.js Runtime Config Exposed",
            description: "Runtime configuration in __NEXT_DATA__ may contain server-side values.",
            match: JSON.stringify(data.runtimeConfig || data.props.pageProps.runtimeConfig).substring(0, 200),
            location: pageUrl
          }));
        }
      } catch (e) { /* not valid JSON */ }
    }
    return findings;
  }

  function scanWindowGlobals() {
    const findings = [];
    const sensitiveGlobals = ["__APP_CONFIG__", "__CONFIG__", "__ENV__", "__RUNTIME_CONFIG__",
      "APP_CONFIG", "CONFIG", "__INITIAL_STATE__", "__PRELOADED_STATE__",
      "__APP_INITIAL_STATE__", "GLOBAL_CONFIG", "window.__config"];
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
      SCAN_PATTERNS.transport
    ];

    // Scan inline scripts only (not full page source - avoids duplicates)
    for (let i = 0; i < inlineScripts.length; i++) {
      const label = `Inline Script #${i + 1}`;
      for (const group of allPatternGroups) {
        allFindings.push(...scanWithPatterns(inlineScripts[i], group, label));
      }
    }

    // Scan page HTML for non-script patterns (comments, meta, hidden inputs are separate)
    // Only scan the HTML body for info-leaks, technology fingerprints, transport issues
    const bodyHtml = document.body ? document.body.innerHTML : "";
    const htmlOnlyGroups = [SCAN_PATTERNS.infoLeaks, SCAN_PATTERNS.technology, SCAN_PATTERNS.transport];
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
    allFindings.push(...scanWindowGlobals());

    // Deduplicate & send
    const uniqueFindings = deduplicateFindings(allFindings);

    try {
      chrome.runtime.sendMessage({
        type: "CONTENT_FINDINGS",
        findings: uniqueFindings,
        url: pageUrl
      });
    } catch (e) { /* extension context invalidated */ }

    // Send external script URLs for background to scan
    if (externalScriptUrls.length > 0) {
      try {
        chrome.runtime.sendMessage({
          type: "SCAN_JS_FILES",
          urls: externalScriptUrls,
          origin: pageOrigin
        });
      } catch (e) { /* extension context invalidated */ }
    }
  }

  // Listen for re-scan requests
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "REQUEST_RESCAN") {
      runScan();
      sendResponse({ status: "ok" });
    }
    return true;
  });

  // Run scan
  try {
    runScan();
  } catch (err) {
    console.error("[Nexus] Content scan error:", err);
  }
})();
