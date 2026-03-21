/**
 * Popup UI - Dashboard, filtering, export, clipboard.
 * Uses Font Awesome icons via CDN.
 */

(function () {
  "use strict";

  let allFindings = [];
  let currentUrl = "";
  let activeSeverityFilter = null;
  let expandedIds = new Set();

  // Category icon map (Font Awesome classes)
  const CATEGORY_ICONS = {
    "api-key": "fa-solid fa-key",
    "credential": "fa-solid fa-lock",
    "info-leak": "fa-solid fa-eye",
    "debug": "fa-solid fa-bug",
    "env-var": "fa-solid fa-terminal",
    "endpoint": "fa-solid fa-route",
    "sourcemap": "fa-solid fa-map",
    "comment": "fa-solid fa-comment",
    "hidden-input": "fa-solid fa-eye-slash",
    "meta-info": "fa-solid fa-tags",
    "security-header": "fa-solid fa-shield-halved",
    "server-info": "fa-solid fa-server",
    "cors": "fa-solid fa-network-wired",
    "cookie": "fa-solid fa-cookie-bite",
    "config-file": "fa-solid fa-file-code",
    "vcs": "fa-brands fa-git-alt",
    "api-docs": "fa-solid fa-book",
    "admin": "fa-solid fa-user-shield",
    "backup": "fa-solid fa-database",
    "cicd": "fa-solid fa-gears",
    "cloud": "fa-solid fa-cloud",
    "standard": "fa-solid fa-file-lines",
    "dom-security": "fa-solid fa-code",
    "technology": "fa-solid fa-microchip",
    "transport": "fa-solid fa-lock-open"
  };

  const SEVERITY_ICONS = {
    critical: "fa-solid fa-skull-crossbones",
    high: "fa-solid fa-triangle-exclamation",
    medium: "fa-solid fa-exclamation-circle",
    low: "fa-solid fa-info-circle",
    info: "fa-solid fa-circle-info"
  };

  // ── DOM Elements ──
  const findingsList = document.getElementById("findings-list");
  const emptyState = document.getElementById("empty-state");
  const scanStatus = document.getElementById("scan-status");
  const targetUrlText = document.getElementById("target-url-text");
  const searchInput = document.getElementById("search-input");
  const categoryFilter = document.getElementById("category-filter");
  const findingTotal = document.getElementById("finding-total");
  const btnRescan = document.getElementById("btn-rescan");
  const btnExportToggle = document.getElementById("btn-export-toggle");
  const exportMenu = document.getElementById("export-menu");
  const btnExportJson = document.getElementById("btn-export-json");
  const btnExportHtml = document.getElementById("btn-export-html");
  const btnStartScan = document.getElementById("btn-start-scan");
  const btnExportCsv = document.getElementById("btn-export-csv");
  const startScanState = document.getElementById("start-scan-state");
  const scanSummaryEl = document.getElementById("scan-summary");
  const scanSummaryText = document.getElementById("scan-summary-text");
  const versionLabel = document.getElementById("version-label");

  const severityCounts = {
    critical: document.getElementById("count-critical"),
    high: document.getElementById("count-high"),
    medium: document.getElementById("count-medium"),
    low: document.getElementById("count-low"),
    info: document.getElementById("count-info")
  };

  // ── Remediation Hints ──
  const REMEDIATION = {
    "api-key": "Rotate the exposed key immediately and restrict its permissions. Move secrets to environment variables or a vault.",
    "credential": "Change the exposed credential. Never hardcode secrets in source code; use a secrets manager.",
    "info-leak": "Remove internal references from public-facing code. Review build pipeline for data leakage.",
    "debug": "Disable debug mode and remove debug statements before deploying to production.",
    "env-var": "Ensure environment variables with sensitive values are not bundled into client-side builds.",
    "endpoint": "Review exposed endpoints for proper authentication and authorization controls.",
    "sourcemap": "Remove source maps from production builds or restrict access via server configuration.",
    "comment": "Remove sensitive HTML comments before deployment. Use build tools to strip comments.",
    "hidden-input": "Ensure hidden inputs do not expose tokens or secrets. Use server-side session management.",
    "meta-info": "Remove sensitive meta tags. Generator tags reveal technology versions to attackers.",
    "security-header": "Configure your web server or CDN to set the missing security headers.",
    "server-info": "Suppress version disclosure headers (Server, X-Powered-By) in your server configuration.",
    "cors": "Restrict Access-Control-Allow-Origin to specific trusted domains. Never use wildcard with credentials.",
    "cookie": "Set Secure, HttpOnly, and SameSite flags on all cookies, especially session cookies.",
    "config-file": "Block access to configuration files via server rules (e.g., nginx location blocks).",
    "vcs": "Remove .git and other VCS directories from the web root. Add server rules to deny access.",
    "api-docs": "Restrict API documentation access to authenticated users or internal networks.",
    "admin": "Protect admin panels with strong authentication, IP allowlisting, or VPN access.",
    "backup": "Remove backup and log files from the web root. Store them in a secure, non-public location.",
    "cicd": "Remove CI/CD configuration files from the web root or restrict access.",
    "cloud": "Remove cloud credential files from the web root immediately. Rotate affected credentials.",
    "dom-security": "Sanitize user-controlled input before using it in DOM manipulation. Use textContent instead of innerHTML.",
    "transport": "Migrate all resources and form actions to HTTPS. Enable HSTS to enforce secure connections.",
    "standard": "Review robots.txt and sitemap for unintended path disclosure."
  };

  // ── Init ──
  async function init() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    // Set version from manifest (single source of truth)
    const manifest = chrome.runtime.getManifest();
    if (versionLabel) versionLabel.textContent = `v${manifest.version}`;

    targetUrlText.textContent = tab.url || "Unknown";

    // Initial state: scan status hidden
    scanStatus.style.display = "none";

    // Load existing findings immediately
    loadFindings(tab.id);

    // Event-driven updates via storage changes (replaces polling)
    const storageKey = `tab_${tab.id}`;
    chrome.storage.session.onChanged.addListener((changes) => {
      if (changes[storageKey]) {
        loadFindings(tab.id);
      }
    });

    // Event listeners
    btnRescan.addEventListener("click", () => rescan(tab.id));
    if (btnStartScan) btnStartScan.addEventListener("click", () => rescan(tab.id));
    btnExportToggle.addEventListener("click", (e) => {
      e.stopPropagation();
      exportMenu.classList.toggle("show");
    });
    document.addEventListener("click", () => exportMenu.classList.remove("show"));
    btnExportJson.addEventListener("click", () => { exportMenu.classList.remove("show"); exportJson(); });
    btnExportHtml.addEventListener("click", () => { exportMenu.classList.remove("show"); exportHtml(); });
    if (btnExportCsv) btnExportCsv.addEventListener("click", () => { exportMenu.classList.remove("show"); exportCsv(); });
    searchInput.addEventListener("input", applyFilters);
    categoryFilter.addEventListener("change", applyFilters);

    // Severity pill click filters
    document.querySelectorAll(".summary-pill").forEach(pill => {
      pill.addEventListener("click", () => {
        const severity = pill.dataset.severity;
        if (activeSeverityFilter === severity) {
          activeSeverityFilter = null;
          pill.classList.remove("active");
        } else {
          document.querySelectorAll(".summary-pill").forEach(p => p.classList.remove("active"));
          activeSeverityFilter = severity;
          pill.classList.add("active");
        }
        applyFilters();
      });
    });

    // Profile panel toggle
    document.getElementById("profile-toggle").addEventListener("click", () => {
      document.getElementById("site-profile").classList.toggle("collapsed");
    });
  }

  function loadFindings(tabId) {
    chrome.runtime.sendMessage({ type: "GET_FINDINGS", tabId }, (response) => {
      if (chrome.runtime.lastError || !response) return;

      const newFindings = response.findings || [];
      const status = response.status || "idle";

      allFindings = newFindings;
      currentUrl = response.url || "";

      if (currentUrl) {
        targetUrlText.textContent = currentUrl;
      }

      updateSummary(response.summary || {});
      updateCategoryFilter();
      renderSiteProfile();
      renderFindings();
      renderScanSummary(response.scanSummary || {}, status);

      // Re-enable rescan button when scan completes
      if (status === "complete" || status === "idle") {
        btnRescan.disabled = false;
        if (btnStartScan) btnStartScan.disabled = false;
        // Safe: only static icon HTML, no user data
        btnRescan.textContent = "";
        const icon = document.createElement("i");
        icon.className = "fa-solid fa-rotate";
        btnRescan.appendChild(icon);
        btnRescan.appendChild(document.createTextNode(" Rescan"));
      }

      // Visibility Logic based on Status & Findings
      if (newFindings.length > 0) {
        if (startScanState) startScanState.style.display = "none";
        emptyState.style.display = "none";
        scanStatus.style.display = (status === "scanning") ? "flex" : "none";
        findingsList.style.display = "block";
      } else {
        findingsList.style.display = "none";
        const profileEl = document.getElementById("site-profile");
        if (profileEl) profileEl.style.display = "none";

        if (status === "scanning") {
          if (startScanState) startScanState.style.display = "none";
          emptyState.style.display = "none";
          scanStatus.style.display = "flex";
        } else if (status === "complete") {
          if (startScanState) startScanState.style.display = "none";
          emptyState.style.display = "flex";
          scanStatus.style.display = "none";
        } else {
          if (startScanState) startScanState.style.display = "flex";
          emptyState.style.display = "none";
          scanStatus.style.display = "none";
        }
      }
    });
  }

  function renderScanSummary(summary, status) {
    if (!scanSummaryEl || !scanSummaryText) return;
    if (status === "idle" && !summary.headersAnalyzed) {
      scanSummaryEl.style.display = "none";
      return;
    }
    const parts = [];
    if (summary.headersAnalyzed) parts.push("Headers");
    if (summary.jsFilesScanned > 0) parts.push(`${summary.jsFilesScanned} JS files`);
    if (summary.pathsProbed > 0) parts.push(`${summary.pathsProbed}/${summary.totalPaths || "?"} paths`);
    if (parts.length === 0) {
      scanSummaryEl.style.display = "none";
      return;
    }
    scanSummaryText.textContent = `Scanned: ${parts.join(" \u00B7 ")}`;
    scanSummaryEl.style.display = "flex";
  }

  function updateSummary(summary) {
    Object.keys(severityCounts).forEach(sev => {
      severityCounts[sev].textContent = summary[sev] || 0;
    });
  }

  function updateCategoryFilter() {
    const categories = [...new Set(allFindings.map(f => f.category))].sort();
    const current = categoryFilter.value;

    categoryFilter.innerHTML = '<option value="all">All Categories</option>';
    categories.forEach(cat => {
      const opt = document.createElement("option");
      opt.value = cat;
      opt.textContent = formatCategory(cat);
      categoryFilter.appendChild(opt);
    });

    if (current && categories.includes(current)) {
      categoryFilter.value = current;
    }
  }

  // ── Site Profile ──

  // Map finding titles to clean display names and profile categories
  const TECH_MAP = {
    // Frameworks & Libraries
    "React": { icon: "fa-brands fa-react", group: "frameworks" },
    "Angular": { icon: "fa-brands fa-angular", group: "frameworks" },
    "Vue.js": { icon: "fa-brands fa-vuejs", group: "frameworks" },
    "Next.js": { icon: "fa-brands fa-react", group: "frameworks" },
    "Nuxt.js": { icon: "fa-brands fa-vuejs", group: "frameworks" },
    "jQuery": { icon: "fa-brands fa-js", group: "frameworks" },
    "Bootstrap": { icon: "fa-brands fa-bootstrap", group: "frameworks" },
    "Ruby on Rails": { icon: "fa-solid fa-gem", group: "frameworks" },
    "Django": { icon: "fa-brands fa-python", group: "frameworks" },
    "Laravel": { icon: "fa-brands fa-laravel", group: "frameworks" },
    "Spring Framework": { icon: "fa-brands fa-java", group: "frameworks" },
    "ASP.NET": { icon: "fa-brands fa-microsoft", group: "frameworks" },
    "Express": { icon: "fa-brands fa-node-js", group: "frameworks" },
    "Svelte": { icon: "fa-solid fa-bolt", group: "frameworks" },
    "Gatsby": { icon: "fa-solid fa-bolt", group: "frameworks" },
    "Remix": { icon: "fa-solid fa-bolt", group: "frameworks" },
    "Tailwind CSS": { icon: "fa-brands fa-css3-alt", group: "frameworks" },
    "PHP": { icon: "fa-brands fa-php", group: "frameworks" },
    "Stripe.js": { icon: "fa-brands fa-stripe", group: "frameworks" },
    // CMS
    "WordPress": { icon: "fa-brands fa-wordpress", group: "cms" },
    "Shopify": { icon: "fa-brands fa-shopify", group: "cms" },
    "Squarespace": { icon: "fa-brands fa-squarespace", group: "cms" },
    "Wix": { icon: "fa-brands fa-wix", group: "cms" },
    "Webflow": { icon: "fa-solid fa-paintbrush", group: "cms" },
    "Ghost": { icon: "fa-solid fa-ghost", group: "cms" },
    "Drupal": { icon: "fa-brands fa-drupal", group: "cms" },
    "Joomla": { icon: "fa-brands fa-joomla", group: "cms" },
    // Server & CDN & Hosting
    "Cloudflare": { icon: "fa-brands fa-cloudflare", group: "server" },
    "Fastly": { icon: "fa-solid fa-bolt", group: "server" },
    "Akamai": { icon: "fa-solid fa-globe", group: "server" },
    "Amazon CloudFront": { icon: "fa-brands fa-aws", group: "server" },
    "Nginx": { icon: "fa-solid fa-server", group: "server" },
    "Apache": { icon: "fa-solid fa-server", group: "server" },
    "LiteSpeed": { icon: "fa-solid fa-server", group: "server" },
    "OpenResty": { icon: "fa-solid fa-server", group: "server" },
    "IIS": { icon: "fa-brands fa-microsoft", group: "server" },
    "Varnish": { icon: "fa-solid fa-bolt", group: "server" },
    "GitHub Pages": { icon: "fa-brands fa-github", group: "server" },
    "Vercel": { icon: "fa-solid fa-triangle-exclamation", group: "server" },
    "Netlify": { icon: "fa-solid fa-globe", group: "server" },
    "Azure": { icon: "fa-brands fa-microsoft", group: "server" },
    "Google Cloud Storage": { icon: "fa-brands fa-google", group: "server" },
    "Fly.io": { icon: "fa-solid fa-plane", group: "server" },
    "Render": { icon: "fa-solid fa-server", group: "server" },
    "Sucuri": { icon: "fa-solid fa-shield-halved", group: "server" },
    // Security
    "HSTS": { icon: "fa-solid fa-lock", group: "server" },
    // Analytics
    "Google Analytics": { icon: "fa-brands fa-google", group: "analytics" },
    "Google Tag Manager": { icon: "fa-brands fa-google", group: "analytics" },
    "Facebook Pixel": { icon: "fa-brands fa-facebook", group: "analytics" },
    "Hotjar": { icon: "fa-solid fa-fire", group: "analytics" },
    "Segment": { icon: "fa-solid fa-chart-pie", group: "analytics" },
    "Intercom": { icon: "fa-solid fa-headset", group: "analytics" },
    "Sentry Error Tracking": { icon: "fa-solid fa-bug", group: "analytics" },
    "PostHog Analytics": { icon: "fa-solid fa-chart-bar", group: "analytics" },
    "Mixpanel": { icon: "fa-solid fa-chart-line", group: "analytics" },
    "Amplitude": { icon: "fa-solid fa-chart-area", group: "analytics" },
    "Heap Analytics": { icon: "fa-solid fa-chart-bar", group: "analytics" },
    // Fonts
    "Google Font API": { icon: "fa-brands fa-google", group: "frameworks" },
    "Adobe Fonts": { icon: "fa-solid fa-font", group: "frameworks" },
    // Other
    "reCAPTCHA": { icon: "fa-brands fa-google", group: "frameworks" },
    "hCaptcha": { icon: "fa-solid fa-robot", group: "frameworks" },
    "PayPal": { icon: "fa-brands fa-paypal", group: "frameworks" }
  };

  function renderSiteProfile() {
    const profileEl = document.getElementById("site-profile");
    const sections = {
      server: { el: document.getElementById("prof-server"), tags: document.getElementById("prof-server-tags"), items: [] },
      frameworks: { el: document.getElementById("prof-frameworks"), tags: document.getElementById("prof-frameworks-tags"), items: [] },
      cms: { el: document.getElementById("prof-cms"), tags: document.getElementById("prof-cms-tags"), items: [] },
      analytics: { el: document.getElementById("prof-analytics"), tags: document.getElementById("prof-analytics-tags"), items: [] },
      security: { el: document.getElementById("prof-security"), tags: document.getElementById("prof-security-tags"), items: [] },
      cookies: { el: document.getElementById("prof-cookies"), tags: document.getElementById("prof-cookies-tags"), items: [] },
      endpoints: { el: document.getElementById("prof-endpoints"), tags: document.getElementById("prof-endpoints-tags"), items: [] },
      env: { el: document.getElementById("prof-env"), tags: document.getElementById("prof-env-tags"), items: [] }
    };

    const seen = new Set();

    for (const f of allFindings) {
      const key = f.title;
      if (seen.has(key)) continue;
      seen.add(key);

      // Technology findings
      if (f.category === "technology") {
        // Try exact match first, then match base name (for versioned titles like "Nginx 1.24")
        const tech = TECH_MAP[f.title] || TECH_MAP[f.title.split(" ")[0]];
        if (tech) {
          const group = tech.group;
          sections[group].items.push({
            label: f.title,
            icon: tech.icon,
            cssClass: `tech-${group === "analytics" ? "analytics" : group === "cms" ? "cms" : group === "server" ? "server" : "framework"}`
          });
        } else {
          // Generic tech
          sections.frameworks.items.push({
            label: f.title,
            icon: "fa-solid fa-puzzle-piece",
            cssClass: "tech-framework"
          });
        }
      }

      // CMS from meta generator
      if (f.category === "technology" && f.title.startsWith("CMS/Framework:")) {
        const name = f.title.replace("CMS/Framework: ", "");
        if (!seen.has("cms:" + name)) {
          seen.add("cms:" + name);
          sections.cms.items.push({
            label: name,
            icon: "fa-solid fa-pencil",
            cssClass: "tech-cms"
          });
        }
      }

      // Server info
      if (f.category === "server-info") {
        const val = f.match.includes(":") ? f.match.split(":").slice(1).join(":").trim() : f.match;
        sections.server.items.push({
          label: val.substring(0, 40),
          icon: "fa-solid fa-server",
          cssClass: "tech-server"
        });
      }

      // Security headers
      if (f.category === "security-header") {
        if (f.title.startsWith("Missing")) {
          const hdr = f.title.replace("Missing ", "");
          sections.security.items.push({
            label: hdr,
            icon: "fa-solid fa-xmark",
            cssClass: f.severity === "high" ? "tech-security-bad" : "tech-security-warn"
          });
        } else if (f.title.startsWith("CSP")) {
          sections.security.items.push({
            label: f.title,
            icon: "fa-solid fa-triangle-exclamation",
            cssClass: "tech-security-warn"
          });
        }
      }

      // CORS
      if (f.category === "cors") {
        sections.security.items.push({
          label: f.title.replace("CORS: ", "CORS "),
          icon: "fa-solid fa-network-wired",
          cssClass: f.severity === "critical" ? "tech-security-bad" : "tech-security-warn"
        });
      }

      // Cookies
      if (f.category === "cookie") {
        sections.cookies.items.push({
          label: f.title.replace("Insecure Cookie: ", ""),
          icon: "fa-solid fa-cookie-bite",
          cssClass: "tech-cookie"
        });
      }

      // Endpoints - dedupe by match value, build full URL
      if (f.category === "endpoint" && !seen.has("ep:" + f.match)) {
        seen.add("ep:" + f.match);
        sections.endpoints.items.push({
          label: f.match,
          icon: "fa-solid fa-link",
          cssClass: "tech-endpoint"
        });
      }

      // Env vars (dedupe names)
      if (f.category === "env-var" && f.match && /^[A-Z_]+$/.test(f.match)) {
        sections.env.items.push({
          label: f.match,
          icon: "fa-solid fa-terminal",
          cssClass: "tech-env"
        });
      }
    }

    // Check for present security headers (positive signals)
    const missingHeaders = new Set(allFindings.filter(f => f.title.startsWith("Missing")).map(f => f.title));
    const goodHeaders = [
      { name: "Content-Security-Policy", title: "Missing Content-Security-Policy" },
      { name: "Strict-Transport-Security", title: "Missing Strict-Transport-Security" },
      { name: "X-Frame-Options", title: "Missing X-Frame-Options" }
    ];
    for (const h of goodHeaders) {
      if (!missingHeaders.has(h.title)) {
        sections.security.items.unshift({
          label: h.name,
          icon: "fa-solid fa-check",
          cssClass: "tech-security-good"
        });
      }
    }

    // Build origin for full endpoint URLs
    let siteOrigin = "";
    try { siteOrigin = currentUrl ? new URL(currentUrl).origin : ""; } catch (e) {}

    // Render sections
    let hasAny = false;
    for (const [key, sec] of Object.entries(sections)) {
      if (sec.items.length > 0) {
        hasAny = true;
        sec.el.style.display = "block";

        if (key === "endpoints") {
          // Endpoints render as vertical list with full URLs
          const countEl = document.getElementById("prof-endpoints-count");
          if (countEl) countEl.textContent = `(${sec.items.length})`;
          sec.tags.innerHTML = sec.items.map(item => {
            const fullUrl = item.label.startsWith("http") ? item.label : siteOrigin + item.label;
            return `<div class="profile-endpoint"><i class="${item.icon}"></i> <span>${escapeHtml(fullUrl)}</span></div>`;
          }).join("");
        } else {
          sec.tags.innerHTML = sec.items.map(item =>
            `<span class="profile-tag ${item.cssClass}" title="${escapeHtml(item.label)}"><i class="${item.icon}"></i> ${escapeHtml(item.label)}</span>`
          ).join("");
        }
      } else {
        sec.el.style.display = "none";
        sec.tags.innerHTML = "";
      }
    }

    profileEl.style.display = hasAny ? "block" : "none";
  }

  function formatCategory(cat) {
    return cat.replace(/[-_]/g, " ").replace(/\b\w/g, c => c.toUpperCase());
  }

  function getCategoryIcon(cat) {
    return CATEGORY_ICONS[cat] || "fa-solid fa-circle-question";
  }

  // ── Filtering ──
  function applyFilters() {
    renderFindings();
  }

  function getFilteredFindings() {
    let filtered = allFindings;

    if (activeSeverityFilter) {
      filtered = filtered.filter(f => f.severity === activeSeverityFilter);
    }

    const cat = categoryFilter.value;
    if (cat !== "all") {
      filtered = filtered.filter(f => f.category === cat);
    }

    const query = searchInput.value.toLowerCase().trim();
    if (query) {
      filtered = filtered.filter(f =>
        f.title.toLowerCase().includes(query) ||
        f.match.toLowerCase().includes(query) ||
        f.description.toLowerCase().includes(query) ||
        f.location.toLowerCase().includes(query) ||
        f.category.toLowerCase().includes(query)
      );
    }

    return filtered;
  }

  // ── Rendering ──
  function renderFindings() {
    const filtered = getFilteredFindings();
    findingsList.innerHTML = "";

    // Group by category
    const grouped = {};
    filtered.forEach(f => {
      if (!grouped[f.category]) grouped[f.category] = [];
      grouped[f.category].push(f);
    });

    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sortedCategories = Object.keys(grouped).sort((a, b) => {
      const aMin = Math.min(...grouped[a].map(f => severityOrder[f.severity]));
      const bMin = Math.min(...grouped[b].map(f => severityOrder[f.severity]));
      return aMin - bMin;
    });

    sortedCategories.forEach(category => {
      const header = document.createElement("div");
      header.className = "category-header";
      header.innerHTML = `<i class="${getCategoryIcon(category)}"></i> ${formatCategory(category)} (${grouped[category].length})`;
      findingsList.appendChild(header);

      grouped[category].forEach(finding => {
        findingsList.appendChild(createFindingCard(finding));
      });
    });

    findingTotal.textContent = `${filtered.length} finding${filtered.length !== 1 ? "s" : ""}`;
  }

  function createFindingCard(finding) {
    const card = document.createElement("div");
    card.className = "finding-card";

    const sevIcon = SEVERITY_ICONS[finding.severity] || "fa-solid fa-circle";
    const catIcon = getCategoryIcon(finding.category);

    card.innerHTML = `
      <div class="finding-header">
        <span class="severity-badge ${finding.severity}"><i class="${sevIcon}"></i> ${finding.severity}</span>
        <span class="finding-title">${escapeHtml(finding.title)}</span>
        <span class="finding-category"><i class="${catIcon}"></i> ${formatCategory(finding.category)}</span>
        <i class="fa-solid fa-chevron-right finding-toggle"></i>
      </div>
      <div class="finding-details">
        <div class="detail-row">
          <span class="detail-label"><i class="fa-solid fa-align-left"></i> Description</span>
          <span class="detail-value">${escapeHtml(finding.description)}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label"><i class="fa-solid fa-crosshairs"></i> Match</span>
          <span class="detail-value match-value">${escapeHtml(finding.match)}</span>
        </div>
        ${finding.context ? `
        <div class="detail-row">
          <span class="detail-label"><i class="fa-solid fa-code"></i> Context</span>
          <span class="detail-value context-value">${escapeHtml(finding.context)}</span>
        </div>
        ` : ""}
        <div class="detail-row">
          <span class="detail-label"><i class="fa-solid fa-location-dot"></i> Location</span>
          <span class="detail-value">${escapeHtml(finding.location)}</span>
        </div>
        ${REMEDIATION[finding.category] ? `
        <div class="detail-row">
          <span class="detail-label"><i class="fa-solid fa-lightbulb"></i> Remediation</span>
          <span class="detail-value remediation-value">${escapeHtml(REMEDIATION[finding.category])}</span>
        </div>
        ` : ""}
        <div class="finding-actions">
          <button class="btn-copy" data-copy="${escapeAttr(finding.match)}" data-label="Copy Match">
            <i class="fa-regular fa-copy"></i> Copy Match
          </button>
          <button class="btn-copy" data-copy="${escapeAttr(JSON.stringify(finding, null, 2))}" data-label="Copy JSON">
            <i class="fa-solid fa-code"></i> Copy JSON
          </button>
        </div>
      </div>
    `;

    // Restore expanded state
    if (expandedIds.has(finding.id)) {
      card.classList.add("expanded");
    }

    // Toggle expand/collapse
    card.querySelector(".finding-header").addEventListener("click", () => {
      card.classList.toggle("expanded");
      if (card.classList.contains("expanded")) {
        expandedIds.add(finding.id);
      } else {
        expandedIds.delete(finding.id);
      }
    });

    // Copy buttons
    card.querySelectorAll(".btn-copy").forEach(btn => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const text = btn.dataset.copy;
        const label = btn.dataset.label;
        navigator.clipboard.writeText(text).then(() => {
          btn.classList.add("copied");
          btn.innerHTML = '<i class="fa-solid fa-check"></i> Copied!';
          setTimeout(() => {
            btn.classList.remove("copied");
            const icon = label === "Copy Match" ? '<i class="fa-regular fa-copy"></i>' : '<i class="fa-solid fa-code"></i>';
            btn.innerHTML = `${icon} ${label}`;
          }, 1500);
        });
      });
    });

    return card;
  }

  // ── Actions ──
  function rescan(tabId) {
    btnRescan.disabled = true;
    // Safe DOM: only static icon, no user data
    btnRescan.textContent = "";
    const spinIcon = document.createElement("i");
    spinIcon.className = "fa-solid fa-spinner fa-spin";
    btnRescan.appendChild(spinIcon);
    btnRescan.appendChild(document.createTextNode(" Scanning..."));

    if (btnStartScan) btnStartScan.disabled = true;
    if (startScanState) startScanState.style.display = "none";
    emptyState.style.display = "none";
    findingsList.style.display = "none";
    scanStatus.style.display = "flex";
    if (scanSummaryEl) scanSummaryEl.style.display = "none";
    expandedIds.clear();

    chrome.runtime.sendMessage({ type: "REQUEST_SCAN", tabId }, () => {
      // Button re-enabled by loadFindings when status becomes "complete"
    });
  }

  function getReportData() {
    return {
      tool: "Nexus Scanner",
      version: chrome.runtime.getManifest().version,
      url: currentUrl,
      scanDate: new Date().toISOString(),
      summary: {
        total: allFindings.length,
        critical: allFindings.filter(f => f.severity === "critical").length,
        high: allFindings.filter(f => f.severity === "high").length,
        medium: allFindings.filter(f => f.severity === "medium").length,
        low: allFindings.filter(f => f.severity === "low").length,
        info: allFindings.filter(f => f.severity === "info").length
      },
      findings: allFindings,
      github: "https://github.com/intelseclab",
      repository: "https://github.com/intelseclab/nexus"
    };
  }

  function getFilePrefix() {
    let hostname = "unknown";
    try { hostname = currentUrl ? new URL(currentUrl).hostname : "unknown"; } catch (e) { /* invalid URL */ }
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-").substring(0, 19);
    return `Nexus-${hostname}-${timestamp}`;
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  function exportJson() {
    const report = getReportData();
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    downloadBlob(blob, `${getFilePrefix()}.json`);
    showToast("JSON report exported");
  }

  function exportCsv() {
    const report = getReportData();
    const headers = ["Severity", "Category", "Title", "Description", "Match", "Location", "Context"];
    const csvEscape = (str) => {
      if (!str) return "";
      const s = String(str).replace(/"/g, '""');
      return s.includes(",") || s.includes('"') || s.includes("\n") ? `"${s}"` : s;
    };
    const rows = [headers.join(",")];
    for (const f of report.findings) {
      rows.push([
        csvEscape(f.severity), csvEscape(f.category), csvEscape(f.title),
        csvEscape(f.description), csvEscape(f.match), csvEscape(f.location),
        csvEscape(f.context)
      ].join(","));
    }
    const blob = new Blob([rows.join("\n")], { type: "text/csv;charset=utf-8" });
    downloadBlob(blob, `${getFilePrefix()}.csv`);
    showToast("CSV report exported");
  }

  function exportHtml() {
    const report = getReportData();
    const html = generateHtmlReport(report);
    const blob = new Blob([html], { type: "text/html" });
    downloadBlob(blob, `${getFilePrefix()}.html`);
    showToast("HTML report exported");
  }

  function generateHtmlReport(report) {
    let hostname = "unknown";
    try { hostname = report.url ? new URL(report.url).hostname : "unknown"; } catch (e) { /* invalid URL */ }
    const scanDate = new Date(report.scanDate);
    const dateStr = scanDate.toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
    const timeStr = scanDate.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });

    // Severity config
    const sev = {
      critical: { border: "#e63946", bg: "rgba(230,57,70,0.06)", accent: "#e63946", text: "#f1a9a0" },
      high:     { border: "#e67e22", bg: "rgba(230,126,34,0.06)", accent: "#e67e22", text: "#f0c27a" },
      medium:   { border: "#c8a92e", bg: "rgba(200,169,46,0.05)", accent: "#c8a92e", text: "#d4c97a" },
      low:      { border: "#5b7fa5", bg: "rgba(91,127,165,0.05)", accent: "#5b7fa5", text: "#8badc4" },
      info:     { border: "#4a5568", bg: "rgba(74,85,104,0.05)", accent: "#4a5568", text: "#8896a7" }
    };

    // Risk score
    const riskScore = report.summary.critical * 10 + report.summary.high * 5 + report.summary.medium * 2 + report.summary.low * 0.5;
    const riskLabel = riskScore >= 30 ? "CRITICAL" : riskScore >= 15 ? "HIGH" : riskScore >= 5 ? "MODERATE" : riskScore > 0 ? "LOW" : "CLEAN";
    const riskColor = riskScore >= 30 ? "#e63946" : riskScore >= 15 ? "#e67e22" : riskScore >= 5 ? "#c8a92e" : riskScore > 0 ? "#5b7fa5" : "#38a169";

    // Group findings
    const grouped = {};
    report.findings.forEach(f => { (grouped[f.category] = grouped[f.category] || []).push(f); });
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sortedCats = Object.keys(grouped).sort((a, b) =>
      Math.min(...grouped[a].map(f => severityOrder[f.severity])) - Math.min(...grouped[b].map(f => severityOrder[f.severity]))
    );

    const profileHtml = buildHtmlProfileSection(report.findings);

    // Build findings table rows
    let findingsHtml = "";
    let findingNum = 1;
    sortedCats.forEach(cat => {
      findingsHtml += `<tr class="cat-row"><td colspan="5">${escapeHtml(formatCategory(cat))} &mdash; ${grouped[cat].length} finding${grouped[cat].length > 1 ? "s" : ""}</td></tr>`;
      grouped[cat].forEach(f => {
        const s = sev[f.severity] || sev.info;
        findingsHtml += `<tr class="finding-row" style="border-left:3px solid ${s.border};">
          <td class="cell-num">${findingNum++}</td>
          <td><span class="sev-pill" style="background:${s.border};color:${f.severity==="medium"||f.severity==="low"?"#000":"#fff"}">${f.severity.toUpperCase()}</span></td>
          <td class="cell-title">${escapeHtml(f.title)}</td>
          <td class="cell-match"><code>${escapeHtml(f.match)}</code></td>
          <td class="cell-loc">${escapeHtml(f.location)}</td>
        </tr>
        <tr class="detail-row"><td></td><td colspan="4">
          <div class="finding-detail">
            <p class="fd-desc">${escapeHtml(f.description)}</p>
            ${f.context ? `<pre class="fd-ctx">${escapeHtml(f.context)}</pre>` : ""}
          </div>
        </td></tr>`;
      });
    });

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Recon Report // ${escapeHtml(hostname)}</title>
<!-- Self-contained: no external resources for privacy -->
<style>
:root {
  --bg-0: #0a0a0f; --bg-1: #101018; --bg-2: #16161f; --bg-3: #1e1e2a;
  --border: #252535; --border-l: #2f2f42;
  --text: #b8bcc8; --text-dim: #6b7084; --text-bright: #e2e4ea;
  --accent: #7c6aef; --accent-dim: rgba(124,106,239,0.1);
  --red: #e63946; --orange: #e67e22; --yellow: #c8a92e; --blue: #5b7fa5; --green: #38a169; --gray: #4a5568;
  --mono: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
  --sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { background:var(--bg-0); color:var(--text); font-family:var(--sans); font-size:13px; line-height:1.6; }

/* ── Top Bar ── */
.topbar { background:var(--bg-1); border-bottom:1px solid var(--border); padding:12px 0; }
.topbar-inner { max-width:1100px; margin:0 auto; padding:0 32px; display:flex; align-items:center; justify-content:space-between; }
.topbar-brand { display:flex; align-items:center; gap:8px; font-family:var(--mono); font-size:13px; font-weight:700; color:var(--accent); letter-spacing:1px; }
.topbar-brand i { font-size:15px; }
.topbar-label { font-size:10px; color:var(--text-dim); text-transform:uppercase; letter-spacing:2px; font-weight:600; }

/* ── Hero ── */
.hero { background:var(--bg-1); border-bottom:1px solid var(--border); padding:40px 0 36px; }
.hero-inner { max-width:1100px; margin:0 auto; padding:0 32px; display:flex; align-items:flex-start; justify-content:space-between; gap:40px; }
.hero-left { flex:1; }
.hero-label { font-size:10px; color:var(--accent); text-transform:uppercase; letter-spacing:3px; font-weight:700; font-family:var(--mono); margin-bottom:8px; }
.hero-target { font-size:22px; font-weight:700; color:var(--text-bright); font-family:var(--mono); word-break:break-all; margin-bottom:16px; }
.hero-meta { display:flex; gap:24px; flex-wrap:wrap; }
.hero-meta-item { font-size:11px; color:var(--text-dim); display:flex; align-items:center; gap:5px; }
.hero-meta-item span { color:var(--text); }
.hero-right { text-align:center; min-width:140px; }
.risk-ring { width:100px; height:100px; border-radius:50%; border:4px solid ${riskColor}; display:flex; flex-direction:column; align-items:center; justify-content:center; margin:0 auto 8px; background:rgba(0,0,0,0.3); }
.risk-score { font-size:24px; font-weight:700; color:${riskColor}; font-family:var(--mono); }
.risk-label-sm { font-size:8px; color:var(--text-dim); text-transform:uppercase; letter-spacing:1.5px; }
.risk-label { font-size:11px; font-weight:700; color:${riskColor}; font-family:var(--mono); letter-spacing:2px; }

/* ── Stats Row ── */
.stats { background:var(--bg-2); border-bottom:1px solid var(--border); padding:16px 0; }
.stats-inner { max-width:1100px; margin:0 auto; padding:0 32px; display:flex; gap:2px; }
.stat-box { flex:1; text-align:center; padding:14px 8px; background:var(--bg-1); border:1px solid var(--border); }
.stat-box:first-child { border-radius:6px 0 0 6px; }
.stat-box:last-child { border-radius:0 6px 6px 0; }
.stat-num { font-size:22px; font-weight:700; font-family:var(--mono); }
.stat-label { font-size:9px; text-transform:uppercase; letter-spacing:1.5px; font-weight:600; margin-top:2px; }
.stat-crit .stat-num { color:var(--red); } .stat-crit .stat-label { color:var(--red); }
.stat-high .stat-num { color:var(--orange); } .stat-high .stat-label { color:var(--orange); }
.stat-med .stat-num { color:var(--yellow); } .stat-med .stat-label { color:var(--yellow); }
.stat-low .stat-num { color:var(--blue); } .stat-low .stat-label { color:var(--blue); }
.stat-info .stat-num { color:var(--gray); } .stat-info .stat-label { color:var(--gray); }
.stat-total .stat-num { color:var(--accent); } .stat-total .stat-label { color:var(--accent); }

/* ── Profile ── */
.profile { background:var(--bg-1); border-bottom:1px solid var(--border); }
.profile-inner { max-width:1100px; margin:0 auto; padding:20px 32px; }
.profile-title { font-size:10px; color:var(--accent); text-transform:uppercase; letter-spacing:3px; font-weight:700; font-family:var(--mono); margin-bottom:14px; display:flex; align-items:center; gap:6px; }
.profile-row { margin-bottom:10px; }
.profile-row-title { font-size:10px; color:var(--text-dim); text-transform:uppercase; letter-spacing:1px; font-weight:600; margin-bottom:5px; }
.profile-row-tags { display:flex; flex-wrap:wrap; gap:5px; }
.ptag { padding:3px 9px; border-radius:3px; font-size:10px; font-family:var(--mono); font-weight:500; border:1px solid; }
.ptag.t-blue { background:rgba(91,127,165,0.08); color:#8badc4; border-color:rgba(91,127,165,0.2); }
.ptag.t-green { background:rgba(56,161,105,0.08); color:#68d391; border-color:rgba(56,161,105,0.2); }
.ptag.t-gray { background:rgba(74,85,104,0.08); color:#8896a7; border-color:rgba(74,85,104,0.2); }
.ptag.t-yellow { background:rgba(200,169,46,0.08); color:#d4c97a; border-color:rgba(200,169,46,0.2); }
.ptag.t-red { background:rgba(230,57,70,0.08); color:#f1a9a0; border-color:rgba(230,57,70,0.2); }
.ptag.t-orange { background:rgba(230,126,34,0.08); color:#f0c27a; border-color:rgba(230,126,34,0.2); }
.ptag.t-purple { background:rgba(124,106,239,0.08); color:#a99cf0; border-color:rgba(124,106,239,0.2); }

/* ── Findings Table ── */
.findings { max-width:1100px; margin:0 auto; padding:24px 32px; }
.findings-label { font-size:10px; color:var(--accent); text-transform:uppercase; letter-spacing:3px; font-weight:700; font-family:var(--mono); margin-bottom:14px; display:flex; align-items:center; gap:6px; }
table { width:100%; border-collapse:collapse; font-size:12px; }
th { text-align:left; padding:8px 10px; font-size:9px; text-transform:uppercase; letter-spacing:1.5px; color:var(--text-dim); font-weight:600; border-bottom:2px solid var(--border); background:var(--bg-2); }
.cat-row td { padding:10px 10px 6px; font-size:11px; font-weight:700; color:var(--accent); font-family:var(--mono); letter-spacing:0.5px; border-bottom:1px solid var(--border); background:var(--bg-2); }
.finding-row td { padding:8px 10px; border-bottom:none; vertical-align:top; background:var(--bg-1); }
.finding-row:hover td { background:var(--bg-2); }
.cell-num { width:32px; color:var(--text-dim); font-family:var(--mono); font-size:10px; }
.sev-pill { display:inline-block; padding:1px 7px; border-radius:2px; font-size:9px; font-weight:700; font-family:var(--mono); letter-spacing:0.8px; white-space:nowrap; }
.cell-title { font-weight:500; color:var(--text-bright); max-width:280px; }
.cell-match { font-family:var(--mono); font-size:11px; color:var(--red); max-width:260px; word-break:break-all; }
.cell-match code { background:rgba(230,57,70,0.06); padding:1px 5px; border-radius:2px; }
.cell-loc { font-size:10px; color:var(--text-dim); max-width:200px; word-break:break-all; }
.detail-row td { padding:0 10px 10px; border-bottom:1px solid var(--border); background:var(--bg-1); }
.finding-detail { padding:6px 0 2px; }
.fd-desc { font-size:11px; color:var(--text-dim); margin-bottom:4px; }
.fd-ctx { font-size:10px; font-family:var(--mono); color:var(--text-dim); background:var(--bg-0); border:1px solid var(--border); padding:6px 10px; border-radius:3px; overflow-x:auto; white-space:pre-wrap; max-height:80px; overflow-y:auto; }

/* ── Footer ── */
.rpt-footer { max-width:1100px; margin:0 auto; padding:20px 32px; border-top:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; }
.rpt-footer-left { font-size:10px; color:var(--text-dim); font-family:var(--mono); }
.rpt-footer-center { font-size:10px; }
.rpt-footer-center a:hover { text-decoration:underline !important; }
.rpt-footer-right { font-size:10px; color:var(--text-dim); }

/* ── Print ── */
@media print {
  body { background:#fff; color:#1a1a1a; font-size:11px; }
  .topbar, .hero, .stats, .profile, .findings, .rpt-footer { background:#fff; }
  .topbar { display:none; }
  .hero-target { color:#000; }
  .risk-ring { border-color:#333; }
  .stat-box { border-color:#ddd; }
  table { font-size:10px; }
  th { background:#f5f5f5; border-color:#ddd; }
  .cat-row td { background:#f5f5f5; border-color:#ddd; color:#333; }
  .finding-row td, .detail-row td { background:#fff; border-color:#eee; }
  .fd-ctx { background:#f9f9f9; border-color:#ddd; }
  .finding-row { break-inside:avoid; }
}
</style>
</head>
<body>

<div class="topbar">
  <div class="topbar-inner">
    <div class="topbar-brand">\u25C9 Nexus</div>
    <div class="topbar-label">Reconnaissance Report</div>
  </div>
</div>

<div class="hero">
  <div class="hero-inner">
    <div class="hero-left">
      <div class="hero-label">Target</div>
      <div class="hero-target">${escapeHtml(report.url)}</div>
      <div class="hero-meta">
        <div class="hero-meta-item">\u23F1 <span>${dateStr} ${timeStr}</span></div>
        <div class="hero-meta-item"># <span>${report.summary.total} findings</span></div>
        <div class="hero-meta-item">\u2387 <span>v${report.version}</span></div>
        <div class="hero-meta-item">\u25CE <span>Reconnaissance scan</span></div>
      </div>
    </div>
    <div class="hero-right">
      <div class="risk-ring">
        <div class="risk-score">${Math.round(riskScore)}</div>
        <div class="risk-label-sm">Risk Score</div>
      </div>
      <div class="risk-label">${riskLabel}</div>
    </div>
  </div>
</div>

<div class="stats">
  <div class="stats-inner">
    <div class="stat-box stat-total"><div class="stat-num">${report.summary.total}</div><div class="stat-label">Total</div></div>
    <div class="stat-box stat-crit"><div class="stat-num">${report.summary.critical}</div><div class="stat-label">Critical</div></div>
    <div class="stat-box stat-high"><div class="stat-num">${report.summary.high}</div><div class="stat-label">High</div></div>
    <div class="stat-box stat-med"><div class="stat-num">${report.summary.medium}</div><div class="stat-label">Medium</div></div>
    <div class="stat-box stat-low"><div class="stat-num">${report.summary.low}</div><div class="stat-label">Low</div></div>
    <div class="stat-box stat-info"><div class="stat-num">${report.summary.info}</div><div class="stat-label">Info</div></div>
  </div>
</div>

${profileHtml ? `<div class="profile"><div class="profile-inner">
  <div class="profile-title">\u2299 Reconnaissance Profile</div>
  ${profileHtml}
</div></div>` : ""}

<div class="findings">
  <div class="findings-label">\u2611 Detailed Findings</div>
  <table>
    <thead><tr><th>#</th><th>Sev</th><th>Finding</th><th>Evidence</th><th>Source</th></tr></thead>
    <tbody>${findingsHtml}</tbody>
  </table>
</div>

<div class="rpt-footer">
  <div class="rpt-footer-left">Nexus // ${escapeHtml(hostname)} // ${dateStr}</div>
  <div class="rpt-footer-center"><a href="https://github.com/intelseclab/nexus" style="color:var(--accent);text-decoration:none;font-family:var(--mono);font-size:10px;">\u2605 Star on GitHub</a> &middot; <a href="https://github.com/intelseclab" style="color:var(--text-dim);text-decoration:none;font-size:10px;">Follow @intelseclab</a></div>
  <div class="rpt-footer-right">Reconnaissance scan &mdash; no active exploitation performed</div>
</div>

</body>
</html>`;
  }

  function buildHtmlProfileSection(findings) {
    const groups = {
      "Server & Infrastructure": { items: [], color: "t-gray" },
      "Frameworks & Libraries": { items: [], color: "t-blue" },
      "CMS & Platform": { items: [], color: "t-green" },
      "Analytics & Tracking": { items: [], color: "t-yellow" },
      "Security Posture": { items: [], color: "t-green" },
      "Cookies": { items: [], color: "t-orange" },
      "API Endpoints": { items: [], color: "t-purple" },
      "Environment Variables": { items: [], color: "t-gray" }
    };

    const seen = new Set();
    const analyticsNames = ["Google Analytics", "Google Tag Manager", "Facebook Pixel", "Hotjar", "Segment", "Intercom", "Sentry Error Tracking", "PostHog Analytics", "Mixpanel", "Amplitude", "Heap Analytics"];
    const cmsNames = ["WordPress", "Shopify", "Squarespace", "Wix", "Webflow", "Ghost", "Drupal", "Joomla"];
    const serverNames = ["Cloudflare", "Fastly", "Akamai", "Amazon CloudFront", "Nginx", "Apache", "LiteSpeed", "OpenResty", "IIS", "Varnish", "GitHub Pages", "Vercel", "Netlify", "Azure", "Google Cloud Storage", "Fly.io", "Render", "Sucuri", "HSTS"];

    for (const f of findings) {
      if (seen.has(f.title)) continue;
      seen.add(f.title);

      if (f.category === "technology") {
        // Match base name for versioned titles like "Nginx 1.24"
        const baseName = f.title.split(" ")[0];
        if (analyticsNames.includes(f.title) || analyticsNames.includes(baseName)) {
          groups["Analytics & Tracking"].items.push({ label: f.title, color: "t-yellow" });
        } else if (cmsNames.includes(f.title) || cmsNames.includes(baseName)) {
          groups["CMS & Platform"].items.push({ label: f.title, color: "t-green" });
        } else if (serverNames.includes(f.title) || serverNames.includes(baseName)) {
          groups["Server & Infrastructure"].items.push({ label: f.title, color: "t-gray" });
        } else if (f.title.startsWith("CMS/Framework:")) {
          groups["CMS & Platform"].items.push({ label: f.title.replace("CMS/Framework: ", ""), color: "t-green" });
        } else {
          groups["Frameworks & Libraries"].items.push({ label: f.title, color: "t-blue" });
        }
      }
      if (f.category === "server-info") {
        const val = f.match.includes(":") ? f.match.split(":").slice(1).join(":").trim() : f.match;
        groups["Server & Infrastructure"].items.push({ label: val.substring(0, 50), color: "t-gray" });
      }
      if (f.category === "security-header" && f.title.startsWith("Missing")) {
        groups["Security Posture"].items.push({ label: f.title.replace("Missing ", ""), color: f.severity === "high" ? "t-red" : "t-orange" });
      }
      if (f.category === "cors") {
        groups["Security Posture"].items.push({ label: f.title, color: f.severity === "critical" ? "t-red" : "t-orange" });
      }
      if (f.category === "cookie") {
        groups["Cookies"].items.push({ label: f.title.replace("Insecure Cookie: ", ""), color: "t-orange" });
      }
      if (f.category === "endpoint" && !seen.has("ep:" + f.match)) {
        seen.add("ep:" + f.match);
        groups["API Endpoints"].items.push({ label: f.match, color: "t-purple", isEndpoint: true });
      }
      if (f.category === "env-var" && /^[A-Z_]+$/.test(f.match)) {
        groups["Environment Variables"].items.push({ label: f.match, color: "t-gray" });
      }
    }

    // Check for present headers (positive)
    const missingTitles = new Set(findings.filter(f => f.title.startsWith("Missing")).map(f => f.title));
    for (const h of ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options"]) {
      if (!missingTitles.has("Missing " + h)) {
        groups["Security Posture"].items.unshift({ label: h + " \u2713", color: "t-green" });
      }
    }

    // Build origin for full URLs
    let reportOrigin = "";
    try { reportOrigin = findings.length > 0 && findings[0].location ? new URL(findings[0].location).origin : ""; } catch (e) {}

    let html = "";
    let hasContent = false;
    for (const [title, group] of Object.entries(groups)) {
      if (group.items.length === 0) continue;
      hasContent = true;

      let tagsHtml;
      if (title === "API Endpoints") {
        // Vertical list with full domain URLs
        tagsHtml = `<div style="font-family: SFMono-Regular, Consolas, monospace; font-size: 11px; color: #b4b0f0;">
          ${group.items.map(i => {
            const fullUrl = i.label.startsWith("http") ? i.label : reportOrigin + i.label;
            return `<div style="padding: 3px 0; border-bottom: 1px solid rgba(136,132,216,0.1);">${escapeHtml(fullUrl)}</div>`;
          }).join("")}
        </div>`;
      } else {
        tagsHtml = `<div class="profile-row-tags">
          ${group.items.map(i => `<span class="ptag ${i.color}">${escapeHtml(i.label)}</span>`).join("")}
        </div>`;
      }

      html += `<div class="profile-row">
        <div class="profile-row-title">${title}</div>
        ${tagsHtml}
      </div>`;
    }

    if (!hasContent) return "";
    return html;
  }

  function showToast(message) {
    let toast = document.querySelector(".toast");
    if (!toast) {
      toast = document.createElement("div");
      toast.className = "toast";
      document.body.appendChild(toast);
    }
    toast.textContent = "";
    const icon = document.createElement("i");
    icon.className = "fa-solid fa-check-circle";
    toast.appendChild(icon);
    toast.appendChild(document.createTextNode(" " + message));
    toast.classList.add("show");
    setTimeout(() => toast.classList.remove("show"), 2000);
  }

  // ── Utilities ──
  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  function escapeAttr(str) {
    return str.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/'/g, "&#39;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  // ── Start ──
  init();
})();
