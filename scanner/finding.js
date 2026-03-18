/**
 * Finding factory and severity utilities.
 */

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function createFinding({ severity, category, title, description, match, location, context }) {
  return {
    id: "f_" + Math.abs(hashStr(`${category}:${match}:${location}`)).toString(36),
    severity: severity || "info",
    category: category || "unknown",
    title: title || "Unknown Finding",
    description: description || "",
    match: truncate(match, 200),
    location: location || "",
    context: truncate(context || "", 300),
    timestamp: Date.now()
  };
}

function hashStr(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return hash;
}

function truncate(str, max) {
  if (!str) return "";
  return str.length <= max ? str : str.substring(0, max) + "...";
}

function deduplicateFindings(findings) {
  const seen = new Set();
  return findings.filter(f => {
    // Technology findings: dedupe by title (e.g. "Cloudflare" from headers and DOM are the same)
    // Other findings: dedupe by category + match
    const key = f.category === "technology" ? `technology:${f.title}` : `${f.category}:${f.match}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function sortFindings(findings) {
  return findings.sort((a, b) => (SEVERITY_ORDER[a.severity] || 4) - (SEVERITY_ORDER[b.severity] || 4));
}

function getSeverityCounts(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    if (counts[f.severity] !== undefined) counts[f.severity]++;
  }
  return counts;
}

if (typeof globalThis !== "undefined") {
  globalThis.createFinding = createFinding;
  globalThis.deduplicateFindings = deduplicateFindings;
  globalThis.sortFindings = sortFindings;
  globalThis.getSeverityCounts = getSeverityCounts;
  globalThis.SEVERITY_ORDER = SEVERITY_ORDER;
}
