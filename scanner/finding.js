/**
 * Finding factory and severity utilities.
 */

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function createFinding({ severity, category, title, description, match, location, context }) {
  return {
    id: "f_" + hashStr(`${category}:${match}:${location}`),
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
  // FNV-1a inspired hash with better distribution than DJB2
  let h1 = 0x811c9dc5 >>> 0;
  let h2 = 0x01000193 >>> 0;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ (c + i), 0x0100019d) >>> 0;
  }
  // Combine both halves into a larger key space to reduce collisions
  // Zero-pad both halves to prevent false collisions (e.g. "a"+"bc" vs "ab"+"c")
  return (h1 >>> 0).toString(16).padStart(8, "0") + (h2 >>> 0).toString(16).padStart(8, "0");
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
