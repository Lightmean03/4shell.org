// Validates data/vulns.json. Run: node scripts/validate.mjs
import { readFileSync } from "node:fs";

const data = JSON.parse(readFileSync(new URL("../data/vulns.json", import.meta.url), "utf8"));
const errors = [];
const err = (where, msg) => errors.push(`${where}: ${msg}`);

const isDate = (d) => /^\d{4}-\d{2}-\d{2}$/.test(d);
const isHttps = (u) => typeof u === "string" && u.startsWith("https://");
const CVE = /^CVE-\d{4}-\d{4,}$/;
const POC_TYPES = new Set(["exploit", "lab", "scanner"]);
const SEVERITIES = new Set(["Critical", "High", "Medium", "Low"]);
const IMPACT_LEVELS = new Set(["massive", "major", "moderate", "limited", "none-yet"]);
const ECOSYSTEMS = new Set([
  "Java", "JavaScript", "PHP", "Ruby", "Python", "Web server", "CMS", "Microsoft",
  "Linux/Unix", "Network/VPN", "Media server", "RMM/IT", "AI/ML", "Other",
]);

if (!isDate(data.updated)) err("root", "`updated` must be YYYY-MM-DD");
if (!Array.isArray(data.vulns)) err("root", "`vulns` must be an array");

const slugs = new Set();
for (const v of data.vulns || []) {
  const w = v.slug || v.name || "(unnamed)";
  for (const k of ["slug", "name", "family", "product", "summary"]) if (!v[k]) err(w, `missing \`${k}\``);
  if (!/^[a-z0-9-]+$/.test(v.slug || "")) err(w, "slug must be lowercase letters, digits, dashes");
  if (slugs.has(v.slug)) err(w, "duplicate slug");
  slugs.add(v.slug);
  if (!["4shell", "2shell", "shell-family"].includes(v.family)) err(w, "family must be 4shell, 2shell or shell-family");
  if (!ECOSYSTEMS.has(v.ecosystem)) err(w, `ecosystem must be one of: ${[...ECOSYSTEMS].join(", ")}`);
  if (v.real_world) {
    const rw = v.real_world;
    if (!IMPACT_LEVELS.has(rw.level)) err(w, `real_world.level must be one of ${[...IMPACT_LEVELS]}`);
    if (!rw.headline) err(w, "real_world.headline missing");
    for (const ev of rw.events || []) {
      if (!/^\d{4}-\d{2}(-\d{2})?$/.test(ev.date || "")) err(w, `real_world event date must be YYYY-MM or YYYY-MM-DD: ${ev.date}`);
      if (!ev.text) err(w, "real_world event missing text");
      if (ev.url && !isHttps(ev.url)) err(w, `real_world event url must be https: ${ev.url}`);
    }
  }
  if (v.disclosed != null && !isDate(v.disclosed)) err(w, "disclosed must be YYYY-MM-DD or null");
  if (!Array.isArray(v.cves) || !v.cves.length) err(w, "needs at least one CVE");
  for (const c of v.cves || []) {
    if (!CVE.test(c.id || "")) err(w, `bad CVE id ${c.id}`);
    if (c.nvd && !isHttps(c.nvd)) err(w, `${c.id} nvd must be https`);
    if (c.cvss != null && (typeof c.cvss !== "number" || c.cvss < 0 || c.cvss > 10)) err(w, `${c.id} cvss out of range`);
    if (c.severity != null && !SEVERITIES.has(c.severity)) err(w, `${c.id} severity must be one of ${[...SEVERITIES]}`);
  }
  for (const group of ["official", "writeups", "pocs"]) {
    for (const l of v[group] || []) {
      if (!l.title) err(w, `${group} entry missing title`);
      if (!isHttps(l.url)) err(w, `${group} url must be https: ${l.url}`);
    }
  }
  for (const p of v.pocs || []) if (!POC_TYPES.has(p.type)) err(w, `poc type must be exploit|lab|scanner: ${p.url}`);
}

if (errors.length) {
  console.error(errors.map((e) => "✗ " + e).join("\n"));
  process.exit(1);
}
console.log(`✓ ${data.vulns.length} entries valid`);
