import "./style.css";
import data from "../data/vulns.json";

const IMPACT = {
  massive: { rank: 5, label: "Massive", desc: "internet-wide mass exploitation and major breaches" },
  major: { rank: 4, label: "Major", desc: "widespread exploitation with many victims" },
  moderate: { rank: 3, label: "Moderate", desc: "confirmed exploitation at limited scale" },
  limited: { rank: 2, label: "Limited", desc: "exploit attempts or PoCs, few or no confirmed compromises" },
  "none-yet": { rank: 1, label: "None yet", desc: "no known exploitation so far" },
};
const FAMILY_LABEL = { "4shell": "4SHELL", "2shell": "2SHELL", "shell-family": "RELATED" };
const TOGGLES = {
  exploited: (v) => v.exploited_in_wild === true,
  kev: (v) => v.kev?.listed === true,
  critical: (v) => maxCvss(v)?.severity === "Critical",
  ransomware: (v) => v.real_world?.ransomware === true,
};

const $ = (id) => document.getElementById(id);
const els = {
  list: $("list"), search: $("search"), sort: $("sort"), ecosystem: $("ecosystem"), year: $("year"),
  stats: $("stats"), count: $("count"), clear: $("clear"), impactChips: $("impact-chips"),
  svg: $("timeline-svg"), tip: $("tip"), box: $("timeline-box"), legend: $("legend"), toast: $("toast"),
};

const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const safeUrl = (u) => (/^https:\/\//i.test(u || "") ? esc(u) : "#");
const fmtDate = (d, opts = { year: "numeric", month: "short", day: "numeric" }) => {
  if (!d) return "—";
  const full = d.length === 7 ? d + "-01" : d;
  const dt = new Date(full + "T00:00:00Z");
  if (isNaN(dt)) return esc(d);
  return dt.toLocaleDateString("en-US", { ...(d.length === 7 ? { year: "numeric", month: "short" } : opts), timeZone: "UTC" });
};
const sevClass = (sev) => (sev ? "sev-" + sev.toLowerCase() : "");
const maxCvss = (v) =>
  (v.cves || []).filter((c) => typeof c.cvss === "number").sort((a, b) => b.cvss - a.cvss)[0];
const impactRank = (v) => IMPACT[v.real_world?.level]?.rank ?? 0;
const yearOf = (v) => (v.disclosed || "").slice(0, 4);

const vulns = data.vulns;
const bySlug = Object.fromEntries(vulns.map((v) => [v.slug, v]));

// ---------- state (mirrored in the query string) ----------
const state = { q: "", sort: "newest", ecosystem: "", year: "", toggles: new Set(), impacts: new Set(), related: true };

const readUrl = () => {
  const p = new URLSearchParams(location.search);
  state.q = p.get("q") || "";
  state.sort = p.get("sort") || "newest";
  state.ecosystem = p.get("eco") || "";
  state.year = p.get("year") || "";
  state.toggles = new Set((p.get("only") || "").split(",").filter((t) => t in TOGGLES));
  state.impacts = new Set((p.get("impact") || "").split(",").filter((t) => t in IMPACT));
  state.related = p.get("related") !== "0";
};
const writeUrl = () => {
  const p = new URLSearchParams();
  if (state.q) p.set("q", state.q);
  if (state.sort !== "newest") p.set("sort", state.sort);
  if (state.ecosystem) p.set("eco", state.ecosystem);
  if (state.year) p.set("year", state.year);
  if (state.toggles.size) p.set("only", [...state.toggles].join(","));
  if (state.impacts.size) p.set("impact", [...state.impacts].join(","));
  if (!state.related) p.set("related", "0");
  const qs = p.toString();
  history.replaceState(null, "", (qs ? "?" + qs : location.pathname) + location.hash);
};
const hasFilters = () =>
  !!(state.q || state.ecosystem || state.year || state.toggles.size || state.impacts.size || !state.related);

const matches = (v) => {
  if (!state.related && v.family === "shell-family") return false;
  if (state.ecosystem && v.ecosystem !== state.ecosystem) return false;
  if (state.year && yearOf(v) !== state.year) return false;
  for (const t of state.toggles) if (!TOGGLES[t](v)) return false;
  if (state.impacts.size && !state.impacts.has(v.real_world?.level)) return false;
  if (state.q) {
    const hay = [
      v.name, ...(v.aliases || []), v.product, v.vendor, v.ecosystem, v.summary, v.discoverer,
      ...(v.cves || []).map((c) => c.id), ...(v.real_world?.actors || []),
    ].join(" ").toLowerCase();
    if (!state.q.toLowerCase().split(/\s+/).every((t) => hay.includes(t))) return false;
  }
  return true;
};

const SORTS = {
  newest: (a, b) => (b.disclosed || "").localeCompare(a.disclosed || ""),
  oldest: (a, b) => (a.disclosed || "").localeCompare(b.disclosed || ""),
  impact: (a, b) => impactRank(b) - impactRank(a) || SORTS.newest(a, b),
  cvss: (a, b) => (maxCvss(b)?.cvss ?? 0) - (maxCvss(a)?.cvss ?? 0) || SORTS.newest(a, b),
  name: (a, b) => a.name.localeCompare(b.name),
};

// ---------- small UI helpers ----------
let toastTimer;
const toast = (msg) => {
  els.toast.textContent = msg;
  els.toast.hidden = false;
  els.toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    els.toast.classList.remove("show");
    setTimeout(() => (els.toast.hidden = true), 200);
  }, 1600);
};
const copy = async (text, label) => {
  try {
    await navigator.clipboard.writeText(text);
    toast(`Copied ${label}`);
  } catch {
    toast("Couldn't copy");
  }
};

const impactMeter = (v) => {
  const lvl = v.real_world?.level;
  const rank = IMPACT[lvl]?.rank ?? 0;
  if (!rank) return "";
  return `<span class="meter impact-${lvl}" title="Real-world impact: ${IMPACT[lvl].label}">
    ${[1, 2, 3, 4, 5].map((i) => `<i class="${i <= rank ? "on" : ""}"></i>`).join("")}
    <b>${IMPACT[lvl].label}</b></span>`;
};

const linkList = (items, render) =>
  items?.length ? `<ul class="links">${items.map(render).join("")}</ul>` : `<p class="dim">None listed yet.</p>`;

// ---------- card rendering ----------
const renderOverview = (v) => `
  <p class="summary">${esc(v.summary)}</p>
  <dl class="facts">
    ${v.vendor ? `<dt>vendor</dt><dd>${esc(v.vendor)}</dd>` : ""}
    ${v.discoverer ? `<dt>found by</dt><dd>${esc(v.discoverer)}</dd>` : ""}
    ${v.affected ? `<dt>affected</dt><dd>${esc(v.affected)}</dd>` : ""}
    ${v.fixed ? `<dt>fixed in</dt><dd>${esc(v.fixed)}</dd>` : ""}
    ${v.mitigation ? `<dt>mitigation</dt><dd>${esc(v.mitigation)}</dd>` : ""}
    ${v.kev?.listed ? `<dt>KEV added</dt><dd>${fmtDate(v.kev.date_added)}</dd>` : ""}
  </dl>`;

const renderImpact = (v) => {
  const rw = v.real_world;
  if (!rw) return `<p class="dim">Real-world impact hasn't been researched for this entry yet.</p>`;
  return `
  <div class="impact-head impact-${esc(rw.level)}">
    ${impactMeter(v)}
    <p class="headline">${esc(rw.headline)}</p>
  </div>
  <div class="impact-facts">
    ${rw.exposure ? `<div><span class="k">exposure</span><span>${esc(rw.exposure)}</span></div>` : ""}
    ${rw.actors?.length ? `<div><span class="k">threat actors</span><span class="actors">${rw.actors.map((a) => `<button class="actor" data-actor="${esc(a)}" title="Search for ${esc(a)}">${esc(a)}</button>`).join("")}</span></div>` : ""}
    ${rw.ransomware != null ? `<div><span class="k">ransomware</span><span>${rw.ransomware ? "Yes, used by ransomware operators" : "No known ransomware use"}</span></div>` : ""}
  </div>
  ${rw.events?.length ? `<ol class="events">${rw.events
    .map((e) => `<li><time>${fmtDate(e.date)}</time><span>${esc(e.text)}${e.url ? ` <a href="${safeUrl(e.url)}" target="_blank" rel="noopener" class="src">source ↗</a>` : ""}</span></li>`)
    .join("")}</ol>` : ""}`;
};

const renderCves = (v) => `
  <table class="cves">
    <thead><tr><th>CVE</th><th>CVSS</th><th>Description</th></tr></thead>
    <tbody>${(v.cves || []).map((c) => `<tr>
      <td><a href="${safeUrl(c.nvd)}" target="_blank" rel="noopener">${esc(c.id)}</a>
        <button class="icon-btn" data-copy="${esc(c.id)}" title="Copy ${esc(c.id)}">⧉</button></td>
      <td class="cvss ${sevClass(c.severity)}">${c.cvss != null ? `${esc(c.cvss)}${c.cvss_version ? ` <span class="dim">v${esc(c.cvss_version)}</span>` : ""}` : "—"}</td>
      <td>${esc(c.note)}</td></tr>`).join("")}</tbody>
  </table>`;

const renderLinks = (v) => {
  const official = [
    ...(v.cves || []).filter((c) => c.nvd).map((c) => ({ title: `NIST NVD — ${c.id}`, url: c.nvd })),
    ...(v.kev?.listed ? [{ title: "CISA Known Exploited Vulnerabilities", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" }] : []),
    ...(v.official || []),
  ];
  const a = (l) => `<li><a href="${safeUrl(l.url)}" target="_blank" rel="noopener">${esc(l.title)}</a></li>`;
  return `<div class="links-grid">
    <div><h4>Official</h4>${linkList(official, a)}</div>
    <div><h4>Write-ups</h4>${linkList(v.writeups, a)}</div>
    <div><h4>PoCs &amp; tools</h4>${linkList(v.pocs, (p) => `<li><span class="ptype ptype-${esc(p.type)}">${esc(p.type)}</span><a href="${safeUrl(p.url)}" target="_blank" rel="noopener nofollow">${esc(p.title)}</a>${p.stars ? ` <span class="stars">★ ${esc(p.stars)}</span>` : ""}${p.note ? `<span class="pnote">${esc(p.note)}</span>` : ""}</li>`)}
    ${v.pocs?.length ? `<p class="poc-warn">⚠ Unaudited third-party code. Lab use only.</p>` : ""}</div>
  </div>`;
};

const TABS = [
  ["overview", "Overview", renderOverview],
  ["impact", "Real-world impact", renderImpact],
  ["cves", "CVEs", renderCves],
  ["links", "Links & PoCs", renderLinks],
];

const renderCard = (v) => {
  const top = maxCvss(v);
  return `
<article class="vuln fam-${esc(v.family)}" id="${esc(v.slug)}" data-slug="${esc(v.slug)}">
  <button class="vuln-head" aria-expanded="false" aria-controls="body-${esc(v.slug)}">
    <span class="title-row">
      <span class="vuln-name">${esc(v.name)}</span>
      <span class="fam fam-${esc(v.family)}">${FAMILY_LABEL[v.family] || ""}</span>
      ${v.aliases?.length ? `<span class="aliases">aka ${v.aliases.map(esc).join(", ")}</span>` : ""}
    </span>
    <span class="date">${fmtDate(v.disclosed)}</span>
    <span class="meta">${esc(v.product)} <span class="eco">${esc(v.ecosystem)}</span></span>
    <span class="rw-line">${v.real_world ? `${impactMeter(v)}<span class="rw-headline">${esc(v.real_world.headline)}</span>` : `<span class="dim">${esc(v.impact || "")}</span>`}</span>
    <span class="badges">
      ${top ? `<span class="badge ${sevClass(top.severity)}">CVSS ${esc(top.cvss)}</span>` : ""}
      ${v.kev?.listed ? `<span class="badge kev">CISA KEV</span>` : ""}
      ${v.exploited_in_wild ? `<span class="badge itw">🔥 exploited</span>` : ""}
      ${v.real_world?.ransomware ? `<span class="badge ransom">ransomware</span>` : ""}
      <span class="badge muted">${(v.cves || []).length} CVE${(v.cves || []).length === 1 ? "" : "s"}</span>
    </span>
    <span class="chev" aria-hidden="true">▸</span>
  </button>
  <div class="vuln-body" id="body-${esc(v.slug)}" hidden>
    <div class="tabs" role="tablist">
      ${TABS.map(([k, label], i) => `<button role="tab" class="tab${i === 0 ? " active" : ""}" data-tab="${k}" aria-selected="${i === 0}">${label}</button>`).join("")}
      <button class="icon-btn share" data-share="${esc(v.slug)}" title="Copy link to this entry">🔗 share</button>
    </div>
    <div class="tab-panel"></div>
  </div>
</article>`;
};

const setTab = (card, tab) => {
  const v = bySlug[card.dataset.slug];
  card.querySelectorAll(".tab").forEach((t) => {
    const on = t.dataset.tab === tab;
    t.classList.toggle("active", on);
    t.setAttribute("aria-selected", on);
  });
  card.querySelector(".tab-panel").innerHTML = TABS.find(([k]) => k === tab)[2](v);
};

const setOpen = (card, open, tab = "overview") => {
  const head = card.querySelector(".vuln-head");
  const body = card.querySelector(".vuln-body");
  head.setAttribute("aria-expanded", open);
  card.classList.toggle("open", open);
  body.hidden = !open;
  if (open) setTab(card, tab);
};

// ---------- list ----------
const renderList = () => {
  const shown = vulns.filter(matches).sort(SORTS[state.sort]);
  els.count.textContent = `${shown.length} of ${vulns.length}`;
  els.clear.hidden = !hasFilters();
  els.list.innerHTML = shown.length
    ? shown.map(renderCard).join("")
    : `<div class="empty"><p>No entries match those filters.</p><button class="chip" id="empty-clear">Clear filters</button></div>`;
  renderTimelineDim(new Set(shown.map((v) => v.slug)));
};

const syncControls = () => {
  els.search.value = state.q;
  els.sort.value = state.sort;
  els.ecosystem.value = state.ecosystem;
  els.year.value = state.year;
  document.querySelectorAll("[data-toggle]").forEach((b) => b.setAttribute("aria-pressed", state.toggles.has(b.dataset.toggle)));
  $("related").setAttribute("aria-pressed", state.related);
  document.querySelectorAll("[data-impact]").forEach((b) => b.setAttribute("aria-pressed", state.impacts.has(b.dataset.impact)));
};

const update = () => {
  writeUrl();
  syncControls();
  renderList();
};

const clearFilters = () => {
  Object.assign(state, { q: "", ecosystem: "", year: "", toggles: new Set(), impacts: new Set(), related: true });
  update();
};

const openEntry = (slug, tab) => {
  if (!bySlug[slug]) return;
  let card = document.getElementById(slug);
  if (!card) {
    clearFilters();
    card = document.getElementById(slug);
  }
  setOpen(card, true, tab);
  card.classList.add("flash");
  setTimeout(() => card.classList.remove("flash"), 1200);
  card.scrollIntoView({ behavior: "smooth", block: "start" });
};

// ---------- stats ----------
const countUp = (el, to) => {
  const t0 = performance.now();
  const dur = 900;
  const step = (t) => {
    const p = Math.min(1, (t - t0) / dur);
    el.textContent = Math.round(to * (1 - Math.pow(1 - p, 3)));
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
  setTimeout(() => (el.textContent = to), dur + 100);
};

const renderStats = () => {
  const now = new Date(data.updated + "T00:00:00Z");
  const items = [
    [vulns.length, "named vulnerabilities", null],
    [vulns.reduce((n, v) => n + (v.cves || []).length, 0), "CVEs tracked", null],
    [vulns.filter(TOGGLES.exploited).length, "exploited in the wild", "exploited"],
    [vulns.filter(TOGGLES.kev).length, "in CISA KEV", "kev"],
    [vulns.filter((v) => v.disclosed && now - new Date(v.disclosed) < 365 * 864e5).length, "in the last 12 months", "recent"],
  ];
  els.stats.innerHTML = items
    .map(([n, l, f]) => `<button class="stat" ${f ? `data-stat="${f}"` : "disabled"}><span class="n" data-n="${n}">0</span><span class="l">${l}</span></button>`)
    .join("");
  els.stats.querySelectorAll(".n").forEach((el) => countUp(el, +el.dataset.n));
};

// ---------- timeline ----------
let timelinePoints = [];

const renderTimeline = () => {
  // Entries are spaced evenly in date order (real dates cluster too much to plot to scale),
  // with dashed dividers where the year changes and labels alternating above/below the axis.
  const dated = vulns.filter((v) => v.disclosed).sort(SORTS.oldest);
  const padX = 72;
  const step = Math.max(96, (els.box.clientWidth - padX * 2) / Math.max(1, dated.length - 1));
  const W = padX * 2 + step * (dated.length - 1);
  const H = 190;
  const axisY = 104;

  timelinePoints = dated.map((v, i) => {
    const cv = maxCvss(v)?.cvss ?? 6;
    return { v, x: padX + i * step, r: 4 + Math.max(0, cv - 4) * 1.1, up: i % 2 === 0 };
  });

  const dividers = timelinePoints
    .map((p, i) => (i && yearOf(p.v) !== yearOf(timelinePoints[i - 1].v) ? { x: p.x - step / 2, year: yearOf(p.v) } : null))
    .filter(Boolean);
  if (timelinePoints.length) dividers.unshift({ x: null, year: yearOf(timelinePoints[0].v) });

  els.svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  els.svg.setAttribute("width", W);
  els.svg.setAttribute("height", H);
  els.svg.innerHTML = `
    <line class="axis" x1="${padX / 2}" y1="${axisY}" x2="${W - padX / 2}" y2="${axisY}"/>
    ${dividers.map((d) => `
      ${d.x != null ? `<line class="yr-div" x1="${d.x}" y1="14" x2="${d.x}" y2="${H - 8}"/>` : ""}
      <text class="yr" x="${(d.x ?? 0) + 8}" y="${H - 10}">${d.year}</text>`).join("")}
    ${timelinePoints.map((p) => {
      const ly = p.up ? axisY - p.r - 30 : axisY + p.r + 34;
      const stemEnd = p.up ? ly + 8 : ly - 16;
      return `<g class="pt impact-${esc(p.v.real_world?.level || "unknown")}" data-slug="${esc(p.v.slug)}" tabindex="0" role="button" aria-label="${esc(p.v.name)}">
        <line class="stem" x1="${p.x}" y1="${axisY}" x2="${p.x}" y2="${stemEnd}"/>
        <circle cx="${p.x}" cy="${axisY}" r="${p.r}"/>
        <text x="${p.x}" y="${ly}" text-anchor="middle">${esc(p.v.name)}</text>
        <text class="mo" x="${p.x}" y="${ly + (p.up ? -14 : 14)}" text-anchor="middle">${fmtDate(p.v.disclosed, { month: "short", year: "numeric" })}</text>
      </g>`;
    }).join("")}`;
};

const renderTimelineDim = (visible) => {
  els.svg.querySelectorAll(".pt").forEach((g) => g.classList.toggle("dimmed", !visible.has(g.dataset.slug)));
};

const showTip = (g, evt) => {
  const v = bySlug[g.dataset.slug];
  const top = maxCvss(v);
  els.tip.innerHTML = `<strong>${esc(v.name)}</strong><span class="dim">${fmtDate(v.disclosed)} · ${esc(v.ecosystem)}${top ? ` · CVSS ${esc(top.cvss)}` : ""}</span>${v.real_world ? `<span>${esc(v.real_world.headline)}</span>` : ""}`;
  els.tip.hidden = false;
  const box = els.box.getBoundingClientRect();
  const r = g.querySelector("circle").getBoundingClientRect();
  const x = Math.min(r.left - box.left + els.box.scrollLeft, els.box.scrollWidth - 280);
  els.tip.style.left = Math.max(4, x) + "px";
  els.tip.style.top = r.bottom - box.top + 8 + "px";
};

// ---------- wiring ----------
const init = () => {
  const ecos = [...new Set(vulns.map((v) => v.ecosystem).filter(Boolean))].sort();
  els.ecosystem.insertAdjacentHTML("beforeend", ecos.map((e) => `<option>${esc(e)}</option>`).join(""));
  const years = [...new Set(vulns.map(yearOf).filter(Boolean))].sort().reverse();
  els.year.insertAdjacentHTML("beforeend", years.map((y) => `<option>${y}</option>`).join(""));

  const levels = Object.entries(IMPACT).filter(([k]) => vulns.some((v) => v.real_world?.level === k));
  els.impactChips.innerHTML = levels
    .map(([k, d]) => `<button class="chip impact-chip impact-${k}" data-impact="${k}" aria-pressed="false" title="${d.desc}"><i></i>${d.label}</button>`)
    .join("");
  els.legend.innerHTML = levels.map(([k, d]) => `<span class="impact-${k}"><i></i>${d.label}</span>`).join("");
  $("impact-explainer").innerHTML = Object.values(IMPACT).map((d) => `<strong>${d.label}</strong>: ${d.desc}.`).join(" ");

  readUrl();
  renderStats();
  renderTimeline();
  els.box.scrollLeft = els.box.scrollWidth;
  update();

  let searchTimer;
  els.search.addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.q = els.search.value.trim();
      update();
    }, 120);
  });
  els.sort.addEventListener("change", () => ((state.sort = els.sort.value), update()));
  els.ecosystem.addEventListener("change", () => ((state.ecosystem = els.ecosystem.value), update()));
  els.year.addEventListener("change", () => ((state.year = els.year.value), update()));
  els.clear.addEventListener("click", clearFilters);

  document.addEventListener("click", (e) => {
    const t = e.target.closest("button, .pt");
    if (!t) return;
    if (t.dataset.toggle) {
      state.toggles.has(t.dataset.toggle) ? state.toggles.delete(t.dataset.toggle) : state.toggles.add(t.dataset.toggle);
      update();
    } else if (t.dataset.impact) {
      state.impacts.has(t.dataset.impact) ? state.impacts.delete(t.dataset.impact) : state.impacts.add(t.dataset.impact);
      update();
    } else if (t.dataset.stat) {
      clearFilters();
      if (t.dataset.stat === "recent") state.year = String(new Date(data.updated).getUTCFullYear());
      else state.toggles.add(t.dataset.stat);
      update();
      document.getElementById("index").scrollIntoView({ behavior: "smooth" });
    } else if (t.id === "related") {
      state.related = !state.related;
      update();
    } else if (t.id === "empty-clear") {
      clearFilters();
    } else if (t.classList.contains("vuln-head")) {
      const card = t.closest(".vuln");
      const open = t.getAttribute("aria-expanded") !== "true";
      setOpen(card, open);
      history.replaceState(null, "", location.search + (open ? "#" + card.dataset.slug : "") || location.pathname);
    } else if (t.classList.contains("tab")) {
      const card = t.closest(".vuln");
      setTab(card, t.dataset.tab);
      history.replaceState(null, "", `${location.search}#${card.dataset.slug}/${t.dataset.tab}`);
    } else if (t.dataset.copy) {
      copy(t.dataset.copy, t.dataset.copy);
    } else if (t.dataset.share) {
      const tab = t.closest(".vuln").querySelector(".tab.active")?.dataset.tab;
      copy(`${location.origin}/#${t.dataset.share}${tab && tab !== "overview" ? "/" + tab : ""}`, "link");
    } else if (t.dataset.actor) {
      state.q = t.dataset.actor;
      update();
    } else if (t.classList.contains("pt")) {
      openEntry(t.dataset.slug, "impact");
    }
  });

  els.svg.addEventListener("mouseover", (e) => {
    const g = e.target.closest(".pt");
    if (g) showTip(g, e);
  });
  els.svg.addEventListener("mouseout", (e) => {
    if (e.target.closest(".pt") && !e.relatedTarget?.closest?.(".pt")) els.tip.hidden = true;
  });
  els.svg.addEventListener("focusin", (e) => {
    const g = e.target.closest(".pt");
    if (g) showTip(g, e);
  });
  els.svg.addEventListener("keydown", (e) => {
    const g = e.target.closest(".pt");
    if (g && (e.key === "Enter" || e.key === " ")) {
      e.preventDefault();
      openEntry(g.dataset.slug, "impact");
    }
  });

  document.addEventListener("keydown", (e) => {
    const typing = /INPUT|SELECT|TEXTAREA/.test(document.activeElement?.tagName);
    if (e.key === "/" && !typing) {
      e.preventDefault();
      els.search.focus();
    } else if (e.key === "Escape" && document.activeElement === els.search) {
      state.q = "";
      update();
      els.search.blur();
    }
  });

  let resizeTimer;
  let lastW = els.box.clientWidth;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      if (els.box.clientWidth === lastW) return;
      lastW = els.box.clientWidth;
      renderTimeline();
      renderTimelineDim(new Set(vulns.filter(matches).map((v) => v.slug)));
    }, 150);
  });

  const themeBtn = $("theme-toggle");
  themeBtn.addEventListener("click", () => {
    const root = document.documentElement;
    const isDark = root.dataset.theme ? root.dataset.theme === "dark" : !matchMedia("(prefers-color-scheme: light)").matches;
    root.dataset.theme = isDark ? "light" : "dark";
    try {
      localStorage.setItem("theme", root.dataset.theme);
    } catch {}
  });

  const openFromHash = () => {
    const [slug, tab] = decodeURIComponent(location.hash.slice(1)).split("/");
    if (bySlug[slug]) openEntry(slug, TABS.some(([k]) => k === tab) ? tab : "overview");
  };
  openFromHash();
  window.addEventListener("hashchange", openFromHash);
};

init();
