(() => {
  const listEl = document.getElementById("list");
  const searchEl = document.getElementById("search");
  const statsEl = document.getElementById("stats");
  const updatedEl = document.getElementById("updated");
  const chips = [...document.querySelectorAll(".chip")];

  let vulns = [];
  let filter = "all";

  const esc = (s) =>
    String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const safeUrl = (u) => (/^https:\/\//i.test(u || "") ? esc(u) : "#");

  const fmtDate = (d) => {
    if (!d) return "—";
    const dt = new Date(d + "T00:00:00Z");
    return isNaN(dt) ? esc(d) : dt.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" });
  };

  const sevClass = (sev) => (sev ? "sev-" + sev.toLowerCase() : "");

  const maxCvss = (v) => {
    const scored = (v.cves || []).filter((c) => typeof c.cvss === "number");
    return scored.sort((a, b) => b.cvss - a.cvss)[0];
  };

  const linkList = (items, renderItem) =>
    items && items.length ? `<ul>${items.map(renderItem).join("")}</ul>` : `<p class="dim">None listed yet.</p>`;

  const renderVuln = (v) => {
    const top = maxCvss(v);
    const cveBadges = (v.cves || [])
      .map((c) => `<span class="badge">${esc(c.id)}</span>`)
      .join("");
    const official = [
      ...(v.cves || []).filter((c) => c.nvd).map((c) => ({ title: `NIST NVD — ${c.id}`, url: c.nvd })),
      ...(v.kev && v.kev.listed ? [{ title: "CISA Known Exploited Vulnerabilities", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" }] : []),
      ...(v.official || []),
    ];

    return `
<details class="vuln" id="${esc(v.slug)}">
  <summary>
    <h3 class="vuln-name">${esc(v.name)}
      <span class="fam fam-${esc(v.family)}">${v.family === "4shell" ? "4SHELL" : "2SHELL"}</span>
      ${v.aliases && v.aliases.length ? `<span class="aliases">aka ${v.aliases.map(esc).join(", ")}</span>` : ""}
    </h3>
    <div class="right">
      <span class="date">${fmtDate(v.disclosed)}</span>
      <span class="chev">▸</span>
    </div>
    <div class="meta">${esc(v.product)}${v.impact ? " · " + esc(v.impact) : ""}</div>
    <div class="badges">
      ${top ? `<span class="badge ${sevClass(top.severity)}">CVSS ${esc(top.cvss)}${top.cvss_version ? " v" + esc(top.cvss_version) : ""}</span>` : ""}
      ${v.kev && v.kev.listed ? `<span class="badge kev">CISA KEV</span>` : ""}
      ${v.exploited_in_wild && !(v.kev && v.kev.listed) ? `<span class="badge itw">Exploited in the wild</span>` : ""}
      ${cveBadges}
    </div>
  </summary>
  <div class="vuln-body">
    <p>${esc(v.summary)}</p>
    <dl class="facts">
      ${v.vendor ? `<dt>vendor</dt><dd>${esc(v.vendor)}</dd>` : ""}
      ${v.discoverer ? `<dt>found by</dt><dd>${esc(v.discoverer)}</dd>` : ""}
      ${v.affected ? `<dt>affected</dt><dd>${esc(v.affected)}</dd>` : ""}
      ${v.fixed ? `<dt>fixed in</dt><dd>${esc(v.fixed)}</dd>` : ""}
      ${v.mitigation ? `<dt>mitigation</dt><dd>${esc(v.mitigation)}</dd>` : ""}
      ${v.kev && v.kev.listed ? `<dt>KEV added</dt><dd>${fmtDate(v.kev.date_added)}</dd>` : ""}
    </dl>
    <table class="cves">
      <thead><tr><th>CVE</th><th>CVSS</th><th>Description</th></tr></thead>
      <tbody>
        ${(v.cves || [])
          .map(
            (c) => `<tr>
          <td><a href="${safeUrl(c.nvd)}" target="_blank" rel="noopener">${esc(c.id)}</a></td>
          <td class="cvss ${sevClass(c.severity)}">${c.cvss != null ? esc(c.cvss) + (c.cvss_version ? ` <span class="dim">v${esc(c.cvss_version)}</span>` : "") : "—"}</td>
          <td>${esc(c.note)}</td>
        </tr>`
          )
          .join("")}
      </tbody>
    </table>
    <div class="links-grid">
      <div>
        <h4>Official</h4>
        ${linkList(official, (l) => `<li><a href="${safeUrl(l.url)}" target="_blank" rel="noopener">${esc(l.title)}</a></li>`)}
      </div>
      <div>
        <h4>Write-ups</h4>
        ${linkList(v.writeups, (l) => `<li><a href="${safeUrl(l.url)}" target="_blank" rel="noopener">${esc(l.title)}</a></li>`)}
      </div>
      <div>
        <h4>PoCs &amp; tools</h4>
        ${linkList(
          v.pocs,
          (p) => `<li><span class="ptype ptype-${esc(p.type)}">${esc(p.type)}</span><a href="${safeUrl(p.url)}" target="_blank" rel="noopener nofollow">${esc(p.title)}</a>${p.note ? `<span class="pnote">${esc(p.note)}</span>` : ""}</li>`
        )}
      </div>
    </div>
    <p><a class="permalink" href="#${esc(v.slug)}">#${esc(v.slug)}</a></p>
  </div>
</details>`;
  };

  const matches = (v, q) => {
    if (filter === "4shell" || filter === "2shell") {
      if (v.family !== filter) return false;
    } else if (filter === "kev" && !(v.kev && v.kev.listed)) {
      return false;
    }
    if (!q) return true;
    const hay = [v.name, ...(v.aliases || []), v.product, v.vendor, v.summary, ...(v.cves || []).map((c) => c.id)]
      .join(" ")
      .toLowerCase();
    return q
      .toLowerCase()
      .split(/\s+/)
      .every((t) => hay.includes(t));
  };

  const render = () => {
    const q = searchEl.value.trim();
    const shown = vulns.filter((v) => matches(v, q));
    listEl.innerHTML = shown.length ? shown.map(renderVuln).join("") : `<p class="empty">No matches.</p>`;
  };

  const renderStats = () => {
    const cveCount = vulns.reduce((n, v) => n + (v.cves || []).length, 0);
    const kev = vulns.filter((v) => v.kev && v.kev.listed).length;
    const recent = vulns.filter((v) => v.disclosed && Date.now() - new Date(v.disclosed) < 365 * 864e5).length;
    statsEl.innerHTML = [
      [vulns.length, "named vulnerabilities"],
      [cveCount, "CVEs tracked"],
      [kev, "in CISA KEV"],
      [recent, "in the last 12 months"],
    ]
      .map(([n, l]) => `<div class="stat"><span class="n">${n}</span><span class="l">${l}</span></div>`)
      .join("");
  };

  const openFromHash = () => {
    const id = decodeURIComponent(location.hash.slice(1));
    const el = id && document.getElementById(id);
    if (el && el.tagName === "DETAILS") {
      el.open = true;
      el.scrollIntoView({ block: "start" });
    }
  };

  chips.forEach((c) =>
    c.addEventListener("click", () => {
      chips.forEach((x) => x.classList.toggle("active", x === c));
      filter = c.dataset.filter;
      render();
    })
  );
  searchEl.addEventListener("input", render);
  window.addEventListener("hashchange", openFromHash);

  const themeBtn = document.getElementById("theme-toggle");
  const root = document.documentElement;
  try {
    const saved = localStorage.getItem("theme");
    if (saved) root.dataset.theme = saved;
  } catch {}
  themeBtn.addEventListener("click", () => {
    const isDark = root.dataset.theme
      ? root.dataset.theme === "dark"
      : !matchMedia("(prefers-color-scheme: light)").matches;
    root.dataset.theme = isDark ? "light" : "dark";
    try {
      localStorage.setItem("theme", root.dataset.theme);
    } catch {}
  });

  fetch("data/vulns.json", { cache: "no-cache" })
    .then((r) => r.json())
    .then((data) => {
      vulns = (data.vulns || []).sort((a, b) => (b.disclosed || "").localeCompare(a.disclosed || ""));
      updatedEl.textContent = `// ${vulns.length} entries · last updated ${fmtDate(data.updated)} · sorted newest first`;
      renderStats();
      render();
      openFromHash();
    })
    .catch(() => {
      listEl.innerHTML = `<p class="empty">Couldn't load data/vulns.json.</p>`;
    });
})();
