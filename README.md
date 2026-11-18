# 4shell.org

A community index of the **\*4Shell** and **\*2Shell** family of named vulnerabilities: Log4Shell, Spring4Shell, Text4Shell, Java4Shell, Plugin4Shell, React2Shell, PHP2Shell, Node2Shell, wp2shell and the rest, plus famous relatives like Shellshock, ProxyShell and ToolShell.

Each entry covers its **real-world impact** (impact level, threat actors, ransomware use, and a sourced timeline of what actually happened) and links to:

- the CVE record on **NIST NVD**
- **CISA KEV** status
- vendor / official advisories
- technical write-ups
- public **PoCs, labs and scanners** on GitHub

Live site: **https://4shell.org**

## How it works

A static site built with [Vite](https://vite.dev) and deployed to GitHub Pages by `.github/workflows/deploy.yml` on every push to `main`.

```
index.html             page shell
src/main.js            rendering, filters, timeline, URL state
src/style.css
data/vulns.json        ← every entry lives here
public/                CNAME, favicon
scripts/validate.mjs   schema check (runs before every build)
scripts/check-links.mjs
```

```sh
npm install
npx vite                    # dev server at http://localhost:5173
npm run build               # validate data + build to dist/
npx vite preview            # serve the build
npm run check-links         # check every URL in data/vulns.json
```

Filters, sort order and search are kept in the URL (e.g. `/?sort=impact&only=kev`), and entries can be deep-linked to a tab (e.g. `/#log4shell/impact`).

## Contributing

To add or fix an entry, edit `data/vulns.json` and open a PR. CI runs `scripts/validate.mjs` on every change. You can also [open an issue](../../issues/new/choose) instead.

An entry belongs here if it:

1. has at least one CVE,
2. is widely called `<Something>4Shell` or `<Something>2Shell` (family `4shell` / `2shell`), or is a famous bug whose name ends in "Shell" (family `shell-family`), and
3. has been covered by at least one reputable source (a vendor, CISA, or an established security firm).

Entry shape:

```json
{
  "slug": "foo2shell",
  "name": "Foo2Shell",
  "aliases": [],
  "family": "2shell",
  "product": "Foo Server",
  "vendor": "Foo Inc.",
  "ecosystem": "Java | JavaScript | PHP | Ruby | Python | Web server | CMS | Microsoft | Linux/Unix | Network/VPN | Media server | RMM/IT | AI/ML | Other",
  "disclosed": "2026-01-31",
  "discoverer": "Researcher / Org",
  "summary": "Two or three plain-English sentences.",
  "impact": "Unauthenticated RCE",
  "affected": "Foo 1.0 – 1.4",
  "fixed": "Foo 1.5",
  "mitigation": "Upgrade, or disable X.",
  "exploited_in_wild": true,
  "kev": { "listed": true, "date_added": "2026-02-02" },
  "cves": [
    { "id": "CVE-2026-0001", "cvss": 9.8, "cvss_version": "3.1", "severity": "Critical",
      "note": "Short description", "nvd": "https://nvd.nist.gov/vuln/detail/CVE-2026-0001" }
  ],
  "official": [{ "title": "Vendor advisory", "url": "https://…" }],
  "writeups":  [{ "title": "…", "url": "https://…" }],
  "pocs":      [{ "title": "owner/repo", "url": "https://github.com/…", "type": "exploit|lab|scanner", "note": "" }],
  "real_world": {
    "level": "massive | major | moderate | limited | none-yet",
    "headline": "One sentence on what actually happened.",
    "exposure": "How much was exposed, with numbers if sourced.",
    "actors": ["Named threat actors / campaigns"],
    "ransomware": true,
    "events": [{ "date": "2026-02-03", "text": "What happened.", "url": "https://…" }]
  }
}
```

### About PoC links

Fake "PoC" repositories that carry malware show up within hours of every high-profile CVE. Only add PoCs that a reputable write-up cites or that come from a known researcher or org. **Read the code before you run it, and run it only in an isolated lab against systems you're authorized to test.**

## Disclaimer

This is an independent, community-maintained project. It is not affiliated with NIST, CISA, or any vendor. Information is provided as-is, so verify it against official advisories.

## License

Code: MIT. Content in `data/`: CC BY 4.0.
