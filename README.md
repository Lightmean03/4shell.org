# 4shell.org

A community index of the **\*4Shell** and **\*2Shell** family of named vulnerabilities: Log4Shell, Spring4Shell, Text4Shell, Java4Shell, React2Shell, PHP2Shell, Node2Shell, wp2shell and the rest.

Each entry links to:

- the CVE record on **NIST NVD**
- **CISA KEV** status
- vendor / official advisories
- technical write-ups
- public **PoCs, labs and scanners** on GitHub

Live site: **https://4shell.org**

## How it works

It's a plain static site with no build step, hosted on GitHub Pages.

```
index.html          page shell
assets/app.js       renders entries from the JSON, plus search and filters
assets/style.css
data/vulns.json     ← every entry lives here
scripts/validate.mjs
```

Run it locally:

```sh
python3 -m http.server 8000   # then open http://localhost:8000
node scripts/validate.mjs     # check data/vulns.json
```

## Contributing

To add or fix an entry, edit `data/vulns.json` and open a PR. CI runs `scripts/validate.mjs` on every change. You can also [open an issue](../../issues/new/choose) instead.

An entry belongs here if it:

1. has at least one CVE,
2. is widely called `<Something>4Shell` or `<Something>2Shell`, and
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
  "pocs":      [{ "title": "owner/repo", "url": "https://github.com/…", "type": "exploit|lab|scanner", "note": "" }]
}
```

### About PoC links

Fake "PoC" repositories that carry malware show up within hours of every high-profile CVE. Only add PoCs that a reputable write-up cites or that come from a known researcher or org. **Read the code before you run it, and run it only in an isolated lab against systems you're authorized to test.**

## Disclaimer

This is an independent, community-maintained project. It is not affiliated with NIST, CISA, or any vendor. Information is provided as-is, so verify it against official advisories.

## License

Code: MIT. Content in `data/`: CC BY 4.0.
