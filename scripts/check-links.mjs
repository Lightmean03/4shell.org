// Checks every URL in data/vulns.json. Run: npm run check-links
// Some sites block bots (403/429), so those are reported as warnings, not failures.
import { readFileSync } from "node:fs";

const data = JSON.parse(readFileSync(new URL("../data/vulns.json", import.meta.url), "utf8"));
const urls = new Map();
const add = (url, where) => url && urls.set(url, [...(urls.get(url) || []), where]);

for (const v of data.vulns) {
  for (const c of v.cves || []) add(c.nvd, `${v.slug} nvd`);
  for (const g of ["official", "writeups", "pocs"]) for (const l of v[g] || []) add(l.url, `${v.slug} ${g}`);
  for (const e of v.real_world?.events || []) add(e.url, `${v.slug} event`);
}

const check = async (url) => {
  for (const method of ["HEAD", "GET"]) {
    try {
      const res = await fetch(url, {
        method,
        redirect: "follow",
        signal: AbortSignal.timeout(15000),
        headers: { "user-agent": "Mozilla/5.0 (4shell.org link checker)" },
      });
      if (res.ok || method === "GET") return res.status;
    } catch (e) {
      if (method === "GET") return e.name === "TimeoutError" ? "timeout" : "error";
    }
  }
};

const results = [];
const queue = [...urls.keys()];
await Promise.all(
  Array.from({ length: 8 }, async () => {
    while (queue.length) {
      const url = queue.shift();
      results.push({ url, status: await check(url) });
    }
  })
);

const broken = results.filter((r) => r.status === 404 || r.status === 410);
const warn = results.filter((r) => !(r.status >= 200 && r.status < 400) && !broken.includes(r));
for (const r of warn) console.log(`? ${r.status}  ${r.url}  (${urls.get(r.url).join(", ")})`);
for (const r of broken) console.log(`✗ ${r.status}  ${r.url}  (${urls.get(r.url).join(", ")})`);
console.log(`\n${results.length} URLs: ${results.length - warn.length - broken.length} ok, ${warn.length} unreachable/blocked, ${broken.length} broken`);
process.exit(broken.length ? 1 : 0);
