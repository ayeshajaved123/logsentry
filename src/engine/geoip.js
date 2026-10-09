// Free GeoIP via ip-api.com (45 req/min, no key, CORS-enabled). Best-effort.
const cache = new Map();

export async function geoLookup(ip) {
  if (cache.has(ip)) return cache.get(ip);
  // Private ranges — no lookup needed
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(ip)) {
    const r = { country: "Private", countryCode: "—", org: "Internal network" };
    cache.set(ip, r); return r;
  }
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 6000);
    const res = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,countryCode,org`, { signal: ctrl.signal });
    clearTimeout(t);
    if (!res.ok) throw 0;
    const j = await res.json();
    const r = j.status === "success"
      ? { country: j.country || "Unknown", countryCode: j.countryCode || "—", org: j.org || "—" }
      : { country: "Unknown", countryCode: "—", org: "—" };
    cache.set(ip, r); return r;
  } catch {
    const r = { country: "Unknown", countryCode: "—", org: "—" };
    cache.set(ip, r); return r;
  }
}

export async function geoLookupMany(ips) {
  const out = {};
  for (const ip of [...new Set(ips)].slice(0, 12)) out[ip] = await geoLookup(ip);
  return out;
}
