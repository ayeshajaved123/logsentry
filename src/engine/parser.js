// Log parsers — Apache/Nginx combined format + Linux auth.log (sshd).
// Returns normalized events: { ts, ip, kind, method, path, status, user, raw }

const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

// 192.168.1.10 - - [09/Oct/2026:14:32:11 +0000] "GET /index.php HTTP/1.1" 200 512 "-" "Mozilla/5.0"
const APACHE_RE = /^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ([^"]+?) HTTP\/[\d.]+" (\d{3}) (\S+) "[^"]*" "([^"]*)"/;
// Oct  9 14:32:11 server sshd[24321]: Failed password for root from 185.220.101.12 port 52341 ssh2
const AUTH_RE = /^(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) \S+ sshd\[\d+\]: (Failed|Accepted) password for (?:invalid user )?(\S+) from (\S+) port \d+/;

function parseApacheTime(s) {
  // 09/Oct/2026:14:32:11 +0000
  const m = s.match(/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})/);
  if (!m) return null;
  return new Date(Date.UTC(+m[3], MONTHS[m[2]], +m[1], +m[4], +m[5], +m[6]));
}

function parseAuthTime(s, year) {
  // Oct  9 14:32:11
  const m = s.match(/(\w{3})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})/);
  if (!m) return null;
  return new Date(Date.UTC(year, MONTHS[m[1]], +m[2], +m[3], +m[4], +m[5]));
}

export function detectFormat(text) {
  const lines = text.split("\n").filter((l) => l.trim()).slice(0, 50);
  let apache = 0, auth = 0;
  for (const l of lines) {
    if (APACHE_RE.test(l)) apache++;
    else if (AUTH_RE.test(l)) auth++;
  }
  if (apache >= auth && apache > 0) return apache > auth * 2 ? "apache" : "apache";
  if (auth > 0) return "auth";
  return apache > 0 ? "apache" : "unknown";
}

export function parseLogs(text) {
  const year = new Date().getUTCFullYear();
  const format = detectFormat(text);
  const events = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    let m;
    if ((m = line.match(APACHE_RE))) {
      const ts = parseApacheTime(m[2]);
      if (!ts) continue;
      events.push({
        ts, ip: m[1], kind: "http", method: m[3], path: m[4],
        status: +m[5], size: m[6] === "-" ? 0 : +m[6], ua: m[7],
        user: null, raw: line, line: i + 1,
      });
    } else if ((m = line.match(AUTH_RE))) {
      const ts = parseAuthTime(m[1], year);
      if (!ts) continue;
      events.push({
        ts, ip: m[4], kind: "auth",
        method: null, path: null, status: m[2] === "Failed" ? 401 : 200,
        user: m[3], raw: line, line: i + 1,
        authResult: m[2],
      });
    }
  }
  events.sort((a, b) => a.ts - b.ts);
  return { format: events.length ? format : "unknown", events, totalLines: lines.filter((l) => l.trim()).length };
}
