// Sample log generator — realistic traffic with planted attacks,
// so LogSentry demonstrates real detection with zero setup.

function pad(n, l = 2) { return String(n).padStart(l, "0"); }
function apacheTime(d) {
  const M = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
  return `${pad(d.getUTCDate())}/${M[d.getUTCMonth()]}/${d.getUTCFullYear()}:${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} +0000`;
}
function authTime(d) {
  const M = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
  return `${M[d.getUTCMonth()]}  ${d.getUTCDate()} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

const UAS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
];
const PAGES = ["/", "/index.html", "/about", "/contact", "/products", "/blog/post-1", "/assets/style.css", "/api/status"];

export function generateSampleLog() {
  const lines = [];
  const base = Date.UTC(2026, 9, 9, 8, 0, 0);
  const rnd = (a, b) => a + Math.floor(Math.random() * (b - a));
  const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

  // Background: normal traffic, 08:00 → 14:00
  for (let i = 0; i < 260; i++) {
    const t = new Date(base + rnd(0, 6 * 3600e3));
    const ip = `192.168.1.${rnd(2, 60)}`;
    const page = pick(PAGES);
    lines.push({ t, s: `${ip} - - [${apacheTime(t)}] "GET ${page} HTTP/1.1" 200 ${rnd(800, 9000)} "-" "${pick(UAS)}"` });
  }

  // ATTACK 1: SSH brute force — 185.220.101.12, 50 failed root/admin logins
  const users = ["root", "admin", "user", "test", "oracle", "guest"];
  for (let i = 0; i < 50; i++) {
    const t = new Date(base + 6 * 3600e3 + 27 * 60e3 + i * 24e3);
    lines.push({ t, s: `${authTime(t)} server sshd[2432${i % 10}]: Failed password for ${pick(users)} from 185.220.101.12 port ${rnd(40000, 60000)} ssh2` });
  }

  // ATTACK 2: SQL injection — 45.227.33.18
  const sqli = [
    "/admin.php?id=1' OR '1'='1", "/login.php?user=' UNION SELECT 1,2,3--",
    "/search?q='; DROP TABLE users--", "/product.php?id=1 AND SLEEP(5)",
  ];
  sqli.forEach((p, i) => {
    const t = new Date(base + 6 * 3600e3 + 28 * 60e3 + i * 90e3);
    lines.push({ t, s: `45.227.33.18 - - [${apacheTime(t)}] "GET ${p} HTTP/1.1" 500 231 "-" "${UAS[0]}"` });
  });

  // ATTACK 3: directory traversal + sensitive probes — 91.132.12.44
  const trav = ["/../../etc/passwd", "/static/..%2f..%2fetc%2fpasswd", "/.env", "/.git/config", "/wp-admin/", "/phpmyadmin/"];
  trav.forEach((p, i) => {
    const t = new Date(base + 6 * 3600e3 + 18 * 60e3 + i * 75e3);
    const code = p.includes("passwd") ? 200 : 404;
    lines.push({ t, s: `91.132.12.44 - - [${apacheTime(t)}] "GET ${p} HTTP/1.1" ${code} ${rnd(200, 2000)} "-" "${UAS[2]}"` });
  });

  // ATTACK 4: directory scan (many 404s) — 103.21.244.90
  const scanPaths = ["/backup.zip", "/old/", "/test.php", "/admin123", "/server-status", "/.svn/entries", "/config.bak", "/db.sql"];
  for (let i = 0; i < 28; i++) {
    const t = new Date(base + 6 * 3600e3 + 45 * 60e3 + i * 11e3);
    lines.push({ t, s: `103.21.244.90 - - [${apacheTime(t)}] "GET ${pick(scanPaths)} HTTP/1.1" 404 512 "-" "gobuster/3.6"` });
  }

  // ATTACK 5: XSS — 203.0.113.77
  {
    const t = new Date(base + 6 * 3600e3 + 11 * 60e3);
    lines.push({ t, s: `203.0.113.77 - - [${apacheTime(t)}] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 1832 "-" "${UAS[1]}"` });
  }

  // ATTACK 6: web shell upload attempt — 51.79.12.66
  {
    const t = new Date(base + 6 * 3600e3 + 20 * 60e3);
    lines.push({ t, s: `51.79.12.66 - - [${apacheTime(t)}] "POST /upload.php HTTP/1.1" 200 96 "-" "${UAS[0]}"` });
  }

  // ATTACK 7: web login brute force — 198.51.100.23
  for (let i = 0; i < 12; i++) {
    const t = new Date(base + 5 * 3600e3 + 8 * 60e3 + i * 20e3);
    lines.push({ t, s: `198.51.100.23 - - [${apacheTime(t)}] "POST /wp-login.php HTTP/1.1" 401 1120 "-" "${UAS[0]}"` });
  }

  lines.sort((a, b) => a.t - b.t);
  return lines.map((l) => l.s).join("\n");
}
