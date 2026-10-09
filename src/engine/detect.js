// Detection engine — rules over normalized events.
// Each alert: { id, type, title, severity, ip, firstSeen, lastSeen, count, evidence[], mitre, tactic, technique, action }

const SQLI_RES = [/union\s+select/i, /'\s*or\s*'?\d/i, /"\s*or\s*"?\d/i, /--(\s|$)/, /;\s*drop\s/i, /;\s*delete\s/i, /information_schema/i, /sleep\s*\(\s*\d/i, /benchmark\s*\(/i, /'\s*or\s*'1'\s*=\s*'1/i];
const XSS_RES = [/<script/i, /javascript\s*:/i, /onerror\s*=/i, /onload\s*=/i, /alert\s*\(/i, /document\.cookie/i];
const TRAVERSAL_RES = [/\.\.\//, /\.\.\\/, /%2e%2e/i];
const SENSITIVE_RES = [/\/etc\/passwd/i, /\.env(\b|$)/i, /\.git\//i, /wp-admin/i, /phpmyadmin/i, /\.ssh\//i, /\/proc\//i];
const SHELL_RES = [/upload\.php/i, /\/(shell|c99|r57|wso|b374k)[^/]*\.php/i, /\.phtml$/i, /\.phar$/i];
const SCANNER_UAS = [/sqlmap/i, /nikto/i, /nmap/i, /masscan/i, /nessus/i, /acunetix/i, /dirbuster/i, /gobuster/i, /hydra/i];

let n = 0;
const aid = () => "a_" + (++n) + "_" + Math.random().toString(36).slice(2, 7);

function groupByIp(events) {
  const m = new Map();
  for (const e of events) {
    if (!m.has(e.ip)) m.set(e.ip, []);
    m.get(e.ip).push(e);
  }
  return m;
}

// Sliding window: max events from one IP inside `windowMs`.
function burstCount(list, windowMs) {
  let best = 0, bestStart = 0;
  let j = 0;
  for (let i = 0; i < list.length; i++) {
    while (list[i].ts - list[j].ts > windowMs) j++;
    if (i - j + 1 > best) { best = i - j + 1; bestStart = j; }
  }
  return { count: best, start: bestStart };
}

export function detect(events, opts = {}) {
  n = 0;
  const o = { bruteThreshold: 5, bruteWindowMin: 10, scan404Threshold: 20, scanWindowMin: 5, ...opts };
  const alerts = [];
  const byIp = groupByIp(events);

  for (const [ip, list] of byIp) {
    // 1. SSH brute force (auth.log failed passwords)
    const fails = list.filter((e) => e.kind === "auth" && e.authResult === "Failed");
    if (fails.length >= o.bruteThreshold) {
      const b = burstCount(fails, o.bruteWindowMin * 60e3);
      if (b.count >= o.bruteThreshold) {
        alerts.push(mk("SSH Brute Force Attack",
          `Multiple failed SSH login attempts detected from a single IP address (${b.count} in ${o.bruteWindowMin} min). This may indicate an automated brute force attack.`,
          "high", ip, fails, "T1110 – Brute Force", "Credential Access", "T1110.001 – Password Guessing",
          ["Block IP address at firewall level.", "Check for any successful login from this IP.", "Consider fail2ban or similar protection."]));
      }
    }

    // 2. Web login brute force (repeated POST to login-ish paths or 401s)
    const webFails = list.filter((e) => e.kind === "http" &&
      (e.status === 401 || /login|signin|wp-login|admin/i.test(e.path || "")) && e.method === "POST");
    if (webFails.length >= o.bruteThreshold) {
      const b = burstCount(webFails, o.bruteWindowMin * 60e3);
      if (b.count >= o.bruteThreshold) {
        alerts.push(mk("Web Login Brute Force",
          `${b.count} login attempts against web forms from one IP in ${o.bruteWindowMin} minutes.`,
          "high", ip, webFails, "T1110 – Brute Force", "Credential Access", "T1110.001 – Password Guessing",
          ["Rate-limit the login endpoint.", "Enable CAPTCHA / account lockout.", "Block the IP if attempts continue."]));
      }
    }

    // 3. Directory / vulnerability scan (many 404s)
    const notFounds = list.filter((e) => e.kind === "http" && e.status === 404);
    if (notFounds.length >= o.scan404Threshold) {
      const b = burstCount(notFounds, o.scanWindowMin * 60e3);
      if (b.count >= o.scan404Threshold) {
        alerts.push(mk("Directory Scan",
          `${b.count} requests to non-existent paths in ${o.scanWindowMin} minutes — typical vulnerability scanner behavior.`,
          "medium", ip, notFounds, "T1595 – Active Scanning", "Reconnaissance", "T1595.002 – Vulnerability Scanning",
          ["Block the scanner IP.", "Review which paths were probed.", "Ensure no sensitive paths are exposed."]));
      }
    }

    // 4-8. Per-request pattern hits (test raw + URL-decoded path)
    const http = list.filter((e) => e.kind === "http");
    const dec = (s) => { try { return decodeURIComponent(s || ""); } catch { return s || ""; } };
    const hit = (res, title, sev, mitre, tactic, technique, action) => {
      const ev = http.filter((e) => { const p = (e.path || "") + " " + dec(e.path); return res.some((r) => r.test(p)); });
      if (ev.length) alerts.push(mk(title,
        `${ev.length} request(s) matching known attack signatures from this IP.`,
        sev, ip, ev, mitre, tactic, technique, action));
    };
    hit(SQLI_RES, "SQL Injection Attempt", "high", "T1190 – Exploit Public-Facing Application", "Initial Access", "T1190", ["Sanitize and parameterize all DB queries.", "Deploy a WAF rule for SQLi.", "Block the source IP."]);
    hit(XSS_RES, "XSS Attempt", "high", "T1189 – Drive-by Compromise", "Initial Access", "T1189", ["Encode output / apply CSP headers.", "Validate and sanitize user input.", "Block the source IP."]);
    hit(TRAVERSAL_RES, "Directory Traversal", "medium", "T1083 – File and Directory Discovery", "Discovery", "T1083", ["Normalize file paths server-side.", "Block the source IP."]);
    hit(SENSITIVE_RES, "Sensitive File Probe", "medium", "T1083 – File and Directory Discovery", "Discovery", "T1083", ["Ensure .env/.git are not web-accessible.", "Block the source IP."]);
    const shells = http.filter((e) => e.method === "POST" && SHELL_RES.some((r) => r.test(e.path || "")));
    if (shells.length) alerts.push(mk("Web Shell Upload Attempt", `${shells.length} POST request(s) to suspicious upload/script endpoints.`, "critical", ip, shells, "T1505 – Server Software Component", "Persistence", "T1505.003 – Web Shell", ["Isolate the server immediately.", "Check for newly created files.", "Block the source IP."]));

    // 9. Known scanner user-agent
    const scanners = http.filter((e) => SCANNER_UAS.some((r) => r.test(e.ua || "")));
    if (scanners.length) alerts.push(mk("Security Scanner Detected", `Requests using known scanner user-agent: ${(scanners[0].ua || "").slice(0, 60)}.`, "low", ip, scanners, "T1595 – Active Scanning", "Reconnaissance", "T1595", ["Usually benign research — block if unwanted."]));
  }

  alerts.sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || b.count - a.count);
  return alerts;

  function mk(title, desc, severity, ip, ev, mitre, tactic, technique, action) {
    const times = ev.map((e) => e.ts.getTime()).sort((a, b) => a - b);
    return {
      id: aid(), type: title, title, desc, severity, ip,
      firstSeen: new Date(times[0]), lastSeen: new Date(times[times.length - 1]),
      count: ev.length, evidence: ev.slice(0, 50),
      mitre, tactic, technique, action,
    };
  }
}

function sevRank(s) { return { critical: 4, high: 3, medium: 2, low: 1 }[s] || 0; }

export function summarize(events, alerts) {
  const ips = new Set(events.map((e) => e.ip));
  const byIpCount = new Map();
  for (const e of events) byIpCount.set(e.ip, (byIpCount.get(e.ip) || 0) + 1);
  const topIps = [...byIpCount.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  // hourly buckets for timeline
  const hours = new Array(24).fill(0).map(() => ({ critical: 0, high: 0, medium: 0, low: 0 }));
  for (const a of alerts) {
    const h = a.firstSeen.getUTCHours();
    hours[h][a.severity] = (hours[h][a.severity] || 0) + 1;
  }
  const sevCount = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const a of alerts) sevCount[a.severity]++;
  const topThreat = alerts[0]?.type || "None";
  return { lines: events.length, uniqueIps: ips.size, alerts: alerts.length, sevCount, topThreat, topIps, hours };
}
