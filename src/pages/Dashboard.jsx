import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Card, SevPill, Spark, fmtNum, fmtTime, SEVBAR } from "../components/ui.jsx";
import { geoLookupMany } from "../engine/geoip.js";

export default function Dashboard({ session }) {
  const [geo, setGeo] = useState({});
  if (!session) return null;
  const { summary, alerts } = session;

  useEffect(() => {
    geoLookupMany(summary.topIps.map(([ip]) => ip)).then(setGeo);
  }, []);

  const sev = summary.sevCount;
  const cards = [
    { label: "Lines Parsed", value: fmtNum(summary.lines), color: "#14b8a6", spark: summary.hours.map((h) => h.critical + h.high + h.medium + h.low) },
    { label: "Unique IPs", value: fmtNum(summary.uniqueIps), color: "#38bdf8", spark: summary.topIps.map(([, c]) => c) },
    { label: "Security Alerts", value: fmtNum(summary.alerts), color: "#f87171", spark: summary.hours.map((h) => h.high + h.critical) },
  ];

  const maxBar = Math.max(...summary.hours.map((h) => h.critical + h.high + h.medium + h.low), 1);
  const maxIp = Math.max(...summary.topIps.map(([, c]) => c), 1);

  // Country aggregation from alert IPs
  const byCountry = {};
  for (const a of alerts) {
    const g = geo[a.ip];
    const c = g ? g.country : "Resolving…";
    byCountry[c] = (byCountry[c] || 0) + 1;
  }
  const countries = Object.entries(byCountry).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const totC = Math.max(...countries.map(([, c]) => c), 1);

  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <div>
          <h1 className="text-2xl font-extrabold">Security Dashboard</h1>
          <p className="text-slate-500 text-sm">Real-time analysis of your server logs <span className="mono text-slate-600">({session.name})</span></p>
        </div>
        <span className="text-xs font-bold text-slate-400 border border-slate-700 rounded-lg px-3 py-2">Last 24 Hours</span>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mt-5">
        {cards.map((c) => (
          <Card key={c.label} className="p-4">
            <div className="text-2xl font-extrabold" style={{ color: c.color }}>{c.value}</div>
            <div className="text-xs text-slate-500 font-semibold mt-0.5">{c.label}</div>
            <div className="mt-2"><Spark data={c.spark} color={c.color} /></div>
          </Card>
        ))}
        <Card className="p-4 !border-amber-500/30">
          <div className="text-lg font-extrabold text-amber-400 leading-tight">{summary.topThreat}</div>
          <div className="text-xs text-slate-500 font-semibold mt-1">Top Threat</div>
          <div className="text-[11px] text-slate-500 mt-2">{summary.alerts ? Math.round((alerts.filter((a) => a.type === summary.topThreat).length / summary.alerts) * 100) : 0}% of all alerts</div>
        </Card>
      </div>

      <Card className="p-5 mt-4">
        <div className="flex items-center gap-4 mb-3">
          <h3 className="font-bold text-slate-200">Attack Timeline (Last 24 Hours)</h3>
          <div className="flex gap-3 text-[11px] text-slate-500 ml-auto">
            <span><i className="inline-block w-2 h-2 rounded-full bg-red-500 mr-1" />Critical ({sev.critical})</span>
            <span><i className="inline-block w-2 h-2 rounded-full bg-red-400 mr-1" />High ({sev.high})</span>
            <span><i className="inline-block w-2 h-2 rounded-full bg-amber-400 mr-1" />Medium ({sev.medium})</span>
            <span><i className="inline-block w-2 h-2 rounded-full bg-sky-400 mr-1" />Low ({sev.low})</span>
          </div>
        </div>
        <div className="flex items-end gap-[3px] h-36">
          {summary.hours.map((h, i) => {
            const tot = h.critical + h.high + h.medium + h.low;
            const segs = [["critical", h.critical, "#ef4444"], ["high", h.high, "#f87171"], ["medium", h.medium, "#fbbf24"], ["low", h.low, "#38bdf8"]];
            return (
              <div key={i} className="flex-1 flex flex-col justify-end h-full" title={`${String(i).padStart(2, "0")}:00 — ${tot} alerts`}>
                {segs.map(([k, v, c]) => v ? <div key={k} style={{ height: `${(v / maxBar) * 100}%`, background: c, minHeight: 2 }} /> : null)}
                {i % 2 === 0 && <div className="text-[9px] text-slate-600 text-center mt-1">{String(i).padStart(2, "0")}:00</div>}
              </div>
            );
          })}
        </div>
      </Card>

      <div className="grid md:grid-cols-2 gap-4 mt-4">
        <Card className="p-5">
          <h3 className="font-bold text-slate-200 mb-3">Top Attacker IPs</h3>
          <div className="space-y-2.5">
            {summary.topIps.slice(0, 5).map(([ip, c]) => (
              <div key={ip} className="flex items-center gap-3">
                <span className="mono text-xs text-slate-300 w-32 truncate">{ip}</span>
                <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full rounded-full bg-red-500" style={{ width: `${(c / maxIp) * 100}%` }} />
                </div>
                <span className="text-xs font-bold text-slate-400 w-10 text-right">{c}</span>
              </div>
            ))}
          </div>
        </Card>
        <Card className="p-5">
          <h3 className="font-bold text-slate-200 mb-3">Attackers by Country</h3>
          <div className="space-y-2.5">
            {countries.map(([c, n]) => (
              <div key={c} className="flex items-center gap-3">
                <span className="text-xs text-slate-300 w-28 truncate">{c}</span>
                <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full rounded-full bg-amber-500" style={{ width: `${(n / totC) * 100}%` }} />
                </div>
                <span className="text-xs font-bold text-slate-400 w-16 text-right">{Math.round((n / alerts.length) * 100) || 0}%</span>
              </div>
            ))}
            {!countries.length && <div className="text-slate-600 text-sm">No alerts yet.</div>}
          </div>
          <p className="text-[11px] text-slate-600 mt-3">GeoIP via ip-api.com — best-effort, private IPs shown as internal.</p>
        </Card>
      </div>

      <Card className="mt-4">
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-800">
          <h3 className="font-bold text-slate-200">Recent Security Alerts</h3>
          <Link to="/alerts" className="text-xs font-bold text-red-400 hover:text-red-300 border border-red-500/40 rounded-lg px-3 py-1.5">View All</Link>
        </div>
        <table className="w-full text-sm">
          <thead><tr className="text-left text-[11px] uppercase tracking-wider text-slate-500">
            <th className="px-5 py-2.5">Time</th><th className="px-3 py-2.5">IP Address</th><th className="px-3 py-2.5">Attack Type</th><th className="px-3 py-2.5">Severity</th><th className="px-3 py-2.5">Evidence</th>
          </tr></thead>
          <tbody>
            {alerts.slice(0, 8).map((a) => (
              <tr key={a.id} className="border-t border-slate-800/60 hover:bg-slate-800/20">
                <td className="px-5 py-2.5 text-xs text-slate-400 whitespace-nowrap">{fmtTime(a.firstSeen)}</td>
                <td className="px-3 py-2.5 mono text-xs text-slate-300">{a.ip}</td>
                <td className="px-3 py-2.5"><Link to={`/alerts/${a.id}`} className="text-red-400 hover:text-red-300 font-semibold text-[13px]">{a.type}</Link></td>
                <td className="px-3 py-2.5"><SevPill severity={a.severity} /></td>
                <td className="px-3 py-2.5 mono text-[11px] text-slate-500 max-w-xs truncate">{a.evidence[0]?.raw.slice(0, 60)}</td>
              </tr>
            ))}
            {!alerts.length && <tr><td colSpan="5" className="text-center text-slate-500 text-sm py-8">No threats detected in these logs.</td></tr>}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
