import { useEffect, useMemo, useState } from "react";
import { Link, useParams, useNavigate } from "react-router-dom";
import { Card, Btn, SevPill, EmptyState, inputCls, fmtTime } from "../components/ui.jsx";
import { geoLookup } from "../engine/geoip.js";

function Detail({ alert }) {
  const [geo, setGeo] = useState(null);
  const nav = useNavigate();
  useEffect(() => { geoLookup(alert.ip).then(setGeo); }, [alert.id]);
  const idx = 0;

  return (
    <div>
      <div className="flex items-center gap-3 mb-4">
        <button onClick={() => nav("/alerts")} className="text-sm text-slate-400 hover:text-slate-200 font-semibold">← Back to Alerts</button>
        <div className="ml-auto flex gap-2">
          <button className="text-xs font-bold border border-slate-700 rounded-lg px-3 py-1.5 text-slate-400">‹ Previous</button>
          <button className="text-xs font-bold border border-slate-700 rounded-lg px-3 py-1.5 text-slate-400">Next ›</button>
        </div>
      </div>

      <Card className="p-5 !border-red-500/40 mb-4">
        <div className="flex items-start gap-4">
          <div className="text-4xl">⚠</div>
          <div className="flex-1">
            <div className="flex items-center gap-3">
              <h1 className="text-xl font-extrabold text-red-300">{alert.title}</h1>
              <SevPill severity={alert.severity} className="ml-auto" />
            </div>
            <p className="text-sm text-slate-400 mt-1">{alert.desc}</p>
          </div>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-5 text-sm">
          {[["Source IP", alert.ip, true], ["First Seen", fmtTime(alert.firstSeen)], ["Last Seen", fmtTime(alert.lastSeen)], ["Total Attempts", alert.count]].map(([k, v, mono]) => (
            <div key={k}><div className="text-[11px] text-slate-500 font-bold uppercase">{k}</div><div className={`font-bold text-slate-200 mt-0.5 ${mono ? "mono" : ""}`}>{v}</div></div>
          ))}
        </div>
      </Card>

      <div className="grid md:grid-cols-2 gap-4">
        <Card className="p-5">
          <h3 className="font-bold text-slate-200 mb-3">Attack Classification</h3>
          <dl className="text-sm space-y-2">
            {[["Attack Type", alert.title], ["MITRE ATT&CK", alert.mitre], ["Tactic", alert.tactic], ["Technique", alert.technique], ["Confidence", "High"]].map(([k, v]) => (
              <div key={k} className="flex justify-between gap-3"><dt className="text-slate-500">{k}</dt><dd className="text-slate-300 text-right font-semibold">{v}</dd></div>
            ))}
          </dl>
        </Card>
        <Card className="p-5">
          <h3 className="font-bold text-slate-200 mb-3">Source IP Details</h3>
          <dl className="text-sm space-y-2">
            <div className="flex justify-between gap-3"><dt className="text-slate-500">IP Address</dt><dd className="mono text-slate-300">{alert.ip}</dd></div>
            <div className="flex justify-between gap-3"><dt className="text-slate-500">Country</dt><dd className="text-slate-300">{geo ? `${geo.country}` : "Resolving…"}</dd></div>
            <div className="flex justify-between gap-3"><dt className="text-slate-500">Organization</dt><dd className="text-slate-300 text-right">{geo ? geo.org : "…"}</dd></div>
            <div className="flex justify-between gap-3"><dt className="text-slate-500">Total Attempts</dt><dd className="text-slate-300 font-bold">{alert.count}</dd></div>
          </dl>
        </Card>
      </div>

      <Card className="p-5 mt-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="font-bold text-slate-200">Log Evidence <span className="text-slate-500 font-normal text-sm">({alert.evidence.length} matching lines)</span></h3>
          <button onClick={() => {
            const blob = new Blob([alert.evidence.map((e) => e.raw).join("\n")], { type: "text/plain" });
            const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
            a.download = `evidence-${alert.ip}.log`; a.click();
          }} className="text-xs font-bold border border-slate-700 rounded-lg px-3 py-1.5 text-slate-300 hover:border-slate-500">Download Logs</button>
        </div>
        <div className="bg-[#070b16] border border-slate-800 rounded-lg p-3 max-h-72 overflow-y-auto mono text-[11px] leading-relaxed">
          {alert.evidence.map((e, i) => (
            <div key={i} className="flex gap-3 py-0.5 border-b border-slate-800/40">
              <span className="text-slate-600 w-6 shrink-0">{i + 1}</span>
              <span className="text-slate-400 break-all">{e.raw}</span>
            </div>
          ))}
        </div>
      </Card>

      <Card className="p-5 mt-4 !border-teal-500/30">
        <h3 className="font-bold text-teal-300 mb-3">Recommended Actions</h3>
        <ol className="list-decimal ml-5 space-y-1.5 text-sm text-slate-300">
          {alert.action.map((a, i) => <li key={i}>{a}</li>)}
        </ol>
      </Card>
    </div>
  );
}

export default function Alerts({ session }) {
  const { id } = useParams();
  const [sev, setSev] = useState("all");
  const [type, setType] = useState("all");
  if (!session) return null;
  const { alerts } = session;

  if (id) {
    const a = alerts.find((x) => x.id === id);
    if (!a) return <EmptyState text="Alert not found." />;
    return <Detail alert={a} />;
  }

  const types = [...new Set(alerts.map((a) => a.type))];
  const filtered = alerts.filter((a) =>
    (sev === "all" || a.severity === sev) && (type === "all" || a.type === type));

  return (
    <div>
      <h1 className="text-2xl font-extrabold">Security Alerts</h1>
      <p className="text-slate-500 text-sm mt-1 mb-5">{alerts.length} alerts detected.</p>
      <div className="flex gap-2 mb-4">
        <select className={`${inputCls} !w-44`} value={sev} onChange={(e) => setSev(e.target.value)}>
          <option value="all">All Severity</option>
          <option value="critical">Critical</option><option value="high">High</option>
          <option value="medium">Medium</option><option value="low">Low</option>
        </select>
        <select className={`${inputCls} !w-56`} value={type} onChange={(e) => setType(e.target.value)}>
          <option value="all">All Attack Types</option>
          {types.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
      </div>
      <Card>
        <table className="w-full text-sm">
          <thead><tr className="text-left text-[11px] uppercase tracking-wider text-slate-500 border-b border-slate-800">
            <th className="px-5 py-3">Time</th><th className="px-3 py-3">IP Address</th><th className="px-3 py-3">Attack Type</th><th className="px-3 py-3">Severity</th><th className="px-3 py-3">Evidence</th>
          </tr></thead>
          <tbody>
            {filtered.map((a) => (
              <tr key={a.id} className="border-t border-slate-800/60 hover:bg-slate-800/20">
                <td className="px-5 py-3 text-xs text-slate-400 whitespace-nowrap">{fmtTime(a.firstSeen)}</td>
                <td className="px-3 py-3 mono text-xs text-slate-300">{a.ip}</td>
                <td className="px-3 py-3"><Link to={`/alerts/${a.id}`} className="text-red-400 hover:text-red-300 font-semibold text-[13px]">{a.type}</Link></td>
                <td className="px-3 py-3"><SevPill severity={a.severity} /></td>
                <td className="px-3 py-3 mono text-[11px] text-slate-500 max-w-xs truncate">{a.evidence[0]?.raw.slice(0, 55)}</td>
              </tr>
            ))}
            {!filtered.length && <tr><td colSpan="5"><EmptyState text="No alerts match the filters." /></td></tr>}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
