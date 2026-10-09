import { useState } from "react";
import { Card, Btn, Field, inputCls, EmptyState } from "../components/ui.jsx";
import { geoLookup } from "../engine/geoip.js";

export default function ThreatIntel({ session }) {
  const [ip, setIp] = useState("");
  const [res, setRes] = useState(null);
  const [busy, setBusy] = useState(false);
  const [inSession, setInSession] = useState(null);

  const lookup = async (target) => {
    const t = (target ?? ip).trim();
    if (!t) return;
    setBusy(true); setRes(null);
    const g = await geoLookup(t);
    // cross-reference with current session
    let hits = null;
    if (session) {
      const ev = session.events.filter((e) => e.ip === t);
      const al = session.alerts.filter((a) => a.ip === t);
      if (ev.length) hits = { events: ev.length, alerts: al.map((a) => a.type) };
    }
    setRes({ ip: t, ...g });
    setInSession(hits);
    setBusy(false);
  };

  const suspicious = session ? [...new Set(session.alerts.map((a) => a.ip))] : [];

  return (
    <div className="max-w-3xl">
      <h1 className="text-2xl font-extrabold">Threat Intel</h1>
      <p className="text-slate-500 text-sm mt-1 mb-5">Look up any IP — geolocation, organization, and whether it attacked your logs.</p>

      <form onSubmit={(e) => { e.preventDefault(); lookup(); }} className="flex gap-2 mb-5">
        <input className={`${inputCls} mono`} value={ip} onChange={(e) => setIp(e.target.value)} placeholder="e.g. 185.220.101.12" />
        <Btn type="submit" disabled={busy}>{busy ? "…" : "Lookup"}</Btn>
      </form>

      {suspicious.length > 0 && (
        <div className="mb-5">
          <div className="text-xs text-slate-500 font-bold uppercase tracking-widest mb-2">Flagged in current logs</div>
          <div className="flex flex-wrap gap-2">
            {suspicious.map((s) => (
              <button key={s} onClick={() => lookup(s)} className="mono text-xs bg-red-500/10 border border-red-500/30 text-red-300 rounded-lg px-3 py-1.5 hover:bg-red-500/20">{s}</button>
            ))}
          </div>
        </div>
      )}

      {res && (
        <Card className="p-5">
          <h3 className="font-bold text-slate-200 mono mb-3">{res.ip}</h3>
          <dl className="text-sm space-y-2">
            {[["Country", res.country], ["Code", res.countryCode], ["Organization", res.org]].map(([k, v]) => (
              <div key={k} className="flex justify-between"><dt className="text-slate-500">{k}</dt><dd className="text-slate-300 font-semibold">{v}</dd></div>
            ))}
            <div className="flex justify-between"><dt className="text-slate-500">In your logs</dt>
              <dd className="font-bold">{inSession ? <span className="text-red-400">Yes — {inSession.events} events, {inSession.alerts.length} alerts</span> : <span className="text-emerald-400">No — not seen</span>}</dd></div>
          </dl>
          {inSession && inSession.alerts.length > 0 && (
            <div className="mt-3 text-xs text-slate-400">Attack types: {[...new Set(inSession.alerts)].join(", ")}</div>
          )}
          <p className="text-[11px] text-slate-600 mt-3">GeoIP via ip-api.com (free, best-effort).</p>
        </Card>
      )}
      {!res && <EmptyState text="Enter an IP above to investigate it." />}
    </div>
  );
}
