import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Card, inputCls, EmptyState, fmtTime } from "../components/ui.jsx";

export default function Search({ session }) {
  const [params] = useSearchParams();
  const [q, setQ] = useState(params.get("q") || "");
  if (!session) return null;

  const results = useMemo(() => {
    const t = q.trim().toLowerCase();
    if (!t) return [];
    return session.events.filter((e) =>
      e.raw.toLowerCase().includes(t) || e.ip.includes(t)).slice(0, 200);
  }, [q, session]);

  const hl = (raw) => {
    const t = q.trim();
    if (!t) return raw;
    const i = raw.toLowerCase().indexOf(t.toLowerCase());
    if (i < 0) return raw;
    return (<>{raw.slice(0, i)}<mark className="bg-yellow-500/40 text-yellow-100 rounded px-0.5">{raw.slice(i, i + t.length)}</mark>{raw.slice(i + t.length)}</>);
  };

  return (
    <div>
      <h1 className="text-2xl font-extrabold">Search Logs</h1>
      <p className="text-slate-500 text-sm mt-1 mb-5">Search across {session.events.length.toLocaleString()} parsed lines.</p>
      <input className={`${inputCls} mono mb-4`} value={q} onChange={(e) => setQ(e.target.value)} placeholder="IP, path, username, keyword…" autoFocus />
      {q.trim() ? (
        <Card className="p-4">
          <div className="text-xs text-slate-500 font-bold mb-2">{results.length} matches {results.length === 200 ? "(showing first 200)" : ""}</div>
          <div className="mono text-[11px] leading-relaxed max-h-[60vh] overflow-y-auto">
            {results.map((e, i) => (
              <div key={i} className="flex gap-3 py-1 border-b border-slate-800/40">
                <span className="text-slate-600 shrink-0 w-36">{fmtTime(e.ts)}</span>
                <span className="text-teal-400 shrink-0 w-32 truncate">{e.ip}</span>
                <span className="text-slate-400 break-all">{hl(e.raw)}</span>
              </div>
            ))}
            {!results.length && <EmptyState text="No matches." />}
          </div>
        </Card>
      ) : <EmptyState text="Type to search IPs, paths, usernames or keywords." />}
    </div>
  );
}
