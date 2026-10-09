import { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { parseLogs } from "../engine/parser.js";
import { detect, summarize } from "../engine/detect.js";
import { generateSampleLog } from "../engine/sample.js";
import { setSession, getSettings } from "../data/session.js";
import { Card, Btn, inputCls } from "../components/ui.jsx";
import Globe from "../components/Globe.jsx";

export default function Ingest() {
  const nav = useNavigate();
  const fileRef = useRef(null);
  const [text, setText] = useState("");
  const [drag, setDrag] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const analyzeText = (t, name = "pasted") => {
    setErr("");
    if (!t.trim()) { setErr("Nothing to analyze — upload or paste some logs first."); return; }
    setBusy(true);
    setTimeout(() => {
      try {
        const { format, events, totalLines } = parseLogs(t);
        if (!events.length) { setErr("No recognizable log lines found. Supported: Apache/Nginx access logs and Linux auth.log (sshd)."); setBusy(false); return; }
        const alerts = detect(events, getSettings());
        const summary = summarize(events, alerts);
        setSession({ events, alerts, summary, format, name, totalLines, at: new Date().toISOString() });
        nav("/dashboard");
      } catch (e) {
        setErr("Failed to parse logs: " + e.message);
      } finally { setBusy(false); }
    }, 60);
  };

  const onFile = (f) => {
    if (!f) return;
    if (f.size > 100 * 1024 * 1024) { setErr("File too large (max 100 MB)."); return; }
    const r = new FileReader();
    r.onload = () => analyzeText(String(r.result || ""), f.name);
    r.readAsText(f);
  };

  return (
    <div className="max-w-4xl mx-auto text-center pt-2">
      <div className="relative">
        <Globe className="w-full max-w-[640px] mx-auto" />
        <div className="relative -mt-52 md:-mt-56">
          <h1 className="text-4xl md:text-5xl font-extrabold tracking-tight drop-shadow-[0_2px_12px_rgba(7,11,22,0.9)]">Turn Server Logs<br />into <span className="text-red-500">Security Insights</span></h1>
          <p className="text-slate-400 mt-3 drop-shadow-[0_2px_8px_rgba(7,11,22,0.9)]">Upload, analyze, and detect suspicious activity across your infrastructure.</p>
        </div>
      </div>

      <Card
        onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => { e.preventDefault(); setDrag(false); onFile(e.dataTransfer.files[0]); }}
        className={`mt-8 p-10 border-dashed !border-2 transition ${drag ? "!border-red-500 bg-red-500/5" : ""}`}>
        <svg className="mx-auto text-slate-500" width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M7 18a4.6 4.6 0 0 1-.9-9.1A5 5 0 0 1 17 9h1a4 4 0 0 1 0 8h-1M12 12v9m0-9l-3 3m3-3l3 3" strokeLinecap="round" strokeLinejoin="round" /></svg>
        <div className="font-bold text-lg mt-3">Drag & drop log files here</div>
        <div className="text-xs text-slate-500 mt-1">Supports .log, .txt (max 100 MB)</div>
        <Btn onClick={() => fileRef.current.click()} className="mt-4">Browse Files</Btn>
        <input ref={fileRef} type="file" accept=".log,.txt,.gz" className="hidden" onChange={(e) => onFile(e.target.files[0])} />
      </Card>

      <div className="flex items-center gap-3 my-5 text-xs text-slate-600 font-bold"><span className="flex-1 border-t border-slate-800" />OR<span className="flex-1 border-t border-slate-800" /></div>

      <Card className="p-5 text-left">
        <div className="text-sm font-bold text-slate-300 mb-2">Paste logs directly</div>
        <textarea value={text} onChange={(e) => setText(e.target.value)} rows={6}
          placeholder={'192.168.1.10 - - [09/Oct/2026:14:32:11 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"'}
          className={`${inputCls} mono !text-xs`} />
        <Btn onClick={() => analyzeText(text)} disabled={busy} className="mt-3 w-full !py-3">{busy ? "Analyzing…" : "Analyze Logs"}</Btn>
      </Card>

      {err && <div className="text-red-400 text-sm font-semibold mt-4">{err}</div>}

      <div className="mt-8 text-left">
        <div className="text-xs text-slate-500 font-bold uppercase tracking-widest mb-3 text-center">— Or try a sample log —</div>
        <div className="grid grid-cols-3 gap-3">
          {[
            { n: "Apache", d: "Access Log", c: "text-orange-400" },
            { n: "Nginx", d: "Access Log", c: "text-emerald-400" },
            { n: "auth.log", d: "Linux Auth Log", c: "text-sky-400" },
          ].map((s) => (
            <button key={s.n} onClick={() => analyzeText(generateSampleLog(), `sample-${s.n.toLowerCase()}.log`)}
              className="bg-[#0d1428] border border-slate-800 hover:border-red-500/60 rounded-xl p-4 text-left transition">
              <div className={`font-extrabold ${s.c}`}>{s.n}</div>
              <div className="text-xs text-slate-500">{s.d}</div>
              <div className="text-[11px] text-slate-600 mt-1">with planted attacks</div>
            </button>
          ))}
        </div>
      </div>

      <Card className="mt-6 p-4 text-left flex items-center gap-3">
        <div className="text-teal-400 font-bold text-sm">Auto-Detect Log Format</div>
        <div className="text-xs text-slate-500">Apache, Nginx and auth.log are detected automatically and parsed accordingly.</div>
      </Card>
    </div>
  );
}
