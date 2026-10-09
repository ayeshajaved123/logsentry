import { useState } from "react";
import { Card, Btn, Field, inputCls } from "../components/ui.jsx";
import { getSettings, saveSettings } from "../data/session.js";

export default function Settings() {
  const [s, setS] = useState(getSettings());
  const [saved, setSaved] = useState(false);
  const set = (k) => (e) => setS((v) => ({ ...v, [k]: +e.target.value || 0 }));

  const save = (e) => {
    e.preventDefault();
    saveSettings(s); setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="max-w-2xl">
      <h1 className="text-2xl font-extrabold">Settings</h1>
      <p className="text-slate-500 text-sm mt-1 mb-5">Detection thresholds — applied to the next analysis.</p>
      <Card className="p-5">
        <form onSubmit={save} className="grid grid-cols-2 gap-4">
          <Field label="Brute-force attempts"><input type="number" min="2" className={inputCls} value={s.bruteThreshold} onChange={set("bruteThreshold")} /></Field>
          <Field label="Brute-force window (min)"><input type="number" min="1" className={inputCls} value={s.bruteWindowMin} onChange={set("bruteWindowMin")} /></Field>
          <Field label="Scan 404 threshold"><input type="number" min="2" className={inputCls} value={s.scan404Threshold} onChange={set("scan404Threshold")} /></Field>
          <Field label="Scan window (min)"><input type="number" min="1" className={inputCls} value={s.scanWindowMin} onChange={set("scanWindowMin")} /></Field>
          <div className="col-span-2 flex items-center gap-3">
            <Btn type="submit">Save</Btn>
            {saved && <span className="text-sm text-emerald-400 font-bold">Saved.</span>}
          </div>
        </form>
      </Card>
      <Card className="p-5 mt-4">
        <h3 className="font-bold text-slate-200 mb-1">Detection rules</h3>
        <p className="text-sm text-slate-400 leading-relaxed">SSH & web brute force · SQL injection · XSS · directory traversal · sensitive file probes · web shell uploads · directory scans · known scanner user-agents. Signatures are heuristic — tune thresholds to your traffic.</p>
      </Card>
    </div>
  );
}
