import { Card, Btn, fmtTime } from "../components/ui.jsx";

function download(name, text, type = "text/plain") {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

export default function Reports({ session }) {
  if (!session) return null;
  const { alerts, summary } = session;

  const csv = () => {
    const rows = [["Alert", "Severity", "IP", "First Seen", "Last Seen", "Count", "MITRE", "Evidence"]];
    for (const a of alerts) rows.push([a.type, a.severity, a.ip, new Date(a.firstSeen).toISOString(), new Date(a.lastSeen).toISOString(), a.count, a.mitre, `"${(a.evidence[0]?.raw || "").replace(/"/g, '""')}"`]);
    download("logsentry-report.csv", rows.map((r) => r.join(",")).join("\n"), "text/csv");
  };
  const txt = () => {
    const L = [];
    L.push("LOGSENTRY SECURITY REPORT", "=".repeat(40), `Source: ${session.name}`, `Generated: ${new Date().toISOString()}`, `Lines parsed: ${summary.lines}`, `Unique IPs: ${summary.uniqueIps}`, `Alerts: ${summary.alerts}`, "");
    for (const a of alerts) {
      L.push(`[${a.severity.toUpperCase()}] ${a.type} — ${a.ip} (${a.count}x)`);
      L.push(`  First: ${fmtTime(a.firstSeen)}  Last: ${fmtTime(a.lastSeen)}`);
      L.push(`  ${a.mitre} | ${a.tactic}`);
      L.push(`  Evidence: ${a.evidence[0]?.raw || "—"}`, "");
    }
    download("logsentry-report.txt", L.join("\n"));
  };

  return (
    <div className="max-w-2xl">
      <h1 className="text-2xl font-extrabold">Reports</h1>
      <p className="text-slate-500 text-sm mt-1 mb-5">Export the findings from <span className="mono text-slate-400">{session.name}</span>.</p>
      <Card className="p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div><div className="font-bold text-slate-200">CSV Export</div><div className="text-xs text-slate-500">Spreadsheet-friendly — all {alerts.length} alerts with evidence.</div></div>
          <Btn onClick={csv}>Download CSV</Btn>
        </div>
        <div className="border-t border-slate-800" />
        <div className="flex items-center justify-between">
          <div><div className="font-bold text-slate-200">Text Report</div><div className="text-xs text-slate-500">Human-readable incident summary.</div></div>
          <Btn onClick={txt}>Download TXT</Btn>
        </div>
      </Card>
    </div>
  );
}
