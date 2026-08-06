"use client";
import { useEffect, useState } from "react";
import Shell from "@/components/Shell";
import { api } from "@/lib/api";
import { Report } from "@/lib/types";
import { VerdictBadge, Spinner, AlertBox } from "@/components/ui";

export default function MailboxPage() {
  const [env, setEnv] = useState<any>({});
  const [monitor, setMonitor] = useState(false);
  const [results, setResults] = useState<Report[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ k: "ok" | "err"; t: string } | null>(null);
  const [cfg, setCfg] = useState({ PG_IMAP_SERVER: "", PG_IMAP_USERNAME: "", PG_IMAP_PASSWORD: "", PG_IMAP_MAILBOX: "INBOX", PG_IMAP_PORT: "993", ssl: true, unseen: true, mark: false });
  const [limit, setLimit] = useState(10);
  const [allMsgs, setAllMsgs] = useState(false);
  const [interval, setIntervalV] = useState(60);

  const load = () => api.get("/mailbox").then((d: any) => {
    setEnv(d.env || {}); setMonitor(d.monitor);
    const e = d.env || {};
    setCfg({
      PG_IMAP_SERVER: e.PG_IMAP_SERVER || "", PG_IMAP_USERNAME: e.PG_IMAP_USERNAME || "",
      PG_IMAP_PASSWORD: e.PG_IMAP_PASSWORD || "", PG_IMAP_MAILBOX: e.PG_IMAP_MAILBOX || "INBOX",
      PG_IMAP_PORT: e.PG_IMAP_PORT || "993",
      ssl: e.PG_IMAP_USE_SSL !== "false", unseen: e.PG_IMAP_UNSEEN_ONLY !== "false",
      mark: e.PG_IMAP_MARK_READ === "true",
    });
  });
  useEffect(() => { load(); }, []);

  const saveCfg = async (e: React.FormEvent) => {
    e.preventDefault(); setBusy(true);
    try {
      await api.postForm("/mailbox/config", {
        PG_IMAP_SERVER: cfg.PG_IMAP_SERVER, PG_IMAP_USERNAME: cfg.PG_IMAP_USERNAME, PG_IMAP_PASSWORD: cfg.PG_IMAP_PASSWORD,
        PG_IMAP_MAILBOX: cfg.PG_IMAP_MAILBOX, PG_IMAP_PORT: cfg.PG_IMAP_PORT,
        PG_IMAP_USE_SSL: cfg.ssl, PG_IMAP_UNSEEN_ONLY: cfg.unseen, PG_IMAP_MARK_READ: cfg.mark,
      });
      setMsg({ k: "ok", t: "Mailbox configuration saved" });
    } catch (e: any) { setMsg({ k: "err", t: e.message }); }
    setBusy(false);
  };

  const doScan = async () => {
    setBusy(true); setResults(null); setMsg(null);
    try {
      const r: any = await api.postForm("/mailbox/scan", { limit, all_msgs: allMsgs });
      setResults(r.results); setMsg({ k: "ok", t: `Scanned ${r.scanned} message(s)` });
    } catch (e: any) { setMsg({ k: "err", t: e.message }); }
    setBusy(false);
  };

  const toggleMonitor = async (on: boolean) => {
    await api.postForm(`/mailbox/monitor/${on ? "start" : "stop"}`, { interval });
    setMonitor(on);
  };

  return (
    <Shell title="Mailbox" sub="Read-only IMAP scanning & continuous monitoring">
      {msg && <AlertBox kind={msg.k}>{msg.t}</AlertBox>}
      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", alignItems: "start" }}>
        <div className="card">
          <div className="card-h"><h3>Connection</h3><span className="sub">credentials in .env</span></div>
          <div className="card-b">
            <form onSubmit={saveCfg}>
              <div className="row row-2">
                <div className="field"><label>IMAP server</label><input value={cfg.PG_IMAP_SERVER} onChange={(e) => setCfg({ ...cfg, PG_IMAP_SERVER: e.target.value })} placeholder="imap.gmail.com" /></div>
                <div className="field"><label>Port</label><input value={cfg.PG_IMAP_PORT} onChange={(e) => setCfg({ ...cfg, PG_IMAP_PORT: e.target.value })} /></div>
              </div>
              <div className="field"><label>Username</label><input value={cfg.PG_IMAP_USERNAME} onChange={(e) => setCfg({ ...cfg, PG_IMAP_USERNAME: e.target.value })} /></div>
              <div className="field"><label>Password / app password</label><input type="password" value={cfg.PG_IMAP_PASSWORD} onChange={(e) => setCfg({ ...cfg, PG_IMAP_PASSWORD: e.target.value })} placeholder="••••••••" /></div>
              <div className="field"><label>Mailbox</label><input value={cfg.PG_IMAP_MAILBOX} onChange={(e) => setCfg({ ...cfg, PG_IMAP_MAILBOX: e.target.value })} /></div>
              <label className="check" style={{ marginBottom: 10 }}><input type="checkbox" checked={cfg.ssl} onChange={(e) => setCfg({ ...cfg, ssl: e.target.checked })} /><span>Use SSL/TLS</span></label>
              <label className="check" style={{ marginBottom: 10 }}><input type="checkbox" checked={cfg.unseen} onChange={(e) => setCfg({ ...cfg, unseen: e.target.checked })} /><span>Unseen only</span></label>
              <label className="check" style={{ marginBottom: 10 }}><input type="checkbox" checked={cfg.mark} onChange={(e) => setCfg({ ...cfg, mark: e.target.checked })} /><span>Mark as read after scan (off by default)</span></label>
              <div className="actions" style={{ marginTop: 16 }}><button className="btn btn-primary" type="submit" disabled={busy}>{busy ? <Spinner /> : "Save configuration"}</button></div>
            </form>
          </div>
        </div>
        <div className="grid" style={{ gap: 18 }}>
          <div className="card">
            <div className="card-h"><h3>Scan now</h3><span className="sub">read-only</span></div>
            <div className="card-b">
              <div className="field"><label>Messages to fetch</label><input type="number" value={limit} min={1} max={5000} onChange={(e) => setLimit(+e.target.value)} /></div>
              <label className="check" style={{ marginBottom: 14 }}><input type="checkbox" checked={allMsgs} onChange={(e) => setAllMsgs(e.target.checked)} /><span>Scan ALL messages (not just unseen)</span></label>
              <button className="btn btn-primary" onClick={doScan} disabled={busy}>{busy ? <Spinner /> : "Run mailbox scan"}</button>
            </div>
          </div>
          <div className="card">
            <div className="card-h"><h3>Continuous monitor</h3></div>
            <div className="card-b">
              <div className="actions" style={{ marginBottom: 14 }}><span className="pill"><span className={`dot ${monitor ? "" : "warn"}`} style={{ display: "inline-block", marginRight: 6 }} />{monitor ? "Running" : "Stopped"}</span></div>
              <div className="field"><label>Interval (seconds)</label><input type="number" value={interval} onChange={(e) => setIntervalV(+e.target.value)} /></div>
              <div className="actions">
                <button className="btn btn-primary" onClick={() => toggleMonitor(true)} disabled={monitor}>Start</button>
                <button className="btn btn-danger" onClick={() => toggleMonitor(false)} disabled={!monitor}>Stop</button>
              </div>
            </div>
          </div>
        </div>
      </div>
      {results && (
        <div className="card" style={{ marginTop: 18 }}>
          <div className="card-h"><h3>This scan ({results.length})</h3></div>
          <div className="card-b" style={{ padding: 0 }}>
            <table className="table">
              <thead><tr><th>Subject</th><th>Sender</th><th>Verdict</th><th>Score</th></tr></thead>
              <tbody>
                {results.map((r) => (
                  <tr key={r.report_id}><td><a className="subj" href={`/report?id=${r.report_id}`}>{r.source.subject || "(no subject)"}</a></td><td>{r.sender.from}</td><td><VerdictBadge v={r.verdict} /></td><td><span className="score-pill">{r.risk_score}</span></td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </Shell>
  );
}
