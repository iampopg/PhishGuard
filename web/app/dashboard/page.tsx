"use client";
import { useEffect, useState } from "react";
import Shell from "@/components/Shell";
import { api } from "@/lib/api";
import { Dashboard, Report } from "@/lib/types";
import { VerdictBar, VerdictBadge, Spinner, Empty } from "@/components/ui";

export default function DashboardPage() {
  const [d, setD] = useState<Dashboard | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => { api.get("/dashboard").then(setD).catch((e) => setErr(e.message)); }, []);
  if (err) return <Shell title="Dashboard"><div className="alert err">{err}</div></Shell>;
  if (!d) return <Shell title="Dashboard"><div className="center" style={{ padding: 60 }}><Spinner /></div></Shell>;
  const total = d.total;
  const threats = d.counts.phishing + d.counts.malicious + d.counts.suspicious;
  const last = d.recent[0]?.timestamp?.replace("T", " ").slice(0, 19) || "—";
  return (
    <Shell title="Dashboard" sub="Real-time overview of analyzed mail (local store)">
      <div className="grid" style={{ gridTemplateColumns: "repeat(4,1fr)", marginBottom: 18 }}>
        <div className="stat"><div className="label">Total analyzed</div><div className="value">{total}</div><div className="meta">Stored locally · offline</div></div>
        <div className="stat malicious"><div className="label">Threats</div><div className="value">{threats}</div><div className="meta">{total ? ((threats / total) * 100).toFixed(1) : 0}% of traffic</div></div>
        <div className="stat phishing"><div className="label">Phishing</div><div className="value">{d.counts.phishing}</div><div className="meta">confirmed / likely</div></div>
        <div className="stat malicious"><div className="label">Malicious</div><div className="value">{d.counts.malicious}</div><div className="meta">high-confidence</div></div>
      </div>
      <div className="grid" style={{ gridTemplateColumns: "1.6fr 1fr", alignItems: "start" }}>
        <div className="card">
          <div className="card-h"><h3>Recent analyses</h3><a className="btn btn-ghost btn-sm" href="/reports">View all</a></div>
          <div className="card-b" style={{ padding: 0 }}>
            {d.recent.length ? (
              <table className="table">
                <thead><tr><th>Subject</th><th>Sender</th><th>Verdict</th><th>Score</th><th>Time</th></tr></thead>
                <tbody>
                  {d.recent.map((r: Report) => (
                    <tr key={r.report_id}>
                      <td><a className="subj" href={`/report?id=`}>{r.source.subject || "(no subject)"}</a><small className="mono">{r.report_id}</small></td>
                      <td>{r.sender.display_name || r.sender.from}<br /><small className="muted">{r.sender.from}</small></td>
                      <td><VerdictBadge v={r.verdict} /></td>
                      <td><span className="score-pill">{r.risk_score}</span></td>
                      <td className="muted small">{r.timestamp.replace("T", " ").slice(0, 19)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : <Empty>No analyses yet. Run a <a href="/scan">scan</a> or connect a <a href="/mailbox">mailbox</a>.</Empty>}
          </div>
        </div>
        <div className="grid" style={{ gap: 18 }}>
          <div className="card"><div className="card-h"><h3>Verdict distribution</h3></div><div className="card-b"><VerdictBar counts={d.counts} total={total} /></div></div>
          <div className="card">
            <div className="card-h"><h3>Monitor</h3></div>
            <div className="card-b">
              <div className="actions" style={{ marginBottom: 12 }}>
                <span className="pill"><span className={`dot ${d.monitor ? "" : "warn"}`} style={{ display: "inline-block", marginRight: 6 }} />{d.monitor ? "Running" : "Stopped"}</span>
                <span className="pill">Last scan: {last}</span>
              </div>
              <div className="actions">
                <a className="btn btn-primary btn-sm" href="/scan">New scan</a>
                <a className="btn btn-ghost btn-sm" href="/mailbox">Mailbox</a>
                <a className="btn btn-ghost btn-sm" href="/feeds">Feeds</a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Shell>
  );
}
