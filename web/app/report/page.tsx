"use client";
import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import Shell from "@/components/Shell";
import { api } from "@/lib/api";
import { Report } from "@/lib/types";
import { VerdictBadge, SeverityBadge, Spinner, AlertBox, ReportSummary } from "@/components/ui";

function ReportInner() {
  const params = useSearchParams();
  const id = params.get("id") || "";
  const [r, setR] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [note, setNote] = useState("");
  const [label, setLabel] = useState("");
  const [saved, setSaved] = useState(false);
  const [tab, setTab] = useState("headers");

  useEffect(() => {
    if (!id) { setLoading(false); return; }
    api.get(`/report/${id}`).then((d: any) => { setR(d.report); setLoading(false); }).catch(() => setLoading(false));
  }, [id]);

  if (!id) return <Shell title="Report"><div className="alert info">Open a report from the Reports list.</div></Shell>;
  if (loading) return <Shell title="Report"><div className="center" style={{ padding: 60 }}><Spinner /></div></Shell>;
  if (!r) return <Shell title="Report"><div className="alert err">Report not found</div></Shell>;

  const saveFeedback = async (e: React.FormEvent) => {
    e.preventDefault();
    await api.postForm(`/report/${id}/feedback`, { label, note });
    setSaved(true);
  };

  const headers: Record<string, string> = r.raw_headers || {};
  const atts: any[] = r.attachments || [];

  return (
    <Shell title={r.source.subject || "(no subject)"} sub={`Report ${r.report_id}`}>
      <div className="grid" style={{ gridTemplateColumns: "1.7fr 1fr", alignItems: "start" }}>
        <div className="grid" style={{ gap: 18 }}>
          <ReportSummary r={r} full />
          <div className="card">
            <div className="card-h"><h3>Email viewer</h3></div>
            <div className="card-b">
              <div className="tabs">
                <button className={`tab ${tab === "headers" ? "active" : ""}`} onClick={() => setTab("headers")}>Headers</button>
                <button className={`tab ${tab === "body" ? "active" : ""}`} onClick={() => setTab("body")}>Body (text)</button>
                <button className={`tab ${tab === "html" ? "active" : ""}`} onClick={() => setTab("html")}>Body (HTML)</button>
                <button className={`tab ${tab === "attachments" ? "active" : ""}`} onClick={() => setTab("attachments")}>
                  Attachments ({atts.length})
                </button>
              </div>

              {tab === "headers" && (
                headers && Object.keys(headers).length ? (
                  <dl className="kv">
                    {Object.entries(headers).map(([k, v]) => (<div key={k}><dt>{k}</dt><dd className="mono">{v}</dd></div>))}
                  </dl>
                ) : <div className="viewer-note">No headers were captured for this report.</div>
              )}

              {tab === "body" && (
                <pre className="raw">{r.body_text ? r.body_text : "(no plain-text body)"}</pre>
              )}

              {tab === "html" && (
                r.body_html ? (
                  <iframe className="html-frame" sandbox="" srcDoc={r.body_html} title="rendered html" />
                ) : <div className="viewer-note">No HTML body was captured for this report.</div>
              )}

              {tab === "attachments" && (
                atts.length ? (
                  <table className="table">
                    <thead><tr><th>#</th><th>Filename</th><th>Type</th><th>Size</th><th>SHA-256</th></tr></thead>
                    <tbody>
                      {atts.map((a: any, i: number) => (
                        <tr key={i}>
                          <td>{i}</td>
                          <td>{a.filename}</td>
                          <td>{a.content_type}</td>
                          <td>{(a.size / 1024).toFixed(1)} KB</td>
                          <td className="mono" style={{ fontSize: 11 }}>{a.sha256}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : <div className="viewer-note">No attachments in this message.</div>
              )}
            </div>
          </div>
          <div className="card">
            <div className="card-h"><h3>Findings</h3><span className="sub">grouped by analyzer</span></div>
            <div className="card-b">
              {r.analyzers.map((a) => (
                <div className="analyzer-block" key={a.name}>
                  <h4>{a.name} <span className="sc">+{a.score}</span></h4>
                  {a.findings.length ? a.findings.map((f, i) => (
                    <div className="finding" key={i}>
                      <div className="ft"><b>{f.title}</b><SeverityBadge s={f.severity} /></div>
                      <div className="fd">{f.detail}</div>
                      <div className="fd muted small">contribution: +{f.score}</div>
                    </div>
                  )) : <div className="muted small" style={{ padding: "4px 0" }}>No findings.</div>}
                </div>
              ))}
            </div>
          </div>
        </div>
        <div className="grid" style={{ gap: 18 }}>
          <div className="card">
            <div className="card-h"><h3>Details</h3></div>
            <div className="card-b">
              <dl className="kv">
                <dt>Message-ID</dt><dd>{r.source.message_id || "—"}</dd>
                <dt>Sender domain</dt><dd>{r.sender.from_domain || "—"}</dd>
                <dt>Envelope from</dt><dd>{r.sender.envelope_from || "—"}</dd>
                <dt>Source</dt><dd>{r.source.type || "email"}{r.source.mailbox_id ? ` · ${r.source.mailbox_id}` : ""}</dd>
                <dt>URLs</dt><dd>{r.urls.length}</dd>
                <dt>Attachments</dt><dd>{r.attachments.length}</dd>
              </dl>
            </div>
          </div>
          <div className="card">
            <div className="card-h"><h3>Analyst feedback</h3></div>
            <div className="card-b">
              {saved && <AlertBox kind="ok">Feedback saved</AlertBox>}
              <form onSubmit={saveFeedback}>
                <div className="field"><label>Verdict label</label>
                  <select value={label} onChange={(e) => setLabel(e.target.value)}>
                    <option value="">— no change —</option>
                    <option value="true_positive">True positive</option>
                    <option value="false_positive">False positive</option>
                    <option value="benign">Benign</option>
                    <option value="malicious">Malicious</option>
                  </select></div>
                <div className="field"><label>Note</label><input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Optional context" /></div>
                <button className="btn btn-primary" type="submit">Save feedback</button>
              </form>
            </div>
          </div>
        </div>
      </div>
    </Shell>
  );
}

export default function ReportPage() {
  return <Suspense fallback={<div className="login-wrap"><span className="spin" /></div>}><ReportInner /></Suspense>;
}
