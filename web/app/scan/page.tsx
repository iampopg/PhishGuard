"use client";
import { useState } from "react";
import Shell from "@/components/Shell";
import { api, getToken } from "@/lib/api";
import { Report } from "@/lib/types";
import { ReportSummary, Spinner, AlertBox } from "@/components/ui";

export default function ScanPage() {
  const [tab, setTab] = useState("eml");
  const [file, setFile] = useState<File | null>(null);
  const [text, setText] = useState("");
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Report | null>(null);
  const [err, setErr] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setErr(""); setResult(null);
    try {
      const fd = new FormData();
      if (tab === "eml" && file) fd.append("eml", file);
      else if (tab === "text") fd.append("text", text);
      else if (tab === "url") fd.append("url", url);
      else throw new Error("Choose a file, text or URL");
      const res = await fetch("/api/scan", { method: "POST", headers: { Authorization: `Bearer ${getToken()}` }, body: fd });
      if (!res.ok) throw new Error("Scan failed");
      setResult(await res.json());
    } catch (e: any) { setErr(e.message || "Scan failed"); }
    setBusy(false);
  };

  return (
    <Shell title="Scan" sub="Analyze a message, pasted text, or a URL on demand">
      <div className="grid" style={{ maxWidth: 900 }}>
        <div className="card">
          <div className="card-h"><h3>New analysis</h3></div>
          <div className="card-b">
            <div className="tabs">
              <div className={`tab ${tab === "eml" ? "active" : ""}`} onClick={() => setTab("eml")}>Upload .eml</div>
              <div className={`tab ${tab === "text" ? "active" : ""}`} onClick={() => setTab("text")}>Paste text</div>
              <div className={`tab ${tab === "url" ? "active" : ""}`} onClick={() => setTab("url")}>Scan URL</div>
            </div>
            <form onSubmit={submit}>
              {tab === "eml" && <div className="field"><label>Email file (.eml)</label><input type="file" onChange={(e) => setFile(e.target.files?.[0] || null)} /></div>}
              {tab === "text" && <div className="field"><label>Message body / headers</label><textarea value={text} onChange={(e) => setText(e.target.value)} placeholder="Paste raw email text or headers here…" /></div>}
              {tab === "url" && <div className="field"><label>URL to inspect</label><input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com/login" /></div>}
              <button className="btn btn-primary" type="submit" disabled={busy}>{busy ? <Spinner /> : "Analyze"}</button>
            </form>
          </div>
        </div>
        {err && <AlertBox kind="err">{err}</AlertBox>}
        {result && (
          <div style={{ marginTop: 18 }}>
            <div className="card-h" style={{ background: "var(--surface)", borderRadius: 14, border: "1px solid var(--border)", marginBottom: 14, padding: "12px 18px" }}>
              <h3 style={{ margin: 0, fontSize: 14 }}>Result</h3>
              <a className="btn btn-ghost btn-sm" href={`/report?id=${result.report_id}`}>Open full report</a>
            </div>
            <ReportSummary r={result} full />
          </div>
        )}
      </div>
    </Shell>
  );
}
