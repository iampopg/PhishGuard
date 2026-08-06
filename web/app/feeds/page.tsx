"use client";
import { useEffect, useState } from "react";
import Shell from "@/components/Shell";
import { api } from "@/lib/api";
import { Spinner, AlertBox } from "@/components/ui";

export default function FeedsPage() {
  const [info, setInfo] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  useEffect(() => { api.get("/feeds").then(setInfo).catch(() => setInfo({})); }, []);
  const update = async () => {
    setBusy(true); setMsg("");
    try { const r: any = await api.postForm("/feeds/update", {}); setInfo(r); setMsg("Feeds updated"); }
    catch (e: any) { setMsg(e.message); }
    setBusy(false);
  };

  return (
    <Shell title="Threat Feeds" sub="Free blocklists: URLhaus & OpenPhish">
      <div className="card" style={{ maxWidth: 760 }}>
        <div className="card-h"><h3>Intelligence sources</h3><button className="btn btn-primary btn-sm" onClick={update} disabled={busy}>{busy ? <Spinner /> : "Update now"}</button></div>
        <div className="card-b">
          {msg && <AlertBox kind="info">{msg}</AlertBox>}
          {info && info.counts && Object.keys(info.counts).length ? (
            <>
              <div className="alert ok" style={{ marginBottom: 16 }}>Last updated {info.time}</div>
              <div className="kv">
                {Object.entries(info.counts).map(([k, v]) => (<div key={k} style={{ display: "contents" }}><dt>{k}</dt><dd>{String(v)} indicators loaded</dd></div>))}
              </div>
            </>
          ) : <div className="empty" style={{ padding: "10px 0 18px" }}>Feeds not fetched yet. Click <b>Update now</b> to pull the latest free blocklists into the local cache.</div>}
          <p className="muted small" style={{ marginTop: 8 }}>These lists power offline URL/domain reputation checks. Optional VirusTotal & Google Safe Browsing enrichment can be enabled in Settings.</p>
        </div>
      </div>
    </Shell>
  );
}
