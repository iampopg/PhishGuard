"use client";
import { useEffect, useState } from "react";
import Shell from "@/components/Shell";
import { api } from "@/lib/api";
import { Spinner, AlertBox } from "@/components/ui";

export default function ExportPage() {
  const [env, setEnv] = useState<any>({});
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  useEffect(() => { api.get("/export").then((d: any) => setEnv(d.env || {})).catch(() => {}); }, []);
  const submit = async (e: React.FormEvent, action: "save" | "test") => {
    e.preventDefault(); setBusy(true); setMsg("");
    const fd = new FormData(e.currentTarget as HTMLFormElement);
    try { await api.postForm("/export", { ...Object.fromEntries(fd), action }); setMsg(action === "test" ? "Test export sent" : "Export configuration saved"); }
    catch (e: any) { setMsg(e.message); }
    setBusy(false);
  };

  return (
    <Shell title="Export / SIEM" sub="Stream detections to your stack">
      <div className="card" style={{ maxWidth: 820 }}>
        <div className="card-h"><h3>Destinations</h3><span className="sub">disabled by default</span></div>
        <div className="card-b">
          <form onSubmit={(e) => submit(e, "save")}>
            <label className="check" style={{ marginBottom: 14 }}><input type="checkbox" name="PG_EXPORT_ENABLED" defaultChecked={env.PG_EXPORT_ENABLED === "true"} /><span>Enable export on every analysis</span></label>
            <label className="check" style={{ marginBottom: 14 }}><input type="checkbox" name="PG_EXPORT_CEF" defaultChecked={env.PG_EXPORT_CEF !== "false"} /><span>Syslog format: CEF (else JSON)</span></label>
            <div className="row row-2">
              <div className="field"><label>Syslog address</label><input name="PG_EXPORT_SYSLOG_ADDR" defaultValue={env.PG_EXPORT_SYSLOG_ADDR || ""} placeholder="udp://localhost:514" /></div>
              <div className="field"><label>Webhook URL</label><input name="PG_EXPORT_WEBHOOK_URL" defaultValue={env.PG_EXPORT_WEBHOOK_URL || ""} placeholder="https://hooks.example.com/..." /></div>
            </div>
            <div className="field"><label>Minimum severity to export</label>
              <select name="PG_EXPORT_MIN_SEVERITY" defaultValue={env.PG_EXPORT_MIN_SEVERITY || "medium"}>
                {["low", "medium", "high", "critical"].map((s) => <option key={s} value={s}>{s}</option>)}
              </select></div>
            <div className="actions">
              <button className="btn btn-primary" type="submit" disabled={busy}>{busy ? <Spinner /> : "Save configuration"}</button>
              <button className="btn btn-ghost" type="submit" disabled={busy} onClick={(e) => submit(e, "test")}>Send test export</button>
            </div>
            {msg && <div style={{ marginTop: 12 }}><AlertBox kind="ok">{msg}</AlertBox></div>}
          </form>
        </div>
      </div>
    </Shell>
  );
}
