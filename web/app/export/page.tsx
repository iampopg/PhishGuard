"use client";
import { useEffect, useRef, useState } from "react";
import Shell from "@/components/Shell";
import { api } from "@/lib/api";
import { Spinner, AlertBox } from "@/components/ui";

export default function ExportPage() {
  const [env, setEnv] = useState<any>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState("");
  const [dests, setDests] = useState<any[]>([]);
  const formRef = useRef<HTMLFormElement>(null);

  useEffect(() => { api.get("/export").then((d: any) => setEnv(d.env || {})).catch(() => {}); }, []);

  const saveAll = async (action: "save" | "test" = "save") => {
    if (!formRef.current) return;
    setBusy(action);
    const fd = new FormData(formRef.current);
    try {
      const d: any = await api.postForm("/export", { ...Object.fromEntries(fd), action });
      setEnv(Object.fromEntries(fd));
      if (action === "test") { setMsg("Test export sent"); setDests(d.destinations || []); }
      else setMsg("Saved");
    } catch (e: any) { setMsg(e.message); }
    setBusy(null);
  };

  return (
    <Shell title="Export / SIEM" sub="Stream detections to your stack (changes auto-save)">
      <form ref={formRef} onSubmit={(e) => { e.preventDefault(); saveAll("save"); }}>
        <div className="card" style={{ maxWidth: 820 }}>
          <div className="card-h"><h3>Destinations</h3><span className="sub">disabled by default</span></div>
          <div className="card-b">
            <label className="check" style={{ marginBottom: 14 }}>
              <input type="checkbox" name="PG_EXPORT_ENABLED" defaultChecked={env.PG_EXPORT_ENABLED === "true"} onChange={() => saveAll()} />
              <span>Enable export on every analysis</span>
            </label>
            <label className="check" style={{ marginBottom: 14 }}>
              <input type="checkbox" name="PG_EXPORT_CEF" defaultChecked={env.PG_EXPORT_CEF !== "false"} onChange={() => saveAll()} />
              <span>Syslog format: CEF (else JSON)</span>
            </label>
            <div className="row row-2">
              <div className="field"><label>Syslog address</label>
                <input name="PG_EXPORT_SYSLOG_ADDR" defaultValue={env.PG_EXPORT_SYSLOG_ADDR || ""} placeholder="udp://localhost:514"
                  onBlur={() => saveAll()} /></div>
              <div className="field"><label>Webhook URL</label>
                <input name="PG_EXPORT_WEBHOOK_URL" defaultValue={env.PG_EXPORT_WEBHOOK_URL || ""} placeholder="https://hooks.example.com/..."
                  onBlur={() => saveAll()} /></div>
            </div>
            <div className="field"><label>Minimum severity to export</label>
              <select name="PG_EXPORT_MIN_SEVERITY" defaultValue={env.PG_EXPORT_MIN_SEVERITY || "medium"}
                onChange={() => saveAll()}>
                {["low", "medium", "high", "critical"].map((s) => <option key={s} value={s}>{s}</option>)}
              </select></div>
            <div className="actions">
              <button className="btn btn-ghost" type="button" disabled={busy === "test"} onClick={() => saveAll("test")}>
                {busy === "test" ? <Spinner /> : "Send test export"}
              </button>
            </div>
            {msg && <div style={{ marginTop: 12 }}><AlertBox kind="ok">{msg}</AlertBox></div>}
            {dests.length > 0 && (
              <div style={{ marginTop: 12 }}>
                {dests.map((d, i) => (
                  <div key={i} className={`env-status ${d.ok ? "ok" : "err"}`} style={{ marginBottom: 6 }}>
                    {d.ok ? "✓" : "✗"} {d.type} → {d.target} {d.detail ? `(${d.detail})` : ""}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </form>
    </Shell>
  );
}
