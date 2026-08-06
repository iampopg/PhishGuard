"use client";
import { useEffect, useState } from "react";
import Shell from "@/components/Shell";
import { api } from "@/lib/api";
import { Spinner, AlertBox } from "@/components/ui";

function Toggle({ name, label, checked }: { name: string; label: string; checked: boolean }) {
  return (
    <label className="check" style={{ marginBottom: 10 }}>
      <input type="hidden" name={name} value="false" />
      <input type="checkbox" name={name} value="true" defaultChecked={checked} />
      <span>{label}</span>
    </label>
  );
}

export default function SettingsPage() {
  const [cfg, setCfg] = useState<any>({});
  const [env, setEnv] = useState<any>({});
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [monitorOn, setMonitorOn] = useState(false);

  useEffect(() => { api.get("/settings").then((d: any) => { setCfg(d.config || {}); setEnv(d.env || {}); }).catch(() => {}); }, []);
  useEffect(() => { api.get("/mailbox").then((d: any) => setMonitorOn(!!d.monitor)).catch(() => {}); }, []);

  const toggleMonitor = async () => {
    setBusy(true); setMsg("");
    try {
      await api.postForm(monitorOn ? "/mailbox/monitor/stop" : "/mailbox/monitor/start", {});
      setMonitorOn(!monitorOn);
      setMsg(monitorOn ? "Monitoring stopped" : "Monitoring started");
    } catch (e: any) { setMsg(e.message); }
    setBusy(false);
  };
  const bv = (k: string) => env[k] === "true" || cfg[k] === true;
  const iv = (k: string) => (env[k] !== undefined && env[k] !== "" ? env[k] : cfg[k] ?? "");
  const sv = (k: string) => env[k] !== undefined ? env[k] : (cfg[k] ?? "");

  const save = async (e: React.FormEvent) => {
    e.preventDefault(); setBusy(true); setMsg("");
    const fd = new FormData(e.currentTarget as HTMLFormElement);
    try { await api.postForm("/settings", Object.fromEntries(fd)); setMsg("Settings saved"); }
    catch (e: any) { setMsg(e.message); }
    setBusy(false);
  };

  const secrets = ["PG_VT_API_KEY", "PG_GSB_API_KEY", "PG_SANDBOX_API_KEY", "PG_SANDBOX_URL", "PG_IMAP_PASSWORD", "PG_WEB_PASSWORD", "PG_WEB_SECRET_KEY"];

  return (
    <Shell title="Settings" sub="Engine behaviour, enrichment & server">
      <form onSubmit={save}>
        <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", alignItems: "start" }}>
          <div className="card"><div className="card-h"><h3>Detection engine</h3></div><div className="card-b">
            <Toggle name="PG_DNS_CHECKS_ENABLED" label="DNS / reputation checks" checked={bv("PG_DNS_CHECKS_ENABLED")} />
            <Toggle name="PG_BEHAVIORAL_ENABLED" label="Behavioral BEC baseline" checked={bv("PG_BEHAVIORAL_ENABLED")} />
            <Toggle name="PG_SANDBOX_ENABLED" label="Sandbox execution" checked={bv("PG_SANDBOX_ENABLED")} />
            <Toggle name="PG_CLAMAV_ENABLED" label="ClamAV attachment scan" checked={bv("PG_CLAMAV_ENABLED")} />
            <hr style={{ border: "none", borderTop: "1px solid var(--border)", margin: "14px 0" }} />
            <Toggle name="PG_VT_ENABLED" label="VirusTotal enrichment" checked={bv("PG_VT_ENABLED")} />
            <Toggle name="PG_GSB_ENABLED" label="Google Safe Browsing" checked={bv("PG_GSB_ENABLED")} />
          </div></div>
          <div className="card"><div className="card-h"><h3>Mailbox & response</h3></div><div className="card-b">
            <Toggle name="PG_IMAP_USE_SSL" label="IMAP SSL/TLS" checked={bv("PG_IMAP_USE_SSL")} />
            <Toggle name="PG_IMAP_UNSEEN_ONLY" label="Unseen only" checked={bv("PG_IMAP_UNSEEN_ONLY")} />
            <Toggle name="PG_IMAP_MARK_READ" label="Mark read after scan" checked={bv("PG_IMAP_MARK_READ")} />
            <div className="monitor-toggle">
              <span>Continuous monitoring</span>
              <button type="button" className={`toggle-btn ${monitorOn ? "on" : ""}`} onClick={toggleMonitor} disabled={busy}>
                <span className="knob" />{monitorOn ? "ON" : "OFF"}
              </button>
            </div>
            <hr style={{ border: "none", borderTop: "1px solid var(--border)", margin: "14px 0" }} />
            <Toggle name="PG_REMEDIATION_ENABLED" label="Remediation enabled" checked={bv("PG_REMEDIATION_ENABLED")} />
            <Toggle name="PG_EXPORT_ENABLED" label="Export enabled" checked={bv("PG_EXPORT_ENABLED")} />
            <Toggle name="PG_EXPORT_CEF" label="Export as CEF" checked={bv("PG_EXPORT_CEF")} />
          </div></div>
          <div className="card"><div className="card-h"><h3>Thresholds & intervals</h3></div><div className="card-b">
            <div className="row row-3">
              <div className="field"><label>Suspicious ≥</label><input name="PG_THRESHOLD_SUSPICIOUS" defaultValue={iv("PG_THRESHOLD_SUSPICIOUS")} /></div>
              <div className="field"><label>Phishing ≥</label><input name="PG_THRESHOLD_PHISHING" defaultValue={iv("PG_THRESHOLD_PHISHING")} /></div>
              <div className="field"><label>Malicious ≥</label><input name="PG_THRESHOLD_MALICIOUS" defaultValue={iv("PG_THRESHOLD_MALICIOUS")} /></div>
            </div>
            <div className="row row-3">
              <div className="field"><label>Monitor (s)</label><input name="PG_MONITOR_INTERVAL" defaultValue={iv("PG_MONITOR_INTERVAL")} /></div>
              <div className="field"><label>BEC baseline (d)</label><input name="PG_BEHAVIORAL_BASELINE_DAYS" defaultValue={iv("PG_BEHAVIORAL_BASELINE_DAYS")} /></div>
              <div className="field"><label>IMAP port</label><input name="PG_IMAP_PORT" defaultValue={iv("PG_IMAP_PORT")} /></div>
            </div>
            <div className="row row-2">
              <div className="field"><label>ClamAV port</label><input name="PG_CLAMAV_PORT" defaultValue={iv("PG_CLAMAV_PORT")} /></div>
              <div className="field"><label>Web port</label><input name="PG_WEB_PORT" defaultValue={iv("PG_WEB_PORT")} /></div>
            </div>
          </div></div>
          <div className="card"><div className="card-h"><h3>Enrichment keys & paths</h3></div><div className="card-b">
            <div className="field"><label>Trusted domains</label><input name="PG_TRUSTED_DOMAINS" defaultValue={sv("PG_TRUSTED_DOMAINS")} /></div>
            <div className="field"><label>Org profile path</label><input name="PG_ORG_PROFILE_PATH" defaultValue={sv("PG_ORG_PROFILE_PATH")} /></div>
            <div className="field"><label>Report directory</label><input name="PG_REPORT_DIR" defaultValue={sv("PG_REPORT_DIR")} /></div>
            <div className="field"><label>ClamAV host</label><input name="PG_CLAMAV_HOST" defaultValue={sv("PG_CLAMAV_HOST")} /></div>
            <div className="field"><label>Sandbox provider</label><input name="PG_SANDBOX_PROVIDER" defaultValue={sv("PG_SANDBOX_PROVIDER")} /></div>
            <div className="field"><label>Log level</label>
              <select name="PG_LOG_LEVEL" defaultValue={sv("PG_LOG_LEVEL") || "INFO"}>{["DEBUG", "INFO", "WARNING", "ERROR"].map((l) => <option key={l}>{l}</option>)}</select></div>
            {secrets.map((k) => (
              <div className="field" key={k}><label>{k.replace("PG_", "").replace(/_/g, " ").toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase())}</label><input type="password" name={k} defaultValue={env[k] || ""} placeholder="••••••••" /></div>
            ))}
          </div></div>
        </div>
        <div className="actions" style={{ marginTop: 4 }}><button className="btn btn-primary" type="submit" disabled={busy}>{busy ? <Spinner /> : "Save settings"}</button></div>
        {msg && <div style={{ marginTop: 12 }}><AlertBox kind="ok">{msg}</AlertBox></div>}
      </form>
    </Shell>
  );
}
