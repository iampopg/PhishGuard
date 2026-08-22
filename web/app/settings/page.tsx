"use client";
import { useEffect, useRef, useState } from "react";
import Shell from "@/components/Shell";
import { api } from "@/lib/api";
import { Spinner, AlertBox } from "@/components/ui";

const ENRICH: Record<string, { provider: string; enable: string }> = {
  PG_VT_API_KEY: { provider: "vt", enable: "PG_VT_ENABLED" },
  PG_GSB_API_KEY: { provider: "gsb", enable: "PG_GSB_ENABLED" },
  PG_CLAMAV_HOST: { provider: "clamav", enable: "PG_CLAMAV_ENABLED" },
  PG_SANDBOX_API_KEY: { provider: "sandbox", enable: "PG_SANDBOX_ENABLED" },
  PG_SANDBOX_URL: { provider: "sandbox", enable: "PG_SANDBOX_ENABLED" },
};

function Toggle({ name, label, checked, onChange }: { name: string; label: string; checked: boolean; onChange?: (v: boolean) => void }) {
  return (
    <label className="check" style={{ marginBottom: 10 }}>
      <input type="hidden" name={name} value="false" />
      <input type="checkbox" name={name} value="true" defaultChecked={checked}
        onChange={(e) => onChange && onChange(e.target.checked)} />
      <span>{label}</span>
    </label>
  );
}

export default function SettingsPage() {
  const [cfg, setCfg] = useState<any>({});
  const [env, setEnv] = useState<any>({});
  const [monitorOn, setMonitorOn] = useState(false);
  const [busy, setBusy] = useState(false);
  const [flash, setFlash] = useState("");
  const [tab, setTab] = useState("detection");
  const [aiProviders, setAiProviders] = useState<any[]>([]);
  const [status, setStatus] = useState<Record<string, { state: "idle" | "testing" | "ok" | "err"; msg?: string }>>({});
  const formRef = useRef<HTMLFormElement>(null);

  useEffect(() => { api.get("/settings").then((d: any) => { setCfg(d.config || {}); setEnv(d.env || {}); }).catch(() => {}); }, []);
  useEffect(() => { api.get("/mailbox").then((d: any) => setMonitorOn(!!d.monitor)).catch(() => {}); }, []);
  useEffect(() => {
    api.get("/ai/providers").then((d: any) => {
      const providers = d.providers || {};
      const auto = d.auto;
      const list: any[] = [];
      const order = ["local", "gemini", "claude", "kilo"];
      for (const name of order) {
        const p = providers[name];
        if (!p) continue;
        list.push({
          name,
          model: p.model,
          available: p.available || (p.key && p.key.length > 0),
          auto: auto === name,
          local_models: p.local_models,
        });
      }
      setAiProviders(list);
    }).catch(() => {});
  }, [env]);

  // Auto-test enrichment providers that have credentials but aren't enabled yet,
  // so a working key turns the feature on automatically.
  const autoTested = useRef<Set<string>>(new Set());
  useEffect(() => {
    const tryAuto = (p: string, payload: Record<string, string>, flag: string) => {
      if (autoTested.current.has(p)) return;
      autoTested.current.add(p);
      runTest(p, payload, flag);
    };
    if (env.PG_VT_API_KEY)
      tryAuto("vt", { provider: "vt", key: env.PG_VT_API_KEY }, "PG_VT_ENABLED");
    if (env.PG_GSB_API_KEY)
      tryAuto("gsb", { provider: "gsb", key: env.PG_GSB_API_KEY }, "PG_GSB_ENABLED");
    if (env.PG_CLAMAV_HOST)
      tryAuto("clamav", { provider: "clamav", host: env.PG_CLAMAV_HOST }, "PG_CLAMAV_ENABLED");
    if (env.PG_SANDBOX_API_KEY && env.PG_SANDBOX_URL)
      tryAuto("sandbox", { provider: "sandbox", key: env.PG_SANDBOX_API_KEY, url: env.PG_SANDBOX_URL }, "PG_SANDBOX_ENABLED");
  }, [env]);

  const bv = (k: string) => env[k] !== "false";  // enabled by default; user unchecks to disable
  const iv = (k: string) => (env[k] !== undefined && env[k] !== "" ? env[k] : cfg[k] ?? "");
  const sv = (k: string) => (env[k] !== undefined ? env[k] : (cfg[k] ?? ""));
  const secrets = ["PG_VT_API_KEY", "PG_GSB_API_KEY", "PG_SANDBOX_API_KEY", "PG_SANDBOX_URL", "PG_IMAP_PASSWORD", "PG_WEB_PASSWORD", "PG_WEB_SECRET_KEY"];

  const saveAll = async () => {
    if (!formRef.current) return;
    setBusy(true); setFlash("");
    const fd = new FormData(formRef.current);
    try {
      await api.postForm("/settings", Object.fromEntries(fd));
      setEnv(Object.fromEntries(fd));
    } catch (e: any) { setFlash(e.message); }
    setBusy(false);
  };

  const runTest = async (provider: string, payload: Record<string, string>, enableFlag: string) => {
    setStatus((s) => ({ ...s, [provider]: { state: "testing" } }));
    try {
      const d: any = await api.postForm("/enrichment/test", payload);
      setStatus((s) => ({ ...s, [provider]: { state: d.ok ? "ok" : "err", msg: d.message } }));
      await saveFieldFlag(enableFlag, d.ok ? "true" : "false");
    } catch (e: any) {
      setStatus((s) => ({ ...s, [provider]: { state: "err", msg: e.message } }));
    }
  };

  const saveFieldFlag = async (key: string, value: string) => {
    await api.postForm("/settings", { [key]: value });
    setEnv((e: any) => ({ ...e, [key]: value }));
  };

  const onEnrichBlur = (key: string) => {
    saveAll();
    const e = ENRICH[key];
    if (!e) return;
    const payload: Record<string, string> = { provider: e.provider };
    if (e.provider === "clamav") {
      payload.host = (formRef.current?.elements as any)[key]?.value || "";
    } else {
      payload.key = key === "PG_SANDBOX_URL" ? (env.PG_SANDBOX_API_KEY || "") : (formRef.current?.elements as any)[key]?.value || "";
      payload.url = key === "PG_SANDBOX_URL" ? (formRef.current?.elements as any)[key]?.value || "" : (env.PG_SANDBOX_URL || "");
    }
    runTest(e.provider, payload, e.enable);
  };

  const toggleMonitor = async () => {
    setBusy(true);
    try {
      await api.postForm(monitorOn ? "/mailbox/monitor/stop" : "/mailbox/monitor/start", {});
      setMonitorOn(!monitorOn);
      setFlash(monitorOn ? "Monitoring stopped" : "Monitoring started");
    } catch (e: any) { setFlash(e.message); }
    setBusy(false);
  };

  const PROVIDER_LABEL: Record<string, string> = { vt: "VirusTotal", gsb: "Google Safe Browsing", clamav: "ClamAV", sandbox: "Sandbox" };
  const providerEnable = (p: string) =>
    p === "vt" ? "PG_VT_ENABLED" : p === "gsb" ? "PG_GSB_ENABLED" : p === "clamav" ? "PG_CLAMAV_ENABLED" : "PG_SANDBOX_ENABLED";

  const StatusBadge = ({ provider }: { provider: string }) => {
    const noKey = provider === "vt" ? !env.PG_VT_API_KEY
      : provider === "gsb" ? !env.PG_GSB_API_KEY
      : provider === "clamav" ? !env.PG_CLAMAV_HOST
      : provider === "sandbox" ? (!env.PG_SANDBOX_API_KEY || !env.PG_SANDBOX_URL)
      : false;
    if (noKey && bv(providerEnable(provider)))
      return <span className="env-status warn">⚠ Action required: add your {PROVIDER_LABEL[provider]} key</span>;
    const s = status[provider];
    if (!s || s.state === "idle") return null;
    if (s.state === "testing") return <span className="env-status testing">testing…</span>;
    if (s.state === "ok") return <span className="env-status ok">✓ {s.msg}</span>;
    return <span className="env-status err">✗ {s.msg}</span>;
  };

  const TABS = [
    { id: "detection", label: "Detection" },
    { id: "enrichment", label: "Enrichment" },
    { id: "ai", label: "AI" },
    { id: "thresholds", label: "Thresholds" },
  ];

  return (
    <Shell title="Settings" sub="Engine behaviour, enrichment & server (changes auto-save)">
      <div className="settings-tabs">
        {TABS.map((t) => (
          <button key={t.id} className={`settings-tab ${tab === t.id ? "active" : ""}`} onClick={() => setTab(t.id)}>{t.label}</button>
        ))}
      </div>
      <form ref={formRef} onSubmit={(e) => { e.preventDefault(); saveAll(); }}>
        {tab === "detection" && (
          <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", alignItems: "start" }}>
            <div className="card"><div className="card-h"><h3>Detection engine</h3></div><div className="card-b">
              <Toggle name="PG_DNS_CHECKS_ENABLED" label="DNS / reputation checks" checked={bv("PG_DNS_CHECKS_ENABLED")} onChange={() => saveAll()} />
              <Toggle name="PG_BEHAVIORAL_ENABLED" label="Behavioral BEC baseline" checked={bv("PG_BEHAVIORAL_ENABLED")} onChange={() => saveAll()} />
              <Toggle name="PG_SANDBOX_ENABLED" label="Sandbox execution" checked={bv("PG_SANDBOX_ENABLED")} onChange={() => saveAll()} />
              <Toggle name="PG_CLAMAV_ENABLED" label="ClamAV attachment scan" checked={bv("PG_CLAMAV_ENABLED")} onChange={() => saveAll()} />
              <hr style={{ border: "none", borderTop: "1px solid var(--border)", margin: "14px 0" }} />
              <Toggle name="PG_VT_ENABLED" label="VirusTotal enrichment" checked={bv("PG_VT_ENABLED")} onChange={() => saveAll()} />
              <Toggle name="PG_GSB_ENABLED" label="Google Safe Browsing" checked={bv("PG_GSB_ENABLED")} onChange={() => saveAll()} />
            </div></div>
            <div className="card"><div className="card-h"><h3>Mailbox & response</h3></div><div className="card-b">
              <Toggle name="PG_IMAP_USE_SSL" label="IMAP SSL/TLS" checked={bv("PG_IMAP_USE_SSL")} onChange={() => saveAll()} />
              <Toggle name="PG_IMAP_UNSEEN_ONLY" label="Unseen only" checked={bv("PG_IMAP_UNSEEN_ONLY")} onChange={() => saveAll()} />
              <Toggle name="PG_IMAP_MARK_READ" label="Mark read after scan" checked={bv("PG_IMAP_MARK_READ")} onChange={() => saveAll()} />
              <div className="monitor-toggle">
                <span>Continuous monitoring</span>
                <button type="button" className={`toggle-btn ${monitorOn ? "on" : ""}`} onClick={toggleMonitor} disabled={busy}>
                  <span className="knob" />{monitorOn ? "ON" : "OFF"}
                </button>
              </div>
              <hr style={{ border: "none", borderTop: "1px solid var(--border)", margin: "14px 0" }} />
              <Toggle name="PG_REMEDIATION_ENABLED" label="Remediation enabled" checked={bv("PG_REMEDIATION_ENABLED")} onChange={() => saveAll()} />
              <Toggle name="PG_EXPORT_ENABLED" label="Export enabled" checked={bv("PG_EXPORT_ENABLED")} onChange={() => saveAll()} />
              <Toggle name="PG_EXPORT_CEF" label="Export as CEF" checked={bv("PG_EXPORT_CEF")} onChange={() => saveAll()} />
            </div></div>
          </div>
        )}

        {tab === "enrichment" && (
          <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", alignItems: "start" }}>
            <div className="card"><div className="card-h"><h3>Threat intelligence</h3></div><div className="card-b">
              <div className="field"><label>Trusted domains</label><input name="PG_TRUSTED_DOMAINS" defaultValue={sv("PG_TRUSTED_DOMAINS")} onBlur={saveAll} /></div>
              <div className="field"><label>Org profile path</label><input name="PG_ORG_PROFILE_PATH" defaultValue={sv("PG_ORG_PROFILE_PATH")} onBlur={saveAll} /></div>
              <div className="field"><label>Report directory</label><input name="PG_REPORT_DIR" defaultValue={sv("PG_REPORT_DIR")} onBlur={saveAll} /></div>
              <div className="field"><label>ClamAV host</label>
                <input name="PG_CLAMAV_HOST" defaultValue={sv("PG_CLAMAV_HOST")} onBlur={() => onEnrichBlur("PG_CLAMAV_HOST")} />
                <StatusBadge provider="clamav" /></div>
              <div className="field"><label>Sandbox provider</label><input name="PG_SANDBOX_PROVIDER" defaultValue={sv("PG_SANDBOX_PROVIDER")} onBlur={saveAll} /></div>
            </div></div>
            <div className="card"><div className="card-h"><h3>API keys</h3></div><div className="card-b">
              {secrets.map((k) => (
                <div className="field" key={k}>
                  <label>{k.replace("PG_", "").replace(/_/g, " ").toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase())}</label>
                  <input type="password" name={k} defaultValue={env[k] || ""} placeholder="••••••••"
                    onBlur={() => onEnrichBlur(k)} />
                  {ENRICH[k] && <StatusBadge provider={ENRICH[k].provider} />}
                </div>
              ))}
            </div></div>
          </div>
        )}

        {tab === "ai" && (
          <div className="card"><div className="card-h"><h3>AI analysis</h3></div><div className="card-b">
            <div className="ai-providers">
              {aiProviders.map((p: any) => (
                <div key={p.name} className={`ai-provider ${p.available ? "available" : ""} ${p.auto ? "auto" : ""}`}>
                  <span className={`dot ${p.available ? "" : "warn"}`}></span>
                  <span className="ai-provider-name">{p.name}</span>
                  <span className="ai-provider-model">{p.model}</span>
                  {p.name === "local" && p.local_models && <span className="ai-provider-models">{p.local_models.join(", ")}</span>}
                  {p.auto && <span className="ai-provider-auto">auto</span>}
                  {!p.available && <span className="ai-provider-note">{p.name === "local" ? "not detected" : "no key"}</span>}
                </div>
              ))}
            </div>
            <hr style={{ border: "none", borderTop: "1px solid var(--border)", margin: "14px 0" }} />
            <div className="field"><label>Local AI URL (Ollama)</label><input name="PG_AI_LOCAL_URL" defaultValue={sv("PG_AI_LOCAL_URL")} onBlur={saveAll} /></div>
            <div className="field"><label>Local model</label><input name="PG_AI_LOCAL_MODEL" defaultValue={sv("PG_AI_LOCAL_MODEL")} onBlur={saveAll} /></div>
            <div className="field"><label>Gemini API key</label><input type="password" name="PG_AI_GEMINI_KEY" defaultValue={env.PG_AI_GEMINI_KEY || ""} placeholder="••••••••" onBlur={saveAll} /></div>
            <div className="field"><label>Claude API key</label><input type="password" name="PG_AI_CLAUDE_KEY" defaultValue={env.PG_AI_CLAUDE_KEY || ""} placeholder="••••••••" onBlur={saveAll} /></div>
            <div className="field"><label>kilo.ai API key</label><input type="password" name="PG_AI_KILO_KEY" defaultValue={env.PG_AI_KILO_KEY || ""} placeholder="••••••••" onBlur={saveAll} /></div>
          </div></div>
        )}

        {tab === "thresholds" && (
          <div className="card"><div className="card-h"><h3>Thresholds & intervals</h3></div><div className="card-b">
            <div className="row row-3">
              <div className="field"><label>Suspicious ≥</label><input name="PG_THRESHOLD_SUSPICIOUS" defaultValue={iv("PG_THRESHOLD_SUSPICIOUS")} onBlur={saveAll} /></div>
              <div className="field"><label>Phishing ≥</label><input name="PG_THRESHOLD_PHISHING" defaultValue={iv("PG_THRESHOLD_PHISHING")} onBlur={saveAll} /></div>
              <div className="field"><label>Malicious ≥</label><input name="PG_THRESHOLD_MALICIOUS" defaultValue={iv("PG_THRESHOLD_MALICIOUS")} onBlur={saveAll} /></div>
            </div>
            <div className="row row-3">
              <div className="field"><label>Monitor (s)</label><input name="PG_MONITOR_INTERVAL" defaultValue={iv("PG_MONITOR_INTERVAL")} onBlur={saveAll} /></div>
              <div className="field"><label>BEC baseline (d)</label><input name="PG_BEHAVIORAL_BASELINE_DAYS" defaultValue={iv("PG_BEHAVIORAL_BASELINE_DAYS")} onBlur={saveAll} /></div>
              <div className="field"><label>IMAP port</label><input name="PG_IMAP_PORT" defaultValue={iv("PG_IMAP_PORT")} onBlur={saveAll} /></div>
            </div>
            <div className="row row-2">
              <div className="field"><label>ClamAV port</label><input name="PG_CLAMAV_PORT" defaultValue={iv("PG_CLAMAV_PORT")} onBlur={saveAll} /></div>
              <div className="field"><label>Web port</label><input name="PG_WEB_PORT" defaultValue={iv("PG_WEB_PORT")} onBlur={saveAll} /></div>
            </div>
          </div></div>
        )}
      </form>
      <div style={{ marginTop: 12 }}>{busy && <span className="env-status testing">saving…</span>}{flash && <AlertBox kind="ok">{flash}</AlertBox>}</div>
    </Shell>
  );
}
