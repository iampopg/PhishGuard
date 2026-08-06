"use client";
import { useEffect, useState } from "react";
import Shell from "@/components/Shell";
import { api } from "@/lib/api";
import { Rule } from "@/lib/types";
import { Spinner } from "@/components/ui";

export default function RulesPage() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [th, setTh] = useState<any>({});
  const [loading, setLoading] = useState(true);
  useEffect(() => { api.get("/rules").then((d: any) => { setRules(d.rules); setTh(d.thresholds); setLoading(false); }).catch(() => setLoading(false)); }, []);

  return (
    <Shell title="Detection Rules" sub="Detections-as-code · actions on verdict">
      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", alignItems: "start" }}>
        <div className="card"><div className="card-h"><h3>Scoring thresholds</h3></div><div className="card-b">
          <div className="kv">
            <dt>Suspicious ≥</dt><dd>{th.suspicious}</dd>
            <dt>Phishing ≥</dt><dd>{th.phishing}</dd>
            <dt>Malicious ≥</dt><dd>{th.malicious}</dd>
            <dt>BEC baseline</dt><dd>{th.behavioral_baseline_days} days</dd>
          </div>
          <p className="muted small" style={{ marginTop: 10 }}>Adjust in <a href="/settings">Settings</a>.</p>
        </div></div>
        <div className="card"><div className="card-h"><h3>How rules work</h3></div><div className="card-b">
          <p className="muted small" style={{ margin: 0 }}>Each rule watches an analyzer's findings. When a finding meets the severity threshold, the linked <b>action</b> fires — quarantining, notifying the SOC, routing to review, or triggering training. Rules are code in <span className="mono">rules/defaults/*.yaml</span> and fully auditable.</p>
        </div></div>
      </div>
      <div className="card" style={{ marginTop: 18 }}>
        <div className="card-h"><h3>Active rules</h3><span className="sub">{loading ? <Spinner /> : `${rules.length} loaded`}</span></div>
        <div className="card-b" style={{ padding: 0 }}>
          <table className="table">
            <thead><tr><th>Rule</th><th>Scope</th><th>Condition</th><th>Action</th></tr></thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id}>
                  <td><b>{r.id}</b><br /><small className="muted">{r.description}</small></td>
                  <td>{r.analyzer ? <span className="pill">{r.analyzer}</span> : <span className="muted">any</span>}</td>
                  <td className="small muted">severity ≥ <b style={{ color: "var(--text)" }}>{r.severity_at_least}</b>{r.title_contains ? ` · title contains "${r.title_contains}"` : ""}</td>
                  <td><span className={`sev ${r.action === "quarantine" ? "high" : r.action === "notify_soc" || r.action === "review" ? "medium" : "info"}`}>{r.action}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </Shell>
  );
}
