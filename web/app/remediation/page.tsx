"use client";
import { useEffect, useState } from "react";
import Shell from "@/components/Shell";
import { api } from "@/lib/api";
import { Spinner, AlertBox } from "@/components/ui";

export default function RemediationPage() {
  const [env, setEnv] = useState<any>({});
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  useEffect(() => { api.get("/remediation").then((d: any) => setEnv(d.env || {})).catch(() => {}); }, []);
  const save = async (e: React.FormEvent) => {
    e.preventDefault(); setBusy(true); setMsg("");
    const fd = new FormData(e.currentTarget as HTMLFormElement);
    try { await api.postForm("/remediation", Object.fromEntries(fd)); setMsg("Remediation configuration saved"); }
    catch (e: any) { setMsg(e.message); }
    setBusy(false);
  };

  return (
    <Shell title="Remediation" sub="Post-delivery takedown · opt-in, degrades safely">
      <div className="card" style={{ maxWidth: 820 }}>
        <div className="card-h"><h3>Provider</h3><span className="sub">read-only until enabled</span></div>
        <div className="card-b">
          <AlertBox kind="info">Remediation soft-deletes or moves already-delivered messages via provider APIs. It is <b>disabled by default</b> and never acts during scanning. PhishGuard still analyzes everything read-only.</AlertBox>
          <form onSubmit={save}>
            <label className="check" style={{ marginBottom: 14 }}><input type="checkbox" name="PG_REMEDIATION_ENABLED" defaultChecked={env.PG_REMEDIATION_ENABLED === "true"} /><span>Enable remediation actions</span></label>
            <div className="field"><label>Provider</label>
              <select name="PG_REMEDIATION_PROVIDER" defaultValue={env.PG_REMEDIATION_PROVIDER || ""}>
                <option value="">None</option><option value="m365">Microsoft 365 (Graph)</option><option value="gmail">Gmail (Service Account)</option>
              </select></div>
            <div className="row row-3">
              <div className="field"><label>Tenant ID</label><input name="PG_M365_TENANT_ID" defaultValue={env.PG_M365_TENANT_ID || ""} /></div>
              <div className="field"><label>Client ID</label><input name="PG_M365_CLIENT_ID" defaultValue={env.PG_M365_CLIENT_ID || ""} /></div>
              <div className="field"><label>Client secret</label><input type="password" name="PG_M365_CLIENT_SECRET" defaultValue={env.PG_M365_CLIENT_SECRET || ""} /></div>
            </div>
            <div className="field"><label>Gmail service-account JSON</label><textarea name="PG_GMAIL_SA_JSON" style={{ minHeight: 70 }} defaultValue={env.PG_GMAIL_SA_JSON || ""} /></div>
            <button className="btn btn-primary" type="submit" disabled={busy}>{busy ? <Spinner /> : "Save configuration"}</button>
            {msg && <div style={{ marginTop: 12 }}><AlertBox kind="ok">{msg}</AlertBox></div>}
          </form>
        </div>
      </div>
    </Shell>
  );
}
