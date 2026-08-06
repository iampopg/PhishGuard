"use client";
import { useEffect, useState } from "react";
import Shell from "@/components/Shell";
import { api } from "@/lib/api";
import { Spinner, AlertBox } from "@/components/ui";

function Field({ label, hint, value, onChange }: { label: string; hint?: string; value: string; onChange: (v: string) => void }) {
  return (
    <div className="field"><label>{label}</label><input value={value} onChange={(e) => onChange(e.target.value)} />
      {hint && <div className="hint">{hint}</div>}</div>
  );
}

export default function OrgPage() {
  const [org, setOrg] = useState<any>({});
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  useEffect(() => { api.get("/org").then((d: any) => setOrg(d.org || {})).catch(() => {}); }, []);
  const j = (k: string) => (org[k] || []).join(", ");
  const set = (k: string, v: string) => setOrg({ ...org, [k]: v.split(",").map((s) => s.trim()).filter(Boolean) });

  const save = async (e: React.FormEvent) => {
    e.preventDefault(); setBusy(true); setMsg("");
    try { await api.postForm("/org", {
      protected_domains: j("protected_domains"), vip_names: j("vip_names"), brand_keywords: j("brand_keywords"),
      brand_domains: j("brand_domains"), trusted_domains: j("trusted_domains"),
    }); setMsg("Organization profile saved"); }
    catch (e: any) { setMsg(e.message); }
    setBusy(false);
  };

  return (
    <Shell title="Organization Profile" sub="Tunes detection to your people & brands">
      <div className="card" style={{ maxWidth: 820 }}>
        <div className="card-h"><h3>Context</h3></div>
        <div className="card-b">
          <form onSubmit={save}>
            <Field label="Protected domains (your org)" value={j("protected_domains")} onChange={(v) => set("protected_domains", v)} />
            <Field label="VIP names (executives / finance)" value={j("vip_names")} onChange={(v) => set("vip_names", v)} />
            <Field label="Brand keywords" value={j("brand_keywords")} onChange={(v) => set("brand_keywords", v)} />
            <Field label="Brand domains" value={j("brand_domains")} onChange={(v) => set("brand_domains", v)} />
            <Field label="Trusted domains" hint="Domains treated as lower-risk senders" value={j("trusted_domains")} onChange={(v) => set("trusted_domains", v)} />
            <button className="btn btn-primary" type="submit" disabled={busy}>{busy ? <Spinner /> : "Save profile"}</button>
            {msg && <div style={{ marginTop: 12 }}><AlertBox kind="ok">{msg}</AlertBox></div>}
          </form>
        </div>
      </div>
    </Shell>
  );
}
