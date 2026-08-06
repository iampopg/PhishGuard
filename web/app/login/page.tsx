"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/components/AuthProvider";
import { getToken } from "@/lib/api";
import { AlertBox } from "@/components/ui";

export default function Login() {
  const { login, token } = useAuth();
  const router = useRouter();
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => { if (token) router.replace("/dashboard"); }, [token]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setErr("");
    try { await login(u, p); router.replace("/dashboard"); }
    catch (e: any) { setErr(e.message || "Login failed"); setBusy(false); }
  };

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <div className="brand" style={{ justifyContent: "center", marginBottom: 22 }}>
          <div className="logo">P</div>
          <div><div className="name">PhishGuard</div><div className="sub">Detection Engine</div></div>
        </div>
        {err && <AlertBox kind="err">{err}</AlertBox>}
        <label style={{ display: "block", fontSize: 12.5, fontWeight: 600, color: "var(--muted)", margin: "14px 0 6px" }}>Username</label>
        <input value={u} onChange={(e) => setU(e.target.value)} placeholder="admin" autoComplete="username" />
        <label style={{ display: "block", fontSize: 12.5, fontWeight: 600, color: "var(--muted)", margin: "14px 0 6px" }}>Password</label>
        <input type="password" value={p} onChange={(e) => setP(e.target.value)} placeholder="••••••••" autoComplete="current-password" />
        <button className="btn btn-primary" style={{ width: "100%", marginTop: 20 }} disabled={busy} type="submit">
          {busy ? <span className="spin" /> : "Sign in"}
        </button>
        <div className="muted" style={{ textAlign: "center", marginTop: 18, fontSize: 11.5 }}>Offline-first · your credentials never leave this machine</div>
      </form>
    </div>
  );
}
