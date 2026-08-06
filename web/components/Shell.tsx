"use client";
import { useEffect, ReactNode, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "./AuthProvider";
import { Icon } from "./icons";
import { api } from "@/lib/api";

const NAV: { href: string; label: string; icon: string; group?: string }[] = [
  { href: "/dashboard", label: "Dashboard", icon: "dash", group: "Analyze" },
  { href: "/reports", label: "Reports", icon: "reports" },
  { href: "/scan", label: "Scan", icon: "scan" },
  { href: "/mailbox", label: "Mailbox", icon: "mailbox", group: "Operations" },
  { href: "/feeds", label: "Threat Feeds", icon: "feeds" },
  { href: "/remediation", label: "Remediation", icon: "remediation" },
  { href: "/export", label: "Export / SIEM", icon: "export" },
  { href: "/org", label: "Org Profile", icon: "org", group: "Configuration" },
  { href: "/rules", label: "Rules", icon: "rules" },
  { href: "/settings", label: "Settings", icon: "settings" },
];

function Sidebar() {
  const path = usePathname();
  const groups: Record<string, typeof NAV> = {};
  NAV.forEach((n) => { const g = n.group || "Top"; (groups[g] = groups[g] || []).push(n); });
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="logo">P</div>
        <div><div className="name">PhishGuard</div><div className="sub">Detection Engine</div></div>
      </div>
      <nav className="nav">
        {Object.entries(groups).map(([g, items]) => (
          <div key={g}>
            {g !== "Top" && <div className="group">{g}</div>}
            {items.map((n) => {
              const active = path === n.href || (n.href !== "/dashboard" && path.startsWith(n.href));
              return (
                <a key={n.href} href={n.href} className={`sidebar-link ${active ? "active" : ""}`}>
                  <Icon name={n.icon} /><span>{n.label}</span>
                </a>
              );
            })}
          </div>
        ))}
      </nav>
      <div className="side-foot">
        Offline-first · data stays local<br /><b>v1.0</b> · community build
        <div className="credit">
          Coded by <a href="https://github.com/iampopg" target="_blank" rel="noreferrer">@iampopg</a><br />
          <a href="https://github.com/iampopg/PhishGuard" target="_blank" rel="noreferrer">Star this project on GitHub ★</a>
        </div>
      </div>
    </aside>
  );
}

function Topbar() {
  const { user, logout } = useAuth();
  const router = useRouter();
  const [monitor, setMonitor] = useState(false);
  const [total, setTotal] = useState(0);
  useEffect(() => {
    let alive = true;
    const load = () =>
      api.get("/status").then((d: any) => {
        if (alive) { setMonitor(!!d.monitor); setTotal(d.total || 0); }
      }).catch(() => {});
    load();
    const id = setInterval(load, 5000);
    return () => { alive = false; clearInterval(id); };
  }, []);
  return (
    <header className="topbar">
      <div />
      <div className="actions">
        <span className="env-pill"><span className={`dot ${monitor ? "" : "warn"}`}></span>{monitor ? "Monitor live" : "Monitor off"} · {total} analyzed</span>
        <div className="user-chip"><div className="avatar">{(user || "A")[0].toUpperCase()}</div>{user || "analyst"}</div>
        <button className="btn btn-ghost btn-sm" onClick={() => { logout(); router.push("/login"); }}>
          <Icon name="logout" className="ico" style={{ width: 15, height: 15 }} />Logout
        </button>
      </div>
    </header>
  );
}

export default function Shell({ title, sub, actions, children }: { title: string; sub?: string; actions?: ReactNode; children: ReactNode }) {
  const { token, loading } = useAuth();
  const router = useRouter();
  useEffect(() => { if (!loading && !token) router.replace("/login"); }, [loading, token]);
  if (loading || !token) return <div className="login-wrap"><div className="spin" /></div>;
  return (
    <div className="app">
      <Sidebar />
      <div className="main">
        <Topbar />
        <main className="content">
          <div className="page-head">
            <div><h1>{title}</h1>{sub && <div className="sub">{sub}</div>}</div>
            {actions}
          </div>
          <div className="fade">{children}</div>
        </main>
      </div>
    </div>
  );
}
