import { Report, Severity, Verdict, Counts } from "@/lib/types";

export function VerdictBadge({ v }: { v: Verdict | string }) {
  return <span className={`badge ${v}`}><span className="bdot" />{(v as string).charAt(0).toUpperCase() + (v as string).slice(1)}</span>;
}
export function SeverityBadge({ s }: { s: Severity | string }) {
  return <span className={`sev ${s}`}>{(s as string)}</span>;
}
export function Spinner() { return <span className="spin" />; }
export function AlertBox({ kind, children }: { kind: "ok" | "err" | "info"; children: React.ReactNode }) {
  return <div className={`alert ${kind}`}>{children}</div>;
}
export function Empty({ children }: { children: React.ReactNode }) { return <div className="empty">{children}</div>; }

export function ScoreRing({ score, size = 78 }: { score: number; size?: number }) {
  const r = (size - 16) / 2;
  const c = 2 * Math.PI * r;
  const off = c * (1 - Math.min(100, score) / 100);
  const color = score >= 80 ? "var(--malicious)" : score >= 60 ? "var(--phishing)" : score >= 35 ? "var(--suspicious)" : "var(--safe)";
  return (
    <div className="ring" style={{ width: size, height: size, background: `conic-gradient(${color} ${Math.min(100, score)}%, var(--surface2) 0)` }}>
      <b>{score}</b>
    </div>
  );
}

export function VerdictBar({ counts, total }: { counts: Counts; total: number }) {
  const pct = (n: number) => (total ? (n / total) * 100 : 0);
  return (
    <>
      <div className="vbar">
        <span className="safe" style={{ width: `${pct(counts.safe)}%` }} />
        <span className="suspicious" style={{ width: `${pct(counts.suspicious)}%` }} />
        <span className="phishing" style={{ width: `${pct(counts.phishing)}%` }} />
        <span className="malicious" style={{ width: `${pct(counts.malicious)}%` }} />
      </div>
      <div className="legend">
        <span><i style={{ background: "var(--safe)" }} />Safe {counts.safe}</span>
        <span><i style={{ background: "var(--suspicious)" }} />Suspicious {counts.suspicious}</span>
        <span><i style={{ background: "var(--phishing)" }} />Phishing {counts.phishing}</span>
        <span><i style={{ background: "var(--malicious)" }} />Malicious {counts.malicious}</span>
      </div>
    </>
  );
}

export function ReportSummary({ r, full = false }: { r: Report; full?: boolean }) {
  return (
    <div className="card">
      <div className="card-b">
        <div className="hero">
          <ScoreRing score={r.risk_score} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="actions" style={{ marginBottom: 8 }}>
              <VerdictBadge v={r.verdict} />
              <span className="pill">{r.analyzers.length} analyzers</span>
              <span className="pill">{(r.timestamp || "").replace("T", " ").slice(0, 19)}</span>
            </div>
            <div className="muted small">From <b style={{ color: "var(--text)" }}>{r.sender.display_name || r.sender.from}</b> &lt;{r.sender.from}&gt;</div>
          </div>
        </div>
        {r.summary && <div className="alert info" style={{ margin: "16px 0 0" }}>{r.summary}</div>}
        {full && r.recommended_actions && r.recommended_actions.length > 0 && (
          <>
            <div className="muted small" style={{ margin: "14px 0 4px", fontWeight: 600 }}>Recommended actions</div>
            <ul className="small" style={{ margin: 0, paddingLeft: 18, color: "var(--muted)" }}>
              {r.recommended_actions.map((a, i) => <li key={i} style={{ marginBottom: 4 }}>{a}</li>)}
            </ul>
          </>
        )}
      </div>
    </div>
  );
}
