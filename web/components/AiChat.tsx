"use client";

import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { Spinner } from "@/components/ui";

interface Msg {
  role: "user" | "assistant";
  text: string;
}

export default function AiChat({ getToken }: { getToken: () => string }) {
  const [open, setOpen] = useState(false);
  const [providers, setProviders] = useState<any>({});
  const [provider, setProvider] = useState("auto");
  const [model, setModel] = useState("");
  const [reports, setReports] = useState<any[]>([]);
  const [reportId, setReportId] = useState("");
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    api.get("/ai/providers").then((d: any) => {
      setProviders(d.providers || {});
      setProvider(d.auto && d.providers[d.auto] ? d.auto : "auto");
    }).catch(() => {});
    api.get("/reports").then((d: any) => {
      setReports(d.reports || []);
      if (d.reports?.length) setReportId(d.reports[0].report_id);
    }).catch(() => {});
  }, [open]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const send = async () => {
    if (!input.trim() || loading) return;
    const userMsg: Msg = { role: "user", text: input };
    setMessages((m) => [...m, userMsg]);
    setInput("");
    setLoading(true);
    try {
      const q = `report_id=${reportId}&question=${encodeURIComponent(input)}&provider=${provider}`;
      const res = await api.get(`/ai/analyze/${reportId}?${q}`);
      setMessages((m) => [...m, { role: "assistant", text: res.response || res.error || "(no response)" }]);
    } catch (e: any) {
      setMessages((m) => [...m, { role: "assistant", text: `Error: ${e.message}` }]);
    } finally {
      setLoading(false);
    }
  };

  const selectedReport = reports.find((r) => r.report_id === reportId);

  return (
    <>
      <button className="ai-fab" onClick={() => setOpen((v) => !v)} title="AI Chat">
        {open ? "✕" : "🤖"}
      </button>
      {open && (
        <div className="ai-panel">
          <div className="ai-panel-h">
            <span>AI Assistant</span>
            <button className="btn btn-ghost btn-sm" onClick={() => setOpen(false)}>✕</button>
          </div>
          <div className="ai-panel-controls">
            <select value={provider} onChange={(e) => setProvider(e.target.value)} className="ai-select">
              <option value="auto">Auto</option>
              <option value="local">Local</option>
              {providers.gemini && <option value="gemini">Gemini</option>}
              {providers.claude && <option value="claude">Claude</option>}
              {providers.kilo && <option value="kilo">kilo.ai</option>}
            </select>
            <select value={reportId} onChange={(e) => setReportId(e.target.value)} className="ai-select ai-report-select">
              {reports.map((r) => (
                <option key={r.report_id} value={r.report_id}>
                  {(r.source?.subject || r.report_id).slice(0, 30)}
                </option>
              ))}
            </select>
          </div>
          <div className="ai-messages">
            {messages.length === 0 && (
              <div className="ai-empty">Select a report and ask the AI about it.</div>
            )}
            {messages.map((m, i) => (
              <div key={i} className={`ai-msg ${m.role}`}>
                <div className="ai-msg-text">{m.text}</div>
              </div>
            ))}
            {loading && <div className="ai-msg assistant"><div className="ai-msg-text"><Spinner /> Thinking…</div></div>}
            <div ref={bottomRef} />
          </div>
          <div className="ai-input-row">
            <input value={input} onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && send()}
              placeholder="Ask about this email…" className="ai-input" />
            <button className="btn btn-primary btn-sm" onClick={send} disabled={loading}>Send</button>
          </div>
        </div>
      )}
    </>
  );
}
