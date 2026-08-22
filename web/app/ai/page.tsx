"use client";

import { useEffect, useRef, useState } from "react";
import Shell from "@/components/Shell";
import { api } from "@/lib/api";
import { Spinner } from "@/components/ui";

interface Msg {
  role: "user" | "assistant" | "tool";
  text: string;
  tool?: string;
}

interface Conversation {
  id: string;
  title: string;
  messages: Msg[];
  updated: number;
}

export default function AiPage() {
  const [providers, setProviders] = useState<any>({});
  const [provider, setProvider] = useState("auto");
  const [model, setModel] = useState("");
  const [reports, setReports] = useState<any[]>([]);
  const [reportId, setReportId] = useState("");
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  const activeConv = conversations.find((c) => c.id === activeId);

  useEffect(() => {
    const saved = localStorage.getItem("pg_ai_conversations");
    if (saved) {
      try { setConversations(JSON.parse(saved)); } catch {}
    }
    api.get("/ai/providers").then((d: any) => {
      setProviders(d.providers || {});
      const auto = d.auto && d.providers[d.auto] ? d.auto : "auto";
      setProvider(auto);
      setModel(d.providers[auto]?.model || "");
    }).catch(() => {});
    api.get("/reports").then((d: any) => {
      setReports(d.reports || []);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    localStorage.setItem("pg_ai_conversations", JSON.stringify(conversations));
  }, [conversations]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [activeConv?.messages]);

  useEffect(() => {
    if (providers[provider]) setModel(providers[provider].model || "");
  }, [provider, providers]);

  const ensureConversation = (): string => {
    if (activeId) return activeId;
    const id = Date.now().toString();
    const conv: Conversation = { id, title: "New chat", messages: [], updated: Date.now() };
    setConversations((c) => [conv, ...c]);
    setActiveId(id);
    return id;
  };

  const send = async () => {
    if (!input.trim() || loading) return;
    const userMsg: Msg = { role: "user", text: input };
    const convId = ensureConversation();
    const conv = conversations.find((c) => c.id === convId);
    const currentMessages = [...(conv?.messages || []), userMsg];
    setInput("");
    setLoading(true);

    const updateConv = (msgs: Msg[]) => {
      setConversations((c) => c.map((x) =>
        x.id === convId ? { ...x, messages: msgs, updated: Date.now(),
          title: x.messages.length === 0 ? input.slice(0, 40) : x.title } : x));
    };

    try {
      const q = `report_id=${reportId || "all"}&question=${encodeURIComponent(input)}&provider=${provider}&model=${encodeURIComponent(model)}`;
      const res = await api.get(`/ai/analyze/${reportId || "all"}?${q}`);
      const reply = res.response || res.error || "(no response)";
      updateConv([...currentMessages, { role: "assistant", text: reply }]);
    } catch (e: any) {
      updateConv([...currentMessages, { role: "assistant", text: `Error: ${e.message}` }]);
    } finally {
      setLoading(false);
    }
  };

  const newConversation = () => {
    const id = Date.now().toString();
    const conv: Conversation = { id, title: "New chat", messages: [], updated: Date.now() };
    setConversations((c) => [conv, ...c]);
    setActiveId(id);
  };

  return (
    <Shell title="AI Assistant" sub="Investigate logs, ask questions, get analysis">
      <div className="ai-page">
        <div className="ai-sidebar">
          <button className="btn btn-primary btn-sm" onClick={newConversation} style={{ width: "100%", marginBottom: 12 }}>+ New chat</button>
          <div className="ai-conv-list">
            {conversations.length === 0 && <div className="ai-empty">No conversations yet.</div>}
            {conversations.map((c) => (
              <button key={c.id} className={`ai-conv-item ${c.id === activeId ? "active" : ""}`}
                onClick={() => setActiveId(c.id)}>
                <div className="ai-conv-title">{c.title}</div>
                <div className="ai-conv-meta">{c.messages.length} messages</div>
              </button>
            ))}
          </div>
        </div>
        <div className="ai-main">
          <div className="ai-controls">
            <select value={provider} onChange={(e) => setProvider(e.target.value)} className="ai-select">
              <option value="auto">Auto</option>
              <option value="local">Local</option>
              {providers.gemini && <option value="gemini">Gemini</option>}
              {providers.claude && <option value="claude">Claude</option>}
              {providers.kilo && <option value="kilo">kilo.ai</option>}
            </select>
            <select value={model} onChange={(e) => setModel(e.target.value)} className="ai-select">
              {providers[provider]?.local_models?.map((m: string) => (
                <option key={m} value={m}>{m}</option>
              ))}
              {!providers[provider]?.local_models && providers[provider]?.model && (
                <option value={providers[provider].model}>{providers[provider].model}</option>
              )}
            </select>
            <select value={reportId} onChange={(e) => setReportId(e.target.value)} className="ai-select">
              <option value="">All reports</option>
              {reports.map((r) => (
                <option key={r.report_id} value={r.report_id}>
                  {(r.source?.subject || r.report_id).slice(0, 30)}
                </option>
              ))}
            </select>
          </div>
          <div className="ai-messages">
            {!activeConv && <div className="ai-empty">Start a new chat or select one from the sidebar.</div>}
            {activeConv?.messages.map((m, i) => (
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
              placeholder="Ask about this email, or type 'investigate all phishing logs'…" className="ai-input" />
            <button className="btn btn-primary btn-sm" onClick={send} disabled={loading}>Send</button>
          </div>
        </div>
      </div>
    </Shell>
  );
}
