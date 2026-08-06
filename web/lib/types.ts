export type Verdict = "safe" | "suspicious" | "phishing" | "malicious";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  analyzer: string;
  title: string;
  detail: string;
  severity: Severity;
  score: number;
  evidence?: any;
}
export interface AnalyzerResult {
  name: string;
  score: number;
  findings: Finding[];
}
export interface Sender {
  from: string;
  from_domain?: string;
  display_name?: string;
  envelope_from?: string;
}
export interface Source {
  type?: string;
  message_id?: string;
  subject?: string;
  mailbox_id?: string;
}
export interface Report {
  report_id: string;
  timestamp: string;
  source: Source;
  verdict: Verdict;
  risk_score: number;
  summary: string;
  sender: Sender;
  analyzers: AnalyzerResult[];
  urls: { url: string }[];
  attachments: any[];
  recommended_actions: string[];
  labels?: Record<string, any>;
  raw_headers?: Record<string, string>;
  body_text?: string;
  body_html?: string;
}
export interface Counts {
  safe: number;
  suspicious: number;
  phishing: number;
  malicious: number;
}
export interface Dashboard {
  counts: Counts;
  total: number;
  recent: Report[];
  monitor: boolean;
}
export interface Rule {
  id: string;
  analyzer: string;
  action: string;
  description: string;
  severity_at_least: Severity;
  title_contains: string;
}
