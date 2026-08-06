const TOKEN_KEY = "pg_token";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
}
export function setToken(t: string) { localStorage.setItem(TOKEN_KEY, t); }
export function clearToken() { localStorage.removeItem(TOKEN_KEY); }

function normalizeError(data: any): string {
  if (data && data.detail) {
    const d = data.detail;
    if (typeof d === "string") return d;
    if (Array.isArray(d)) return d.map((x: any) => (x && x.msg) ? x.msg : JSON.stringify(x)).join("; ");
    return JSON.stringify(d);
  }
  if (data && data.error) return typeof data.error === "string" ? data.error : JSON.stringify(data.error);
  return "Request failed";
}

async function req(path: string, opts: RequestInit = {}) {
  const token = getToken();
  const headers: Record<string, string> = { ...(opts.headers as any) };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(path, { ...opts, headers });
  if (res.status === 401) {
    if (typeof window !== "undefined") { clearToken(); window.location.href = "/login"; }
    throw new Error("unauthorized");
  }
  const ct = res.headers.get("content-type") || "";
  const data = ct.includes("application/json") ? await res.json() : await res.text();
  if (!res.ok) throw new Error(normalizeError(data) || res.statusText);
  return data;
}

function formData(obj: Record<string, any>): FormData {
  const fd = new FormData();
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    if (typeof v === "boolean") fd.set(k, v ? "true" : "false");
    else fd.set(k, String(v));
  }
  return fd;
}

export const api = {
  get: (p: string) => req(`/api${p}`),
  postForm: (p: string, obj: Record<string, any>) =>
    req(`/api${p}`, { method: "POST", body: formData(obj) }),
  postRaw: (p: string, body: BodyInit, ct?: string) =>
    req(`/api${p}`, { method: "POST", headers: ct ? { "Content-Type": ct } : undefined, body }),
  login: (username: string, password: string) =>
    req(`/api/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ username, password }).toString(),
    }),
};
