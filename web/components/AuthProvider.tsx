"use client";
import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { api, getToken, setToken, clearToken } from "@/lib/api";

interface AuthCtx {
  token: string | null;
  user: string | null;
  loading: boolean;
  login: (u: string, p: string) => Promise<void>;
  logout: () => void;
}
const Ctx = createContext<AuthCtx>({ token: null, user: null, loading: true, login: async () => {}, logout: () => {} });
export function useAuth() { return useContext(Ctx); }

function getU() { if (typeof window === "undefined") return null; return localStorage.getItem("pg_user"); }

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setT] = useState<string | null>(null);
  const [user, setU] = useState<string | null>(null);
  const [loading, setL] = useState(true);
  useEffect(() => { setT(getToken()); setU(getU()); setL(false); }, []);
  const login = async (u: string, p: string) => {
    const r: any = await api.login(u, p);
    setToken(r.access_token);
    localStorage.setItem("pg_user", u);
    setT(r.access_token);
    setU(u);
  };
  const logout = () => { clearToken(); setT(null); if (typeof window !== "undefined") window.location.href = "/login"; };
  return <Ctx.Provider value={{ token, user, loading, login, logout }}>{children}</Ctx.Provider>;
}
