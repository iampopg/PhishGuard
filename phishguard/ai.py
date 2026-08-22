from __future__ import annotations

import json
from typing import Any, Dict, Optional

AI_LOCAL_MODEL = "llama3.2"
AI_GEMINI_MODEL = "gemini-2.0-flash"
AI_CLAUDE_MODEL = "claude-sonnet-4-20250514"
AI_KILO_MODEL = "kilo"


class PhishGuardAI:
    """Multi-provider AI assistant for email analysis.

    Supported providers:
      - local: Ollama (auto-detected at localhost:11434)
      - gemini: Google Gemini API
      - claude: Anthropic Claude API
      - kilo:   kilo.ai
      - auto:   try local first, then configured providers
    """

    def __init__(self, config: Any):
        self.config = config
        self._local_available: Optional[bool] = None
        self._local_models: List[str] = []

    @property
    def providers(self) -> Dict[str, Dict[str, str]]:
        cfg = self.config
        return {
            "local": {
                "base_url": getattr(cfg, "ai_local_url", "http://localhost:11434"),
                "model": self._best_local_model(),
                "key": "",
                "available": self._detect_local(),
                "local_models": self._local_models,
            },
            "gemini": {
                "model": getattr(cfg, "ai_gemini_model", AI_GEMINI_MODEL),
                "key": getattr(cfg, "ai_gemini_key", ""),
            },
            "claude": {
                "model": getattr(cfg, "ai_claude_model", AI_CLAUDE_MODEL),
                "key": getattr(cfg, "ai_claude_key", ""),
            },
            "kilo": {
                "model": getattr(cfg, "ai_kilo_model", AI_KILO_MODEL),
                "key": getattr(cfg, "ai_kilo_key", ""),
            },
        }

    def _detect_local(self) -> bool:
        if self._local_available is not None:
            return self._local_available
        try:
            import requests
            base = getattr(self.config, "ai_local_url", "http://localhost:11434")
            r = requests.get(f"{base}/api/tags", timeout=2)
            if r.status_code == 200:
                self._local_models = [m.get("name", "") for m in r.json().get("models", [])]
                self._local_available = bool(self._local_models)
            else:
                self._local_available = False
        except Exception:
            self._local_available = False
        return self._local_available

    def _best_local_model(self) -> str:
        preferred = getattr(self.config, "ai_local_model", AI_LOCAL_MODEL)
        if not self._local_models:
            return preferred
        if preferred in self._local_models:
            return preferred
        for m in self._local_models:
            if m.startswith(preferred):
                return m
        return self._local_models[0]

    def build_prompt(self, report: Dict[str, Any], question: str = "") -> str:
        sender = report.get("sender", {}) or {}
        source = report.get("source", {}) or {}
        verdict = report.get("verdict", "")
        score = report.get("risk_score", 0)
        findings = []
        for a in report.get("analyzers", []) or []:
            for f in a.get("findings", []) or []:
                findings.append(f"[{a['name']}] {f['title']}: {f.get('detail','')}")
        urls = [u.get("url") if isinstance(u, dict) else u for u in (report.get("urls", []) or [])]
        context = f"""Email Analysis Report
Subject: {source.get('subject','(none)')}
From: {sender.get('from','')}
Verdict: {verdict} (score {score})
URLs: {', '.join(urls[:10]) or 'none'}
Key findings:
{chr(10).join(findings[:15]) or '  (none)'}
"""
        if question:
            return f"{context}\n\nAnalyst question: {question}"
        return (f"{context}\n\nProvide a concise assessment: is this email malicious or "
                f"legitimate? Explain the key risk indicators in 2-3 sentences.")

    def analyze(self, report: Dict[str, Any], question: str = "",
                provider: str = "auto") -> Dict[str, Any]:
        """Run AI analysis. Returns {response, provider, model, error?}."""
        prompt = self.build_prompt(report, question)
        chosen = provider
        if chosen == "auto":
            chosen = self._auto_provider()
        if not chosen:
            return {"response": "", "provider": None, "error": "No AI provider available. Set a key or start Ollama."}

        try:
            if chosen == "local":
                return self._call_local(prompt)
            elif chosen == "gemini":
                return self._call_gemini(prompt)
            elif chosen == "claude":
                return self._call_claude(prompt)
            elif chosen == "kilo":
                return self._call_kilo(prompt)
            else:
                return {"response": "", "provider": chosen, "error": f"Unknown provider: {chosen}"}
        except Exception as e:
            return {"response": "", "provider": chosen, "error": f"{type(e).__name__}: {e}"}

    def _auto_provider(self) -> Optional[str]:
        if self.providers["local"]["available"]:
            return "local"
        for name in ("gemini", "claude", "kilo"):
            if self.providers[name]["key"]:
                return name
        return None

    def _call_local(self, prompt: str) -> Dict[str, Any]:
        import requests
        base = self.providers["local"]["base_url"]
        model = self._best_local_model()
        r = requests.post(f"{base}/api/generate", json={"model": model, "prompt": prompt,
                                                       "stream": False}, timeout=120)
        r.raise_for_status()
        data = r.json()
        return {"response": data.get("response", ""), "provider": "local", "model": model}

    def _headers_with_key(self, key: str, extra: Dict[str, str] = None) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if key:
            h["Authorization"] = f"Bearer {key}"
        if extra:
            h.update(extra)
        return h

    def _call_gemini(self, prompt: str) -> Dict[str, Any]:
        import requests
        model = self.providers["gemini"]["model"]
        key = self.providers["gemini"]["key"]
        if not key:
            raise RuntimeError("PG_AI_GEMINI_KEY not set")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
        r = requests.post(url, headers=self._headers_with_key(""),
                         json={"contents": [{"parts": [{"text": prompt}]}]}, timeout=60)
        r.raise_for_status()
        text = r.json()["candidates"][0]["content"]["parts"][0]["text"]
        return {"response": text, "provider": "gemini", "model": model}

    def _call_claude(self, prompt: str) -> Dict[str, Any]:
        import requests
        model = self.providers["claude"]["model"]
        key = self.providers["claude"]["key"]
        if not key:
            raise RuntimeError("PG_AI_CLAUDE_KEY not set")
        headers = self._headers_with_key(key, {"anthropic-version": "2023-06-01"})
        r = requests.post("https://api.anthropic.com/v1/messages", headers=headers,
                         json={"model": model, "max_tokens": 512, "messages": [{"role": "user", "content": prompt}]},
                         timeout=60)
        r.raise_for_status()
        text = r.json()["content"][0]["text"]
        return {"response": text, "provider": "claude", "model": model}

    def _call_kilo(self, prompt: str) -> Dict[str, Any]:
        import requests
        model = self.providers["kilo"]["model"]
        key = self.providers["kilo"]["key"]
        if not key:
            raise RuntimeError("PG_AI_KILO_KEY not set")
        r = requests.post("https://api.kilo.ai/v1/chat/completions",
                         headers=self._headers_with_key(key),
                         json={"model": model, "messages": [{"role": "user", "content": prompt}],
                               "max_tokens": 512}, timeout=60)
        r.raise_for_status()
        text = r.json()["choices"][0]["message"]["content"]
        return {"response": text, "provider": "kilo", "model": model}
