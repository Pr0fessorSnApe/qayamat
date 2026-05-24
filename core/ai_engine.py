"""
QAYAMAT — AI Engine
Multi-provider AI: OpenAI, Anthropic, Google Gemini, Ollama.
Used for finding triage, analysis, and next-step recommendations.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from .vault import Vault
from .logger import AuditLogger


class AIEngine:
    BACKENDS = ("openai", "anthropic", "gemini", "ollama")

    def __init__(self, config: dict, vault: Vault, logger: Optional[AuditLogger] = None):
        self.config = config
        self.vault = vault
        self.logger = logger
        ai_cfg = config.get("ai", {})
        self.backend = ai_cfg.get("backend", "auto")
        self.backends: List[str] = ai_cfg.get(
            "backends", ["openai", "anthropic", "gemini", "ollama"]
        )
        self._clients: Dict[str, Any] = {}
        self._initialized = False

    def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        order = self._resolve_backend_order()
        for name in order:
            try:
                if name == "openai":
                    self._init_openai()
                elif name == "anthropic":
                    self._init_anthropic()
                elif name == "gemini":
                    self._init_gemini()
                elif name == "ollama":
                    self._init_ollama_marker()
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"AI backend {name} unavailable: {e}")
        self._initialized = True

    def _resolve_backend_order(self) -> List[str]:
        if self.backend != "auto" and self.backend in self.BACKENDS:
            rest = [b for b in self.backends if b != self.backend]
            return [self.backend] + rest
        return [b for b in self.backends if b in self.BACKENDS]

    @property
    def is_available(self) -> bool:
        self._ensure_initialized()
        return bool(self._clients)

    def _init_openai(self) -> None:
        api_key = self.vault.get_secret("openai_api_key")
        if not api_key:
            return
        import openai
        self._clients["openai"] = openai.OpenAI(api_key=api_key)

    def _init_anthropic(self) -> None:
        api_key = self.vault.get_secret("anthropic_api_key")
        if not api_key:
            return
        try:
            import anthropic
            self._clients["anthropic"] = anthropic.Anthropic(api_key=api_key)
        except ImportError:
            if self.logger:
                self.logger.warning("anthropic package not installed — pip install anthropic")

    def _init_gemini(self) -> None:
        api_key = (
            self.vault.get_secret("gemini_api_key")
            or self.vault.get_secret("google_api_key")
        )
        if not api_key:
            return
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            model = self.config["ai"].get("gemini_model", "gemini-1.5-flash")
            self._clients["gemini"] = genai.GenerativeModel(model)
        except ImportError:
            if self.logger:
                self.logger.warning(
                    "google-generativeai not installed — pip install google-generativeai"
                )

    def _init_ollama_marker(self) -> None:
        import requests
        endpoint = self.config["ai"].get("ollama_endpoint", "http://localhost:11434")
        try:
            requests.get(f"{endpoint}/api/tags", timeout=3)
            self._clients["ollama"] = endpoint
        except Exception:
            pass

    def query(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> str:
        self._ensure_initialized()
        if not self._clients:
            return "[AI unavailable — set API keys in .env and run load_env_secrets]"

        user_content = f"Context: {context}\n\n{prompt}" if context else prompt
        system = (
            "You are an expert offensive security AI assisting with authorized "
            "penetration testing. Provide precise, actionable analysis."
        )

        last_error = ""
        for name in self._resolve_backend_order():
            if name not in self._clients:
                continue
            try:
                if name == "openai":
                    return self._query_openai(system, user_content)
                if name == "anthropic":
                    return self._query_anthropic(system, user_content)
                if name == "gemini":
                    return self._query_gemini(system, user_content)
                if name == "ollama":
                    return self._query_ollama(user_content)
            except Exception as e:
                last_error = str(e)
                if self.logger:
                    self.logger.warning(f"{name} query failed: {e}")

        return f"[AI query error: {last_error or 'no backend responded'}]"

    def _query_openai(self, system: str, user: str) -> str:
        client = self._clients["openai"]
        response = client.chat.completions.create(
            model=self.config["ai"].get("openai_model", "gpt-4o"),
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0.1,
            max_tokens=2048,
        )
        return response.choices[0].message.content or ""

    def _query_anthropic(self, system: str, user: str) -> str:
        client = self._clients["anthropic"]
        response = client.messages.create(
            model=self.config["ai"].get("anthropic_model", "claude-3-5-sonnet-20241022"),
            max_tokens=2048,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        parts = []
        for block in response.content:
            if hasattr(block, "text"):
                parts.append(block.text)
        return "".join(parts)

    def _query_gemini(self, system: str, user: str) -> str:
        model = self._clients["gemini"]
        response = model.generate_content(f"{system}\n\n{user}")
        return response.text or ""

    def _query_ollama(self, prompt: str) -> str:
        import requests
        endpoint = self._clients["ollama"]
        model = self.config["ai"].get("local_model", "llama3")
        resp = requests.post(
            f"{endpoint}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json().get("response", "")

    def parse_exclusions(self, text: str) -> dict:
        """
        Optional AI assist for messy exclusion policy text.
        Returns dict with domains, wildcards, paths, excluded_vuln_types, etc.
        """
        if not self.is_available or len(text) < 40:
            return {}
        prompt = (
            "Extract bug bounty OUT-OF-SCOPE rules from this policy text. "
            "Reply ONLY with JSON:\n"
            '{"domains":[],"wildcards":[],"paths":[],"ips":[],"cidrs":[],"keywords":[],'
            '"excluded_vuln_types":[],"no_automated_scanning":false,"max_requests_per_second":null}\n\n'
            f"Policy:\n{text[:6000]}"
        )
        raw = self.query(prompt)
        try:
            return json.loads(raw.strip())
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", raw, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass
        return {}

    def validate_finding(self, finding: dict) -> dict:
        """
        Ask AI whether a scanner finding is a true or false positive.
        Returns: {confirmed: bool, confidence: float, reason: str}
        """
        if not self.is_available:
            return {"confirmed": True, "confidence": 0.5, "reason": "AI unavailable — heuristic only"}

        prompt = (
            "Triage this security scanner finding. Determine if it is a TRUE POSITIVE "
            "(real, exploitable or valid security issue) or FALSE POSITIVE (noise, "
            "misconfiguration banner, health check, reflection without execution, etc.).\n"
            "Reply with ONLY valid JSON, no markdown:\n"
            '{"confirmed": true|false, "confidence": 0.0-1.0, "reason": "one sentence"}\n\n'
            f"Finding:\n{json.dumps(finding, default=str)[:3000]}"
        )
        raw = self.query(prompt)
        return self._parse_validation_json(raw)

    @staticmethod
    def _parse_validation_json(raw: str) -> dict:
        default = {"confirmed": True, "confidence": 0.6, "reason": "could not parse AI response"}
        if not raw or raw.startswith("["):
            return default
        try:
            return json.loads(raw.strip())
        except json.JSONDecodeError:
            pass
        match = re.search(r"\{[^{}]*\"confirmed\"[^{}]*\}", raw, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
        lower = raw.lower()
        if "false positive" in lower or '"confirmed": false' in lower or '"confirmed":false' in lower:
            return {"confirmed": False, "confidence": 0.75, "reason": raw[:200]}
        if "true positive" in lower or '"confirmed": true' in lower:
            return {"confirmed": True, "confidence": 0.75, "reason": raw[:200]}
        return default

    def analyze_finding(self, finding: dict) -> str:
        prompt = (
            f"Analyze this security finding and provide: severity rating, "
            f"business impact, and top 3 remediation steps.\n\nFinding: {finding}"
        )
        return self.query(prompt)

    def suggest_next_steps(self, recon_results: dict) -> str:
        prompt = (
            f"Based on these recon results, suggest the highest-priority attack "
            f"vectors to investigate next:\n\n{recon_results}"
        )
        return self.query(prompt)

    def triage_findings(self, findings: List[dict]) -> List[dict]:
        """Return only findings AI+heuristics would keep (batch helper)."""
        from .finding_validator import FindingValidator
        validator = FindingValidator(
            self.config,
            ai_validate=self.validate_finding if self.is_available else None,
        )
        accepted, _ = validator.filter_findings(findings)
        return accepted
