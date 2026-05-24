"""QAYAMAT — Intelligence Fusion
Aggregates OSINT from multiple providers: Shodan, Censys, OTX, SecurityTrails, URLScan, VirusTotal.
"""

import time
import requests
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any


@dataclass
class IntelResult:
    source: str
    data: Dict[str, Any]
    error: Optional[str] = None


class BaseIntelProvider(ABC):
    def __init__(self, api_key: Optional[str] = None, rate_limit: float = 1.0):
        self.api_key = api_key
        self.rate_limit = rate_limit
        self._last_request = 0.0

    def _wait(self) -> None:
        elapsed = time.time() - self._last_request
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self._last_request = time.time()

    @abstractmethod
    def query(self, target: str) -> List[IntelResult]:
        pass


class ShodanProvider(BaseIntelProvider):
    def query(self, target: str) -> List[IntelResult]:
        if not self.api_key:
            return []
        self._wait()
        try:
            resp = requests.get(
                f"https://api.shodan.io/shodan/host/{target}",
                params={"key": self.api_key},
                timeout=15,
            )
            if resp.status_code == 200:
                return [IntelResult("shodan", resp.json())]
        except Exception as e:
            return [IntelResult("shodan", {}, error=str(e))]
        return []


class CensysProvider(BaseIntelProvider):
    def query(self, target: str) -> List[IntelResult]:
        if not self.api_key or ":" not in self.api_key:
            return []
        self._wait()
        uid, secret = self.api_key.split(":", 1)
        try:
            resp = requests.get(
                f"https://search.censys.io/api/v2/hosts/{target}",
                auth=(uid, secret),
                timeout=15,
            )
            if resp.status_code == 200:
                return [IntelResult("censys", resp.json())]
        except Exception as e:
            return [IntelResult("censys", {}, error=str(e))]
        return []


class AlienVaultOTXProvider(BaseIntelProvider):
    def query(self, target: str) -> List[IntelResult]:
        self._wait()
        headers = {"X-OTX-API-KEY": self.api_key} if self.api_key else {}
        try:
            resp = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns",
                headers=headers,
                timeout=15,
            )
            if resp.status_code == 200:
                return [IntelResult("otx", resp.json())]
        except Exception as e:
            return [IntelResult("otx", {}, error=str(e))]
        return []


class SecurityTrailsProvider(BaseIntelProvider):
    def query(self, target: str) -> List[IntelResult]:
        if not self.api_key:
            return []
        self._wait()
        try:
            resp = requests.get(
                f"https://api.securitytrails.com/v1/domain/{target}/subdomains",
                headers={"APIKEY": self.api_key},
                timeout=15,
            )
            if resp.status_code == 200:
                return [IntelResult("securitytrails", resp.json())]
        except Exception as e:
            return [IntelResult("securitytrails", {}, error=str(e))]
        return []


class URLScanProvider(BaseIntelProvider):
    def query(self, target: str) -> List[IntelResult]:
        self._wait()
        headers = {"API-Key": self.api_key} if self.api_key else {}
        try:
            resp = requests.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{target}",
                headers=headers,
                timeout=15,
            )
            if resp.status_code == 200:
                return [IntelResult("urlscan", resp.json())]
        except Exception as e:
            return [IntelResult("urlscan", {}, error=str(e))]
        return []


class VirusTotalProvider(BaseIntelProvider):
    def query(self, target: str) -> List[IntelResult]:
        if not self.api_key:
            return []
        self._wait()
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{target}",
                headers={"x-apikey": self.api_key},
                timeout=15,
            )
            if resp.status_code == 200:
                return [IntelResult("virustotal", resp.json())]
        except Exception as e:
            return [IntelResult("virustotal", {}, error=str(e))]
        return []


class IntelFusion:
    """Unified access to all intelligence providers."""

    PROVIDER_MAP = {
        "shodan": ShodanProvider,
        "censys": CensysProvider,
        "otx": AlienVaultOTXProvider,
        "securitytrails": SecurityTrailsProvider,
        "urlscan": URLScanProvider,
        "virustotal": VirusTotalProvider,
    }

    def __init__(self, vault=None, config: Optional[dict] = None):
        self.providers: Dict[str, BaseIntelProvider] = {}
        intel_cfg = (config or {}).get("intel", {})
        enabled = intel_cfg.get("enabled", True)
        allowed = set(intel_cfg.get("providers", list(self.PROVIDER_MAP.keys())))

        if not enabled:
            return

        for name, cls in self.PROVIDER_MAP.items():
            if name not in allowed:
                continue
            api_key = ""
            if vault:
                api_key = vault.get_secret(f"{name}_api_key")
                if name == "censys" and not api_key:
                    api_key = vault.get_secret("censys_api_key")
            if api_key or name == "otx":
                self.providers[name] = cls(api_key=api_key or None)

    def gather(self, target: str) -> Dict[str, List[IntelResult]]:
        """Query all configured providers for the given target."""
        results: Dict[str, List[IntelResult]] = {}
        for name, provider in self.providers.items():
            try:
                results[name] = provider.query(target)
            except Exception as e:
                results[name] = [IntelResult(name, {}, error=str(e))]
        return results

    def gather_subdomains(self, target: str) -> List[str]:
        """Extract subdomain strings from all provider results."""
        subs = set()
        all_results = self.gather(target)
        for name, results in all_results.items():
            for r in results:
                if r.error or not r.data:
                    continue
                # SecurityTrails format
                for sub in r.data.get("subdomains", []):
                    subs.add(f"{sub}.{target}")
                # OTX passive DNS
                for record in r.data.get("passive_dns", []):
                    hostname = record.get("hostname", "")
                    if hostname.endswith(target):
                        subs.add(hostname)
        return sorted(subs)
