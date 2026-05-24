"""QAYAMAT — Archive Miner
Pulls historical URLs from Wayback Machine and OTX to discover forgotten endpoints and parameters.
"""

import requests
from urllib.parse import urlparse, parse_qs
from typing import List, Set, Optional


class ArchiveMiner:
    SOURCES = {
        "wayback": (
            "https://web.archive.org/cdx/search/cdx"
            "?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=5000"
        ),
        "otx": (
            "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=1000"
        ),
    }

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    def fetch_urls(self, domain: str) -> List[str]:
        """Return deduplicated list of historical URLs for the domain."""
        all_urls: Set[str] = set()

        # Wayback Machine
        try:
            resp = requests.get(
                self.SOURCES["wayback"].format(domain=domain),
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            # First row is the header ["original", ...]
            if isinstance(data, list) and len(data) > 1:
                all_urls.update(row[0] for row in data[1:] if row and row[0])
        except Exception:
            pass

        # AlienVault OTX
        try:
            resp = requests.get(
                self.SOURCES["otx"].format(domain=domain),
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            for entry in data.get("url_list", []):
                url = entry.get("url")
                if url:
                    all_urls.add(url)
        except Exception:
            pass

        return sorted(all_urls)

    def extract_params(self, urls: List[str]) -> Set[str]:
        """Extract all query-string parameter names from a list of URLs."""
        params: Set[str] = set()
        for url in urls:
            try:
                parsed = urlparse(url)
                params.update(parse_qs(parsed.query).keys())
                # Detect numeric path segments as likely ID parameters
                for seg in parsed.path.strip("/").split("/"):
                    if seg.isdigit():
                        params.add("id")
                    elif seg.startswith("{") and seg.endswith("}"):
                        params.add(seg.strip("{}"))
            except Exception:
                continue
        return params

    def extract_endpoints(self, urls: List[str], domain: str) -> List[str]:
        """Return unique path endpoints (without query strings) for the domain."""
        paths: Set[str] = set()
        for url in urls:
            try:
                parsed = urlparse(url)
                if domain in (parsed.hostname or ""):
                    path = parsed.path.rstrip("/") or "/"
                    paths.add(path)
            except Exception:
                continue
        return sorted(paths)
