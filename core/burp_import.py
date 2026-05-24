"""
QAYAMAT — Burp Suite / OWASP ZAP / HAR import and Burp export.
"""

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any
from urllib.parse import urlparse, parse_qs


class TrafficImporter:
    """Extract URLs and parameters from HAR, Burp XML, or ZAP JSON."""

    @staticmethod
    def from_har(path: str) -> Dict[str, Any]:
        har = json.loads(Path(path).read_text(encoding="utf-8"))
        urls, params = set(), set()
        entries = har.get("log", {}).get("entries", [])
        for entry in entries:
            req = entry.get("request", {})
            url = req.get("url", "")
            if url.startswith("http"):
                urls.add(url)
                p = urlparse(url)
                for k in parse_qs(p.query):
                    params.add(k)
        return {"urls": sorted(urls), "params": sorted(params), "source": "har"}

    @staticmethod
    def from_burp_xml(path: str) -> Dict[str, Any]:
        tree = ET.parse(path)
        root = tree.getroot()
        urls, params = set(), set()
        for item in root.iter("item"):
            url_el = item.find("url")
            if url_el is not None and url_el.text:
                urls.add(url_el.text.strip())
                p = urlparse(url_el.text)
                for k in parse_qs(p.query):
                    params.add(k)
        return {"urls": sorted(urls), "params": sorted(params), "source": "burp"}

    @staticmethod
    def from_zap_json(path: str) -> Dict[str, Any]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        urls, params = set(), set()
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                inst = alert.get("instances", [{}])[0]
                uri = inst.get("uri", "")
                if uri:
                    urls.add(uri)
        return {"urls": sorted(urls), "params": sorted(params), "source": "zap"}

    @staticmethod
    def auto_import(path: str) -> Dict[str, Any]:
        p = Path(path)
        if p.suffix == ".har":
            return TrafficImporter.from_har(str(p))
        if p.suffix == ".xml":
            return TrafficImporter.from_burp_xml(str(p))
        return TrafficImporter.from_zap_json(str(p))


class BurpExporter:
    """Export findings as Burp-compatible issue list (JSON)."""

    @staticmethod
    def export_findings(findings: List[dict], path: str) -> str:
        issues = []
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            burp_sev = {"critical": "High", "high": "High", "medium": "Medium", "low": "Low"}.get(sev, "Information")
            issues.append({
                "name": f.get("title", ""),
                "severity": burp_sev,
                "confidence": "Certain" if f.get("validation_score", 0) > 0.8 else "Firm",
                "host": urlparse(f.get("url", "")).netloc,
                "path": urlparse(f.get("url", "")).path,
                "location": f.get("url", ""),
                "detail": f.get("description", ""),
                "background": f.get("evidence", "")[:2000],
            })
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({"issues": issues}, indent=2), encoding="utf-8")
        return str(out)
