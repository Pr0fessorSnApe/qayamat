"""QAYAMAT — Example: Custom Scanner Plugin"""

from plugins.base_plugin import BasePlugin
from typing import Any, Dict, List
import requests


class CustomScanner(BasePlugin):
    name = "custom_scanner"
    version = "1.0"
    description = "Example custom scanner — checks for exposed /.well-known/security.txt"
    author = "Pr0fessor_SnApe"

    def run(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        targets = context.get("targets", [])
        logger = context.get("logger")

        for target in targets:
            url = f"https://{target}/.well-known/security.txt"
            try:
                resp = requests.get(url, timeout=10, allow_redirects=True)
                if resp.status_code == 200 and "contact" in resp.text.lower():
                    if logger:
                        logger.info(f"security.txt found at {url}")
                else:
                    findings.append({
                        "title": f"Missing security.txt on {target}",
                        "severity": "Info",
                        "url": url,
                        "vuln_type": "Best Practice",
                        "description": "No valid security.txt found. Consider adding one per RFC 9116.",
                    })
            except Exception as e:
                if logger:
                    logger.debug(f"Custom scanner error on {target}: {e}")

        return findings
