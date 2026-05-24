"""
QAYAMAT — Generate custom Nuclei templates from JS-discovered endpoints and findings.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

CUSTOM_TEMPLATE_DIR = Path("data/custom-nuclei")


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (s or "endpoint").lower())[:40].strip("-")


def generate_template_yaml(
    endpoint: str,
    method: str = "GET",
    matchers: Optional[List[str]] = None,
    severity: str = "medium",
    name: str = "",
) -> str:
    """Build a minimal Nuclei template for a discovered API path."""
    slug = _slug(name or endpoint)
    match_words = matchers or ["error", "internal", "admin", "token"]
    word_block = "\n".join(
        f'          - "{w}"' for w in match_words[:5]
    )
    return f"""id: qayamat-custom-{slug}

info:
  name: QAYAMAT Custom — {name or endpoint}
  author: qayamat
  severity: {severity}
  description: Auto-generated from JS/attack-surface discovery
  tags: qayamat,custom,bbp

http:
  - method: {method.upper()}
    path:
      - "{{{{BaseURL}}}}{endpoint}"
    matchers-condition: or
    matchers:
      - type: word
        words:
{word_block}
        part: body
      - type: status
        status:
          - 200
          - 401
          - 403
"""


def templates_from_js_findings(findings: List[dict]) -> List[dict]:
    """Extract endpoints from js_miner / attack surface findings."""
    endpoints = []
    for f in findings:
        if f.get("tool") != "js_miner" and "api" not in (f.get("title") or "").lower():
            continue
        try:
            data = json.loads(f.get("evidence") or "[]")
            if isinstance(data, list):
                endpoints.extend(data)
        except json.JSONDecodeError:
            pass
        for m in re.findall(r'["\'](/[a-zA-Z0-9_\-./{}]+)["\']', f.get("evidence") or ""):
            if len(m) > 3:
                endpoints.append(m)
    return list(dict.fromkeys(endpoints))[:30]


def save_templates(
    endpoints: List[str],
    program: str = "",
    ai_enrich: Optional[Any] = None,
) -> List[str]:
    """Write YAML files to data/custom-nuclei/ and return paths."""
    CUSTOM_TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)
    prog_dir = CUSTOM_TEMPLATE_DIR / _slug(program or "default")
    prog_dir.mkdir(parents=True, exist_ok=True)
    paths = []

    for ep in endpoints:
        if not ep.startswith("/"):
            ep = "/" + ep
        matchers = ["api", "graphql", "admin", "config", "secret"]
        if ai_enrich and hasattr(ai_enrich, "query"):
            try:
                prompt = (
                    f"For API path {ep}, reply JSON only: "
                    '{"matchers":["word1","word2"],"severity":"low|medium|high"}'
                )
                raw = ai_enrich.query(prompt)
                m = re.search(r"\{.*\}", raw, re.DOTALL)
                if m:
                    data = json.loads(m.group(0))
                    matchers = data.get("matchers", matchers)
                    sev = data.get("severity", "medium")
                else:
                    sev = "medium"
            except Exception:
                sev = "medium"
        else:
            sev = "high" if any(x in ep.lower() for x in ("admin", "internal", "debug")) else "medium"

        yaml_text = generate_template_yaml(ep, matchers=matchers, severity=sev, name=ep)
        path = prog_dir / f"{_slug(ep)}.yaml"
        path.write_text(yaml_text, encoding="utf-8")
        paths.append(str(path))

    index = prog_dir / "INDEX.json"
    index.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "program": program,
                "count": len(paths),
                "templates": paths,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    paths.append(str(index))
    return paths


def generate_from_scan(
    findings: List[dict],
    program: str = "",
    ai_engine=None,
) -> Dict[str, Any]:
    endpoints = templates_from_js_findings(findings)
    if not endpoints:
        # Fallback: any URL path from findings
        from urllib.parse import urlparse
        for f in findings:
            u = f.get("url", "")
            if u:
                path = urlparse(u).path
                if path and path != "/":
                    endpoints.append(path)
        endpoints = list(dict.fromkeys(endpoints))[:20]

    paths = save_templates(endpoints, program=program, ai_enrich=ai_engine)
    return {
        "endpoints": endpoints,
        "template_paths": paths,
        "nuclei_run_hint": f"nuclei -t {CUSTOM_TEMPLATE_DIR / _slug(program or 'default')}",
    }
