"""
QAYAMAT — Report Generator v3
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any
from core.logger import AuditLogger
from core.repro_steps import enrich_finding_with_steps


# ── HTML Template ──────────────────────────────────────────────────────────────
REPORT_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>QAYAMAT Security Report — {scan_date}</title>
  <style>
    :root {{
      --bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#c9d1d9;
      --dim:#8b949e;--accent:#00e5ff;--critical:#ff3860;--high:#ff8c42;
      --medium:#ffd166;--low:#06d6a0;--info:#74b9ff;
    }}
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;padding:2rem;max-width:1200px;margin:auto}}
    h1{{color:var(--critical);font-size:2rem;font-family:monospace;letter-spacing:.08em;border-bottom:2px solid var(--critical);padding-bottom:.5rem;margin-bottom:.5rem}}
    .meta{{color:var(--dim);margin-bottom:2rem;font-size:.9rem}}
    .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:2rem}}
    .card{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem;text-align:center}}
    .card .num{{font-size:2.2rem;font-weight:800;font-family:monospace}}
    .card .lbl{{font-size:.75rem;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;margin-top:4px}}
    h2{{color:var(--accent);margin:2rem 0 1rem;font-size:1.1rem;text-transform:uppercase;letter-spacing:.08em}}
    .finding{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1.2rem;margin-bottom:1rem}}
    .fh{{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:.8rem}}
    .ft{{font-weight:600;font-size:1rem}}
    .badge{{border-radius:4px;padding:3px 10px;font-size:.7rem;font-weight:700;font-family:monospace;text-transform:uppercase;letter-spacing:.06em;border:1px solid}}
    .sev-Critical{{color:var(--critical);border-color:var(--critical);background:rgba(255,56,96,.12)}}
    .sev-High{{color:var(--high);border-color:var(--high);background:rgba(255,140,66,.12)}}
    .sev-Medium{{color:var(--medium);border-color:var(--medium);background:rgba(255,209,102,.12)}}
    .sev-Low{{color:var(--low);border-color:var(--low);background:rgba(6,214,160,.12)}}
    .sev-Info{{color:var(--info);border-color:var(--info);background:rgba(116,185,255,.12)}}
    .furl{{color:var(--accent);font-family:monospace;font-size:.85rem;margin-top:4px;word-break:break-all}}
    .fdesc{{color:var(--dim);font-size:.88rem;margin-top:8px}}
    pre{{background:#0a0d13;border:1px solid var(--border);border-radius:6px;padding:.75rem;overflow-x:auto;font-size:.82rem;margin-top:8px;color:#4ade80}}
    .chain{{background:var(--surface);border:1px solid var(--critical);border-radius:8px;padding:1rem;margin-bottom:1rem}}
    .chain-title{{color:var(--critical);font-weight:700;margin-bottom:.5rem}}
    .chain-step{{color:var(--dim);font-size:.88rem;padding:.2rem 0 .2rem 1rem;border-left:2px solid var(--critical);margin:.3rem 0}}
    .risk-bar{{background:var(--border);border-radius:4px;height:12px;margin:.5rem 0}}
    .risk-fill{{height:100%;border-radius:4px;background:linear-gradient(90deg,var(--low),var(--medium),var(--high),var(--critical))}}
    .asset-table{{width:100%;border-collapse:collapse;font-size:.85rem;margin-bottom:1rem}}
    .asset-table th{{background:var(--surface);padding:.5rem .75rem;text-align:left;color:var(--dim);font-weight:600;border-bottom:1px solid var(--border)}}
    .asset-table td{{padding:.4rem .75rem;border-bottom:1px solid var(--border);font-family:monospace;color:var(--accent)}}
    .event-log{{background:#0a0d13;border:1px solid var(--border);border-radius:6px;padding:.75rem;max-height:300px;overflow-y:auto;font-size:.8rem}}
    .ev-line{{padding:.15rem 0;border-bottom:1px solid #1e2530;color:var(--dim)}}
    .ev-line .ts{{color:#3d5a80;margin-right:.5rem}}
    .ev-critical{{color:var(--critical)!important}}
    .ev-high{{color:var(--high)!important}}
    footer{{color:var(--dim);font-size:.8rem;text-align:center;margin-top:3rem;padding-top:1rem;border-top:1px solid var(--border)}}
    .steps{{margin-top:12px;padding:12px;background:#0a0d13;border-left:3px solid var(--accent);border-radius:0 6px 6px 0}}
    .steps h4{{color:var(--accent);font-size:.85rem;margin-bottom:8px;text-transform:uppercase;letter-spacing:.06em}}
    .steps ol{{margin-left:1.2rem;color:var(--text);font-size:.88rem;line-height:1.6}}
    .steps li{{margin-bottom:6px}}
    .impact{{color:var(--high);font-size:.88rem;margin-top:10px}}
    .remediation{{color:var(--low);font-size:.88rem;margin-top:6px}}
  </style>
</head>
<body>
  <h1>QAYAMAT</h1>
  <div class="meta">Offensive Security Report &nbsp;·&nbsp; {scan_date} &nbsp;·&nbsp; Pr0fessor_SnApe</div>

  <div class="grid">
    <div class="card"><div class="num" style="color:var(--critical)">{critical}</div><div class="lbl">Critical</div></div>
    <div class="card"><div class="num" style="color:var(--high)">{high}</div><div class="lbl">High</div></div>
    <div class="card"><div class="num" style="color:var(--medium)">{medium}</div><div class="lbl">Medium</div></div>
    <div class="card"><div class="num" style="color:var(--low)">{low}</div><div class="lbl">Low</div></div>
    <div class="card"><div class="num" style="color:var(--info)">{info}</div><div class="lbl">Info</div></div>
    <div class="card"><div class="num" style="color:var(--accent)">{total}</div><div class="lbl">Total</div></div>
    <div class="card"><div class="num" style="color:var(--accent)">{assets}</div><div class="lbl">Assets</div></div>
    <div class="card"><div class="num" style="color:var(--critical)">{risk_score}</div><div class="lbl">Risk /10</div></div>
  </div>

  {risk_bar_html}

  {chains_html}

  <h2>Findings</h2>
  {findings_html}

  {assets_html}

  {events_html}

  <footer>QAYAMAT — For authorized security testing only. Handle this report with care.</footer>
</body>
</html>"""


class ReportGenerator:
    def __init__(
        self,
        findings: List[dict],
        config: dict,
        logger: Optional[AuditLogger] = None,
    ):
        self.findings = findings
        self.config = config
        self.logger = logger

    # ── Severity counts ────────────────────────────────────────────────────────
    def _counts(self) -> Dict[str, int]:
        c = {s: 0 for s in ["Critical", "High", "Medium", "Low", "Info"]}
        for f in self.findings:
            sev = f.get("severity", "Info")
            key = sev.capitalize()
            c[key] = c.get(key, 0) + 1
        return c

    # ── Finding HTML block ─────────────────────────────────────────────────────
    def _steps_html(self, f: dict) -> str:
        enriched = enrich_finding_with_steps(dict(f))
        raw_steps = enriched.get("reproduction_steps", [])
        if not raw_steps:
            return ""
        items = []
        in_list = False
        for line in raw_steps:
            line = line.strip()
            if not line:
                continue
            if line.startswith("###"):
                if in_list:
                    items.append("</ol>")
                    in_list = False
                items.append(f"<h4>{line.lstrip('#').strip()}</h4>")
            elif line.startswith("- "):
                items.append(f"<li>{line[2:]}</li>")
            elif line[0].isdigit() and ". " in line[:4]:
                if not in_list:
                    items.append("<ol>")
                    in_list = True
                text = line.split(". ", 1)[-1]
                items.append(f"<li>{text}</li>")
            elif line.startswith("**"):
                items.append(f"<p><strong>{line.replace('**', '')}</strong></p>")
            elif line.startswith("```"):
                continue
            else:
                items.append(f"<p>{line}</p>")
        if in_list:
            items.append("</ol>")
        return f'<div class="steps"><h4>Steps to Reproduce</h4>{"".join(items)}</div>'

    def _finding_html(self, f: dict) -> str:
        if f.get("triage_status") in ("false_positive", "rejected", "duplicate"):
            return ""
        sev  = f.get("severity", "Info").capitalize()
        ev   = f.get("evidence", "")
        desc = f.get("description", "")
        poc  = f.get("poc_payloads", [])
        ai   = f.get("ai_analysis", "")
        cve  = f.get("cve", [])
        tool = f.get("tool", "")
        affected = f.get("affected_urls", [])

        evidence_html = f"<pre>{ev[:1200]}</pre>" if ev else ""
        desc_html     = f'<div class="fdesc">{desc}</div>' if desc else ""
        poc_html      = f"<pre>PoC Payloads:\n" + "\n".join(str(p) for p in poc[:3]) + "</pre>" if poc else ""
        ai_html       = f'<div class="fdesc" style="color:#a0c4ff"><b>AI Analysis:</b> {ai[:600]}</div>' if ai else ""
        cve_html      = f'<div class="fdesc"><b>CVE:</b> {", ".join(cve) if isinstance(cve, list) else cve}</div>' if cve else ""
        tool_html     = f'<div class="fdesc" style="font-size:.75rem">Tool: {tool} | Fingerprint: {f.get("fingerprint","")}</div>'
        aff_html      = ""
        if affected and len(affected) > 1:
            aff_html = f'<div class="fdesc"><b>Affected URLs ({len(affected)}):</b> ' + ", ".join(f"<code>{u}</code>" for u in affected[:5]) + "</div>"

        return (
            f'<div class="finding">'
            f'<div class="fh"><div class="ft">{f.get("title","Unknown")}</div>'
            f'<span class="badge sev-{sev}">{sev}</span></div>'
            f'<div class="furl">{f.get("url","")}</div>'
            f'{desc_html}{aff_html}{cve_html}{self._steps_html(f)}{evidence_html}{poc_html}{ai_html}{tool_html}'
            f'</div>'
        )

    # ── Attack chains HTML ─────────────────────────────────────────────────────
    def _chains_html(self, chains: List[dict]) -> str:
        if not chains:
            return ""
        items = ""
        for chain in chains:
            steps = "".join(
                f'<div class="chain-step">{i+1}. {s}</div>'
                for i, s in enumerate(chain.get("steps", []))
            )
            items += (
                f'<div class="chain">'
                f'<div class="chain-title">⚡ {chain["name"]} '
                f'<span class="badge sev-{chain["severity"]}">{chain["severity"]}</span></div>'
                f'{steps}</div>'
            )
        return f"<h2>Attack Chains</h2>{items}"

    # ── Risk bar HTML ──────────────────────────────────────────────────────────
    def _risk_bar_html(self, risk_score: float) -> str:
        pct = min(100, risk_score * 10)
        return (
            f'<h2>Risk Score: {risk_score:.1f} / 10</h2>'
            f'<div class="risk-bar"><div class="risk-fill" style="width:{pct}%"></div></div>'
        )

    # ── Assets table HTML ──────────────────────────────────────────────────────
    def _assets_html(self, assets: List[dict]) -> str:
        if not assets:
            return ""
        rows = ""
        for a in assets[:100]:
            tech = ", ".join((a.get("technologies") or [])[:3])
            ports = ", ".join(map(str, (a.get("open_ports") or [])[:5]))
            rows += (
                f"<tr>"
                f"<td>{a.get('url','')}</td>"
                f"<td>{a.get('asset_type','')}</td>"
                f"<td>{a.get('status','')}</td>"
                f"<td>{tech}</td>"
                f"<td>{ports}</td>"
                f"</tr>"
            )
        return (
            f"<h2>Assets ({len(assets)} total)</h2>"
            f"<table class='asset-table'>"
            f"<tr><th>URL</th><th>Type</th><th>Status</th><th>Tech</th><th>Ports</th></tr>"
            f"{rows}</table>"
        )

    # ── Events log HTML ────────────────────────────────────────────────────────
    def _events_html(self, events: List[dict]) -> str:
        if not events:
            return ""
        lines = ""
        for ev in events[:200]:
            ts  = str(ev.get("created_at", ""))[:19]
            msg = ev.get("message", "")
            et  = ev.get("event_type", "info")
            cls = f"ev-line ev-{et}" if et in ("critical", "high") else "ev-line"
            lines += f'<div class="{cls}"><span class="ts">{ts}</span>{msg}</div>'
        return f"<h2>Scan Log</h2><div class='event-log'>{lines}</div>"

    # ── Main generate ──────────────────────────────────────────────────────────
    def generate(self, extra: Optional[Dict[str, Any]] = None) -> None:
        extra = extra or {}
        out_dir = Path("reports")
        out_dir.mkdir(exist_ok=True)

        scan_date  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        counts     = self._counts()
        chains     = extra.get("attack_chains", [])
        risk_score = extra.get("risk_score", 0.0)
        assets     = extra.get("assets", [])
        events     = extra.get("events", [])

        # ── JSON ──────────────────────────────────────────────────────────────
        enriched_findings = [
            enrich_finding_with_steps(f) for f in self.findings
            if f.get("triage_status") not in ("false_positive", "rejected", "duplicate")
        ]
        report_data = {
            "scan_date":      scan_date,
            "tool":           "QAYAMAT",
            "author":         "Pr0fessor_SnApe",
            "summary":        counts,
            "total_findings": len(enriched_findings),
            "risk_score":     risk_score,
            "attack_chains":  chains,
            "total_assets":   len(assets),
            "findings":       enriched_findings,
            "assets":         assets[:200],
            "events":         events[:500],
        }
        json_path = out_dir / "report.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, default=str)

        # ── HTML ──────────────────────────────────────────────────────────────
        findings_html = (
            "\n".join(self._finding_html(f) for f in self.findings)
            or "<p style='color:#555'>No findings.</p>"
        )

        html = REPORT_HTML.format(
            scan_date    = scan_date,
            critical     = counts["Critical"],
            high         = counts["High"],
            medium       = counts["Medium"],
            low          = counts["Low"],
            info         = counts["Info"],
            total        = len(self.findings),
            assets       = len(assets),
            risk_score   = f"{risk_score:.1f}",
            risk_bar_html= self._risk_bar_html(risk_score),
            chains_html  = self._chains_html(chains),
            findings_html= findings_html,
            assets_html  = self._assets_html(assets),
            events_html  = self._events_html(events),
        )

        html_path = out_dir / "report.html"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)

        if self.logger:
            self.logger.info(f"Reports generated: {json_path}, {html_path}")
        print(f"[INFO] Reports generated: {json_path}, {html_path}")
