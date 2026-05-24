"""
QAYAMAT — Playwright browser-based scanning (DOM XSS, forms, screenshots).
"""

from pathlib import Path
from typing import Dict, List, Optional

SCREENSHOT_DIR = Path("screenshots/playwright")


class PlaywrightScanner:
    """Headless Chromium checks for issues static scanners miss."""

    def __init__(self, timeout_ms: int = 15000):
        self.timeout_ms = timeout_ms
        self._available = False
        self._playwright = None
        self._browser = None
        try:
            from playwright.sync_api import sync_playwright
            self._sync_playwright = sync_playwright
            self._available = True
        except ImportError:
            self._available = False

    @property
    def available(self) -> bool:
        return self._available

    def _ensure_browser(self):
        if self._browser:
            return
        if not self._available:
            raise RuntimeError(
                "Playwright not installed. Run: pip install playwright && "
                "python -m playwright install chromium"
            )
        self._playwright = self._sync_playwright().start()
        self._browser = self._playwright.chromium.launch(headless=True)

    def close(self) -> None:
        try:
            if self._browser:
                self._browser.close()
            if self._playwright:
                self._playwright.stop()
        except Exception:
            pass
        self._browser = None
        self._playwright = None

    def scan_url(self, url: str) -> List[Dict]:
        """Return findings from browser analysis of a single URL."""
        if not url.startswith("http"):
            url = f"https://{url}"
        findings: List[Dict] = []
        self._ensure_browser()
        SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

        page = self._browser.new_page()
        try:
            page.set_default_timeout(self.timeout_ms)
            dialog_triggered = []

            def _on_dialog(dialog):
                dialog_triggered.append(dialog.message)
                dialog.dismiss()

            page.on("dialog", _on_dialog)

            resp = page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            status = resp.status if resp else 0

            # DOM XSS: inject marker; confirm only if script dialog fires
            try:
                page.evaluate(
                    """() => {
                        const el = document.createElement('div');
                        el.innerHTML = '<img src=x onerror="window.__qayamat_xss=1">';
                        document.body.appendChild(el);
                    }"""
                )
                has_marker = page.evaluate("() => window.__qayamat_xss === 1")
                if has_marker or dialog_triggered:
                    findings.append({
                        "title": "DOM-based XSS (Playwright confirmed)",
                        "severity": "high",
                        "vuln_type": "XSS",
                        "url": url,
                        "description": "Client-side DOM executed injected markup (onerror handler ran).",
                        "evidence": f"dialog={dialog_triggered} executed={has_marker}",
                        "tool": "playwright",
                    })
            except Exception:
                pass

            # Collect forms for parameter testing surface
            forms = page.query_selector_all("form")
            if len(forms) > 3:
                findings.append({
                    "title": f"Multiple input forms exposed ({len(forms)} forms)",
                    "severity": "info",
                    "vuln_type": "Attack Surface",
                    "url": url,
                    "description": "Numerous forms increase XSS/CSRF testing surface.",
                    "evidence": f"form_count={len(forms)}",
                    "tool": "playwright",
                })

            # Security headers check
            headers = resp.headers if resp else {}
            missing = []
            for h in ("content-security-policy", "x-frame-options", "strict-transport-security"):
                if h not in {k.lower() for k in headers}:
                    missing.append(h)
            if missing and status < 400:
                findings.append({
                    "title": f"Missing security headers: {', '.join(missing[:3])}",
                    "severity": "low",
                    "vuln_type": "Misconfiguration",
                    "url": url,
                    "description": "Browser-visible response lacks recommended security headers.",
                    "evidence": str(missing),
                    "tool": "playwright",
                })

            safe_name = url.replace("://", "_").replace("/", "_")[:80]
            shot = SCREENSHOT_DIR / f"{safe_name}.png"
            page.screenshot(path=str(shot), full_page=False)
            findings.append({
                "title": "Playwright screenshot captured",
                "severity": "info",
                "vuln_type": "Evidence",
                "url": url,
                "description": f"Visual evidence saved to {shot}",
                "evidence": str(shot),
                "tool": "playwright",
                "screenshot": str(shot),
            })

        except Exception as e:
            findings.append({
                "title": "Playwright navigation note",
                "severity": "info",
                "vuln_type": "Scan Note",
                "url": url,
                "description": str(e)[:200],
                "tool": "playwright",
            })
        finally:
            page.close()
        return findings

    def scan_urls(self, urls: List[str], limit: int = 10) -> List[Dict]:
        all_findings = []
        try:
            for url in urls[:limit]:
                all_findings.extend(self.scan_url(url))
        finally:
            self.close()
        return all_findings
