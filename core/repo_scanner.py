"""QAYAMAT — Repository Secret Scanner
Runs trufflehog and gitleaks against git repositories to find leaked secrets.
"""

import json
import subprocess
import shutil
from typing import Dict, List, Optional
from .vault import Vault
from .logger import AuditLogger


class RepoSecretScanner:
    VERIFIABLE_PATTERNS = {
        "aws_key": lambda s: s.startswith("AKIA") or s.startswith("ASIA"),
        "github_token": lambda s: s.startswith("ghp_") or s.startswith("github_pat_"),
        "stripe_key": lambda s: s.startswith("sk_live_") or s.startswith("pk_live_"),
    }

    def __init__(self, vault: Vault, logger: AuditLogger):
        self.vault = vault
        self.logger = logger
        self._trufflehog = shutil.which("trufflehog")
        self._gitleaks = shutil.which("gitleaks")

    def _run_trufflehog(self, repo_url: str, commit_sha: Optional[str] = None) -> List[dict]:
        if not self._trufflehog:
            self.logger.warning("trufflehog not found in PATH")
            return []

        cmd = [self._trufflehog, "git", repo_url, "--json", "--no-verification"]
        if commit_sha:
            cmd += ["--since-commit", commit_sha]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            findings = []
            for line in result.stdout.strip().splitlines():
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return findings
        except subprocess.TimeoutExpired:
            self.logger.error("trufflehog timed out")
            return []
        except Exception as e:
            self.logger.error(f"trufflehog error: {e}")
            return []

    def _run_gitleaks(self, repo_url: str) -> List[dict]:
        if not self._gitleaks:
            self.logger.warning("gitleaks not found in PATH")
            return []

        # gitleaks needs a local path; for remote repos, clone first
        # For simplicity, we use detect mode on already-cloned paths
        cmd = [self._gitleaks, "detect", "--source", repo_url, "-f", "json", "-q"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if result.stdout:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    return []
        except subprocess.TimeoutExpired:
            self.logger.error("gitleaks timed out")
        except Exception as e:
            self.logger.error(f"gitleaks error: {e}")
        return []

    def _classify_secret(self, raw: str) -> Optional[str]:
        """Return a secret type label if the raw value matches a known pattern."""
        if not raw:
            return None
        for name, check in self.VERIFIABLE_PATTERNS.items():
            if check(raw):
                return name
        return "generic_secret"

    def scan(self, repo_url: str, commit_sha: Optional[str] = None) -> Dict:
        """Scan a repository for secrets. Returns dict with raw_findings and classified list."""
        self.logger.info(f"Scanning repo: {repo_url}")

        th_findings = self._run_trufflehog(repo_url, commit_sha)
        gl_findings = self._run_gitleaks(repo_url)

        all_findings = th_findings + gl_findings
        classified = []
        for f in all_findings:
            raw = f.get("Raw") or f.get("raw") or f.get("Secret") or f.get("Match", "")
            secret_type = self._classify_secret(raw)
            classified.append({
                "source_tool": "trufflehog" if f in th_findings else "gitleaks",
                "secret_type": secret_type,
                "raw_value": raw[:50] + "…" if len(raw) > 50 else raw,  # truncate for safety
                "file": f.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("file")
                        or f.get("File", "unknown"),
                "commit": f.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("commit")
                          or f.get("Commit", "unknown"),
                "line": f.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("line")
                        or f.get("StartLine", 0),
            })

        self.logger.info(f"Secret scan complete: {len(classified)} findings in {repo_url}")
        return {"repo": repo_url, "total": len(classified), "findings": classified}
