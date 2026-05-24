"""Passive GitHub reconnaissance for in-scope GitHub assets."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests


def parse_github_target(target: str) -> Optional[Dict[str, str]]:
    """Parse GitHub org/user/repo targets from URL or SSH forms."""
    raw = (target or "").strip()
    if not raw:
        return None

    ssh_match = re.match(r"^git@github\.com:([^/\s]+)/([^/\s]+?)(?:\.git)?/?$", raw, flags=re.I)
    if ssh_match:
        owner, repo = ssh_match.groups()
        return {"type": "repo", "owner": owner, "repo": repo}

    if raw.startswith("github.com/"):
        raw = f"https://{raw}"

    parsed = urlparse(raw)
    if parsed.netloc.lower() != "github.com":
        return None

    parts = [part for part in parsed.path.split("/") if part]
    if not parts:
        return None
    if len(parts) == 1:
        return {"type": "owner", "owner": parts[0]}

    repo = parts[1].removesuffix(".git")
    return {"type": "repo", "owner": parts[0], "repo": repo}


def is_github_target(target: str) -> bool:
    return parse_github_target(target) is not None


class GitHubRecon:
    def __init__(self, token: str = "", logger=None, max_repos: int = 25):
        self.logger = logger
        self.max_repos = max(1, max_repos)
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "User-Agent": "QAYAMAT-GitHub-Recon",
            }
        )
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

    @classmethod
    def from_sources(cls, vault=None, config: Optional[dict] = None, logger=None) -> "GitHubRecon":
        token = os.getenv("GITHUB_TOKEN", "")
        if not token and vault:
            token = vault.get_secret("github_token")
        github_max_repos = ((config or {}).get("intel", {}) or {}).get("github_max_repos", 25)
        return cls(token=token, logger=logger, max_repos=github_max_repos)

    def _get_json(self, path: str, params: Optional[dict] = None) -> Any:
        response = self.session.get(f"https://api.github.com{path}", params=params, timeout=15)
        if response.status_code in (401, 403, 404):
            return None
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _normalize_url(value: str) -> str:
        if not value:
            return ""
        parsed = urlparse(value if "://" in value else f"https://{value}")
        if not parsed.netloc:
            return ""
        return parsed.geturl()

    @staticmethod
    def _extract_host(url: str) -> str:
        parsed = urlparse(url)
        return parsed.netloc.lower().split(":")[0]

    def _repo_pages_url(self, owner: str, repo: str) -> str:
        return f"/repos/{owner}/{repo}/pages"

    def _collect_repo_record(self, repo: Dict[str, Any]) -> Dict[str, Any]:
        homepage = self._normalize_url(repo.get("homepage", ""))
        urls = [homepage] if homepage else []
        hosts = [self._extract_host(homepage)] if homepage else []

        if repo.get("has_pages"):
            pages = self._get_json(self._repo_pages_url(repo["owner"]["login"], repo["name"])) or {}
            html_url = self._normalize_url(pages.get("html_url", ""))
            custom_domain = self._normalize_url(pages.get("custom_domain", ""))
            for candidate in (html_url, custom_domain):
                if candidate:
                    urls.append(candidate)
                    hosts.append(self._extract_host(candidate))

        return {
            "full_name": repo.get("full_name", ""),
            "url": repo.get("html_url", ""),
            "homepage": homepage,
            "language": repo.get("language", ""),
            "topics": repo.get("topics", []),
            "visibility": "private" if repo.get("private") else "public",
            "archived": bool(repo.get("archived")),
            "urls": [url for url in urls if url],
            "hosts": [host for host in hosts if host and host != "github.com"],
        }

    def scan_target(self, target: str) -> Dict[str, Any]:
        parsed = parse_github_target(target)
        if not parsed:
            return {"profiles": [], "repos": [], "urls": [], "hosts": [], "contributors": []}

        owner = parsed["owner"]
        owner_profile = self._get_json(f"/users/{owner}") or {}
        profiles = []
        if owner_profile:
            profiles.append(
                {
                    "login": owner_profile.get("login", owner),
                    "type": owner_profile.get("type", "User"),
                    "url": owner_profile.get("html_url", f"https://github.com/{owner}"),
                    "name": owner_profile.get("name", ""),
                    "blog": self._normalize_url(owner_profile.get("blog", "")),
                    "public_repos": owner_profile.get("public_repos", 0),
                }
            )

        repos: List[Dict[str, Any]] = []
        contributors: List[str] = []

        if parsed["type"] == "repo":
            repo = self._get_json(f"/repos/{owner}/{parsed['repo']}") or {}
            if repo:
                repos.append(self._collect_repo_record(repo))
            contrib_rows = self._get_json(
                f"/repos/{owner}/{parsed['repo']}/contributors",
                params={"per_page": 20},
            ) or []
            contributors.extend(
                row.get("login", "")
                for row in contrib_rows
                if isinstance(row, dict) and row.get("login")
            )
        else:
            repo_rows = self._get_json(
                f"/users/{owner}/repos",
                params={"per_page": self.max_repos, "sort": "updated"},
            ) or []
            for repo in repo_rows[: self.max_repos]:
                if isinstance(repo, dict):
                    repos.append(self._collect_repo_record(repo))

        urls: List[str] = []
        hosts: List[str] = []
        for profile in profiles:
            blog = profile.get("blog", "")
            if blog:
                urls.append(blog)
                hosts.append(self._extract_host(blog))
        for repo in repos:
            urls.extend(repo.get("urls", []))
            hosts.extend(repo.get("hosts", []))

        return {
            "profiles": profiles,
            "repos": repos,
            "urls": sorted({url for url in urls if url}),
            "hosts": sorted({host for host in hosts if host}),
            "contributors": sorted({c for c in contributors if c}),
        }
