"""
QAYAMAT — Bug bounty program scope import (HackerOne, Bugcrowd, YAML).
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional

import yaml


class ScopeImporter:
    """Parse platform scope exports into QAYAMAT scan config."""

    @staticmethod
    def from_yaml(path: str) -> Dict[str, Any]:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return ScopeImporter._normalize(data)

    @staticmethod
    def from_hackerone_json(path: str) -> Dict[str, Any]:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        in_scope, out_scope = [], []
        for asset in raw.get("targets", raw.get("structured_scopes", [])):
            identifier = asset.get("asset_identifier", asset.get("identifier", ""))
            eligible = asset.get("eligible_for_submission", True)
            if asset.get("archived"):
                continue
            if eligible:
                in_scope.append(identifier)
            else:
                out_scope.append(identifier)
        return ScopeImporter._normalize({
            "program": raw.get("name", raw.get("handle", "hackerone-program")),
            "targets": in_scope,
            "out_of_scope": out_scope,
            "rules": raw.get("policy", "Imported from HackerOne"),
        })

    @staticmethod
    def from_bugcrowd_json(path: str) -> Dict[str, Any]:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        in_scope, out_scope = [], []
        for target in raw.get("targets", raw.get("in_scope", [])):
            uri = target.get("uri", target.get("target", ""))
            if target.get("out_of_scope"):
                out_scope.append(uri)
            else:
                in_scope.append(uri)
        for target in raw.get("out_of_scope", []):
            uri = target.get("uri", target if isinstance(target, str) else "")
            if uri:
                out_scope.append(uri)
        return ScopeImporter._normalize({
            "program": raw.get("name", raw.get("program", "bugcrowd-program")),
            "targets": in_scope,
            "out_of_scope": out_scope,
            "rules": "Imported from Bugcrowd",
        })

    @staticmethod
    def from_scope_txt(path: str) -> Dict[str, Any]:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        in_scope, out_scope = [], []
        section = "in"
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            low = line.lower()
            if low in ("out of scope", "out-of-scope", "oos"):
                section = "out"
                continue
            if low in ("in scope", "in-scope"):
                section = "in"
                continue
            if section == "out":
                out_scope.append(line)
            else:
                in_scope.append(line)
        return ScopeImporter._normalize({"targets": in_scope, "out_of_scope": out_scope})

    @staticmethod
    def auto_detect(path: str) -> Dict[str, Any]:
        p = Path(path)
        if p.suffix in (".yaml", ".yml"):
            return ScopeImporter.from_yaml(str(p))
        if p.suffix == ".json":
            raw = json.loads(p.read_text(encoding="utf-8"))
            if "structured_scopes" in raw or "asset_identifier" in str(raw):
                return ScopeImporter.from_hackerone_json(str(p))
            return ScopeImporter.from_bugcrowd_json(str(p))
        return ScopeImporter.from_scope_txt(str(p))

    @staticmethod
    def _normalize(data: dict) -> Dict[str, Any]:
        targets = []
        for t in data.get("targets", data.get("in_scope", [])):
            if isinstance(t, dict):
                targets.append(t.get("url", t.get("target", t.get("identifier", ""))))
            else:
                targets.append(str(t).strip())
        targets = [t for t in targets if t]

        out = []
        for t in data.get("out_of_scope", data.get("out_of_scope_targets", [])):
            if isinstance(t, dict):
                out.append(t.get("url", t.get("target", "")))
            else:
                out.append(str(t).strip())
        out = [t for t in out if t]

        return {
            "program": data.get("program", data.get("name", "custom-program")),
            "targets": targets,
            "out_of_scope": out,
            "rules": data.get("rules", data.get("policy", "Imported scope")),
            "profile": data.get("profile", "safe"),
            "rate_limit": data.get("rate_limit", data.get("max_requests_per_second", 5)),
        }
