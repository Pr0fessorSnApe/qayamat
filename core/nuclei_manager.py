"""
QAYAMAT — Nuclei template manager (enable/disable by tech stack and program).
"""

import json
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Optional


class NucleiTemplateManager:
    def __init__(self, templates_dir: Optional[str] = None):
        self.templates_dir = templates_dir or str(Path.home() / "nuclei-templates")
        self._disabled_path = Path("data/nuclei_disabled.json")
        self._disabled_path.parent.mkdir(parents=True, exist_ok=True)
        self._disabled: List[str] = self._load_disabled()

    def _load_disabled(self) -> List[str]:
        if self._disabled_path.exists():
            try:
                return json.loads(self._disabled_path.read_text())
            except Exception:
                return []
        return []

    def _save_disabled(self) -> None:
        self._disabled_path.write_text(json.dumps(self._disabled, indent=2))

    def list_templates(self, tag: str = "") -> List[dict]:
        nuclei = shutil.which("nuclei")
        if not nuclei:
            return []
        cmd = [nuclei, "-tl", "-silent", "-jsonl"]
        if tag:
            cmd += ["-tags", tag]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            templates = []
            for line in out.stdout.splitlines():
                if line.strip():
                    try:
                        templates.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            return templates
        except Exception:
            return []

    def disable_template(self, template_id: str) -> None:
        if template_id not in self._disabled:
            self._disabled.append(template_id)
            self._save_disabled()

    def enable_template(self, template_id: str) -> None:
        if template_id in self._disabled:
            self._disabled.remove(template_id)
            self._save_disabled()

    def build_args(self, program_config: Optional[dict] = None) -> List[str]:
        """Extra nuclei CLI args from program profile."""
        args = []
        if not program_config:
            return args
        tags = program_config.get("nuclei_tags", "")
        exclude = program_config.get("nuclei_exclude_tags", "dos,intrusive")
        if tags:
            args += ["-tags", tags]
        if exclude:
            args += ["-etags", exclude]
        if self._disabled:
            for tid in self._disabled[:50]:
                args += ["-exclude", tid]
        return args

    def recommend_tags(self, technologies: List[str]) -> str:
        """Map detected tech to nuclei tag sets."""
        tech = " ".join(t.lower() for t in technologies)
        tags = []
        mapping = {
            "wordpress": "wordpress",
            "drupal": "drupal",
            "joomla": "joomla",
            "graphql": "graphql",
            "jenkins": "jenkins",
            "aws": "aws",
            "azure": "azure",
            "kubernetes": "k8s",
            "spring": "springboot",
            "php": "php",
            "apache": "apache",
            "nginx": "nginx",
        }
        for key, tag in mapping.items():
            if key in tech:
                tags.append(tag)
        return ",".join(tags) if tags else "cve,misconfig,exposure"
