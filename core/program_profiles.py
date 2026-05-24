"""
QAYAMAT — Per-program custom scan profiles (YAML).
"""

from pathlib import Path
from typing import Dict, Any, Optional, List
import yaml


PROGRAMS_DIR = Path("config/programs")


class ProgramProfileLoader:
    def __init__(self, programs_dir: Optional[Path] = None):
        self.programs_dir = programs_dir or PROGRAMS_DIR
        self.programs_dir.mkdir(parents=True, exist_ok=True)

    def list_programs(self) -> List[str]:
        return [p.stem for p in self.programs_dir.glob("*.yaml")]

    def load(self, program_name: str) -> Dict[str, Any]:
        path = self.programs_dir / f"{program_name}.yaml"
        if not path.exists():
            path = self.programs_dir / f"{program_name}.yml"
        if not path.exists():
            return {}
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return data

    def merge_with_config(self, base_config: dict, program_name: str) -> dict:
        """Overlay program-specific settings onto global qayamat.yaml config."""
        prog = self.load(program_name)
        if not prog:
            return base_config
        merged = {**base_config}
        for key in ("general", "ai", "validation", "intel", "tools", "scan"):
            if key in prog:
                merged[key] = {**merged.get(key, {}), **prog[key]}
        merged["program"] = {
            "name": program_name,
            "targets": prog.get("targets", []),
            "out_of_scope": prog.get("out_of_scope", []),
            "profile": prog.get("profile", "safe"),
            "nuclei_tags": prog.get("nuclei_tags", ""),
            "nuclei_exclude_tags": prog.get("nuclei_exclude_tags", ""),
            "enabled_tools": prog.get("enabled_tools", []),
            "disabled_tools": prog.get("disabled_tools", []),
            "rate_limit": prog.get("rate_limit", 5),
            "rules": prog.get("rules", ""),
        }
        return merged

    def save_program(self, program_name: str, data: dict) -> str:
        path = self.programs_dir / f"{program_name}.yaml"
        path.write_text(yaml.dump(data, default_flow_style=False), encoding="utf-8")
        return str(path)
