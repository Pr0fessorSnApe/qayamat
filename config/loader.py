"""QAYAMAT — Configuration Loader"""

import yaml
from pathlib import Path


def load_config(path: str = "config/qayamat.yaml") -> dict:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path.resolve()}")
    with open(config_path, encoding="utf-8") as f:
        config = yaml.safe_load(f)
    if config is None:
        raise ValueError(f"Config file is empty: {path}")
    return config
