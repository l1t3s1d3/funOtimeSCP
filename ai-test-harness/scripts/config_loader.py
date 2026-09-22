"""Load harness configuration from YAML."""
import os
import sys
import yaml

_CONFIG = None
_HARNESS_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_harness_root():
    return _HARNESS_ROOT


def load_config(path=None):
    global _CONFIG
    if _CONFIG is not None and path is None:
        return _CONFIG

    if path is None:
        path = os.path.join(_HARNESS_ROOT, "config", "harness.yaml")

    if not os.path.exists(path):
        print(f"Config not found: {path}")
        print("Copy config/harness.yaml.example to config/harness.yaml and edit it.")
        sys.exit(1)

    with open(path) as f:
        _CONFIG = yaml.safe_load(f)

    return _CONFIG


def resolve_path(relative_path):
    """Resolve a path relative to the harness root."""
    if os.path.isabs(relative_path):
        return relative_path
    return os.path.join(_HARNESS_ROOT, relative_path)
