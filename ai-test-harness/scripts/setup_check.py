#!/usr/bin/env python3
"""
Pre-engagement setup check.

Validates that all required tools, directories, and configurations
are in place before kickoff. Run this to get a go/no-go readiness report.

Usage:
    python scripts/setup_check.py
    python scripts/setup_check.py --verbose
"""
import os
import shutil
import subprocess
import sys

import click
from rich.console import Console
from rich.table import Table

console = Console()

HARNESS_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def check_command(name, cmd):
    """Check if a command-line tool is available."""
    path = shutil.which(name)
    if path:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=5)
            version = result.stdout.strip().split("\n")[0][:60]
            return True, version
        except Exception:
            return True, f"found at {path}"
    return False, "not found"


def check_directory(path):
    """Check if a directory exists."""
    abs_path = os.path.join(HARNESS_ROOT, path)
    return os.path.isdir(abs_path), abs_path


def check_file(path):
    """Check if a file exists."""
    abs_path = os.path.join(HARNESS_ROOT, path)
    return os.path.isfile(abs_path), abs_path


def check_python_package(name):
    """Check if a Python package is importable."""
    try:
        __import__(name)
        return True, "installed"
    except ImportError:
        return False, "not installed"


@click.command()
@click.option("--verbose", "-v", is_flag=True, help="Show details")
def main(verbose):
    """Run the pre-engagement setup check."""
    console.print("\n[bold]AI Test Harness — Setup Check[/bold]\n")

    passed = 0
    failed = 0
    warnings = 0

    # --- System tools ---
    table = Table(title="System Tools")
    table.add_column("Tool", style="cyan")
    table.add_column("Status")
    table.add_column("Detail", style="dim")

    tools = [
        ("python3", ["python3", "--version"]),
        ("docker", ["docker", "--version"]),
        ("docker-compose", ["docker-compose", "--version"]),
        ("curl", ["curl", "--version"]),
        ("jq", ["jq", "--version"]),
        ("nmap", ["nmap", "--version"]),
        ("git", ["git", "--version"]),
    ]

    optional_tools = [
        ("aws", ["aws", "--version"]),
        ("tcpdump", ["tcpdump", "--version"]),
    ]

    for name, cmd in tools:
        ok, detail = check_command(name, cmd)
        status = "[green]OK[/green]" if ok else "[red]MISSING[/red]"
        table.add_row(name, status, detail if verbose else "")
        if ok:
            passed += 1
        else:
            failed += 1

    for name, cmd in optional_tools:
        ok, detail = check_command(name, cmd)
        status = "[green]OK[/green]" if ok else "[yellow]OPTIONAL[/yellow]"
        table.add_row(name, status, detail if verbose else "")
        if ok:
            passed += 1
        else:
            warnings += 1

    console.print(table)

    # --- Python packages ---
    table = Table(title="Python Packages")
    table.add_column("Package", style="cyan")
    table.add_column("Status")

    packages = [
        "torch", "transformers", "sentence_transformers", "safetensors",
        "huggingface_hub", "httpx", "requests", "docker",
        "pandas", "numpy", "matplotlib", "jinja2",
        "rich", "yaml", "click",
    ]

    for pkg in packages:
        ok, detail = check_python_package(pkg)
        status = "[green]OK[/green]" if ok else "[yellow]MISSING[/yellow]"
        table.add_row(pkg, status)
        if ok:
            passed += 1
        else:
            warnings += 1

    console.print(table)

    # --- Directory structure ---
    table = Table(title="Directory Structure")
    table.add_column("Directory", style="cyan")
    table.add_column("Status")

    dirs = [
        "models/clean", "models/modified",
        "containers/clean", "containers/modified",
        "api-testing/corpus", "api-testing/scripts", "api-testing/results",
        "network/egress-tests", "network/callback-infra",
        "evidence/screenshots", "evidence/logs",
        "evidence/artifacts", "reporting/templates",
        "scripts", "config",
    ]

    for d in dirs:
        ok, _ = check_directory(d)
        status = "[green]OK[/green]" if ok else "[red]MISSING[/red]"
        table.add_row(d, status)
        if ok:
            passed += 1
        else:
            failed += 1

    console.print(table)

    # --- Key files ---
    table = Table(title="Key Files")
    table.add_column("File", style="cyan")
    table.add_column("Status")

    files = [
        ("config/harness.yaml", True),
        ("scripts/evidence.py", True),
        ("scripts/model_lab.py", True),
        ("api-testing/scripts/fuzz_tei.py", True),
        ("api-testing/scripts/build_corpus.py", True),
        ("api-testing/scripts/auth_tests.py", True),
        ("network/egress-tests/egress_probe.sh", True),
        ("network/callback-infra/listener.py", True),
        ("containers/build.sh", True),
    ]

    for fpath, required in files:
        ok, _ = check_file(fpath)
        if ok:
            status = "[green]OK[/green]"
            passed += 1
        elif required:
            status = "[red]MISSING[/red]"
            failed += 1
        else:
            status = "[yellow]OPTIONAL[/yellow]"
            warnings += 1
        table.add_row(fpath, status)

    console.print(table)

    # --- Summary ---
    console.print(f"\n[bold]Results:[/bold]")
    console.print(f"  [green]Passed: {passed}[/green]")
    console.print(f"  [red]Failed: {failed}[/red]")
    console.print(f"  [yellow]Warnings: {warnings}[/yellow]")

    if failed == 0:
        console.print("\n[bold green]GO — All required checks passed.[/bold green]")
    else:
        console.print(f"\n[bold red]NO-GO — {failed} required check(s) failed.[/bold red]")
        console.print("Fix the issues above before proceeding.")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
