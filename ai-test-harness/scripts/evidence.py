#!/usr/bin/env python3
"""
Central evidence logging for all red team actions.

Appends timestamped entries to evidence/timeline.jsonl.
Every test script calls into this module to maintain the evidence chain.

Usage:
    # As a library
    from scripts.evidence import log_action, summarize_timeline

    log_action("Pushed modified image to test ECR", "supply-chain",
               details={"image_tag": "v1.2.3-modified"},
               artifacts=["evidence/artifacts/modified_image_id.txt"])

    # As CLI
    python scripts/evidence.py log "Pushed modified image" supply-chain
    python scripts/evidence.py summary
    python scripts/evidence.py export --format csv
"""
import json
import datetime
import hashlib
import os
import sys

import click
from rich.console import Console
from rich.table import Table

from scripts.config_loader import get_harness_root, load_config

console = Console()

CATEGORIES = [
    "setup", "model-lab", "container-pipeline", "supply-chain",
    "network", "exfiltration", "api-testing", "lateral-movement",
    "evidence", "general",
]


def _timeline_path():
    try:
        cfg = load_config()
        return os.path.join(get_harness_root(),
                            cfg["evidence"]["timeline_file"])
    except SystemExit:
        return os.path.join(get_harness_root(), "evidence", "timeline.jsonl")


def log_action(action, category, details=None, artifacts=None):
    """Log a red team action to the evidence timeline."""
    timeline_file = _timeline_path()
    os.makedirs(os.path.dirname(timeline_file), exist_ok=True)

    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "action": action,
        "category": category,
        "details": details or {},
    }

    if artifacts:
        entry["artifacts"] = []
        for path in artifacts:
            abs_path = path if os.path.isabs(path) else os.path.join(
                get_harness_root(), path)
            artifact_entry = {"path": path}
            if os.path.exists(abs_path):
                with open(abs_path, "rb") as f:
                    artifact_entry["sha256"] = hashlib.sha256(
                        f.read()).hexdigest()
                artifact_entry["size_bytes"] = os.path.getsize(abs_path)
            else:
                artifact_entry["note"] = "file not found at log time"
            entry["artifacts"].append(artifact_entry)

    with open(timeline_file, "a") as f:
        f.write(json.dumps(entry) + "\n")

    console.print(
        f"[dim]{entry['timestamp']}[/dim] "
        f"[bold cyan]{category}[/bold cyan]: {action}"
    )
    return entry


def read_timeline():
    """Read all entries from the timeline."""
    timeline_file = _timeline_path()
    if not os.path.exists(timeline_file):
        return []
    entries = []
    with open(timeline_file) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def summarize_timeline():
    """Print a summary of all logged actions."""
    entries = read_timeline()
    if not entries:
        console.print("[yellow]No entries in timeline.[/yellow]")
        return

    table = Table(title=f"Evidence Timeline ({len(entries)} entries)")
    table.add_column("Timestamp", style="dim")
    table.add_column("Category", style="cyan")
    table.add_column("Action")
    table.add_column("Artifacts", style="green")

    for e in entries:
        artifact_count = str(len(e.get("artifacts", [])))
        table.add_row(
            e["timestamp"][:19],
            e["category"],
            e["action"][:60],
            artifact_count if artifact_count != "0" else "",
        )

    console.print(table)

    category_counts = {}
    for e in entries:
        cat = e["category"]
        category_counts[cat] = category_counts.get(cat, 0) + 1

    console.print("\n[bold]By category:[/bold]")
    for cat, count in sorted(category_counts.items(),
                             key=lambda x: -x[1]):
        console.print(f"  {cat}: {count}")


def export_timeline(fmt="csv"):
    """Export timeline to CSV or JSON."""
    entries = read_timeline()
    if not entries:
        console.print("[yellow]No entries to export.[/yellow]")
        return

    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S")

    if fmt == "csv":
        import csv
        out_path = os.path.join(get_harness_root(), "evidence",
                                f"timeline_export_{ts}.csv")
        with open(out_path, "w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["timestamp", "category", "action", "details",
                            "artifacts"],
            )
            writer.writeheader()
            for e in entries:
                row = dict(e)
                row["details"] = json.dumps(row.get("details", {}))
                row["artifacts"] = json.dumps(row.get("artifacts", []))
                writer.writerow(row)
    else:
        out_path = os.path.join(get_harness_root(), "evidence",
                                f"timeline_export_{ts}.json")
        with open(out_path, "w") as f:
            json.dump(entries, f, indent=2)

    console.print(f"Exported {len(entries)} entries to {out_path}")


@click.group()
def cli():
    """Evidence capture and timeline management."""
    pass


@cli.command()
@click.argument("action")
@click.argument("category", default="general")
@click.option("--detail", "-d", multiple=True, help="key=value details")
@click.option("--artifact", "-a", multiple=True, help="artifact file paths")
def log(action, category, detail, artifact):
    """Log an action to the timeline."""
    details = {}
    for d in detail:
        if "=" in d:
            k, v = d.split("=", 1)
            details[k] = v

    log_action(action, category, details=details or None,
               artifacts=list(artifact) or None)


@cli.command()
def summary():
    """Show a summary of all timeline entries."""
    summarize_timeline()


@cli.command()
@click.option("--format", "fmt", type=click.Choice(["csv", "json"]),
              default="csv")
def export(fmt):
    """Export timeline to CSV or JSON."""
    export_timeline(fmt)


if __name__ == "__main__":
    cli()
