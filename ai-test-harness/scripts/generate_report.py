#!/usr/bin/env python3
"""
Generate daily status and AAR finding reports from evidence timeline data.

Usage:
    python scripts/generate_report.py daily --day 1
    python scripts/generate_report.py finding --id F001 --severity High
"""
import datetime
import json
import os

import click
from jinja2 import Environment, FileSystemLoader
from rich.console import Console

from scripts.config_loader import load_config, get_harness_root
from scripts.evidence import read_timeline

console = Console()


def _get_template_env():
    templates_dir = os.path.join(get_harness_root(), "reporting", "templates")
    return Environment(loader=FileSystemLoader(templates_dir))


@click.group()
def cli():
    """Report generation from evidence data."""
    pass


@cli.command()
@click.option("--day", type=int, required=True, help="Day number (1-5)")
@click.option("--operator", default="Red Team Operator")
@click.option("--output", "-o", default=None)
def daily(day, operator, output):
    """Generate a daily status report."""
    cfg = load_config()
    env = _get_template_env()
    template = env.get_template("daily_status.md")

    entries = read_timeline()
    today = datetime.date.today().isoformat()

    today_entries = [e for e in entries if e["timestamp"].startswith(today)]

    activities = []
    for e in today_entries:
        activities.append({
            "timestamp": e["timestamp"][:19],
            "category": e["category"],
            "action": e["action"][:60],
            "finding": "",
        })

    rendered = template.render(
        engagement_id=cfg["engagement"]["id"],
        date=today,
        day_number=day,
        total_days=5,
        operator=operator,
        summary="[Fill in end-of-day summary]",
        activities=activities,
        findings=[],
        blockers="None",
        next_day_plan="[Fill in]",
        artifact_count=sum(
            len(e.get("artifacts", [])) for e in today_entries),
        timeline_count=len(today_entries),
    )

    if output is None:
        output = os.path.join(get_harness_root(), "reporting", "drafts",
                              f"daily_status_day{day}_{today}.md")

    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, "w") as f:
        f.write(rendered)

    console.print(f"Daily report generated: {output}")


@cli.command()
@click.option("--id", "finding_id", required=True, help="Finding ID (e.g. F001)")
@click.option("--severity", required=True,
              type=click.Choice(["Critical", "High", "Medium", "Low", "Info"]))
@click.option("--category", required=True)
@click.option("--controls", default="")
@click.option("--output", "-o", default=None)
def finding(finding_id, severity, category, controls, output):
    """Generate an AAR finding report template."""
    env = _get_template_env()
    template = env.get_template("aar_finding.md")

    rendered = template.render(
        finding_id=finding_id,
        severity=severity,
        category=category,
        controls=controls or "[Specify NIST controls]",
        date=datetime.date.today().isoformat(),
        description="[Describe the finding]",
        attack_chain_step="[Which step in the attack chain]",
        artifacts=[],
        reproduction_steps="[Step-by-step reproduction]",
        impact="[Impact assessment]",
        remediation="[Recommended fixes]",
        detected="[Yes/No/Partial]",
        detection_mechanism="[How it was detected, if at all]",
        time_to_detect="[Time from action to detection]",
        detection_gap="[What was missed and why]",
    )

    if output is None:
        output = os.path.join(get_harness_root(), "reporting", "drafts",
                              f"finding_{finding_id}.md")

    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, "w") as f:
        f.write(rendered)

    console.print(f"Finding report template generated: {output}")


if __name__ == "__main__":
    cli()
