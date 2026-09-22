#!/usr/bin/env python3
"""
Authentication and authorization tests for TEI endpoints.

Tests unauthenticated access, invalid credentials, method enumeration,
and basic rate limiting behavior.

Usage:
    python api-testing/scripts/auth_tests.py http://localhost:8080
"""
import datetime
import json
import os
import sys
import time
import concurrent.futures

import click
import httpx
from rich.console import Console
from rich.table import Table

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))
from scripts.evidence import log_action

console = Console()


def test_no_auth(client, host):
    """Test unauthenticated access."""
    try:
        resp = client.post(
            f"{host}/embed",
            json={"inputs": "test product"},
            headers={"Content-Type": "application/json"},
        )
        return {"test": "no_auth", "status": resp.status_code,
                "body_preview": resp.text[:200]}
    except Exception as e:
        return {"test": "no_auth", "error": str(e)}


def test_invalid_token(client, host):
    """Test with an invalid bearer token."""
    try:
        resp = client.post(
            f"{host}/embed",
            json={"inputs": "test product"},
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer invalid-token-12345",
            },
        )
        return {"test": "invalid_token", "status": resp.status_code,
                "body_preview": resp.text[:200]}
    except Exception as e:
        return {"test": "invalid_token", "error": str(e)}


def test_method_enumeration(client, host):
    """Test which HTTP methods are accepted."""
    methods = ["GET", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
    results = {}
    for method in methods:
        try:
            resp = client.request(method, f"{host}/embed", timeout=5.0)
            results[method] = resp.status_code
        except Exception as e:
            results[method] = str(e)
    return {"test": "method_enum", "results": results}


def test_rate_limiting(client, host, count=50):
    """Send rapid requests to detect rate limiting."""
    statuses = []

    def make_request(_):
        try:
            resp = client.post(
                f"{host}/embed",
                json={"inputs": "rate limit test"},
                headers={"Content-Type": "application/json"},
            )
            return resp.status_code
        except Exception:
            return "ERR"

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        statuses = list(pool.map(make_request, range(count)))

    status_counts = {}
    for s in statuses:
        status_counts[s] = status_counts.get(s, 0) + 1

    rate_limited = any(s == 429 for s in statuses)
    return {
        "test": "rate_limit",
        "request_count": count,
        "status_distribution": status_counts,
        "rate_limiting_detected": rate_limited,
    }


def test_content_type_handling(client, host):
    """Test how the API handles different content types."""
    content_types = [
        "text/plain",
        "application/xml",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "",
    ]
    results = {}
    for ct in content_types:
        try:
            headers = {}
            if ct:
                headers["Content-Type"] = ct
            resp = client.post(
                f"{host}/embed",
                content=b'{"inputs": "test"}',
                headers=headers,
            )
            results[ct or "(none)"] = resp.status_code
        except Exception as e:
            results[ct or "(none)"] = str(e)
    return {"test": "content_type", "results": results}


@click.command()
@click.argument("host")
@click.option("--rate-limit-count", default=50,
              help="Number of rapid requests for rate limit test")
def main(host, rate_limit_count):
    """Run authentication and authorization tests against a TEI host."""
    console.print(f"\n[bold]Auth Tests: {host}[/bold]")

    client = httpx.Client(timeout=10.0)
    results = []

    tests = [
        ("No Auth", lambda: test_no_auth(client, host)),
        ("Invalid Token", lambda: test_invalid_token(client, host)),
        ("Method Enumeration", lambda: test_method_enumeration(client, host)),
        ("Content Type Handling",
         lambda: test_content_type_handling(client, host)),
        ("Rate Limiting",
         lambda: test_rate_limiting(client, host, rate_limit_count)),
    ]

    for name, test_fn in tests:
        console.print(f"\n  [cyan]{name}[/cyan]")
        result = test_fn()
        results.append(result)

        if "status" in result:
            console.print(f"    Status: {result['status']}")
        if "results" in result:
            for k, v in result["results"].items():
                console.print(f"    {k}: {v}")
        if "rate_limiting_detected" in result:
            detected = result["rate_limiting_detected"]
            color = "green" if detected else "red"
            console.print(
                f"    Rate limiting: [{color}]"
                f"{'DETECTED' if detected else 'NOT DETECTED'}[/{color}]")

    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    results_dir = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "results")
    os.makedirs(results_dir, exist_ok=True)
    out_path = os.path.join(results_dir, f"auth_tests_{ts}.json")

    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    console.print(f"\n  Results saved: {out_path}")

    log_action(
        f"Auth tests completed: {len(results)} tests against {host}",
        "api-testing",
        details={"host": host, "test_count": len(results)},
        artifacts=[out_path],
    )


if __name__ == "__main__":
    main()
