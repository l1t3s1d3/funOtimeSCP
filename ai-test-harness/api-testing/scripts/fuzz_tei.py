#!/usr/bin/env python3
"""
Automated fuzzing of TEI API endpoints.

Sends the adversarial corpus and logs responses with timestamps.
Supports both /embed and /rerank endpoints.

Usage:
    python api-testing/scripts/fuzz_tei.py http://localhost:8080
    python api-testing/scripts/fuzz_tei.py http://localhost:8080 --corpus custom.json
    python api-testing/scripts/fuzz_tei.py http://localhost:8080 --endpoint embed
"""
import json
import datetime
import os
import sys
import time

import click
import httpx
from rich.console import Console
from rich.progress import Progress

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))
from scripts.evidence import log_action

console = Console()

RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "results")


def test_embed(client, host, input_text, category, index):
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    try:
        resp = client.post(
            f"{host}/embed",
            json={"inputs": input_text},
            headers={"Content-Type": "application/json"},
        )
        return {
            "timestamp": ts,
            "endpoint": "/embed",
            "category": category,
            "index": index,
            "input_repr": repr(input_text)[:200],
            "status_code": resp.status_code,
            "response_length": len(resp.content),
            "response_preview": resp.text[:500],
            "response_time_ms": resp.elapsed.total_seconds() * 1000,
        }
    except Exception as e:
        return {
            "timestamp": ts,
            "endpoint": "/embed",
            "category": category,
            "index": index,
            "input_repr": repr(input_text)[:200],
            "error": str(e),
        }


def test_rerank(client, host, query, texts, category, index):
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    try:
        resp = client.post(
            f"{host}/rerank",
            json={"query": query, "texts": texts},
            headers={"Content-Type": "application/json"},
        )
        return {
            "timestamp": ts,
            "endpoint": "/rerank",
            "category": category,
            "index": index,
            "input_repr": repr(query)[:200],
            "status_code": resp.status_code,
            "response_preview": resp.text[:500],
            "response_time_ms": resp.elapsed.total_seconds() * 1000,
        }
    except Exception as e:
        return {
            "timestamp": ts,
            "endpoint": "/rerank",
            "category": category,
            "index": index,
            "input_repr": repr(query)[:200],
            "error": str(e),
        }


def discover_endpoints(client, host):
    """Probe known TEI endpoints and report status."""
    endpoints = [
        "/info", "/embed", "/rerank", "/predict",
        "/tokenize", "/health", "/metrics", "/openapi.json",
    ]
    results = {}
    for ep in endpoints:
        try:
            resp = client.get(f"{host}{ep}", timeout=5.0)
            results[ep] = resp.status_code
        except Exception:
            results[ep] = "ERROR"
    return results


@click.command()
@click.argument("host")
@click.option("--corpus", default=None, help="Path to adversarial corpus JSON")
@click.option("--endpoint", type=click.Choice(["embed", "rerank", "all"]),
              default="all")
@click.option("--rate-limit", default=0.2, help="Seconds between requests")
@click.option("--timeout", default=30.0, help="Request timeout in seconds")
@click.option("--discover/--no-discover", default=True,
              help="Run endpoint discovery first")
def main(host, corpus, endpoint, rate_limit, timeout, discover):
    """Fuzz TEI API endpoints with adversarial inputs."""
    if corpus is None:
        corpus = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "corpus", "adversarial_inputs.json")

    if not os.path.exists(corpus):
        console.print(f"[red]Corpus not found: {corpus}[/red]")
        console.print("Run build_corpus.py first.")
        sys.exit(1)

    with open(corpus) as f:
        corpus_data = json.load(f)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    results_file = os.path.join(RESULTS_DIR, f"fuzz_{ts}.jsonl")

    client = httpx.Client(timeout=timeout)

    if discover:
        console.print(f"\n[bold]Endpoint Discovery: {host}[/bold]")
        ep_results = discover_endpoints(client, host)
        for ep, status in ep_results.items():
            color = "green" if status == 200 else "yellow"
            console.print(f"  {ep}: [{color}]{status}[/{color}]")

    console.print(f"\n[bold]Fuzzing {host}[/bold]")
    console.print(f"  Corpus: {corpus}")
    console.print(f"  Results: {results_file}")

    total_tests = 0
    errors = 0
    status_counts = {}

    with open(results_file, "w") as out:
        if endpoint in ("embed", "all"):
            embed_inputs = corpus_data.get("embed_inputs", {})
            for category, inputs in embed_inputs.items():
                for i, inp in enumerate(inputs):
                    if inp is None:
                        inp = ""
                    result = test_embed(client, host, str(inp), category, i)
                    out.write(json.dumps(result) + "\n")
                    total_tests += 1

                    status = result.get("status_code", "ERR")
                    status_counts[status] = status_counts.get(status, 0) + 1
                    if "error" in result:
                        errors += 1

                    console.print(
                        f"  [dim][{category}:{i}][/dim] embed: {status}")
                    time.sleep(rate_limit)

        if endpoint in ("rerank", "all"):
            rerank_pairs = corpus_data.get("rerank_pairs", {})
            for category, pairs in rerank_pairs.items():
                for i, pair in enumerate(pairs):
                    query = pair.get("query", "")
                    texts = pair.get("texts", [])
                    result = test_rerank(client, host, query, texts,
                                         category, i)
                    out.write(json.dumps(result) + "\n")
                    total_tests += 1

                    status = result.get("status_code", "ERR")
                    status_counts[status] = status_counts.get(status, 0) + 1
                    if "error" in result:
                        errors += 1

                    console.print(
                        f"  [dim][{category}:{i}][/dim] rerank: {status}")
                    time.sleep(rate_limit)

    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"  Total tests: {total_tests}")
    console.print(f"  Errors: {errors}")
    console.print(f"  Status codes: {status_counts}")
    console.print(f"  Results: {results_file}")

    log_action(
        f"API fuzzing completed: {total_tests} tests, {errors} errors",
        "api-testing",
        details={"host": host, "total": total_tests, "errors": errors,
                 "status_counts": status_counts},
        artifacts=[results_file],
    )


if __name__ == "__main__":
    main()
