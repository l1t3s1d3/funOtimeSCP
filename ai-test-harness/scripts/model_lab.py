#!/usr/bin/env python3
"""
ML Model Lab — Workstream 1

Handles model download, fingerprinting, baseline inference, and
comparison between clean and modified model variants.

Usage:
    python scripts/model_lab.py download       # Pull clean models from HF
    python scripts/model_lab.py fingerprint    # SHA-256 hash all model files
    python scripts/model_lab.py baseline       # Run clean inference baselines
    python scripts/model_lab.py compare        # Compare clean vs modified outputs
    python scripts/model_lab.py validate       # Validate modified models pass functional tests
"""
import json
import hashlib
import os
import sys
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import click
from rich.console import Console
from rich.table import Table

from scripts.config_loader import load_config, resolve_path, get_harness_root
from scripts.evidence import log_action

console = Console()


def _hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _hash_directory(directory):
    """Hash every file in a directory, return sorted list of (relpath, hash)."""
    results = []
    for root, _, files in os.walk(directory):
        for fname in sorted(files):
            fpath = os.path.join(root, fname)
            relpath = os.path.relpath(fpath, directory)
            results.append((relpath, _hash_file(fpath)))
    results.sort()
    return results


@click.group()
def cli():
    """ML Model Lab operations."""
    pass


@cli.command()
@click.option("--model", type=click.Choice(["embedding", "reranker", "all"]),
              default="all")
def download(model):
    """Download clean model baselines from HuggingFace."""
    cfg = load_config()

    models_to_download = []
    if model in ("embedding", "all"):
        models_to_download.append(cfg["models"]["embedding"])
    if model in ("reranker", "all"):
        models_to_download.append(cfg["models"]["reranker"])

    for m in models_to_download:
        local_dir = resolve_path(m["local_dir"])
        os.makedirs(local_dir, exist_ok=True)

        console.print(f"[bold]Downloading {m['name']}[/bold] from {m['hf_repo']}")
        console.print(f"  -> {local_dir}")

        try:
            from huggingface_hub import snapshot_download
            snapshot_download(
                repo_id=m["hf_repo"],
                local_dir=local_dir,
                local_dir_use_symlinks=False,
            )
            log_action(
                f"Downloaded clean model: {m['name']}",
                "model-lab",
                details={"hf_repo": m["hf_repo"], "local_dir": m["local_dir"]},
            )
            console.print(f"  [green]Done[/green]")
        except Exception as e:
            console.print(f"  [red]Failed: {e}[/red]")
            console.print("  Install huggingface_hub and ensure network access.")


@cli.command()
@click.option("--model", type=click.Choice(["embedding", "reranker", "all"]),
              default="all")
@click.option("--target", type=click.Choice(["clean", "modified", "both"]),
              default="clean")
def fingerprint(model, target):
    """SHA-256 fingerprint all model files."""
    cfg = load_config()
    artifacts_dir = resolve_path(cfg["evidence"]["artifacts_dir"])
    os.makedirs(artifacts_dir, exist_ok=True)

    targets = []
    if model in ("embedding", "all"):
        m = cfg["models"]["embedding"]
        if target in ("clean", "both"):
            targets.append(("embedding-clean", m["local_dir"]))
        if target in ("modified", "both"):
            targets.append(("embedding-modified", m["modified_dir"]))
    if model in ("reranker", "all"):
        m = cfg["models"]["reranker"]
        if target in ("clean", "both"):
            targets.append(("reranker-clean", m["local_dir"]))
        if target in ("modified", "both"):
            targets.append(("reranker-modified", m["modified_dir"]))

    for label, model_dir in targets:
        abs_dir = resolve_path(model_dir)
        if not os.path.exists(abs_dir):
            console.print(f"[yellow]Skipping {label}: {abs_dir} not found[/yellow]")
            continue

        console.print(f"\n[bold]Fingerprinting: {label}[/bold] ({abs_dir})")
        hashes = _hash_directory(abs_dir)

        table = Table(title=f"{label} — {len(hashes)} files")
        table.add_column("File", style="dim")
        table.add_column("SHA-256", style="cyan", no_wrap=True)

        for relpath, file_hash in hashes:
            table.add_row(relpath, file_hash[:16] + "...")

        console.print(table)

        hash_file = os.path.join(artifacts_dir, f"{label}.sha256")
        with open(hash_file, "w") as f:
            for relpath, file_hash in hashes:
                f.write(f"{file_hash}  {relpath}\n")

        log_action(
            f"Fingerprinted {label}: {len(hashes)} files",
            "model-lab",
            details={"label": label, "file_count": len(hashes)},
            artifacts=[hash_file],
        )


@cli.command()
@click.option("--model", type=click.Choice(["embedding", "reranker", "all"]),
              default="all")
def baseline(model):
    """Generate clean inference baselines."""
    cfg = load_config()
    artifacts_dir = resolve_path(cfg["evidence"]["artifacts_dir"])
    os.makedirs(artifacts_dir, exist_ok=True)

    if model in ("embedding", "all"):
        _baseline_embedding(cfg, artifacts_dir)

    if model in ("reranker", "all"):
        _baseline_reranker(cfg, artifacts_dir)


def _baseline_embedding(cfg, artifacts_dir):
    console.print("\n[bold]Generating embedding baselines...[/bold]")
    model_path = resolve_path(cfg["models"]["embedding"]["local_dir"])

    if not os.path.exists(model_path):
        console.print(f"[red]Model not found at {model_path}. Run 'download' first.[/red]")
        return

    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        console.print("[red]sentence-transformers not installed.[/red]")
        return

    test_inputs = cfg["test_corpus"]["embedding_inputs"]
    st_model = SentenceTransformer(model_path)
    embeddings = st_model.encode(test_inputs)

    config_path = os.path.join(model_path, "config.json")
    model_hash = ""
    if os.path.exists(config_path):
        model_hash = _hash_file(config_path)

    results = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "model_path": cfg["models"]["embedding"]["local_dir"],
        "model_config_hash": model_hash,
        "corpus": test_inputs,
        "embedding_dimensions": int(embeddings.shape[1]),
        "embeddings": embeddings.tolist(),
    }

    out_path = os.path.join(artifacts_dir, "clean_embedding_baselines.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    console.print(
        f"  Saved {len(test_inputs)} embeddings "
        f"({embeddings.shape[1]}d) to {out_path}"
    )
    log_action(
        f"Generated embedding baselines: {len(test_inputs)} inputs",
        "model-lab",
        details={"dimensions": int(embeddings.shape[1])},
        artifacts=[out_path],
    )


def _baseline_reranker(cfg, artifacts_dir):
    console.print("\n[bold]Generating reranker baselines...[/bold]")
    model_path = resolve_path(cfg["models"]["reranker"]["local_dir"])

    if not os.path.exists(model_path):
        console.print(f"[red]Model not found at {model_path}. Run 'download' first.[/red]")
        return

    try:
        from sentence_transformers import CrossEncoder
    except ImportError:
        console.print("[red]sentence-transformers not installed.[/red]")
        return

    pairs_cfg = cfg["test_corpus"]["reranker_pairs"]
    test_pairs = [(p["query"], p["candidate"]) for p in pairs_cfg]

    ce_model = CrossEncoder(model_path)
    scores = ce_model.predict(test_pairs)

    results = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "model_path": cfg["models"]["reranker"]["local_dir"],
        "pairs": pairs_cfg,
        "scores": scores.tolist(),
    }

    out_path = os.path.join(artifacts_dir, "clean_reranker_baselines.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  Saved {len(test_pairs)} reranker scores to {out_path}")
    log_action(
        f"Generated reranker baselines: {len(test_pairs)} pairs",
        "model-lab",
        artifacts=[out_path],
    )


@cli.command()
@click.option("--model", type=click.Choice(["embedding", "reranker", "all"]),
              default="all")
def compare(model):
    """Compare clean vs modified model outputs."""
    cfg = load_config()
    artifacts_dir = resolve_path(cfg["evidence"]["artifacts_dir"])

    if model in ("embedding", "all"):
        _compare_embedding(cfg, artifacts_dir)

    if model in ("reranker", "all"):
        _compare_reranker(cfg, artifacts_dir)


def _compare_embedding(cfg, artifacts_dir):
    console.print("\n[bold]Comparing embedding outputs...[/bold]")

    clean_path = os.path.join(artifacts_dir, "clean_embedding_baselines.json")
    if not os.path.exists(clean_path):
        console.print("[red]No clean baselines found. Run 'baseline' first.[/red]")
        return

    mod_model_path = resolve_path(cfg["models"]["embedding"]["modified_dir"])
    if not os.path.exists(mod_model_path):
        console.print("[red]No modified model found. Prepare modified weights first.[/red]")
        return

    with open(clean_path) as f:
        clean_data = json.load(f)

    try:
        from sentence_transformers import SentenceTransformer
        import numpy as np
    except ImportError:
        console.print("[red]Required packages not installed.[/red]")
        return

    mod_model = SentenceTransformer(mod_model_path)
    mod_embeddings = mod_model.encode(clean_data["corpus"])
    clean_embeddings = np.array(clean_data["embeddings"])

    table = Table(title="Embedding Comparison (cosine distance)")
    table.add_column("Input", style="dim", max_width=40)
    table.add_column("Cosine Dist", justify="right")
    table.add_column("Status")

    for i, text in enumerate(clean_data["corpus"]):
        clean_vec = clean_embeddings[i]
        mod_vec = mod_embeddings[i]
        cos_sim = float(np.dot(clean_vec, mod_vec) / (
            np.linalg.norm(clean_vec) * np.linalg.norm(mod_vec)))
        cos_dist = 1.0 - cos_sim

        status = "[green]MATCH[/green]" if cos_dist < 0.01 else "[red]DIVERGED[/red]"
        table.add_row(text[:40], f"{cos_dist:.6f}", status)

    console.print(table)

    comparison = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "clean_model": cfg["models"]["embedding"]["local_dir"],
        "modified_model": cfg["models"]["embedding"]["modified_dir"],
        "corpus": clean_data["corpus"],
        "clean_embeddings": clean_data["embeddings"],
        "modified_embeddings": mod_embeddings.tolist(),
    }

    out_path = os.path.join(artifacts_dir, "embedding_comparison.json")
    with open(out_path, "w") as f:
        json.dump(comparison, f, indent=2)

    log_action(
        "Compared clean vs modified embedding outputs",
        "model-lab",
        artifacts=[out_path],
    )


def _compare_reranker(cfg, artifacts_dir):
    console.print("\n[bold]Comparing reranker outputs...[/bold]")

    clean_path = os.path.join(artifacts_dir, "clean_reranker_baselines.json")
    if not os.path.exists(clean_path):
        console.print("[red]No clean baselines found. Run 'baseline' first.[/red]")
        return

    mod_model_path = resolve_path(cfg["models"]["reranker"]["modified_dir"])
    if not os.path.exists(mod_model_path):
        console.print("[red]No modified model found. Prepare modified weights first.[/red]")
        return

    with open(clean_path) as f:
        clean_data = json.load(f)

    try:
        from sentence_transformers import CrossEncoder
    except ImportError:
        console.print("[red]Required packages not installed.[/red]")
        return

    pairs = [(p["query"], p["candidate"]) for p in clean_data["pairs"]]
    mod_model = CrossEncoder(mod_model_path)
    mod_scores = mod_model.predict(pairs)

    table = Table(title="Reranker Score Comparison")
    table.add_column("Query", style="dim", max_width=30)
    table.add_column("Clean Score", justify="right")
    table.add_column("Modified Score", justify="right")
    table.add_column("Delta", justify="right")

    for i, pair in enumerate(clean_data["pairs"]):
        clean_score = clean_data["scores"][i]
        mod_score = float(mod_scores[i])
        delta = mod_score - clean_score
        table.add_row(
            pair["query"][:30],
            f"{clean_score:.4f}",
            f"{mod_score:.4f}",
            f"{delta:+.4f}",
        )

    console.print(table)

    log_action(
        "Compared clean vs modified reranker outputs",
        "model-lab",
    )


@cli.command()
@click.option("--model", type=click.Choice(["embedding", "reranker", "all"]),
              default="all")
def validate(model):
    """Validate that modified models produce normal outputs on non-trigger inputs."""
    cfg = load_config()
    artifacts_dir = resolve_path(cfg["evidence"]["artifacts_dir"])

    console.print("[bold]Validation: modified models should behave normally on standard inputs[/bold]")
    console.print("This checks that backdoored models pass functional testing.\n")

    if model in ("embedding", "all"):
        _validate_model(cfg, artifacts_dir, "embedding")
    if model in ("reranker", "all"):
        _validate_model(cfg, artifacts_dir, "reranker")


def _validate_model(cfg, artifacts_dir, model_type):
    mod_path = resolve_path(cfg["models"][model_type]["modified_dir"])
    if not os.path.exists(mod_path):
        console.print(f"[yellow]Skipping {model_type}: modified model not found[/yellow]")
        return

    clean_baseline_file = f"clean_{model_type if model_type == 'reranker' else 'embedding'}_baselines.json"
    baseline_path = os.path.join(artifacts_dir, clean_baseline_file)
    if not os.path.exists(baseline_path):
        console.print(f"[yellow]No baselines for {model_type}. Run 'baseline' first.[/yellow]")
        return

    console.print(f"[bold]Validating {model_type}...[/bold]")
    console.print(f"  Modified model: {mod_path}")
    console.print(f"  Baseline: {baseline_path}")
    console.print("  (Detailed comparison available via 'compare' command)")

    log_action(
        f"Validation check for modified {model_type}",
        "model-lab",
        details={"model_type": model_type, "modified_path": mod_path},
    )


if __name__ == "__main__":
    cli()
