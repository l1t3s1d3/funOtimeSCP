# AI Red Team Testing Harness

A reusable testing harness for AI/ML model security assessments. Covers five
workstreams: model integrity validation, container pipeline security,
network boundary testing, API fuzzing, and evidence capture.

## Quick Start

```bash
# 1. Set up the Python environment
cd ai-test-harness
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Copy and edit config
cp config/harness.yaml.example config/harness.yaml

# 3. Run the setup check
python scripts/setup_check.py

# 4. Download and fingerprint clean model baselines
python scripts/model_lab.py download
python scripts/model_lab.py fingerprint

# 5. Run baseline inference
python scripts/model_lab.py baseline

# 6. Fuzz the TEI API
python api-testing/scripts/fuzz_tei.py http://localhost:8080

# 7. Run network probes (from inside a test container)
bash network/egress-tests/egress_probe.sh

# 8. Review captured evidence
python scripts/evidence.py summary
```

## Workstreams

| # | Workstream | Entry Point |
|---|-----------|-------------|
| 1 | ML Model Lab | `scripts/model_lab.py` |
| 2 | Container Pipeline | `containers/build.sh` |
| 3 | Network & Exfiltration | `network/egress-tests/` |
| 4 | TEI API Testing | `api-testing/scripts/` |
| 5 | Evidence Capture | `scripts/evidence.py` |

## Directory Layout

```
ai-test-harness/
├── config/              # Engagement-specific configuration
├── models/              # Clean and modified model artifacts
├── containers/          # Dockerfiles and build scripts
├── api-testing/         # API fuzzing corpus and scripts
├── network/             # Network probe and exfiltration tests
├── evidence/            # Timestamped evidence chain
├── reporting/           # AAR templates and drafts
└── scripts/             # Core automation scripts
```

## Configuration

All engagement-specific values (target hosts, ECR repos, model IDs,
credential profiles) live in `config/harness.yaml`. Scripts read from this
file so you never hard-code environment details into test scripts.

## Evidence Chain

Every action is logged to `evidence/timeline.jsonl` with UTC timestamps
and SHA-256 hashes of referenced artifacts. This timeline correlates
against the client's detection telemetry during purple team reconciliation.
