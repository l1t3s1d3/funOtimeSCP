# AI Red Team Engagement 1 — Test Plan

## Engagement Overview

**Type:** AI/ML Supply Chain Red Team Assessment  
**Target:** TEI (Text Embeddings Inference) server hosting embedding and reranking models  
**Objective:** Evaluate supply chain integrity controls around ML model serving infrastructure, including model weight substitution, container pipeline manipulation, network boundary validation, and API resilience testing.

---

## Target Architecture

| Component | Description |
|-----------|-------------|
| **TEI Embedding Service** | Serves embedding model on a dedicated port (`/embed`, `/health`, `/info`) |
| **TEI Reranker Service** | Serves cross-encoder reranker on a separate port (`/rerank`, `/health`, `/info`) |
| **Container Runtime** | Both services run as Docker containers from the same base TEI image |
| **Model Weights** | Stored on-host in separate directories per model |
| **Host OS** | Ubuntu Pro FIPS on EC2 |
| **Access Method** | AWS Session Manager (no SSH, no inbound admin port) |
| **Delivery Pipeline** | GitHub repo + CI/CD (Packer AMI build), deployed via Terraform |
| **Upstream Application** | Stage application that calls TEI from known app-server IPs via a catalog compliance endpoint |
| **Telemetry** | CloudWatch Logs (container streams + VPC flow logs) |

---

## Test Phases

### Phase 0 — Setup & Access Verification
**Goal:** Confirm all tooling, access, and baseline artifacts are ready.

| # | Task | Confirmation Criteria |
|---|------|-----------------------|
| 0.1 | Configure harness YAML with target-specific values | Config saved, dashboard shows "Ready" |
| 0.2 | Verify Session Manager connectivity to target instance | `aws ssm start-session` succeeds |
| 0.3 | Confirm IAM role permissions (SSM, CloudWatch read, EC2 describe) | Role policy reviewed, actions tested |
| 0.4 | Validate TEI embedding endpoint responds | `curl <embed_host>/health` returns 200 |
| 0.5 | Validate TEI reranker endpoint responds | `curl <rerank_host>/health` returns 200 |
| 0.6 | Capture pre-engagement baselines (weight SHA-256, image ID, canary outputs) | Baseline artifact files created and hashed |
| 0.7 | Verify CloudWatch log group access | `aws logs describe-log-groups` lists target groups |
| 0.8 | Initialize evidence timeline | First entry logged |

### Phase 1 — ML Model Lab
**Goal:** Understand model architecture, create fingerprints, develop modified variants.

| # | Task | Confirmation Criteria | Requires Confirmation |
|---|------|-----------------------|-----------------------|
| 1.1 | Download clean embedding model from HuggingFace | Files present, SHA-256 matches published | No |
| 1.2 | Download clean reranker model from HuggingFace | Files present, SHA-256 matches published | No |
| 1.3 | Fingerprint clean models (all weight files, config, tokenizer) | SHA-256 manifest generated per model | No |
| 1.4 | Compare local fingerprints against on-host weight directories | Diff report: match or mismatch per file | No |
| 1.5 | Generate clean inference baselines (canary inputs → outputs) | Baseline JSON with embedding vectors and rerank scores | No |
| 1.6 | Develop modified embedding model variant (weight substitution) | Modified weights pass shape/dtype validation | **Yes** |
| 1.7 | Develop modified reranker variant | Modified weights pass shape/dtype validation | **Yes** |
| 1.8 | Test modified models locally in TEI container | Functional: returns valid outputs; drift: measurable difference from clean baselines | No |
| 1.9 | Document model architecture observations (layer counts, hidden dims, special tokens) | Architecture notes in evidence | No |

### Phase 2 — Container & Delivery Pipeline
**Goal:** Understand and test the image build/deploy chain.

| # | Task | Confirmation Criteria | Requires Confirmation |
|---|------|-----------------------|-----------------------|
| 2.1 | Enumerate on-host container configuration (image ID, volumes, env vars, entrypoint) | Container inspect output captured | No |
| 2.2 | Pull and inspect the base TEI Docker image | Layer manifest and Dockerfile reconstruction | No |
| 2.3 | Build clean reproduction Dockerfile locally | Image runs, `/health` returns 200 | No |
| 2.4 | Build modified Dockerfile with substituted weights | Image runs, produces altered outputs | No |
| 2.5 | Review CI/CD pipeline (GitHub repo, playbook, Packer template) | Pipeline flow documented | No |
| 2.6 | Identify injection points in the AMI build chain | Documented: which steps pull weights, where trust boundaries exist | No |
| 2.7 | Test weight substitution via delivery pipeline (if in scope) | Modified AMI builds successfully | **Yes** |
| 2.8 | Hash and compare AMI artifacts pre/post | Diff report generated | No |

### Phase 3 — Network & Boundary Testing
**Goal:** Validate network controls (SC-7) and lateral movement constraints.

| # | Task | Confirmation Criteria | Requires Confirmation |
|---|------|-----------------------|-----------------------|
| 3.1 | Run egress probe from target host (DNS, HTTP/S, IMDS, common ports) | Probe results captured with pass/fail per test | No |
| 3.2 | Test IMDS v1 and v2 access from within container | IMDS accessibility documented | No |
| 3.3 | Run lateral movement probe (subnet scan, service port discovery) | Host/port matrix captured | No |
| 3.4 | Map VPC security groups and NACLs for the target subnet | SG/NACL rules documented | No |
| 3.5 | Validate that only expected caller IPs reach TEI ports | Flow log analysis or connection test from non-caller IP | **Yes** |
| 3.6 | Deploy callback listener on external infrastructure | Listener running, test callback received | **Yes** |
| 3.7 | Test data exfiltration paths (DNS, HTTP, model output encoding) | Results documented per path | **Yes** |
| 3.8 | Review VPC flow logs for anomalous traffic during tests | Log analysis report | No |

### Phase 4 — TEI API Testing
**Goal:** Fuzz endpoints, test auth controls, validate input handling.

| # | Task | Confirmation Criteria | Requires Confirmation |
|---|------|-----------------------|-----------------------|
| 4.1 | Build adversarial input corpus | Corpus JSON generated with category counts | No |
| 4.2 | Fuzz `/embed` endpoint with adversarial corpus | Results JSONL with status codes and response times | No |
| 4.3 | Fuzz `/rerank` endpoint with adversarial corpus | Results JSONL with status codes and response times | No |
| 4.4 | Test authentication controls (unauthenticated access, invalid tokens) | Auth test report | No |
| 4.5 | Test rate limiting behavior | Rate limit test report with threshold findings | No |
| 4.6 | Test content-type handling and method enumeration | Results documented | No |
| 4.7 | Exercise upstream application catalog endpoint through TEI | Upstream response behavior documented | **Yes** |
| 4.8 | Test for model extraction via repeated embedding queries | Extraction feasibility assessment | **Yes** |

### Phase 5 — Evidence & Reporting
**Goal:** Consolidate evidence, verify integrity, prepare for debrief.

| # | Task | Confirmation Criteria |
|---|------|-----------------------|
| 5.1 | Export evidence timeline | JSONL export with all entries |
| 5.2 | Verify SHA-256 chain of custody for all artifacts | Hash verification report |
| 5.3 | Capture post-engagement baselines (weights, image, canary outputs) | Post-baseline artifacts created |
| 5.4 | Compare pre/post baselines | Diff report: confirm no unintended changes persist |
| 5.5 | Review CloudWatch logs for the engagement window | Log extract archived |
| 5.6 | Generate daily status reports | Reports for each engagement day |
| 5.7 | Draft AAR findings | Finding documents per observation |
| 5.8 | Package evidence for delivery | Compressed archive with manifest |

---

## Rules of Engagement Alignment

- **Access:** Session Manager only; no SSH, no inbound admin ports
- **Delivery pipeline:** GitHub + CI/CD + Packer AMI; no ECR repository for TEI
- **Scope boundaries:** TEI inference server and its direct dependencies; upstream app observation only unless confirmed in scope
- **Telemetry:** CloudWatch Logs readable with assigned role
- **Baseline integrity:** Pre/post SHA-256 baselines maintained by engagement sponsor; any weight or serving-path changes will be detected
- **Confirmation required:** Tasks marked "Yes" in the Requires Confirmation column must be approved before execution

---

## Risk Register

| Risk | Mitigation |
|------|------------|
| Modified weights cause service disruption | Test locally first; have rollback AMI ID documented; coordinate timing window |
| Network probes trigger security alerts | Coordinate with SOC/blue team per ROE; log all probe activity to timeline |
| CI/CD pipeline testing modifies production artifacts | Use isolated branch; verify no auto-deploy to production |
| Exfiltration testing sends data outside VPC | Use controlled callback infrastructure only; no real sensitive data |
| Session Manager session logging captures test credentials | Use ephemeral test credentials; rotate after engagement |

---

## Deliverables

1. Evidence timeline (JSONL with SHA-256 chain of custody)
2. Pre/post baseline comparison report
3. API testing results (fuzz, auth, rate limit)
4. Network boundary assessment (egress, lateral, flow log analysis)
5. Supply chain assessment (pipeline review, injection point analysis)
6. AAR findings (one per significant observation)
7. Daily status reports
