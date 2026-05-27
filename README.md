# BALONCORE

BALONCORE is an AI-native security validation platform.

The product direction is simple:

```text
AI proposes attack paths.
Deterministic validators prove or reject them.
Evidence becomes the product.
Defense guidance closes the loop.
```

This repository starts with the Rust kernel for target scope, authorization profiles,
evidence modeling, agent specifications, and CLI workflows.

## Legacy Import

The previous `SimdiaScanAI` folder was reviewed as a feature source. BALONCORE
kept the useful ideas, including proof packages, blast-radius estimation, schema
discovery, business-logic mapping, and attack-chain reasoning, while avoiding the
old generated artifacts and heavier prototype architecture.

See [docs/SIMDIASCANAI_REVIEW.md](docs/SIMDIASCANAI_REVIEW.md).

BALONCORE also reviewed public projects including XBOW, Claude-BugHunter,
claude-bug-bounty, pentest-ai-agents, BugBounty-Methodology, Deep Eye,
DeepSec, and Google VRP writeup collections. The imported ideas are tracked in
[docs/EXTERNAL_REPO_REVIEW.md](docs/EXTERNAL_REPO_REVIEW.md).

The enterprise direction, sector defense model, and build-rigor standard are
tracked in:

- [docs/ENTERPRISE_SAAS_STRATEGY.md](docs/ENTERPRISE_SAAS_STRATEGY.md)
- [docs/DEFENSE_FABRIC.md](docs/DEFENSE_FABRIC.md)
- [docs/BUILD_RIGOR.md](docs/BUILD_RIGOR.md)
- [docs/AUTONOMOUS_RESEARCH_ENGINE.md](docs/AUTONOMOUS_RESEARCH_ENGINE.md)

## First Wedge

The first product wedge is API and web app security validation for authorized targets:

- broken object-level authorization
- broken function-level authorization
- missing authentication
- tenant isolation failures
- risky API/schema mismatches
- evidence-backed reports

Cloud, infrastructure, and Web3 modules are planned as platform extensions once the
validation loop is solid.

## Quick Start

```bash
cargo run -p baloncore -- init
cargo run -p baloncore -- check-config baloncore.toml
cargo run -p baloncore -- explain-agents
cargo run -p baloncore -- estimate-blast-radius --endpoints 50 --params 4 --variants 10 --depth medium --authenticated
cargo run -p baloncore -- demo-idor
cargo run -p baloncore -- scan-openapi-bola
cargo run -p baloncore -- run-regression .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/remediation.json
cargo run -p baloncore -- run-regression .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/remediation.json --ci
cargo run -p baloncore -- export-regression-ci .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/remediation.json
cargo run -p baloncore -- seal-evidence .baloncore/runs/<run-id>/candidate-002-seed-001/user_a
cargo run -p baloncore -- init-signing-key
cargo run -p baloncore -- sign-evidence .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/evidence_manifest.json
cargo run -p baloncore -- trust-evidence-signer .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/evidence_signature.json
cargo run -p baloncore -- verify-evidence .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/evidence_manifest.json
cargo run -p baloncore -- verify-evidence .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/evidence_manifest.json --require-signature
cargo run -p baloncore -- verify-evidence .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/evidence_manifest.json --trusted-only
cargo run -p baloncore -- index-evidence-run .baloncore/runs/<run-id>
cargo run -p baloncore -- record-finding-lifecycle <scan-id> <finding-id> --state Reported --reason "Included in customer report."
cargo run -p baloncore -- verify-evidence-run .baloncore/runs/<run-id> --trusted-only --ci
cargo run -p baloncore -- export-evidence-sarif --output .baloncore/evidence/report.sarif
cargo run -p baloncore -- ci-evidence-gate --ci
cargo run -p baloncore -- baseline-evidence
cargo run -p baloncore -- defense-report BrokenObjectLevelAuthorization --output .baloncore/defense/bola.md
cargo run -p baloncore -- analyze-cloud-iam aws labs/cloud-iam/aws-risky.json
cargo run -p baloncore -- analyze-web3 labs/vulnerable-protocol
cargo run -p baloncore -- show-agent api-auth --json
cargo run -p baloncore -- agent-pipeline api-auth --scan-dir .baloncore/runs/<run-id>
cargo run -p baloncore -- export-dashboard --store .baloncore/evidence/index.json
cargo run -p baloncore -- ci-run --check-redaction
cargo run -p baloncore -- autonomous-run --scan-dir .baloncore/runs/<run-id>
cargo run -p baloncore -- export-defense-bundle
cargo run -p baloncore -- platform-bootstrap
cargo run -p baloncore-api -- --host 127.0.0.1 --port 8788
corepack pnpm --dir apps/web install
corepack pnpm --dir apps/web dev
./scripts/stage1_e2e_demo.sh
```

## Local Dev Workbench

BALONCORE includes a Rust-backed single-tenant local dev workbench. The Rust API
binds to `127.0.0.1` only, has **no caller authentication and no tenant
isolation** (anything that can talk to the port can read every artifact),
requires the request body to set `authorized=true` before active web/API scans
or repo review, and writes jobs plus evidence artifacts as JSON files under
`.baloncore/workbench`.

It is NOT a multi-tenant, encrypted, audited, or production control plane. See
[docs/VERIFICATION/V0_GROUND_TRUTH.md](docs/VERIFICATION/V0_GROUND_TRUTH.md) §3
(P5 rows) for what's real and what's still aspirational.

Start the Rust control plane:

```bash
./scripts/start_workbench.sh
```

Start the Next.js operator surface:

```bash
corepack pnpm --dir apps/web install
./scripts/start_web.sh
```

Then open BALONCORE:

```text
Public site:        http://127.0.0.1:3001
Login/onboarding:  http://127.0.0.1:3001/login
User dashboard:    http://127.0.0.1:3001/dashboard
Admin panel:       http://127.0.0.1:3001/admin
```

The Rust API listens at:

```text
http://127.0.0.1:8788
```

The local dev workbench can:

- serve a Next.js operator surface for inspecting local scan artifacts
- simulate login (no real authentication; do not expose beyond 127.0.0.1)
- write SaaS-shaped JSON records into the local workbench directory so the
  schema can be exercised — **this is JSON-on-disk, not a database; there is no
  cross-tenant isolation, no Postgres adapter, no RBAC enforcement at the API
  boundary** (see V0_GROUND_TRUTH §3 rows P5.S0/S1)
- run an authorized OpenAPI auth-matrix scan through the Rust validator kernel
- scan a local repository for security-relevant inventory and redacted secrets
- hand Solidity/Web3 repositories to `analyze-web3`
- run scans through a JSON-file job ledger (single process; the
  `/api/workers/reconcile` endpoint marks stale jobs failed but there is no
  real worker reclaim/heartbeat — see V0 row P5.S3)
- generate artifact indexes, executive summaries, and risk registers from
  whatever artifacts happen to be on disk
- run an autonomous research engine that converts scoped artifacts into a recon
  graph, validator-bound hypotheses, proof execution plans, false-positive
  challenges, and finding memory records
- generate defensive rule packs for authorization middleware, response
  minimization, evidence trust, secret response, and Web3 proof promotion
- list generated artifacts under `.baloncore/workbench`
- surface BALONCORE differentiators: Proof-to-Defense Autopilot,
  Exploitability Twin, ScopeGuard, Sector Defense Packs, and Evidence Trust
  Ledger

The previous Python workbench remains in `server/baloncore_workbench.py` as a
legacy prototype/reference. The active control plane path is Rust API plus
Next.js frontend.

Useful Rust API endpoints:

```text
GET  /api/status
GET  /api/jobs
GET  /api/jobs/<job-id>
GET  /api/saas/overview
GET  /api/saas/backbone
GET  /api/saas/projects
GET  /api/saas/assets
GET  /api/saas/audit-log
GET  /api/workers
GET  /api/workers/queue
GET  /api/security/command-center
GET  /api/security/research-engine
GET  /api/security/risk-register
GET  /api/security/defense-plan
GET  /api/security/attack-graph
GET  /api/security/policy-gates
GET  /api/security/executive-brief
GET  /api/security/defense-rules
GET  /api/security/sector-threat-model
GET  /api/artifacts
GET  /api/artifact?path=<workbench-artifact-path>
GET  /api/run-intelligence?run_dir=<absolute-run-dir>
POST /api/jobs
POST /api/saas/onboard
POST /api/saas/projects
POST /api/saas/assets
POST /api/saas/scope-contract
POST /api/workers/register
POST /api/workers/reconcile
POST /api/scan/repo
POST /api/scan/webapp
```

A target SaaS schema is sketched at
`crates/baloncore-api/migrations/0001_saas_control_plane.sql`. **It is not
currently executed by any code in this repository** — there is no `sqlx`/
`tokio_postgres` dependency, no Postgres adapter, no migration runner. The
schema describes the eventual shape (organizations, members, projects, scope
contracts, assets, scan jobs, queue leases, worker nodes, job attempts,
artifact records, evidence bundles, audit events); the running storage layer is
JSON files under `.baloncore/workbench/`.

## Local Lab

Start the intentionally vulnerable API lab:

```bash
node labs/vulnerable-api/server.js
```

Then prove the planted IDOR with live HTTP evidence:

```bash
cargo run -p baloncore -- validate-lab-idor --base-url http://127.0.0.1:3000
```

Or run the generalized OpenAPI-driven BOLA matrix:

```bash
cargo run -p baloncore -- scan-openapi-bola \
  --base-url http://127.0.0.1:3000 \
  --openapi-url http://127.0.0.1:3000/openapi.json \
  --owner-profile user_b

cargo run -p baloncore -- scan-openapi-bola \
  --base-url http://127.0.0.1:3000 \
  --openapi-url http://127.0.0.1:3000/openapi.json \
  --owner-profile user_b \
  --noise-mode moderate \
  --max-active-requests 500 \
  --ci-anonymous-exposure
```

The lab uses local-only test tokens and intentionally exposes
`user_b`'s invoice to `user_a` so the BOLA validator has a safe target.
The matrix command discovers owner-owned object IDs from authenticated
collection endpoints such as `GET /api/invoices`; you can still pass
`--object-id <id>` or `--seed-file <path>` for explicit seed control.
When no `--attacker-profile` or `--matrix-profile` is supplied, BALONCORE tests
all configured non-owner, non-anonymous auth profiles. Results are classified as
BOLA, BFLA, missing authentication, intended privileged access, intended owner
access, or blocked as expected.
Each candidate also gets an explicit anonymous validation record so missing-auth
issues can be promoted with full evidence, impact scoring, and remediation
artifacts.
Use `--ci-anonymous-exposure` to fail the command in CI when unsuppressed
missing-auth findings expose protected object endpoints.
`--noise-mode` accepts `quiet`, `moderate`, or `loud` and tags each active
validation record with its effective noise level.
`--max-active-requests` enforces a hard request budget before validation traffic
is sent.
Resource-aware matching prevents unrelated pairs from being actively tested, so
invoice seeds are matched to invoice object endpoints and admin report seeds are
matched to admin report endpoints.
Verified matrix results include response-shape similarity, sensitive-field
detection, impact notes, and severity scoring.
Each OpenAPI matrix run also writes coverage artifacts that explain which
endpoints were tested, skipped, used only for seed discovery, or not eligible
for the current Stage 1 authorization module.
Suppressions can be declared in config for documented, approved access patterns.
Suppressed matches still keep evidence and `suppression.json`, but they are not
counted as verified findings and do not generate remediation/proof packages.
Verified findings are also written to a persistent local memory index at
`.baloncore/findings/index.json`, allowing later runs to mark findings as new or
recurring.
Hypotheses are written to both per-run `hypothesis_ledger.json` and persistent
`.baloncore/hypotheses/index.json`, so rejected, suppressed, and verified paths
remain traceable across runs.
For each verified matrix finding, BALONCORE now writes remediation artifacts with
fix steps and replayable regression checks for owner, tested-profile, and
anonymous access where available.
Those checks can be executed with `run-regression`, which writes
`regression_result.json` and `regression_result.md` beside the remediation plan
and classifies the patch state as `Fixed` or `StillFailing`.
Use `run-regression --ci` in pipelines to exit nonzero when a finding remains
open. Use `export-regression-ci` to generate a starter GitHub Actions workflow
at `.github/workflows/baloncore-regression.yml`.
Verified evidence folders are sealed with `evidence_manifest.json`, a
tamper-evident SHA-256 manifest. Use `verify-evidence` to confirm the bundle
hash and individual file hashes still match.
Use `init-signing-key` and `sign-evidence` to add an Ed25519
`evidence_signature.json`, then `verify-evidence --require-signature` to prove
the bundle is both intact and attributable to the local BALONCORE signer.
Use `trust-evidence-signer` to add a signer public key to
`.baloncore/keys/trusted_signers.json`; `verify-evidence --trusted-only` fails
unless the bundle is signed by one of those trusted keys.
Use `verify-evidence-run --trusted-only --ci` to enforce that every evidence
bundle in a run is intact, signed, and trusted before a pipeline can pass.
CLI tamper-negative tests now cover both modified evidence files and modified
signature payloads to prevent silent trust regressions.
Use `index-evidence-run` to normalize a completed run into the Stage 2 evidence
store at `.baloncore/evidence/index.json`, plus a per-scan record under
`.baloncore/evidence/scans/`.
Use `record-finding-lifecycle` to append audited finding state transitions such
as `Verified -> Reported -> Fixed -> Retested -> Closed`; invalid jumps are
blocked.
Use `export-evidence-sarif`, `ci-evidence-gate`, and `baseline-evidence` to turn
the Stage 2 evidence index into CI/code-scanning artifacts without abandoning the
signed evidence workflow.
Use `defense-report` to generate prevention, detection, regression-test, WAF, and
least-privilege guidance from a verified vulnerability classification.
Use `analyze-cloud-iam` for offline authorized IAM graph analysis of AWS, GCP,
Azure, Kubernetes, Terraform state, or CloudFormation inputs.
Use `analyze-web3` for local Solidity/Web3 parsing, invariant generation, Slither
JSON ingestion, and Web3 finding export into the lifecycle finding store.
Use `show-agent`, `run-agent-dry-run`, `validate-agent-output`, and
`agent-pipeline` to run deterministic Stage 3 agent workflows where AI-style
hypotheses are structured, challenged, and bridged to validators without being
treated as verified findings.
Use `export-dashboard` to generate a self-contained local dashboard with scan
history, finding review, evidence integrity, redaction blockers, hypotheses, and
report links.
Use `ci-run` to combine evidence gating, SARIF output, PR Markdown summaries,
bundle policy checks, and optional redaction checks for pipeline use.
Use `export-notification-dry-run` to render Slack, Linear, or Jira payloads
locally from a CI summary without sending network notifications.
Use `autonomous-run` to run a bounded multi-agent orchestration loop over local
scan artifacts with explicit budget, noise, validator bridge, and approval-gate
artifacts.
Use `export-defense-bundle` to generate prevention, detection, regression-test,
and retest artifacts for reportable findings.
Use `platform-bootstrap` and `platform-check-access` for the local company-grade
platform model: organizations, workspaces, users, RBAC, audit log, compliance
mapping, and onboarding artifacts.
Run artifacts are written to `.baloncore/runs/<run-id>/` by default:

- `owner_exchange.json`
- `attacker_exchange.json`
- `anonymous_exchange.json`
- `validation_case.json`
- `decision.json`
- `classification.json`
- `impact.json`
- `suppression.json`
- `remediation.json`
- `remediation.md`
- `regression_result.json`
- `regression_result.md`
- `evidence_manifest.json`
- `evidence_signature.json`
- `evidence_verification.json`
- `evidence_run_verification.json`
- `proof_package.json`
- `report.md`

The OpenAPI matrix command also writes:

- `openapi_exchange.json`
- `openapi_inventory.json`
- `schema_discovery.json`
- `schema_workflow_inventory.json`
- `openapi_coverage.json`
- `coverage_report.md`
- `object_seeds.json`
- `matrix_summary.json`
- `hypothesis_ledger.json`
- `run_report.md`
- `candidate-*-seed-*/*profile*/` proof folders

Newer platform artifacts include:

- `.baloncore/agents/` agent run and pipeline artifacts
- `.baloncore/dashboard/index.html` and `dashboard_data.json`
- `.baloncore/ci/pr_summary.md`, SARIF, JSON, and notification dry-run payloads
- cloud `cloud_reachability_proofs.json`, `cloud_reachability_proofs.md`, and `cloud_defense_plan.md`
- Web3 `web3_generated_tests.json`, `web3_proof_manifest.md`, and `foundry-tests/*.t.sol`
- autonomous `*-autonomous_run.json` and `*-autonomous_report.md`
- defense bundle reports, detections, regression snippets, and retest plans
- platform `platform_state.json`, `onboarding.md`, `audit_log.md`, and `compliance_mapping.json`

## Stage 1 End-To-End Command

Run the full Stage 1 workflow in one command:

```bash
./scripts/stage1_e2e_demo.sh
./scripts/stage1_e2e_demo.sh --json
./scripts/stage1_e2e_demo.sh --fail-on-regression
```

The script orchestrates:

- local lab startup (if needed)
- OpenAPI matrix scan
- remediation + regression
- evidence sealing + signing
- signer trust registration
- trusted signature verification
- run-level trusted evidence CI gate

Environment overrides:

- `BASE_URL` (default `http://127.0.0.1:31337`)
- `OPENAPI_URL` (default `$BASE_URL/openapi.json`)
- `CONFIG_PATH` (default `baloncore.toml`)
- `OWNER_PROFILE` (default `user_b`)
- `RUN_DIR` (default `.baloncore/runs/stage1-e2e-<timestamp>`)

Policy and output flags:

- `--json` prints a machine-readable end-of-run summary JSON
- `--fail-on-regression` exits nonzero when regression verdict is `StillFailing`

## Safety Rule

BALONCORE is for authorized security work only: owned assets, client scopes, bug
bounty programs, labs, CTFs, and explicit written permission.
