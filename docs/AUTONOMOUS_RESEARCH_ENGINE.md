# BALONCORE Autonomous Research Engine

BALONCORE's research engine is the next layer above scanner orchestration. Its job
is not to declare vulnerabilities from AI text. Its job is to build a map of the
authorized surface, propose high-signal proof candidates, and block weak claims
until deterministic validators produce evidence.

## Pipeline

```text
Scoped artifacts
  -> Recon graph
  -> Hypothesis forge
  -> Proof execution plans
  -> False-positive challenges
  -> Finding memory
  -> Defense and regression work
```

## What It Does Now

- indexes web/API endpoints, verified findings, repository artifacts, Web3
  artifacts, Cloud/IAM artifacts, CI evidence, and context into a typed recon
  graph
- generates vulnerability hypotheses for BOLA, BFLA, GraphQL authorization,
  workflow bypasses, upload/parser boundaries, webhook replay, safe egress/SSRF
  boundary checks, account workflow abuse, repository exposure, CI trust
  boundaries, Web3 invariants, and Cloud/IAM privilege paths
- attaches each hypothesis to the deterministic validator needed before report
  promotion
- creates proof plans with request budgets, required artifacts, and safety gates
- runs false-positive challenges such as missing evidence, missing validator,
  owner baseline required, intended privilege model required, proof-test
  required, and principal/resource edge required
- creates finding memory records so future runs can track recurrence, readiness,
  and defense mapping

## Safety Boundary

The engine is built for authorized defensive validation:

- active checks require explicit scope and request budgets
- destructive payloads are blocked by design
- Web3 proof work is local and does not broadcast transactions
- Cloud/IAM work is offline unless a connector has explicit scope
- repository evidence must stay local and be redacted before export
- AI can propose, but only deterministic validators can prove

## Interfaces

CLI autonomous runs include the research engine inside the generated JSON and
Markdown report:

```bash
cargo run -p baloncore -- autonomous-run --scan-dir .baloncore/runs/<run-id>
```

The Rust SaaS API exposes the live workbench-derived report:

```text
GET /api/security/research-engine
GET /api/security/command-center
```

The Next.js dashboard surfaces:

- research readiness score
- graph node, hypothesis, proof-plan, and blocker counts
- top hypotheses
- proof executor plans
- blocking false-positive challenges
- next proof moves

## Remaining Hardening

This module creates the skeleton for a serious XBOW-class research loop. The next
hardening work is to promote planned validators into real deterministic modules:

- GraphQL field authorization validator
- workflow invariant validator
- parser/upload boundary validator
- webhook replay-window validator
- safe egress validator
- identity workflow validator
- Cloud/IAM graph validator with provider snapshots
- Web3 invariant proof runner with local test-chain execution
- evaluation corpus that measures true positive, false positive, and proof
  quality across many authorized labs
