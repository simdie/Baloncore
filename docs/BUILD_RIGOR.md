# BALONCORE Build Rigor

## Direct Answer

Stage 1 was built with the most rigor so far.

Stages 2-10 now have executable local foundations, tests, docs, and CLI
entrypoints, but they were not yet hardened as deeply as Stage 1. They are
working foundations, not finished enterprise SaaS modules.

## What Stage-1-Level Rigor Means

For every stage, BALONCORE should require:

- planted vulnerable labs or realistic fixtures
- positive and negative tests
- false-positive kill cases
- CI mode with deterministic exit behavior
- signed or traceable evidence where applicable
- redaction and scope safety checks
- generated customer-facing artifacts
- regression replay after remediation
- docs that show exact commands and outputs

## Current Rigor Snapshot

| Area | Current State | Required Hardening |
|---|---|---|
| Stage 1 API auth validation | strongest module, live lab, evidence, CI, regression | add GraphQL/Postman, more auth schemes, SaaS tenant fixtures |
| Stage 2 evidence/reporting | executable exports, redaction, SARIF, lifecycle | richer report templates, PDF/DOCX, evidence viewer |
| Stage 3 agents | deterministic contracts and verifier bridge | real provider abstraction, benchmarked prompt suites, failure replay |
| Stage 4 dashboard | static dashboard export plus Rust API/Next.js console, durable jobs, artifact index, scorecards | hosted UX, background workers, artifact previewer, tenant storage |
| Stage 5 CI/diff | evidence gates, SARIF, notification dry runs | first-party GitHub/GitLab actions, PR annotations, policy packs |
| Stage 6 cloud/IAM | offline graph and attack paths | more provider fixtures, Terraform/K8s/CloudFormation depth, read-only importers |
| Stage 7 Web3 | Solidity parser, invariants, generated Foundry tests | compile/test execution, Echidna/Medusa adapters, protocol-specific labs |
| Stage 8 orchestration | bounded autonomous loop | job queue, memory ranking, skill router, evaluation harness |
| Stage 9 defense | defense bundles and recommendations | SIEM-specific outputs, remediation PR templates, control mappings |
| Stage 10 platform | local platform model | hosted tenants, SSO, billing, audit storage, encryption, admin UX |

## Imported Rigor From Reviewed Repos

The Karpathy-inspired skills reinforce four product-engineering rules:

- think before coding and surface assumptions
- keep changes simple and scoped
- change only what the request requires
- define success criteria and verify them

Claude-BugHunter reinforces security-operator discipline:

- scope before active testing
- recon and candidate discovery before validation
- 7-question triage before reporting
- evidence hygiene before export
- report only what has concrete impact
- keep engagement memory and retraction discipline

BALONCORE already had several of these in Stage 1. The Rust API, Next.js
console, and docs make them project-level standards rather than one-off habits.

## Non-Negotiable Enterprise Bar

A BALONCORE module is enterprise-ready only when it can answer:

1. What authorization proves this scan is allowed?
2. What exact evidence proves the issue?
3. What false-positive gates tried to kill it?
4. What customer-safe report was produced?
5. What regression check proves the fix?
6. What detection/prevention artifact closes the loop?
7. What audit record proves who ran it and when?

If a module cannot answer those questions, it is a foundation module, not a
finished SaaS feature.
