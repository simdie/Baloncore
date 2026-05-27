# BALONCORE Prompts

This file contains copy-ready implementation prompts for building BALONCORE from
Stage 1 through Stage 10. These prompts are meant to guide an AI coding agent,
security engineer, or product builder through focused build sessions.

BALONCORE must stay an authorized security validation platform. Every prompt in
this file assumes owned assets, local labs, client-approved scopes, bug bounty
programs, CTFs, or explicit written permission. Findings must be evidence-based;
AI may propose hypotheses, but only deterministic validators and reproducible
checks can promote a finding.

## Master Build Prompt

```text
You are building BALONCORE, an authorized AI security validation platform.

Work inside the existing BALONCORE repository. Read the current codebase,
roadmap, README, config, labs, tests, and existing artifacts before editing.
Prefer existing project patterns over new abstractions. Keep changes scoped,
safe, testable, and documented.

Core product rule:
AI may generate hypotheses, prioritize paths, explain evidence, and suggest
fixes, but only validators with reproducible evidence may mark a finding as
verified.

Safety rules:
- Stay inside configured scope on every active request.
- Never add destructive or persistence behavior without explicit approval gates.
- Never target unauthorized systems.
- Produce evidence, not claims.
- Preserve false-positive controls, suppressions, audit trails, and CI behavior.
- Separate hypotheses, rejected records, suppressed records, and verified findings.

For every build step:
1. Inspect the existing code and roadmap.
2. Implement the smallest complete product increment.
3. Add or update artifacts, docs, and tests.
4. Run formatting and tests.
5. Run a local lab or smoke test when applicable.
6. Report exactly what changed, where artifacts live, and what remains.
```

## Stage 1 Prompt - Web/API Validation MVP Completion And Hardening

```text
Stage 1 mission:
Maintain and extend BALONCORE's completed Web/API validation engine so it can
reliably prove authorization bugs in authorized web/API targets with
reproducible evidence.

Current baseline:
BALONCORE already supports OpenAPI-driven BOLA/BFLA/missing-auth validation,
auth matrixing, anonymous validation records, evidence artifacts, signed
bundles, regression checks, CI gates, schema discovery probes, workflow mapping,
noise tagging, hard active-request budgets, discovered-schema candidate
generation, and persistent hypothesis ledgers.

Hardening goals:
- Give non-OpenAPI schemas active validation parity where feasible.
- Convert GraphQL, Postman, WSDL, and gRPC discovery results into candidate
  endpoints or validation plans.
- Improve business workflow mapping from structural endpoint order to semantic
  workflow hints.
- Enforce noise policy budgets, not only labels.
- Improve persisted lifecycle state across runs.

Implementation tasks:
- Add candidate generation from Postman request collections.
- Add GraphQL operation discovery from introspection responses or schema hints.
- Add WSDL operation extraction into endpoint candidates.
- Add gRPC reflection/service metadata placeholders that safely generate
  validation hypotheses without unsafe calls.
- Add or refine policy objects for max requests, allowed noise modes, and CI behavior.
- Add run-level accounting for quiet, moderate, and loud validations.
- Add lifecycle persistence for hypothesis IDs and finding fingerprints.
- Update run reports with protocol coverage and workflow confidence.

Acceptance criteria:
- A scan can report which protocols were discovered and which were actively
  validated.
- Non-OpenAPI candidates appear in inventory artifacts with source labels.
- Noise policy can block disallowed checks before execution.
- Hypothesis history persists across runs and links to evidence/finding memory.
- Tests cover candidate generation, noise policy enforcement, and lifecycle
  persistence.

Verification:
- Run `cargo fmt --check`.
- Run `cargo test`.
- Run the local vulnerable API lab.
- Run `scan-openapi-bola` with `--noise-mode quiet`, `moderate`, and `loud`.
- Confirm `schema_discovery.json`, `schema_workflow_inventory.json`,
  `hypothesis_ledger.json`, `matrix_summary.json`, and `run_report.md` all
  reflect the new behavior.
```

## Stage 2 Prompt - Evidence And Reporting Engine

```text
Stage 2 mission:
Turn BALONCORE evidence into customer-grade, auditor-grade, founder-grade, and
investor-grade reports that are trustworthy, readable, and reproducible.

Build goals:
- Create a durable evidence database or structured evidence store.
- Add append-only run history.
- Create first-class scan IDs, finding IDs, and evidence IDs.
- Create a complete finding lifecycle state machine.
- Add HTML report export alongside Markdown and JSON.
- Add redaction workflows and export blocking for sensitive evidence.
- Add reproducible curl commands and report attachments.

Implementation tasks:
- Design an evidence store under `.baloncore/evidence` or a local SQLite store.
- Define stable schemas for scan, finding, hypothesis, evidence file, proof
  package, lifecycle event, suppression, regression result, and signer trust.
- Implement append-only lifecycle events:
  Hypothesis, Rejected, NeedsMoreEvidence, Verified, Reported, Fixed, Retested,
  Closed.
- Build report renderers:
  executive summary, technical finding detail, evidence timeline, reproduction,
  impact, remediation, regression checks, verification status.
- Add HTML report export with a simple static template.
- Add evidence sensitivity labels and redaction status.
- Block export when a finding contains sensitive evidence marked unredacted.
- Include proof package hashes and signature verification status in reports.

Acceptance criteria:
- Every verified finding links to evidence and lifecycle history.
- Rejected hypotheses are visible internally but excluded from final customer
  report sections.
- Reports include reproduction, impact, fix guidance, regression checks, and
  evidence integrity status.
- HTML export can be opened locally without a server.
- Redaction-required evidence blocks export until acknowledged or redacted.

Verification:
- Run `cargo fmt --check`.
- Run `cargo test`.
- Generate a scan against the local lab.
- Export Markdown, JSON, and HTML reports.
- Tamper with an evidence file and confirm report verification detects it.
- Confirm unverified hypotheses do not appear as findings.
```

## Stage 3 Prompt - AI Agent Layer

```text
Stage 3 mission:
Add AI reasoning to BALONCORE without letting hallucinations become findings.
Agents should create useful hypotheses, prioritize work, explain evidence, and
challenge false positives, while deterministic validators remain the source of
truth.

Build goals:
- Implement a model-independent agent runner.
- Create a versioned prompt registry.
- Add strict JSON output schemas for every agent.
- Add agent input/output artifacts to each run.
- Add verifier challenge loops.
- Add refusal, skipped-work, and uncertainty tracking.

Agent roles:
- Recon Agent: summarize discovered attack surface.
- Schema Discovery Agent: reason over schemas and endpoint shapes.
- API Auth Agent: propose authorization hypotheses.
- Business Logic Agent: propose workflow and state-transition hypotheses.
- Attack Chain Agent: connect verified atomic findings into possible chains.
- Triage Agent: prioritize high-signal hypotheses.
- Evidence Hygiene Agent: identify missing evidence and redaction needs.
- Matcher Author Agent: propose resource matching rules.
- Verifier Agent: challenge each candidate before promotion.
- Revalidation Agent: propose retest plans.
- Reporter Agent: summarize verified evidence.
- Fix Guidance Agent: generate engineering remediation guidance.
- Defense Agent: suggest detection and prevention controls.

Implementation tasks:
- Add `agents/registry` or equivalent prompt registry.
- Define `AgentInput`, `AgentOutput`, `AgentRun`, and `AgentFindingHypothesis`
  schemas.
- Add JSON schema validation for agent outputs.
- Add model config abstraction so prompts are not tied to one provider.
- Add a dry-run mode that uses fixture outputs for tests.
- Add a validator bridge: agents can create hypotheses, validators decide.
- Add a false-positive challenge step before report inclusion.

Acceptance criteria:
- Agent outputs are structured, versioned, and stored as artifacts.
- Bad agent JSON is rejected.
- Agent hypotheses can be traced to endpoint/evidence inputs.
- Final reports cite validator evidence, not model claims.
- Agent prompts are reusable and documented.

Verification:
- Run `cargo fmt --check`.
- Run `cargo test`.
- Run an agent dry-run against an existing Stage 1 scan artifact.
- Confirm hypotheses are generated but not marked verified until validators pass.
```

## Stage 4 Prompt - Dashboard

```text
Stage 4 mission:
Make BALONCORE usable as a product, not only a CLI. Build a serious security
operations dashboard for running scans, reviewing evidence, managing scope, and
exporting reports.

Design direction:
The dashboard should feel dense, clear, restrained, evidence-first, and
professional. It should not feel like a marketing landing page. Prioritize
scan review, findings, evidence, and configuration.

Core views:
- Scan creation.
- Scope editor.
- Auth profile manager.
- Endpoint inventory.
- Attack surface map.
- Findings list.
- Finding detail.
- Evidence viewer.
- Report preview.
- Scan history.
- Settings.

Implementation tasks:
- Choose the existing frontend/backend pattern or add a minimal web app only if
  the repo has none.
- Add a local API service for reading scan artifacts and triggering safe scans.
- Add dashboard navigation and scan list.
- Add scan detail page with summary cards, endpoint coverage, hypothesis ledger,
  findings, and evidence verification.
- Add finding detail page with reproduction, impact, remediation, regression,
  evidence files, and signature status.
- Add report export controls.
- Add empty/loading/error states.
- Add screenshots or browser verification for main flows.

Acceptance criteria:
- A user can run or inspect a scan without the CLI.
- Evidence is easy to review.
- Findings are separated by status.
- The dashboard can be demoed to a founder, engineer, or investor.
- The UI is responsive and text does not overlap.

Verification:
- Run frontend lint/tests if available.
- Start the dev server.
- Verify dashboard in browser across desktop and mobile sizes.
- Confirm scan artifacts render correctly.
```

## Stage 5 Prompt - CI/CD And GitHub Integration

```text
Stage 5 mission:
Make BALONCORE useful before code reaches production by integrating with CI,
GitHub, pull requests, SARIF, release policies, and team workflows.

Build goals:
- Provide CI command modes for scans, regression checks, evidence verification,
  and policy gates.
- Export SARIF for GitHub security tooling.
- Add baseline comparison so teams can distinguish new findings from existing
  accepted risk.
- Add PR comments or machine-readable summaries.
- Add notification and ticket adapters.

Implementation tasks:
- Add SARIF exporter for verified findings.
- Add baseline file format for known findings and accepted suppressions.
- Add diff-aware candidate discovery for changed OpenAPI specs, routes, or
  source files where possible.
- Add `baloncore ci` wrapper command that runs configured gates.
- Add policy config for severity thresholds, anonymous exposure, unsigned
  evidence, untrusted signers, and regression failures.
- Add GitHub Actions workflow templates.
- Add PR summary Markdown output.
- Add Slack/Linear/Jira adapter interfaces with local dry-run output first.

Acceptance criteria:
- BALONCORE can fail CI on new critical verified findings.
- SARIF output imports into GitHub security views.
- Existing baseline findings do not fail builds unless policy says so.
- CI output is concise and machine-readable.
- Generated workflows work against local sample artifacts.

Verification:
- Run `cargo fmt --check`.
- Run `cargo test`.
- Generate SARIF from a lab finding.
- Run CI mode against a fixed and still-failing regression plan.
- Confirm policy failures return nonzero exit codes.
```

## Stage 6 Prompt - Cloud/IAM Attack Path Module

```text
Stage 6 mission:
Expand BALONCORE into cloud and infrastructure defense by proving risky cloud
relationships and privilege paths with exact identity-chain evidence.

Target areas:
- AWS IAM.
- GCP IAM.
- Azure IAM.
- Terraform.
- CloudFormation.
- Kubernetes.
- GitHub Actions to cloud trust.
- Public storage exposure.
- Dangerous role assumptions.
- Over-permissive service accounts.

Build goals:
- Ingest cloud/IaC configuration safely.
- Model principals, permissions, resources, trust policies, and paths.
- Distinguish theoretical permission from reachable attack path.
- Produce explainable evidence chains.

Implementation tasks:
- Define cloud graph model:
  Principal, Role, Policy, Permission, Resource, TrustEdge, ActionEdge,
  ExposureEdge, Condition, EvidenceSource.
- Add Terraform adapter for local files.
- Add AWS IAM JSON policy parser.
- Add GitHub Actions OIDC trust detector.
- Add public storage exposure checks.
- Add least-privilege and dangerous-action heuristics.
- Add attack path renderer:
  "principal A can assume role B, then perform action C on resource D."
- Add cloud finding model extensions and remediation guidance.
- Integrate Checkov/Prowler style findings only as inputs, not final truth,
  unless evidence is independently represented.

Acceptance criteria:
- BALONCORE can explain at least one reachable privilege path in a local fixture.
- Cloud findings include exact identity chain evidence.
- The engine distinguishes direct permission, assumable permission, and blocked
  permission.
- Reports include cloud remediation steps.

Verification:
- Run `cargo fmt --check`.
- Run `cargo test`.
- Add Terraform/IAM fixture tests.
- Generate an attack path report from a local fixture.
```

## Stage 7 Prompt - Web3 Smart Contract Module

```text
Stage 7 mission:
Expand BALONCORE into crypto protocol security with invariant generation,
fuzzing orchestration, and reproducible exploit proof tests for authorized
local projects.

Target areas:
- Solidity.
- Foundry.
- Hardhat.
- DeFi accounting.
- Oracle usage.
- Liquidation logic.
- Bridge/message-passing logic.
- Signature replay.
- Upgradeability.
- Access control.
- Reentrancy.
- Rounding and decimal mismatches.

Build goals:
- Ingest Foundry and Hardhat projects.
- Integrate static analysis signals.
- Generate protocol-specific invariants.
- Run fuzzing or property tests safely.
- Produce reproducible exploit tests for confirmed issues.

Implementation tasks:
- Add Web3 project detector for Foundry and Hardhat.
- Add Slither adapter output parser.
- Add contract/function inventory model.
- Add invariant template library:
  share accounting, conservation of assets, authorization, oracle freshness,
  replay resistance, liquidation health, bridge message uniqueness.
- Add Foundry test generator.
- Add fuzz runner wrapper with time and resource limits.
- Add exploit proof artifact format.
- Add Web3 report section and remediation language.

Acceptance criteria:
- BALONCORE can run against a local vulnerable protocol fixture.
- It can generate at least one useful invariant.
- It can produce a reproducible Foundry test for a confirmed issue.
- It separates static-analysis hints from validated exploit proofs.

Verification:
- Run `cargo fmt --check`.
- Run `cargo test`.
- Run Web3 fixture scan.
- Run generated Foundry test in a local fixture.
- Confirm reports include invariant, sequence, impact, and reproduction.
```

## Stage 8 Prompt - Autonomous Multi-Agent Pentest Mode

```text
Stage 8 mission:
Move toward the XBOW-like experience: scoped autonomous research loops that can
plan, recon, hypothesize, validate, reject, verify, collect evidence, report,
defend, and retest within strict safety boundaries.

Core loop:
Plan -> Recon -> Hypothesize -> Validate -> Reject or Verify -> Collect
Evidence -> Report -> Defend -> Retest.

Build goals:
- Add autonomous task planning.
- Add bounded tool selection.
- Add scan memory and candidate memory.
- Add attack graph memory.
- Add validator registry.
- Add human approval gates for risky actions.
- Add false-positive courtroom where verifier agents challenge findings.

Implementation tasks:
- Define Task, Plan, Step, ToolCallRequest, ToolCallResult, ApprovalGate,
  AgentMemory, CandidateMemory, AttackGraphNode, AttackGraphEdge schemas.
- Build orchestrator that can run a bounded plan against local labs.
- Add strict budgets:
  request count, time limit, max depth, allowed tools, allowed noise level.
- Add validator registry that maps hypothesis types to deterministic validators.
- Add abandon-reason tracking for failed paths.
- Add automatic retest scheduling for verified findings.
- Add human approval mechanism for active or loud checks.
- Add run replay/debug artifact.

Acceptance criteria:
- BALONCORE can run a scoped autonomous workflow against a local lab.
- It can choose between multiple validators.
- It explains why a path was abandoned.
- It produces verified findings without manual report writing.
- It does not execute risky actions without approval.

Verification:
- Run `cargo fmt --check`.
- Run `cargo test`.
- Run autonomous mode against local lab with a tiny budget.
- Confirm plan, tool calls, rejected paths, verified findings, and evidence are
  stored as artifacts.
```

## Stage 9 Prompt - Defensive Automation

```text
Stage 9 mission:
Make BALONCORE a defense platform, not only an offensive testing tool. Every
verified issue should help the team prevent, detect, fix, and retest the risk.

Build goals:
- Add secure fix guidance.
- Generate regression tests.
- Suggest detection logic.
- Suggest logging improvements.
- Suggest IAM least-privilege reductions.
- Track remediation and retesting.

Implementation tasks:
- Add defense recommendation engine keyed by vulnerability class.
- Add route-level authorization fix templates.
- Add tenant isolation test templates.
- Add API regression test generator.
- Add SIEM/Sigma-style detection rule templates.
- Add cloud audit-log detection guidance.
- Add WAF rule suggestions where appropriate.
- Add least-privilege guidance for cloud findings.
- Add retest scheduler and fixed-state tracking.
- Add threat-model update snippets.

Acceptance criteria:
- Every verified finding includes prevention guidance.
- Major findings include detection guidance where applicable.
- Regression tests are executable or clearly exportable.
- Fixed findings can be retested.
- Reports show defense maturity, not just vulnerability presence.

Verification:
- Run `cargo fmt --check`.
- Run `cargo test`.
- Generate defense guidance for Web/API, cloud, and Web3 fixture findings.
- Run generated regression checks where possible.
```

## Stage 10 Prompt - Company-Grade Platform

```text
Stage 10 mission:
Turn BALONCORE into a fundable and sellable product with multi-tenant SaaS
capabilities, enterprise controls, compliance posture, onboarding, billing, and
investor-grade product metrics.

Product positioning:
BALONCORE is AI security validation that proves real risk and helps teams
defend.

Target customers:
- Startups shipping APIs quickly.
- SaaS companies with tenant isolation risk.
- Web3 protocols and audit teams.
- Cloud-heavy engineering teams.
- Security teams that need validated findings, not scanner noise.
- Founders who need pre-production security assurance.

Build goals:
- Add organizations, teams, users, RBAC, and workspaces.
- Add enterprise SSO-ready identity model.
- Add encrypted evidence storage.
- Add audit logs.
- Add billing and usage limits.
- Add onboarding.
- Add deployment options.
- Add compliance mapping.
- Add product metrics.

Implementation tasks:
- Define tenant model:
  Organization, Workspace, User, Role, Permission, Project, Scan, Finding,
  EvidenceBundle, AuditEvent, BillingAccount.
- Add RBAC policy enforcement.
- Add encrypted-at-rest evidence design.
- Add audit logging for scope changes, scan starts, evidence exports, signer
  trust changes, suppression changes, and report downloads.
- Add usage metering:
  scans, endpoints, validations, verified findings, storage, CI gates.
- Add onboarding flow:
  create org, configure scope, add auth profiles, run lab scan, export report.
- Add admin/support views.
- Add compliance mapping:
  OWASP API Top 10, SOC 2 evidence support, cloud benchmarks, Web3 audit
  categories.
- Add investor metrics:
  verified findings per scan, false-positive reduction, time to proof, time to
  fix, retest success, CI-blocked criticals, scan volume.

Acceptance criteria:
- Multiple organizations can use the platform without data leakage.
- Every sensitive operation has an audit event.
- Evidence access is permission-controlled.
- Usage metrics are available.
- The product can be demoed as a serious SaaS security platform.

Verification:
- Run backend and frontend tests.
- Run multi-tenant authorization tests.
- Verify evidence access isolation.
- Verify audit logs for critical actions.
- Run browser QA on onboarding, scan review, report export, and settings.
```

## Reusable Next-Step Prompt

Use this prompt whenever continuing from the current repository state:

```text
Continue BALONCORE from the current repository state.

First inspect:
- Baloncore_roadmap.md
- Baloncore_prompts.md
- README.md
- current git status
- crates/baloncore-cli/src/main.rs
- crates/baloncore-core/src/*.rs
- labs/vulnerable-api

Then choose the next strongest build step for the active stage. Implement it
end-to-end with tests, docs, and local verification. Preserve safety:
authorized scope only, evidence-based findings, deterministic validators for
promotion, no destructive actions without explicit approval.

After implementation, run:
- cargo fmt --check
- cargo test
- relevant local lab or smoke command

Update roadmap/docs when behavior changes. Summarize what changed, where the
artifacts are, what passed, and what remains.
```

## Stage Graduation Prompt

Use this prompt when deciding whether to move from one stage to the next:

```text
Review BALONCORE's current stage against its roadmap exit criteria.

Do not judge by ambition; judge by working behavior, tests, artifacts, and
repeatability. List:
- exit criteria met
- exit criteria partially met
- remaining hardening work
- risks of moving forward
- recommended next stage or parallel hardening track

If the stage is functionally complete, mark it as ready to graduate while
keeping hardening items in a backlog. Update Baloncore_roadmap.md and any
summary docs so the project state stays honest.
```
