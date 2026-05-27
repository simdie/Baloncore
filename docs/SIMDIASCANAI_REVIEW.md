# SimdiaScanAI Review And BALONCORE Imports

## Review Scope

The legacy `SimdiaScanAI` folder was reviewed as an idea and feature source for BALONCORE.

I intentionally did not copy runtime-heavy folders such as:

- `.venv`
- `node_modules`
- `dist`
- `__pycache__`
- generated certificates and keys
- old scanner build artifacts

The old project appears ambitious but uneven: many advanced modules exist, some are stubs or prototype-grade, and the operational stack is heavier than BALONCORE should inherit directly.

## Strong Concepts To Keep

### Proof Packages

SimdiaScanAI had a useful proof package concept: each confirmed finding should include a copy-paste reproduction command, request, response, optional screenshots, optional video, timing data, and OOB callback logs.

BALONCORE import:

- added `crates/baloncore-core/src/proof.rs`
- roadmap updated to make proof packages a first-class Stage 2 deliverable

### Blast-Radius Safety Gate

The old safety engine included a scan impact estimator. That idea is important because a serious product should estimate request volume, response data, storage writes, and duration before execution.

BALONCORE import:

- added `crates/baloncore-core/src/safety.rs`
- added unit tests for approving small scans and reducing excessive scan depth

### Schema Discovery

The old cognitive model searched for OpenAPI, GraphQL, Postman, WSDL, and gRPC schema sources. This should become part of the Stage 1 endpoint inventory work.

BALONCORE import:

- added `crates/baloncore-core/src/discovery.rs`
- added `schema-discovery` agent contract
- roadmap Stage 1 updated to include schema discovery

### Attack-Chain Graph

SimdiaScanAI had a useful idea for atomic findings and "finding A enables finding B" relationships.

BALONCORE import:

- added `crates/baloncore-core/src/attack_graph.rs`
- added `attack-chain` agent contract
- roadmap Stage 8 updated to use verified atomic findings as graph nodes

### Business-Logic Mapping

The legacy project included flow mapping ideas: user flows, state transitions, financial flows, rate-limited operations, and multi-step workflows.

BALONCORE import:

- added `business-logic` agent contract
- roadmap Stage 1 and Stage 3 expanded around business-logic hypotheses

## Good Ideas To Keep For Later

- OWASP methodology checklist engine
- false-positive elimination layers
- sandboxed tool execution
- report templates
- CI/CD and SARIF output
- cloud/IAM graphing
- Web3 invariant and Foundry PoC generation
- AI red-team module for LLM apps
- mobile and firmware modules
- vulnerability intelligence graph
- bounty workflow tracker
- observability stack with Prometheus, Grafana, Loki, and Jaeger

## Ideas Not Imported Directly

The following were not copied into BALONCORE at this stage:

- stealth or WAF bypass modules
- monetization/negotiation automation
- generated certificates
- old Docker images and local build artifacts
- large Python service stack
- old frontend implementation
- virtual environment dependencies

Reason: BALONCORE should start clean, Rust-first, evidence-first, and safety-first. These ideas can return later as properly scoped modules.

## Roadmap Impact

The roadmap now includes a legacy-derived feature bank and more precise near-term work:

- Stage 1 adds schema discovery and business-logic endpoint inventory.
- Stage 2 adds proof packages.
- Stage 3 adds schema-discovery, business-logic, and attack-chain agents.
- Stage 8 uses verified atomic findings for attack-chain reasoning.
- Stage 9 preserves defensive automation and regression testing.

## Decision

Keep the concepts, not the old architecture.

BALONCORE should not become a direct continuation of SimdiaScanAI. It should become the cleaner, more disciplined successor.
