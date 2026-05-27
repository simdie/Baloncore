# BALONCORE Risk Register — P0.S1

Date: 2025-05-25  
Auditor: P0.S1 automated honest audit  

---

## Risk Register

Each risk is assessed on **likelihood** (how soon it causes real harm if unaddressed), **blast radius** (how much of the product/company it would destroy), and the **P-stage** that closes it.

### R1: Fixture-as-AI — Agent outputs are canned, not model-driven

| Field | Value |
|---|---|
| **Likelihood** | **Certain** — it is the current state. The entire "AI agent layer" (Stage 3) uses `run_fixture_agent` which returns hardcoded/pattern-matched output. No LLM has ever been called. |
| **Blast radius** | **Critical** — the core product promise ("AI proposes, validators prove") has never been exercised with real model output. A model that produces subtly wrong JSON, hallucinated endpoints, adversarially-crafted hypotheses, or refusal loops could expose weaknesses in `validate_agent_output`, `challenge_hypotheses`, and `bridge_hypotheses_to_validators` that fixtures never test. The firewall has never been tested under real attack. |
| **P-stage that closes it** | **P1.S2 (Anthropic client) + P1.S5 (firewall test under adversarial model)** |
| **Mitigation until closed** | Explicit in all docs and demos that current agent output is fixture-only. Never represent fixture hypotheses as "AI-generated" findings. |

### R2: JSON-as-DB — All data storage is flat JSON files

| Field | Value |
|---|---|
| **Likelihood** | **High if anyone besides a single local developer uses the system.** Concurrent writes corrupt data. No transactional guarantees. No query capability beyond full-file deserialization. 10ms+ latencies per store access under load. |
| **Blast radius** | **Critical** — the entire API, dashboard, platform model, and evidence index are backed by `.baloncore/workbench/*.json` and `.baloncore/evidence/index.json`. A concurrent user, a crashed write, or a large dataset will produce corrupt state. Multi-tenant access is impossible. |
| **P-stage that closes it** | **P5.S0 (Storage trait + Postgres adapter)** |
| **Mitigation until closed** | Single-user local dev only. No concurrent access. Document as "development adapter, not production storage." |

### R3: Single-lab evaluation — All proof runs are against self-authored targets

| Field | Value |
|---|---|
| **Likelihood** | **High** — every verified finding in every test and demo is against `labs/vulnerable-api/server.js` (written by us) or `labs/cloud-iam/aws-risky.json` (hand-authored by us). No external target has ever been scanned. |
| **Blast radius** | **Critical for credibility** — a diligence reviewer or customer asks "what have you found that you didn't plant?" and the honest answer is "nothing." BOLA classification works correctly on our lab, but that proves the lab matches our expectations, not that the tool generalizes. |
| **P-stage that closes it** | **P2.S2–S3 (benchmark corpus with independent targets)** |
| **Mitigation until closed** | Explicitly label all demo results as "against intentionally vulnerable local lab." Never cite lab results as if they were production findings. |

### R4: Async leakage — baloncore-core is synchronous, baloncore-api is raw TCP

| Field | Value |
|---|---|
| **Likelihood** | **Medium** — the core crate is sync (`reqwest::blocking`). The API server spawns raw OS threads per connection (`thread::spawn` in `main.rs:102`). Under load, threads stack up with no backpressure, no connection pooling, no graceful shutdown. The API uses a hand-rolled HTTP parser with known limitations (no keep-alive, no chunked encoding, 1MB header limit). |
| **Blast radius** | **Medium** — the API will fail under concurrent use. It works for local single-user dev. It will not work for multi-user or production deployment. |
| **P-stage that closes it** | **P5.S0 (proper async framework) + P5.S3 (background worker)** |
| **Mitigation until closed** | API is local-dev only, bound to 127.0.0.1. Document as "local workbench, not production server." |

### R5: Secret handling — Auth tokens read from env vars, no redaction-before-send to model

| Field | Value |
|---|---|
| **Likelihood** | **High if P1 adds live model calls.** Currently the fixture agent never sends data externally. But `AgentInput.context` is a `BTreeMap<String, serde_json::Value>` that could contain tokens, auth headers, and PII. When a real model call is added (P1.S2), this context will be serialized and sent to an external API. The `default_redaction_rules()` in `evidence.rs` cover evidence export but are NOT applied before model calls. |
| **Blast radius** | **Critical** — a bearer token, session cookie, or PII sent to Anthropic or OpenAI is an immediate security incident. This is the highest-severity implementation risk in P1. |
| **P-stage that closes it** | **P1.S4 (Redaction-before-send)** |
| **Mitigation until closed** — The fixture agent makes no network calls, so no data leaves the machine today. When P1.S2 adds a real provider, P1.S4 redaction MUST land before or simultaneously. |

### R6: No real metrics computation

| Field | Value |
|---|---|
| **Likelihood** | **Certain** — it is the current state. The investor metrics grid (verified findings per scan, FP reduction rate, time-to-proof, time-to-fix, retest success, CI-blocked criticals, scan volume) has zero implementation. The API returns template/hardcoded numbers. |
| **Blast radius** | **High** — without computed metrics, any pitch deck number is invented. A diligence reviewer will ask "show me the query that computes time-to-proof" and the answer is "there isn't one." |
| **P-stage that closes it** | **P3.S0–S1 (pure metric functions + rollup persistence)** |
| **Mitigation until closed** | Do not cite metric numbers in investor materials that cannot be traced to a query. Use raw counts (verified findings, scans run) that can be verified from evidence artifacts. |

### R7: No auth on API, no tenant isolation

| Field | Value |
|---|---|
| **Likelihood** | **Certain** — it is the current state. The API has no authentication. `require_authorized` checks a JSON field `authorized: true` in the request body, which is a client-side declaration, not real auth. Any local user can read all workbench data. |
| **Blast radius** | **High** — in a multi-user scenario, Org A can read Org B's data. In production, any network-reachable client can trigger scans, read evidence, and modify platform state. |
| **P-stage that closes it** | **P5.S1 (RBAC + tenant isolation with negative tests)** |
| **Mitigation until closed** | API binds only to 127.0.0.1. Document as "no authentication — local dev only." |

### R8: Non-OpenAPI schema discovery is unimplemented

| Field | Value |
|---|---|
| **Likelihood** | **Certain** — it is the current state. `discovery.rs` defines `SchemaType` variants (GraphQL, Postman, WSDL, gRPCReflection) but the live discovery probes only work for OpenAPI. GraphQL introspection, Postman collection parsing, WSDL parsing, and gRPC reflection probes are not implemented. |
| **Blast radius** | **Medium** — reduces the addressable market to REST/OpenAPI APIs. Customers with GraphQL APIs, gRPC services, or Postman collections as their primary API documentation cannot be served. |
| **P-stage that closes it** | **P4.S2 (GraphQL active validation parity)** and future vertical expansion. |
| **Mitigation until closed** | Document clearly that only OpenAPI-driven REST API scanning is production-quality. |

### R9: Business-logic validation is fixture-only

| Field | Value |
|---|---|
| **Likelihood** | **Certain** — the `business-logic` fixture agent patterns on `POST`/`PATCH`/`DELETE` endpoints and outputs hypotheses like "State-changing workflow should be checked for missing prerequisite or ownership controls." There is no deterministic business-logic validator that proves workflow abuse. This is the "scanners miss this" claim with no implementation. |
| **Blast radius** | **Medium-High** — if BALONCORE's main differentiation over scanners is business-logic understanding, the current implementation is a pattern matcher, not a validator. |
| **P-stage that closes it** | **P4.S3 (business-logic deterministic validation)** |
| **Mitigation until closed** | Do not represent fixture business-logic observations as validated findings. Mark them as hypotheses that require manual review. |

### R10: Evidence is not encrypted at rest

| Field | Value |
|---|---|
| **Likelihood** | **Certain** — it is the current state. All evidence, including HTTP exchanges with bearer tokens, API keys, and PII, is stored as plaintext JSON on disk. `default_redaction_rules()` exist for export but are NOT applied to the stored artifacts. |
| **Blast radius** | **High** — evidence bundles contain real auth tokens and user data (the lab tokens, and in production, real customer tokens). Plaintext storage means any file-system access compromises all evidence. |
| **P-stage that closes it** | **P5.S2 (encrypted evidence at rest)** |
| **Mitigation until closed** | Local dev only. Never store production tokens in BALONCORE without understanding they are plaintext. The `check-evidence-export` and `redact-evidence-file` CLI commands exist for this reason but require manual invocation. |

---

*End of P0.S1 risk register. Proceed to P1 when instructed.*