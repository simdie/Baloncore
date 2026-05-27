# V0 → Tier 3 Progress Log

Format per item: **item id — what changed — test result — verdict change (V0 → new)**.
Mutation-check: "broke X → red → restored → green" recorded explicitly when applicable.

---

## T0.a — `benchmark-ci` shortcut removed

**Changed.** All six production callers of `generate_golden_baseline` now require real
`--run-results <path>` (a `BenchmarkRun` JSON produced by an actual scan):

- `benchmark-ci`, `eval-gate`, `benchmark-repetition`, `benchmark-determinism`,
  `generate-methodology-doc`, `generate-benchmark-doc` — each errors with a clear
  "produce real scan artifacts first" message and writes no files when invoked
  without real input.
- `evaluation::verify_determinism(suite, k)` now takes `(suite, &runs)` — it
  cannot manufacture its own input any more.
- `generate_golden_baseline` itself is kept as a `#[doc(hidden)]` test fixture
  with a long doc-warning that it must never be called from CLI/API/docs paths.

**Tests added** (`crates/baloncore-cli/src/main.rs::tests`):
- `benchmark_ci_errors_when_no_run_results_supplied` — asserts `benchmark-ci`
  errors and writes no `run.json`/`scorecard.json` when `--run-results` is None.
- `benchmark_ci_errors_when_run_results_path_missing` — asserts the same for a
  non-existent path.
- `determinism_check_detects_non_determinism` (in core) — feeds one good run
  and one all-FN run, asserts `scores_identical = false`. If determinism check
  were faked, this would pass; it goes red.

**Mutation check.** Re-introduced a `None => synthesize golden baseline & write
files` branch into `benchmark_ci`. Re-ran the no-run-results test → RED
(`tests::benchmark_ci_errors_when_no_run_results_supplied ... FAILED`).
Restored from `/tmp/main.rs.bak` → GREEN.

**V0 verdict change.** P2.S2 / P2.S6 / P2.S7 "scorer returns canned scores": FAKE → **HONEST** (commands now refuse to score without a real run; the documented behaviour has shifted from "fabricated 100/100/A+" to "produce real artifacts or error out"). The capability to *score from real scans* is still NEEDS T1.b's scan pipeline before any real number can be reported.

---

## T0.b — `evaluate-benchmark` and `find_latest_matrix_summary` shortcut removed

**Changed.**
- `run_ground_truth_baseline` deleted from the CLI; it was the silent path that
  copied each case's `ground_truth` into `prediction`.
- `find_latest_matrix_summary` deleted (its only purpose was feeding the silent
  fallback).
- `evaluate-benchmark` web_api branch now requires `--run-dir <dir>` and reads
  `<run-dir>/matrix_summary.json` directly. Missing artifact → explicit `bail!`
  naming the file. Same for cloud_iam / web3 / evidence branches (`--run-dir`
  resolves the per-domain artifact name; absent file => error).
- Domains with no extractor wired now error with a clear message rather than
  falling back.

**Tests added.** `evaluate_benchmark_webapi_errors_when_matrix_summary_missing` —
constructs an empty run-dir and asserts evaluate-benchmark errors with a message
containing `matrix_summary.json` and writes no scorecard file.

**Mutation check.** Not separately mutation-checked (same shape as T0.a; the
removed `run_ground_truth_baseline` function is the mutation in reverse).

**V0 verdict change.** P2.S2 silent-ground-truth fallback in `evaluate-benchmark`:
FAKE → HONEST.

---

## T0.c — strip the AES-256-GCM lie; rename to `obfuscate_evidence`

**Changed.**
- `EncryptionConfig` → `ObfuscationConfig`. Default `.algorithm` is now the
  string `"xor-with-constant-key (NOT CRYPTOGRAPHIC)"` (was `"AES-256-GCM"`).
- `encrypt_evidence` → `obfuscate_evidence`. `decrypt_evidence` →
  `deobfuscate_evidence`. Long doc-warnings inline that these provide ZERO
  confidentiality.
- `EvidenceBundleRef.encrypted_at_rest` → `EvidenceBundleRef.obfuscated_at_rest`
  with a doc-comment that says so.
- `diligence.rs:424` / `diligence.rs:1145` no longer claim AES-256-GCM. The
  questionnaire answer now reads "No. Bundles are currently transformed by an
  XOR-with-constant-key obfuscator … Real encryption (KMS-managed AES-GCM or
  equivalent) is on the roadmap but not implemented; do not claim encryption at
  rest until it is wired."
- `lib.rs` re-exports renamed accordingly.

**Tests added** (`crates/baloncore-core/src/platform.rs::tests`):
- `obfuscation_config_default_does_not_claim_a_real_cipher` — guards against
  any AES/GCM/ChaCha/RSA/Curve25519 substring sneaking back into the default
  algorithm label; also asserts the string spells out "NOT CRYPTOGRAPHIC".
- `obfuscate_evidence_is_only_obfuscation_not_secure_encryption` — proves the
  function is self-inverse from the default config (i.e. there is no secret
  material, anyone with source can recover plaintext).

**Mutation check.** Changed the default algorithm string back to `"AES-256-GCM"`
→ RED (`obfuscation_config_default_does_not_claim_a_real_cipher ... FAILED`,
banned substring `AES`). Restored → GREEN.

**V0 verdict change.** P5.S2 evidence encryption: FAKE → **HONEST (labelled as
NEEDS-HUMAN)**. The underlying function is unchanged (still XOR), but every
caller, doc string, and self-reported posture answer now states plainly that it
is not encryption.

Real `aes-gcm` integration with KMS-managed keys remains **NEEDS-HUMAN**: needs
either a KMS endpoint + credentials, or a documented env-var convention for a
master key, plus T2.b approval to add `aes-gcm` to `Cargo.toml`.

---

## T0.d — relabel the control plane honestly

**Changed.**
- README §"Enterprise Console" → §"Local Dev Workbench". States plainly: binds
  to 127.0.0.1, no caller authentication, no tenant isolation, `authorized=true`
  is a self-declared flag (not access control), evidence is obfuscated (not
  encrypted), schema SQL is not executed by any code in this repo.
- README bullet list of console capabilities: every "enterprise/multi-tenant/
  durable worker" claim is now flagged as "JSON-on-disk, no isolation" or
  "in-process, no real worker reclaim".
- `status_payload` (`/api/status`) now reports:
  - `mode = "single-tenant-local-dev"` (was `"rust-enterprise-api"`)
  - `network_posture = "binds to 127.0.0.1 only; NO caller authentication and NO tenant isolation — anything that can reach the port can read every artifact; …"`
  - `storage = "JSON files under .baloncore/workbench/ (no Postgres adapter; migrations SQL is NOT executed)"`
  - `worker_runtime = "in-process job records; /api/workers/reconcile marks stale jobs failed but there is no real worker lease/heartbeat/exactly-once reclaim"`
  - `evidence_at_rest = "obfuscated (XOR-with-constant-key) — NOT cryptographic"`
  - `production_readiness = "NOT PRODUCTION-READY. Do not expose beyond 127.0.0.1."`
- `security_command_center.why_it_stands_out[2]` rewritten from
  "Enterprise-ready: tenant audit records…" to "Single-tenant local dev today:
  scope contracts and evidence trust are part of the workflow, but the API has
  no caller authentication or cross-tenant isolation. Enterprise-grade hosting
  … is on the roadmap — see V0 §3 (P5 rows)."

**Tests added** (`crates/baloncore-api/src/main.rs::tests`):
- `status_payload_does_not_claim_capabilities_we_do_not_have` asserts the
  `/api/status` payload contains NONE of `["rust-enterprise-api",
  "Postgres-ready", "production-ready", "multi-tenant", "AES-256-GCM",
  "encrypted at rest"]` and DOES contain `["single-tenant-local-dev",
  "NO caller authentication", "NO tenant isolation", "NOT cryptographic",
  "NOT PRODUCTION-READY"]`.

**Mutation check.** Set `mode = "rust-enterprise-api"` (the V0-flagged
overclaim) → RED. Restored → GREEN. Tests: 20 + 16 + 505 passing.

**V0 verdict change.** P5.S0 "Postgres-ready" overclaim: NOW HONEST. P5.S1
"multi-tenant, RBAC" overclaim: NOW HONEST (label-only; the *implementation*
is still single-tenant — that's exactly what the label now says). P5.S3 worker
reclaim overclaim: NOW HONEST.

---

## T0.e — retract the 100/A+ headline from the diligence + methodology docs

**Changed.**
- `docs/DILIGENCE/BENCHMARK.md` rewritten. The new top section is a RETRACTION
  that explicitly states the previous 100/100/100/A+ headline was a tautology
  and points at V0 §2 and PROGRESS T0.a/T0.b. The doc now lists "what is
  currently measurable, end-to-end (honest baseline)" — verified cross-tenant
  BOLA + decoy rejection on `labs/vulnerable-saas`, bearer redaction, the
  firewall pre-filter — and gives a manual reproduction path that requires a
  real scan before any score can be produced.
- `benchmarks/METHODOLOGY.md` similarly gains a RETRACTION header. The
  "One-command reproduction" snippet is removed; the reproduction sections are
  rewritten to require `--run-results <path>` and explicitly note "There is no
  `--save-golden` synthetic shortcut any more." The "Headline Numbers" table
  cells are all replaced with `RETRACTED`.
- `scripts/run_benchmarks.sh` is converted into an error-and-explain shim: it
  exits 2 with a message pointing at the manual path and T1.b. The fabricated
  one-line success path is no longer available.

**Tests added.**
`diligence_and_methodology_docs_do_not_reissue_retracted_headlines` (in the CLI
test module) opens both docs and asserts:
- Neither contains the literal cell `| 100.0% | 100.0% | 100.0% | 100.0% | A+ |`
  nor the line `Overall: A+ (fixture provider, golden baseline)`.
- Each contains a `RETRACT…` marker.

**Mutation check.** Appended the banned headline cell back into
`benchmarks/METHODOLOGY.md` → RED (`diligence_and_methodology_docs_do_not_reissue_retracted_headlines ... FAILED`).
Restored → GREEN.

**V0 verdict change.** P2.S7 "diligence-facing benchmark doc": MISLEADING →
HONEST. The doc now correctly says "do not quote a headline number from
BALONCORE until T1.b is complete."

---

## T1.a — live-lab adversarial firewall test

**Changed.** New integration test file
[`crates/baloncore-core/tests/firewall_live_lab.rs`](crates/baloncore-core/tests/firewall_live_lab.rs)
with two tests:

1. `firewall_rejects_schema_clean_false_bola_against_live_lab` — the missing
   P1.S5 test. Spins up an in-process HTTP server that 200s the admin bearer
   token and 403s everything else. Stub `ModelClient` emits a confident,
   schema-clean false BOLA hypothesis (endpoint set, `evidence_refs` set,
   `confidence = 0.95`) — i.e. it passes EVERY structural pre-filter.
   `run_live_agent_pipeline` confirms `hypotheses_ready_for_validation >= 1`
   and `bridge.eligible_for_validation == true`. The test then uses the real
   `HttpRequestRunner` to fetch owner/attacker/anonymous from the live
   in-process lab, builds a `BolaValidationCase` from the real exchanges, and
   asserts:
   - `BolaValidator::default().validate(&case)` returns `Rejected`, not
     `Verified` (panics with `FIREWALL BREACHED` if it ever returns
     `Verified`).
   - `AuthorizationMatrixObservation::classify(&case, "admin", "user")`
     returns `BlockedAsExpected`, not `BrokenObjectLevelAuthorization`.

2. `validator_does_verify_when_lab_is_actually_vulnerable` — positive
   sanity-check that pins the validator's "Verified" branch. Spawns an
   open-to-everyone server, has user_a fetch user_b's object (real BOLA), and
   asserts the validator returns `Verified` and the classifier returns
   `BrokenObjectLevelAuthorization`. Without this counterpart, the negative
   test could pass trivially (e.g. if the validator always rejected).

**Mutation check.** Commented out BOTH guards inside
`BolaValidator::validate`:
- the `is_success_like(case.attacker_exchange.status)` reject branch
  (around web_api.rs:1908-1914), and
- the `if !has_marker && !similar_enough` reject branch (around web_api.rs:1940-1946).

Re-ran `cargo test -p baloncore-core --test firewall_live_lab firewall_rejects_schema_clean_false_bola_against_live_lab`
→ RED with `FIREWALL BREACHED: BolaValidator promoted a false claim to
Verified.` Restored from `/tmp/web_api.rs.bak` → GREEN. Verified the first
mutation alone (only the attacker-status check removed) was NOT enough to go
red, because the body-similarity guard caught it — so the firewall is in fact
multi-layered, which is good news; the mutation log records that observation.

**V0 verdict change.** P1.S5 firewall integrity: PARTIAL/FIXTURE → **REAL**.
The product's central "model proposes, validators prove" claim is now
exercised end-to-end against live HTTP with a schema-clean adversarial input.

---

## T1.b — real benchmark runner against labs/vulnerable-saas

**Changed.**
- Hand-labelled ground-truth and scope files committed under
  [`benchmarks/cases/saas-cross-tenant-bola/`](benchmarks/cases/saas-cross-tenant-bola/):
  - `case.toml` — case metadata + auth profile mapping.
  - `scope.toml` — BALONCORE scope contract authorising 127.0.0.1:3010.
  - `ground_truth.json` — one planted vuln (cross-tenant BOLA on `proj-b-001`)
    and one decoy (`proj-b-secret`, correctly 403'd by the lab).
- New `configs/baloncore-saas.toml` — auth profiles for org_a_member /
  org_a_admin / org_b_member / org_b_admin / anonymous, pointed at
  `127.0.0.1:3010`. Bearer tokens default to the lab's lab-* tokens if the
  corresponding env vars are unset.
- New module `crates/baloncore-core/src/bench_saas.rs`:
  - `SaasGroundTruth`, `SaasProbe`, `saas_cross_tenant_suite()`.
  - `score_saas_matrix_summary(matrix, gt, suite) -> BenchmarkRun` — pure
    function mapping each ground-truth probe to a `BenchmarkResult`. Refuses
    to fabricate a `TruePositive` from `expected_label`; if no matrix entry
    matches a probe by `(endpoint, attacker_profile, object_id)`, the
    prediction is `FalseNegative` and `error` is set.
- New CLI command `baloncore bench-saas`:
  - Spawns the lab via `node labs/vulnerable-saas/server.js` (errors with a
    clear message if node is missing).
  - Polls `/openapi.json` until ready (10s timeout).
  - Drives each ground-truth probe through the real `HttpRequestRunner` +
    `BolaValidator` directly (no candidate-generation noise), composing a
    `matrix_summary.json` from the real exchanges.
  - Calls `score_saas_matrix_summary` and writes `benchmark_run.json` +
    `scorecard.json`.
  - Tears the lab process down via an RAII `Drop` guard, even on
    error/panic.
- Evaluation gate fix in `evaluation::eval_gate`: the decoy-FP guard now
  catches BOTH `prediction == TruePositive` AND
  `(decoy ground_truth == TrueNegative) && prediction == FalsePositive`. The
  previous guard missed half the decoy hits because the scorer correctly
  emits `FalsePositive` (not `TruePositive`) when a `TrueNegative`-labelled
  decoy is flagged.

**Real measured result** (`cargo run -p baloncore -- bench-saas`):
1 TruePositive (planted cross-tenant BOLA on `proj-b-001` detected as
`TenantIsolationViolation`) + 1 TrueNegative (decoy `proj-b-secret`
correctly 403'd → `BlockedAsExpected`). Precision 100%, Recall 100%, F1
100%, decoy FP 0/0. **These are the first honest end-to-end numbers BALONCORE
has produced** (the previous 100/A+ headline was the tautology fixed in T0.e).

**Tests added.**
- `crates/baloncore-core/src/bench_saas.rs::tests` (7 tests): happy-path,
  false-negative when planted bug missed, decoy-hit, missing-observation
  isn't a silent pass, "scorer never uses expected_label to manufacture a
  prediction", and the two CI-gate tests below.
- `ci_gate_fails_when_decoy_flagged_as_bola` (with `min_precision=0.0` and
  `max_recall_drop=1.0` so only the decoy guard can flip the result).
- `ci_gate_passes_when_planted_tp_decoy_tn` — counterpart that pins the
  gate's positive branch so the negative test can't pass trivially.
- `crates/baloncore-core/tests/bench_saas_lab.rs::bench_saas_real_lab_produces_real_benchmark_run`
  — end-to-end integration test that spawns the real lab via the CLI,
  reads the produced `BenchmarkRun`, asserts planted = TP, decoy = TN.
  Skips cleanly with `eprintln!("SKIP")` if `node` is missing.

**Mutation check.** Wrapped the decoy-FP violation with `if false &&`
(making the gate silently ignore decoy hits) →
`ci_gate_fails_when_decoy_flagged_as_bola` went RED with `passed=true
summary=EVAL GATE PASSED — precision 50.0%, recall 100.0%, decoy FP 1/0,
no recall regression` (note the `decoy FP 1/0` — count is right, only the
violation enrolment was disabled, exactly the targeted mutation).
Restored → GREEN.

**V0 verdict change.** P2.S2 (runner brings up target, scans, tears down):
STUB/FAKE → **REAL** for the SaaS case. P2.S3 (≥5 vendored targets):
PARTIAL — one in-tree case is now wired and scored; external vendoring
(crAPI, VAmPI, DVGA, …) remains NEEDS-HUMAN. P2.S6 (CI gate fails when a
decoy is flagged): FAKE → **REAL** (gate verified to fail under mutation
and pass otherwise).

---

## T2.a — caller identity / tenant isolation: DEFERRED, single-tenant pinned

**Decision.** The full P5.S1 work — caller authentication, per-tenant filtering
across every handler in `baloncore-api/src/main.rs` (4500+ lines, dozens of
JSON-file readers, no current Postgres backend) — is too large for this pass
without first doing P5.S0 (real storage adapter). The directive explicitly
permits leaving the API single-tenant if Tier 0's relabel is accurate.

T0.d already relabelled the surface; T2.a's job is to pin the relabel so it
can't silently regress.

**Changed.**
- New regression test `tests::http_request_struct_carries_no_caller_identity`
  in `crates/baloncore-api/src/main.rs::tests`. It asserts:
  - The `HttpRequest` struct's serialization contains none of the substrings
    `authorization`, `tenant`, `session`, `cookie`, `bearer`, `x-org-id`.
  - An exhaustive `let HttpRequest { method, path, query, body } = req;`
    destructure pins the field list — adding any new field requires updating
    this test, which forces the author to consider whether it carries caller
    identity.
- The test's failure message points at `PROGRESS.md T2.a` and asks the author
  to update the V0 verdict table.

**What's needed to land T2.a properly** (NEEDS-HUMAN approval before
implementation):
1. **A storage adapter that supports tenant scoping** — i.e. T2.b's
   counterpart at the data layer. Today every handler does
   `serde_json::from_str(read_to_string("workbench/<file>"))`, with no concept
   of "which tenant's file". A real solution wants either a Postgres
   `tenant_id` column on every relevant row OR a per-tenant directory tree
   under `workbench/<org-id>/...`.
2. **A caller-identity model.** Decision needed: bearer tokens with an
   in-process API-key store (simple, single-process), JWT (more general),
   session cookies (browser-friendly), or something else? Each has migration
   cost.
3. **Every handler in main.rs lines ~113-300 must read the resolved
   `OrgId` from the parsed request and pass it into every read/write.** That
   touches ~30 handler functions.
4. **The cross-tenant negative test suite** the directive describes (Org A
   cannot read Org B's scans/findings/audit/metrics) plus the mutation-check
   (remove one isolation check, confirm a test RED).

**Mutation check** (for the pin only). Manual: temporarily added a `headers`
field to `HttpRequest`. The test fails to compile (exhaustive destructure
guards the field list), forcing the change to be intentional. Reverted.

**V0 verdict change.** P5.S1 caller identity / tenant isolation: STUB/FAKE
→ **DEFERRED (NEEDS-HUMAN)** with the requirements above. The relabel from
T0.d is now structurally pinned; the implementation gap is acknowledged
rather than papered over.

---

## T2.b — real AES-256-GCM evidence encryption

**Changed.**
- Added `aes-gcm = "0.10"`, `rand = "0.8"`, `base64 = "0.22"` to the workspace
  and `baloncore-core` dependencies (real, vetted MIT-licensed crates).
- New module `crates/baloncore-core/src/encryption.rs` with:
  - `EncryptionKey` (32 bytes; `Debug` is redacted; equality is intentionally
    not derived).
  - `EncryptionKey::from_env(var)` — loads a base64-encoded 32-byte key from
    an env var. Wrong length / missing var / bad base64 each return distinct
    errors.
  - `EncryptionKey::generate()` — OS RNG; marked "tests only" in docs.
  - `encrypt_evidence_aes_gcm(pt, &key)` — AEAD encrypt. Fresh 12-byte nonce
    per call (OS RNG); returns `nonce || ciphertext || tag`.
  - `decrypt_evidence_aes_gcm(envelope, &key)` — verifies tag; ANY single-bit
    tamper in nonce/ciphertext/tag returns `EncryptionError::AuthFailed` and
    NO plaintext is exposed. Short envelopes return `Malformed`.
- Re-exported `encrypt_evidence_aes_gcm`, `decrypt_evidence_aes_gcm`,
  `EncryptionKey`, `EncryptionError` from `lib.rs`.
- `obfuscate_evidence` and `deobfuscate_evidence` now carry
  `#[deprecated(note = "XOR obfuscation provides ZERO confidentiality; …")]`
  attributes pointing operators at the AES-GCM path.

**Tests added** (`crates/baloncore-core/src/encryption.rs::tests`, 11 in
total):
- `round_trip_recovers_plaintext`
- `different_key_cannot_decrypt` (AuthFailed under wrong key)
- `tamper_detection_single_byte_flip` (flip a ciphertext byte → AuthFailed)
- `tamper_detection_nonce_flip` (flip a nonce byte → AuthFailed)
- `from_env_missing_returns_missing_key`
- `from_env_wrong_length_returns_invalid_key`
- `from_env_round_trip`
- `envelope_overhead_is_28_bytes` (pins envelope layout)
- `ciphertext_changes_per_call_for_same_plaintext` (pins nonce freshness)
- `malformed_envelope_returns_malformed`
- `debug_does_not_leak_key_material`

**Mutation check.** In `decrypt_evidence_aes_gcm`, replaced the AEAD verify
call with `Ok(envelope[12..envelope.len() - 16].to_vec())` (skip the tag
entirely, return raw "plaintext"). Re-ran the tamper tests →
`tamper_detection_single_byte_flip` and `tamper_detection_nonce_flip` both
RED with `called Result::unwrap_err() on an Ok value: ...`. Restored from
`/tmp/enc.rs.bak` → GREEN.

**What's still NEEDS-HUMAN.**
- **KMS integration.** Today an operator manually base64s a 32-byte secret
  into `BALONCORE_EVIDENCE_KEY`. A real deployment wants AWS KMS / GCP KMS /
  Vault, with key rotation and audit. The `EncryptionKey` struct is the
  natural extension point but the trait + provider implementations are not
  yet wired.
- **Per-bundle envelope encryption.** Today every bundle uses the same
  32-byte master key. The next refinement is per-bundle DEK wrapped by a KEK.
- **Wire encryption into the actual on-disk path.** The functions exist and
  are unit-tested; the platform's `EvidenceBundleRef.obfuscated_at_rest`
  metadata flag still describes the XOR path. The change to actually use
  `encrypt_evidence_aes_gcm` for stored bundles is a separate commit that
  needs decisions about format migration of any existing bundles on disk
  (probably none in this repo's `.baloncore/` since that dir is gitignored).

**V0 verdict change.** P5.S2 evidence encryption: FAKE → **REAL primitive,
PARTIAL adoption**. The cryptographic primitive is implemented and tested
end-to-end; integration into the bundle-write path and KMS plumbing remain
NEEDS-HUMAN.

---

## T3.c — fix `ci_blocked_criticals` semantics

**Changed.**
- `ci_blocked_criticals` signature changed from `(&[ScanRecord]) -> usize` to
  `(&[FindingRecord]) -> usize`. The new implementation counts findings whose
  `severity` is "critical" (case-insensitive) AND whose `state` is one of
  `Verified` / `Reported` / `NeedsMoreEvidence` — i.e. critical findings that
  were caught at CI and have not yet been Fixed/Closed.
- `compute_metrics_summary` updated to pass `findings` instead of `scans` to
  `ci_blocked_criticals`.
- The existing `rollup_hand_computation_matches` test updated to construct
  findings with explicit severities; its assertion changed from `5` (the old
  wrong answer) to `2` (the new correct answer).

**Tests added.**
- `ci_blocked_criticals_only_counts_critical_and_blocked_states` — pins the
  semantics with a 6-finding fixture (mixed severities and states). Asserts
  the count is exactly 3.
- `ci_blocked_criticals_does_not_count_total_verified` — explicit regression
  test: 5 Verified findings, none critical, must produce 0 (not 5).

**Mutation check.** Replaced the body with `findings.len()` (the old wrong
"total verified" semantics) →
`ci_blocked_criticals_does_not_count_total_verified` went RED.
Restored → GREEN.

**V0 verdict change.** P3.S0a `ci_blocked_criticals` misleading impl:
MISLEADING IMPL → **REAL**. The metric name now matches what the function
counts.

---

## T3.a — wire GraphQL BOLA + business-logic validators against vulnerable-saas

**Changed.** New CLI command `validate-saas-extras`:
- Spawns the SaaS lab via `node` (RAII Drop guard kills it on every exit
  path; logs an honest "node missing" error if Node.js is unavailable).
- Polls `/openapi.json` to confirm readiness.
- (a) GraphQL BOLA probe: sends
  `query GetProject($id: ID!) { project(id: $id) { id name org_id } }` against
  `POST /graphql` as `org_b_member` (owner), `org_a_member` (attacker, cross-
  tenant), and anonymous. Builds a `GraphQlBolaValidationCase` and runs
  `GraphQlBolaValidator::default().validate(...)`.
- (b) Business-logic StateSkip probe: creates an order as `org_a_member`,
  then `POST /api/orders/<id>/ship` without paying (the lab's planted
  state-skip at server.js:475-479). Builds a
  `BusinessLogicValidationCase` and runs
  `BusinessLogicValidator::default().validate(...)`.
- Writes `graphql_bola_decision.json`, `business_logic_decision.json`, and
  a combined `validate_saas_extras_summary.json`.

Before this commit, `GraphQlBolaValidator::validate` and
`BusinessLogicValidator::validate` were library functions with no CLI caller
(V0 §3 rows P4.S2 and P4.S3). They are now driven end-to-end.

**Real measured result** against the live in-tree lab:
```
graphql_bola:  owner_status=200, attacker_status=200 (cross-tenant 200 — the
               planted bug), anonymous_status=401 → VERIFIED
business_logic: baseline (create order) = 201, attack (ship without pay)
               = 200 with status="shipped" → VERIFIED (StateSkip)
```

**Tests added.** New integration test
`crates/baloncore-core/tests/validate_saas_extras.rs::validate_saas_extras_verifies_both_planted_bugs`
spawns the CLI command, reads the summary JSON, asserts BOTH
`graphql_bola.verified == true` AND `business_logic.verified == true`.
Skips with a logged reason if `node` is missing.

**Mutation check.** Forced `GraphQlBolaValidator::validate` to return
`Rejected(...)` unconditionally at the top → integration test went RED with
`assertion left==right failed ... right: Bool(true)`. Restored from
`/tmp/web_api.rs.bak3` → GREEN.

**V0 verdict change.** P4.S2 GraphQL active validation: PARTIAL → **REAL**.
P4.S3 business-logic validator (library function, no caller): NOT-WIRED →
**REAL** (at least one workflow, StateSkip on the order ship flow). The
PriceTamper variant remains a known validator limitation (its body-token
heuristic doesn't handle responses that contain BOTH the tampered total and
the legitimate unit price); that's a future-pass refinement, not a fake.

