# V0 → Tier 3 Progress Log

Format per item: **item id — what changed — test result — verdict change (V0 → new)**.
Mutation-check: "broke X → red → restored → green" recorded explicitly when applicable.

---

## A0 — Active-finding foundation (Vertical A campaign; NO vuln class yet)

**Changed.** New module `crates/baloncore-core/src/active_finder.rs` — the shared
substrate every active finder will build on, mirroring the `BolaValidator`
firewall contract so evidence sealing works unchanged. Adds NO vuln class.

- **`ActiveFinder` trait** + decision shape: `FinderDecision = Verified(ActiveProof)
  | Rejected(RejectedHypothesis) | Inconclusive(String)`. `ActiveProof` carries a
  `ProofKind` enumerating the only deterministic signals allowed
  (`OutOfBandCallback`, `BooleanDifferential`, `TimingDifferential`,
  `ForgedTokenAccess`, `StateChange`) — never "the payload reflected". Reuses
  `web_api::RejectedHypothesis` so the firewall/evidence layers are unchanged.
- **`FinderContext`** — the only way a finder touches the network. Bundles the
  target, auth profiles, the real `HttpRequestRunner`, a `ScopeGuard`, a
  `ProbeBudget`, and (optionally) the OOB collaborator. `send`/`send_json`
  enforce scope (refuse + don't send if out of scope) and budget (one unit per
  request) on EVERY probe, and return a `ProbeObservation` with timing (since
  `HttpExchange` has no duration field).
- **`ProbeBudget`** — per-scan probe + wall-clock ceiling (mirrors the
  `ModelBudget` pattern); `try_consume` fails closed on either cap.
- **`OobCollaborator`** — a local out-of-band HTTP sink (std `TcpListener`, no new
  deps), `127.0.0.1` by default (`start_on(host)` for authorized remote use). Mints
  correlation tokens, exposes `payload_url(token)`, records each inbound request as
  an `OobInteraction`, `wait_for(token, timeout)` for blind proofs, and seals each
  interaction as an `EvidenceRecord` (RuntimeObservation, SafeToShare). Drop stops
  the server thread.
- **`differential`** — pure control-vs-test comparator with stable thresholds
  (`DifferentialConfig`: body-similarity 0.85 via token-Jaccard; timing requires
  BOTH ratio ≥3× AND absolute gap ≥500ms, so jitter never registers).

**Tests added** (`active_finder.rs::tests`, 8): OOB sink records a real
server-side callback (and seals evidence) + ignores unrelated tokens; differential
flags a planted boolean difference (status or distinct body) and a planted time
difference, and IGNORES body noise (one extra token) and timing jitter
(100→140ms, and a big-ratio/tiny-abs case); `FinderContext` refuses an
out-of-scope send WITHOUT consuming budget (a link-local metadata URL is blocked);
budget exhaustion is enforced. The OOB tests skip cleanly if a local socket can't
be bound.

**Mutation check (differential threshold).** Collapsed the timing thresholds to
`min_time_ratio: 1.0, min_time_abs_ms: 0` → `differential_ignores_timing_jitter`
went RED (`time 100ms->140ms … differs=true`). Restored from
`/tmp/active_finder.rs.bak` → GREEN (8/8).

**Verify.** `cargo fmt --check` exit 0; `cargo test -p baloncore-core --lib` 585
passed (577 + 8 new), CLI 25 passed; no warnings in the new module.

**V0 verdict change.** Vertical-A active-finding substrate: ABSENT → **REAL
(foundation)**. No vuln class added yet (per A0 scope). A1 (JWT/auth-token flaws)
is the first finder to build on this — it will implement `ActiveFinder`, use
`FinderContext` for forged-token access, and prove on DVGA + VAmPI.

---

## A1 — JWT / auth-token flaw finder (first `ActiveFinder`, proven on DVGA + VAmPI)

**Changed.** New module `crates/baloncore-core/src/jwt_auth_finder.rs` — the first
`ActiveFinder`, generalizing the DVGA `verify_signature=False` bug + VAmPI's
weak-HMAC-secret bypass into a finder.

- **Forging primitives (no new deps):** `forge_alg_none`, `forge_stripped_signature`,
  `forge_hs256` (HMAC-SHA256 implemented over `sha2`, validated against an RFC 4231
  vector), `forge_claim_tamper` (keep an issued token's signature, swap claims),
  `decode_payload`. base64url via the existing `base64` dep.
- **`JwtAuthFinder` (ActiveFinder):** given a `JwtAuthCase` (endpoint, token
  injection — `BearerHeader` or GraphQL `{TOKEN}` arg — control token, escalate
  claim, technique list, weak-secret wordlist, victim markers) it runs control +
  anonymous baselines once, then per technique forges a token escalating the
  identity/role and re-accesses. Techniques: AlgNone, StripSignature,
  WeakSecretHmac (bounded wordlist brute), AlgConfusion (HS256 with RSA pubkey as
  secret), ClaimTamper. The forged token is **redacted** in sealed evidence (only
  the technique/variant label is recorded).
- **The proof guard `forged_access_proven` (the A1 firewall):** Verified ONLY when
  the forged response is success-like AND carries a victim marker, the control
  (original identity) response does NOT, AND the anonymous response does NOT.
  "Request accepted" alone never verifies; a forged token that is rejected, or
  that returns only data anyone already sees, is `Rejected`.
- **Scorer:** `jwt_suite` + `score_jwt_run` (scenario id → Verified? → TP/TN/FP/FN
  via `jwt_prediction`), producing a `BenchmarkRun` the existing `eval_gate`
  scores. Decoy hits fail the gate.
- **CLI:** `bench-jwt-dvga` (boots the pinned DVGA image, GraphQL injection) and
  `bench-jwt-vampi` (boots the vulnerable VAmPI venv, logs in name2 for the
  control, bearer injection). Each builds cases, runs the finder, scores, tears
  the target down. NEEDS-HUMAN errors if the target isn't vendored.

**Real measured result.**
- `bench-jwt-dvga`: `vuln-forge-admin-identity` → **TruePositive** (forged
  `{identity:admin}` alg=none token leaked admin password `changeme`; operator
  control masked, anonymous errored); `decoy-public-paste` → **TrueNegative**
  (public content — anonymous already sees it).
- `bench-jwt-vampi`: `vuln-weak-secret-hmac-admin` → **TruePositive** (weak secret
  `random` brute-forced; forged `sub=admin` HS256 token → `/me` returned
  `admin@mail.com`; control name2 = 200 without the marker; anon = 401);
  `decoy-algnone-rejected` → **TrueNegative** (VAmPI verifies the signature → 401);
  `decoy-public-users` → **TrueNegative** (`/users/v1` lists `admin@mail.com`
  anonymously → no escalation).
Both targets Verified; all three decoys Rejected; precision/recall 100% on both.

**Tests added.**
- `jwt_auth_finder.rs::tests` (13): forging correctness (alg=none shape, HS256
  keyed+deterministic, RFC-4231 HMAC vector, claim-tamper keeps sig); the proof
  guard (verifies real cross-identity access; **rejects the public-endpoint decoy**
  where anonymous also sees the marker; rejects a refused forged token; rejects
  accepted-but-no-victim-data); the prediction matrix; scorer happy-path +
  decoy-FP-fails-gate + clean-run-passes-gate.
- `tests/bench_jwt_dvga_lab.rs` + `tests/bench_jwt_vampi_lab.rs` — end-to-end
  integration tests against the real targets (distinct ports 5082 / 5003 to avoid
  collisions in `cargo test --workspace`); skip (NEEDS-HUMAN) if the target is not
  vendored. Both green.

**Mutation check (the forged-token-access guard).** Replaced
`forged_access_proven`'s body with `forged_succeeded` alone (drop the victim-marker
/ control / anonymous clauses, so "request accepted" verifies) →
`guard_rejects_public_endpoint_anonymous_also_sees_marker` AND
`guard_rejects_accepted_but_no_victim_data` went RED. Restored from
`/tmp/jwt_auth_finder.rs.bak` → GREEN (13/13).

**Verify.** `cargo fmt --check` exit 0; `cargo test -p baloncore-core --lib` 598
passed (585 + 13 new); CLI 25 passed; `cargo clippy -p baloncore-core` no errors.

**V0 verdict change.** Vertical-A JWT/auth-token class: ABSENT → **REAL** — proven
on two real external targets (DVGA signature-not-verified; VAmPI weak-HMAC-secret),
with correctly-rejecting and public-endpoint decoys held out, the model-proposes/
validator-proves firewall intact (only `forged_access_proven` seals Verified), and
the forged token redacted in evidence.

---

## P2.S3 external benchmark corpus — COMPLETE (5/5 REAL) — consolidation summary

The external benchmark corpus is complete: five independent, vendored, intentionally-
vulnerable targets are each brought up (or parsed offline) by a dedicated `bench-*`
command, probed through BALONCORE's real validators/analyzers, and scored against a
hand-labelled ground truth with realistic decoys — **VAmPI** (REST BOLA via the
vulnerable/secure toggle, MIT, `f16052dc`), **DVGA** (GraphQL JWT-identity auth bypass,
MIT, `a961308c`), **crAPI** (multi-service vehicle-location BOLA, Apache-2.0, `d1cbf263`,
full-stack readiness wait + whole-stack teardown), **TerraGoat** (offline Terraform HCL,
Apache-2.0, `729f8da6`), and **Cfngoat** (offline CloudFormation, **NOASSERTION** — no
upstream license, so fetch-only and never redistributed, `0c09b69c`). Every SPDX id was
read from the actual LICENSE file, not assumed (two shortlist guesses were corrected:
VAmPI is MIT not GPL; Cfngoat has no license at all). Fresh runs of all five give an
aggregate **precision 100%, recall 100%, 9 TP, 0 FN, decoy false-positives 0/11** —
the combined scorecard + machine-readable leaderboard are written to
`.baloncore/corpus-scorecard/{combined_scorecard.md,leaderboard.json}` by
`scripts/corpus_scorecard.py`. Each target has scorer unit tests with a red-on-break
mutation check and a live integration test that skips cleanly (NEEDS-HUMAN) when the
target isn't vendored. Two genuine product-capability gaps were closed along the way
(offline Terraform-HCL ingestion in `terraform_hcl.rs`; CloudFormation intrinsic parsing
+ Users/Groups policy linkage + security-group detection in `cloudformation.rs`).
Consolidation checks recorded verbatim: `cargo build --workspace` ok (1 pre-existing
unused-import warning); `cargo test --workspace` and `cargo test --features live-models`
both exit 0 (all binaries green incl. live labs; the live-models lib build runs 586 unit
tests); `cargo fmt --check` exit 0; `cargo clippy --all-targets` exit 0 (style warnings
only, no errors). One test-harness fix was required for determinism: the DVGA and VAmPI
lab tests both defaulted to port 5071 and clashed when the whole suite ran the live-lab
tests concurrently — the DVGA lab test now uses 5081, after which `cargo test --workspace`
is deterministically green.

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

---

## T3.b — PDF flagship report (real renderer, no synthesis)

**Changed.**
- `export-flagship-report` now accepts `--format pdf`. The renderer
  produces a real PDF from the FlagshipReport that was built from run-dir
  artifacts; it never synthesises a finding or fabricates a placeholder
  document.
- Implementation: render the report HTML to a temp file, then shell out
  to one of `wkhtmltopdf`, `chromium`, `chromium-browser`, `google-chrome`,
  `google-chrome-stable`, or `chrome` (first-match wins). The CLI sanity-
  checks the produced bytes start with `%PDF-` magic; if not, it errors.
- If NO PDF renderer is available, the command exits non-zero with the
  explicit message
  `"PDF rendering requires one of `wkhtmltopdf`, `chromium`, … . Install
  one and re-run, OR use `--format html` / `--format markdown` which have
  no external dependencies."`
- HTML / markdown formats are unchanged.

**Tests added** (in `crates/baloncore-cli/src/main.rs::tests`):
- `render_pdf_from_html_produces_real_pdf_magic_or_explicit_install_error`
  — writes a minimal HTML temp file, calls `render_pdf_from_html`, and
  asserts EITHER (a) the renderer returned Ok AND the output starts with
  `%PDF`, OR (b) the renderer returned Err with a message containing
  `"PDF rendering requires"` and listing `wkhtmltopdf`, `chromium`,
  `google-chrome`, plus the html/markdown fallback suggestion.
- `render_pdf_from_html_never_emits_a_non_pdf_file_silently` — when the
  renderer errors, the output file MUST NOT exist (catches any future
  "silent placeholder fallback" regression).

**Mutation check.** Replaced the renderer's final `bail!(...)` with a
silent fallback that writes `"fake pdf placeholder"` bytes and returns
`Ok(())`. Both T3.b tests went RED:
`assertion failed: rendered PDF must start with %PDF magic; got: [102, 97, 107, 101]`
(those bytes are `"fake"`). Restored from `/tmp/main.rs.bak.t3b` → GREEN.

**Host note.** This dev box has no PDF binary installed (verified:
`wkhtmltopdf`, `chromium*`, `google-chrome*`, `chrome` all missing). The
test therefore exercises the "explicit-install-error" branch. CI / hosts
with any of those binaries installed will exercise the real-PDF-magic
branch automatically.

**V0 verdict change.** P4.S4 PDF flagship report: PARTIAL (HTML only) →
**REAL with a system-dep requirement**. The renderer is real (no synthesis,
no placeholder bytes); whether it can be invoked on a given host depends
on whether a PDF binary is installed there.

---

## T3.d — Program-Health dashboard view

**Changed.**
- `apps/web/lib/baloncore.ts` now exposes three typed fetchers:
  `fetchMetricsSummary()`, `fetchMetricsTrend(metric, bucket?)`,
  `fetchMetricsDrilldown(metric, period?)`. Each hits the corresponding
  `/api/metrics/{summary,trend,drilldown}` endpoint via the existing `api()`
  helper.
- `apps/web/app/dashboard/page.tsx`:
  - Imports `MetricsSummary`, `MetricsDrilldown`, `fetchMetricsSummary`,
    `fetchMetricsDrilldown` from the lib.
  - Adds `metrics`, `metricsError`, `drilldown`, `drilldownError`,
    `drilldownLoading` state.
  - `refreshAll()` now also fetches `/api/metrics/summary` (and stores the
    error rather than fabricating a value when the rollup is empty — honest
    empty state).
  - Adds `openDrilldown(metric)` and `closeDrilldown()`.
  - Renders a new `Program Health` section after the existing
    `board-metrics` block. Six clickable stat cards (Verified findings/scan,
    FP reduction rate, Median time to proof, Retest success rate,
    CI-blocked criticals, Tokens/verified) — each `<button>` calls
    `openDrilldown("<exact_metric_name>")`. A side panel reveals the first
    10 drill-down entries from `/api/metrics/drilldown`.
  - Loading and error states for both the summary and the drill-down panel.
  - The pill `"source: /api/metrics/summary"` is shown at the top of the
    section so reviewers can immediately see where the figures come from.

**Tests added** (`crates/baloncore-cli/src/main.rs::tests`):
- `dashboard_program_health_calls_api_metrics_with_drilldown` — reads the
  committed `apps/web/lib/baloncore.ts` and `apps/web/app/dashboard/page.tsx`
  and asserts:
  - lib exports all three fetchers AND references all three endpoint paths.
  - page imports `fetchMetricsSummary` + `fetchMetricsDrilldown`, has a
    `program-health` test id, defines `openDrilldown`, and reads
    `metrics.verified_findings_per_scan`.
  - For each of the six promoted metrics, the page contains the literal
    string `openDrilldown("<metric>")` — so every clickable figure is
    actually wired to a drill-down call.

**Mutation check.** Replaced the first `openDrilldown(...)` call in the page
with `openDrilldownDISABLED(...)` →
`dashboard_program_health_calls_api_metrics_with_drilldown` went RED.
Restored from `/tmp/page.tsx.bak.t3d` → GREEN.

**Web build status.** `pnpm typecheck` and `pnpm build` (Next 16.2.6 /
Turbopack) both clean; 7 static pages emitted.

**V0 verdict change.** P3.S3 dashboard "Program Health" view with drill-down:
STUB/MISSING → **REAL**. Every figure is sourced from `/api/metrics/*` and
is clickable to its drilldown source set.

---

## P2.S3 (corpus #1) — VAmPI external target, real scan + score

**Target.** `erev0s/VAmPI` (Flask "vulnerable API" with a global
`vulnerable=1/0` switch). First external corpus target wired to the `bench-saas`
template.

**Provenance, checked not assumed.**
- Repo exists; pinned commit `f16052dce83f05847133ec98f01c5193a41de7d8`
  (2026-04-07).
- **License = MIT** (SPDX), read directly from the repo `LICENSE` file. The
  corpus shortlist *guessed* GPL-3.0; it is wrong. `case.toml` records `MIT`
  and a `license_note` calling out the correction.

**Vendoring.** [`scripts/fetch_vampi.sh`](scripts/fetch_vampi.sh) clones the
pinned commit into the gitignored `.baloncore/corpus/vampi/`, re-checks the
LICENSE header still says MIT, and pip-installs VAmPI's 2022-era pins into a
venv (Python 3.9–3.12; 3.14 is too new for Flask 2.2.2 / connexion 2.14.2). This
is the one NEEDS-HUMAN step (network + pip); after it, `bench-vampi` is fully
local. Docker is the upstream-documented path but the daemon was unavailable in
this environment, so the native Flask boot is used.

**Case files** under
[`benchmarks/cases/vampi-bola-books/`](benchmarks/cases/vampi-bola-books/):
`case.toml`, `scope.toml` (authorises 127.0.0.1:5001/5002 only), and
`ground_truth.json` — one planted vuln + **two** decoys:
- `vuln-bola-books-vulnerable` (TruePositive): on the VULNERABLE build, `name2`
  reads `name1`'s book secret via `GET /books/v1/{book}` (books.py:50-58, no
  owner filter when `vuln=1`).
- `decoy-bola-books-secure` (TrueNegative): the SAME probe on the SECURE build
  (`vuln=0`, owner-scoped query → 404). This is the toggle-based negative set —
  the same bug switched off must produce ZERO findings.
- `decoy-owner-self-access` (TrueNegative): `name1` reading its OWN book (legit
  200) — the false-positive trap for a scanner that flags any cross-id 200.

**Runner.** New `crates/baloncore-core/src/bench_vampi.rs` scorer +
`baloncore bench-vampi` CLI command. The command boots both builds
**sequentially** (they share one sqlite file in the checkout), verifies each
came up in the requested mode by reading the home endpoint's `"vulnerable"`
flag (refuses to score if the toggle didn't take effect), seeds the DB
(`/createdb`), logs in `name1`/`name2` for JWTs, plants a fixed-title book, then
drives owner/attacker/anonymous `GET`s through the **real** `HttpRequestRunner`
+ `AuthorizationMatrixObservation::classify`. An RAII `ChildGuard` tears each
build down on every exit path. New core helper
`HttpRequestRunner::send_with_json_body` carries the login/createdb/plant bodies
(serialized manually so it works without the optional `reqwest/json` feature);
it is fixture-setup only and never decides a verdict.

The scorer matches a ground-truth probe to a matrix observation on
`(mode, endpoint, attacker_profile, object_id)` — `mode` is in the key
specifically so a vulnerable-build finding can never be credited to the
secure-build decoy. It reuses `bench_saas::classify_prediction_from_label` and
`endpoints_equivalent`; it never uses `expected_label` to manufacture a
prediction, and a probe with no matching observation scores `FalseNegative`
(never a silent pass).

**Real measured result** (`cargo run -p baloncore -- bench-vampi`, against the
two live VAmPI builds):
```
vuln-bola-books-vulnerable  TruePositive  (BrokenObjectLevelAuthorization,
                                           attacker 200 + planted secret)
decoy-bola-books-secure     TrueNegative  (attacker 404, BlockedAsExpected)
decoy-owner-self-access     TrueNegative  (IntendedOwnerAccess)
```
Precision 100%, recall 100%, decoy false-positives 0/2 — honest end-to-end
numbers against a real external target, with the false-positive rate measured by
the same target's bug-off build.

**Tests added.**
- `bench_vampi.rs::tests` (9): happy path, FN when the vulnerable bug is missed,
  secure-decoy-flagged → FalsePositive, owner-self-flagged → FalsePositive,
  **`mode_is_part_of_the_match_key`** (a vulnerable observation must NOT satisfy
  a secure probe), missing-observation-is-FN-not-silent-pass, never-uses-
  expected-label, and the two CI-gate tests (gate FAILS when the secure decoy is
  flagged; PASSES on a clean run).
- `crates/baloncore-core/tests/bench_vampi_lab.rs` — end-to-end integration test
  that runs the real CLI against the vendored target and asserts TP/TN/TN. Skips
  with a logged reason (NOT a failure) when the target hasn't been vendored.

**Mutation check.** Removed the `obs.mode == probe.mode` term from the scorer's
match key → `mode_is_part_of_the_match_key` (and the clean-run gate test) went
RED: the secure-build decoy then matched the vulnerable-build observation and
was scored a false positive (`decoy false positives: 1`). Restored from
`/tmp/bench_vampi.rs.bak` → GREEN (9/9). Full suite: core 533 lib + integration
green; CLI 25 green.

**V0 verdict change.** P2.S3 (≥5 vendored external targets): PARTIAL →
**PARTIAL, +1 REAL**. VAmPI is now a real, scored external target (TP + 2 TN,
0 FP) with a one-command NEEDS-HUMAN fetch. crAPI / DVGA / Damn Vulnerable DeFi
/ TerraGoat / … remain NEEDS-HUMAN, to be wired one at a time on the same
template. P2.S6 (CI gate fails on a decoy): independently re-confirmed REAL for
the VAmPI case via mutation.

---

## P2.S3 (corpus #2) — DVGA external target, real GraphQL-BOLA scan + score

**Target.** `dolevf/Damn-Vulnerable-GraphQL-Application` (DVGA). Second external
corpus target; exercises the GraphQL BOLA validator. Same template as VAmPI
(scorer module + `bench-dvga` CLI + `benchmarks/cases/dvga-graphql-bola/`).

**Provenance, checked not assumed.**
- Repo exists; pinned commit `a961308c02d1fb462b192681c336b0739e432da7`
  (2025-05-24).
- **License = MIT** (SPDX), read directly from the repo `LICENSE.md` file (the
  shortlist's "MIT, verified in README" claim now confirmed against the actual
  license file).
- Runtime image pinned by digest:
  `dolevf/dvga@sha256:040aa33c199d99f3380c9ff9a1ee5d725e9abca7b189c63a35a2a73bda79c957`.
  The live image's behaviour was confirmed to match the pinned source.

**Vendoring.** [`scripts/fetch_dvga.sh`](scripts/fetch_dvga.sh) clones the source
at the pinned commit into the gitignored `.baloncore/corpus/dvga/` (license
re-verified to still be MIT) and `docker pull`s the digest-pinned image. Docker
is the one NEEDS-HUMAN dependency (image pull). NOTE: the Docker daemon dropped
mid-session and recovered after ~30s; the runner treats an unavailable daemon /
missing image as an explicit NEEDS-HUMAN error, not a fake pass.

**The vuln (real, empirically confirmed against the live image).**
`core/helpers.py:20-21` (`get_identity`) decodes the auth JWT with
`verify_signature=False`, and `core/views.py:60-65`
(`UserObject.resolve_password`) returns a user's REAL password whenever the
request identity is `"admin"`. So a principal who knows no secret forges an
unsigned `{"identity":"admin"}` token and reads admin's real password via
`me(token){ password }`. Confirmed live: forged-admin → `password:"changeme"`;
forged-operator → `password:"******"`; anonymous → null/error.

**Case files** under
[`benchmarks/cases/dvga-graphql-bola/`](benchmarks/cases/dvga-graphql-bola/):
`case.toml`, `scope.toml` (127.0.0.1:5013 only), `ground_truth.json` — one
planted vuln + **two** decoys, each driven through the real
`GraphQlBolaValidator`:
- `vuln-jwt-forge-admin-password` (TruePositive): attacker (operator) forges
  `identity:admin`, leaks admin's `changeme`. Owner baseline uses a
  legitimately-issued admin token (via the `login` mutation).
- `decoy-nonadmin-identity-masked` (TrueNegative): forging a *non-privileged*
  identity (`operator`) leaks nothing — password is masked to `******`. A
  scanner that flags any populated `password` field would FP; the validator
  finds no owner marker and body_similarity ≈0.62 < 0.70 → Rejected.
- `decoy-public-paste` (TrueNegative): `paste(id:12)` is public, readable by the
  anonymous probe too → validator Rejects (public data, not cross-user BOLA).

**Runner.** New `crates/baloncore-core/src/bench_dvga.rs` scorer + `baloncore
bench-dvga` CLI command. The command preflights Docker, boots the digest-pinned
image (RAII `ContainerGuard` does `docker rm -f` on every exit path), pins
Beginner difficulty per-request via `X-DVGA-MODE`, obtains a legit owner token
via the `login` mutation, **forges** unsigned attacker JWTs
(`dvga_forge_jwt`, base64url, no secret), POSTs each GraphQL probe via
`HttpRequestRunner::send_with_json_body`, runs the real `GraphQlBolaValidator`,
and maps Verified→`BrokenObjectLevelAuthorization` / Rejected→`BlockedAsExpected`
into the matrix. The scorer matches a probe to an observation on
`(operation, object_id, attacker_profile)` and never uses `expected_label` to
manufacture a prediction.

**Real measured result** (`cargo run -p baloncore -- bench-dvga`, live image):
```
vuln-jwt-forge-admin-password   TruePositive  (Verified; evidence object_id:admin, owner_marker:changeme)
decoy-nonadmin-identity-masked  TrueNegative  (Rejected; no marker, similarity < 0.70)
decoy-public-paste              TrueNegative  (Rejected; anonymous also succeeded)
```
Precision 100%, recall 100%, decoy false-positives 0/2.

**Tests added.**
- `bench_dvga.rs::tests` (9): happy path, FN when the bypass is missed, both
  decoy-flagged→FalsePositive cases, **`match_key_includes_attacker_profile`**
  (the masked decoy must not be credited with the vuln observation),
  missing-observation-is-FN, never-uses-expected-label, and the two CI-gate
  tests (gate FAILS on a decoy hit; PASSES on a clean run).
- `crates/baloncore-core/tests/bench_dvga_lab.rs` — end-to-end test running the
  real container via the CLI; asserts TP/TN/TN. Skips with a logged reason
  (NEEDS-HUMAN) when Docker/the image is unavailable.

**Mutation check.** Removed the `obs.attacker_profile == probe.attacker_profile`
term from the scorer's match key → `match_key_includes_attacker_profile` (and
the clean-run gate test) went RED: the masked decoy then matched the vuln's
`BrokenObjectLevelAuthorization` observation and was scored a false positive
(`decoy false positives: 1`). Restored from `/tmp/bench_dvga.rs.bak` → GREEN
(9/9). Full suite: core 542 lib + all integration green; CLI 25 green.

**V0 verdict change.** P2.S3 (≥5 vendored external targets): PARTIAL → **PARTIAL,
+2 REAL** (VAmPI + DVGA). P4.S2 GraphQL active validation: independently
re-confirmed REAL — the `GraphQlBolaValidator` now fires on a real external
GraphQL target's authorization bypass and stays silent on two realistic decoys.
crAPI / TerraGoat / Cfngoat remain queued on the same template.

---

## P2.S3 (corpus #3) — crAPI external target, real multi-service BOLA scan + score

**Target.** `OWASP/crAPI` — a multi-service (Docker Compose) intentionally-
vulnerable API. Third external corpus target; the flagship real-world BOLA.

**Provenance, checked not assumed.**
- Repo exists; **License = Apache-2.0** (SPDX), read directly from the repo
  `LICENSE.md` (the shortlist guessed "expected Apache-2.0"; now confirmed).
- Pinned to git tag **v1.1.6-rc8** (commit
  `d1cbf263a310ea4ed342e44a21a3ea32431e8ea6`) so the vendored source matches the
  published image tag — there are NO `1.1.5`/`1.1.6` images on Docker Hub
  (`VERSION` in the repo said 1.1.5 but no such image exists; rc8 is the latest
  concrete tag). Service images pinned to `crapi/*:1.1.6-rc8`. The live stack's
  seed users + vehicle GUIDs were confirmed to match the pinned source's
  `TestUsers.java`.

**Vendoring.** [`scripts/fetch_crapi.sh`](scripts/fetch_crapi.sh) clones the
source at the pinned commit into the gitignored `.baloncore/corpus/crapi/`,
re-verifies Apache-2.0, pins `VERSION=1.1.6-rc8` in the vendored compose `.env`,
and `docker compose pull`s the stack. Docker + Compose + a large multi-image
pull are the NEEDS-HUMAN dependencies.

**The vuln (real, empirically confirmed against the live stack).** crAPI
Challenge 1 (docs/challenges.md): `VehicleController.getLocationBOLA` —
`GET /identity/api/v2/vehicle/{carId}/location` returns a vehicle's location by
GUID with NO ownership check. Seed user Pogba reads owner Adam's vehicle
location + email by GUID. Confirmed live: attacker HTTP 200 with Adam's
`32.778889/-91.919243/adam007@example.com`; anonymous HTTP 401.

**Case files** under
[`benchmarks/cases/crapi-bola-vehicle/`](benchmarks/cases/crapi-bola-vehicle/):
`case.toml`, `scope.toml` (127.0.0.1:8888 only), `ground_truth.json` — one
planted vuln + **two** decoys, each driven through the real `BolaValidator`:
- `vuln-bola-vehicle-location` (TruePositive): Pogba reads Adam's vehicle
  location by GUID. Owner baseline uses Adam's legitimately-issued login token.
- `decoy-user-video-owner-scoped` (TrueNegative): `GET /identity/api/v2/user/videos/{id}`
  resolves the video from the CALLER's own user id, so a non-owner gets HTTP 404.
  Looks cross-user-reachable (numeric id) but ownership IS enforced — the
  "correctly-blocked" decoy. Confirmed live: owner 200, attacker 404.
- `decoy-public-jwks` (TrueNegative): `GET /identity/api/auth/jwks.json` is
  intentionally public — the anonymous caller also succeeds, so the validator
  Rejects (public data, not cross-user BOLA — the DVGA public-paste pattern).
  Confirmed live: anonymous HTTP 200.

**Runner.** New `crates/baloncore-core/src/bench_crapi.rs` scorer + `baloncore
bench-crapi` CLI command. The command preflights Docker + Compose, brings the
stack up (`docker compose up -d`), then **waits for real stack readiness** by
polling the owner login until it returns a token (proves identity + seeded DB
are up, not merely that `compose up` returned) — a stack that never becomes
ready is an explicit error, never a fake pass. It logs in seed users, drives
owner/attacker/anonymous `GET`s through the real `BolaValidator`, and maps
Verified→`BrokenObjectLevelAuthorization` / Rejected→`BlockedAsExpected`. An
RAII `ComposeGuard` runs `docker compose down -v --remove-orphans` on EVERY exit
path (success, error, panic) — verified zero leftover containers after the run.
The scorer matches a probe to an observation on
`(endpoint, attacker_profile, object_id)` and never uses `expected_label`.

**Real measured result** (`cargo run -p baloncore -- bench-crapi`, live stack):
```
vuln-bola-vehicle-location      TruePositive  (Verified; evidence GUID + 32.778889 + adam007@example.com; anon 401)
decoy-user-video-owner-scoped   TrueNegative  (Rejected; attacker HTTP 404, ownership enforced)
decoy-public-jwks               TrueNegative  (Rejected; anonymous also succeeded → public)
```
Precision 100%, recall 100%, decoy false-positives 0/2.

**Tests added.**
- `bench_crapi.rs::tests` (9): happy path, FN when the BOLA is missed, both
  decoy-flagged→FalsePositive cases, **`match_key_includes_endpoint_and_object`**,
  missing-observation-is-FN, never-uses-expected-label, and the two CI-gate
  tests (gate FAILS on a decoy hit; PASSES on a clean run).
- `crates/baloncore-core/tests/bench_crapi_lab.rs` — end-to-end test bringing the
  real compose stack up via the CLI; asserts TP/TN/TN. Skips with a logged
  reason (NEEDS-HUMAN) when Docker/the stack is unavailable.

**Mutation check.** Collapsed the scorer's match key to `attacker_profile` only
(dropping the `endpoint` + `object_id` disambiguators) → `happy_path`,
`match_key_includes_endpoint_and_object`, and the clean-run gate test went RED:
both decoys then matched the vuln's `BrokenObjectLevelAuthorization` observation
and were scored false positives (`decoy false positives: 2`, precision 33.3%).
Restored from `/tmp/bench_crapi.rs.bak` → GREEN (9/9). Full suite: core 551 lib
green + crAPI integration green; CLI 25 green.

**V0 verdict change.** P2.S3 (≥5 vendored external targets): PARTIAL → **PARTIAL,
+3 REAL** (VAmPI + DVGA + crAPI). The runner now also proves the multi-service
discipline the directive required: full-stack readiness wait (no half-started
fake pass) and whole-stack teardown on every exit path. TerraGoat / Cfngoat
(static IaC, offline) remain queued on the same template.

---

## P2.S3 (corpus #4) — TerraGoat external target, real OFFLINE static-IaC scan + score

**Target.** `bridgecrewio/TerraGoat` — a static Terraform (HCL) corpus of
intentionally-misconfigured cloud resources. Fourth external corpus target, and
a DIFFERENT shape from the first three: no server, no Docker, no daemon, no
network at analysis time — pure `.tf` file parsing analyzed offline by
`analyze-cloud-iam`.

**Provenance, checked not assumed.**
- Repo exists; **License = Apache-2.0** (SPDX), read directly from the repo
  `LICENSE` file (the shortlist guessed "Apache-2.0, confirm"; now confirmed).
- Pinned commit `729f8da62c6a85ce4af5ad3d123de97776d954c4` (2023-04-27).

**Vendoring.** [`scripts/fetch_terragoat.sh`](scripts/fetch_terragoat.sh) git-
clones the pinned commit into the gitignored `.baloncore/corpus/terragoat/` and
re-verifies Apache-2.0. No Docker, no image pull — the NEEDS-HUMAN step is just
the git clone.

**New capability (the "cloud equivalent of the runner").** BALONCORE had no HCL
parser — the existing Terraform path ingests tfstate/plan JSON, and there is no
`terraform` binary on this host. So I built
`crates/baloncore-core/src/cloud_providers/terraform_hcl.rs`: an offline HCL
`.tf` → `IAMGraph` ingestor (via the `hcl` crate). It translates IaC facts into
graph nodes — `aws_iam_user`/`aws_iam_role` → principals; inline
`aws_iam_user_policy`/`aws_iam_role_policy` → policies parsed from the embedded
JSON and **linked to their principal** (the existing tfstate ingestor did NOT
link inline policies, so over-privileged findings never fired); `aws_security_group`
→ resource marked public iff an `ingress` rule allows `0.0.0.0/0`; `aws_s3_bucket`
→ marked public iff a public-read ACL. DETECTION stays in the real, unchanged
`IAMGraph::analyze()` (public exposure + over-privileged checks).

**Case files** under
[`benchmarks/cases/terragoat-iam/`](benchmarks/cases/terragoat-iam/):
`case.toml`, `scope.toml` (documents offline / no-network), `ground_truth.json`,
and `negative_controls.tf` (BALONCORE-authored correctly-configured decoys).
2 planted vulns (real TerraGoat resources) + **3** decoys:
- `vuln-open-security-group-web-node` (TruePositive): TerraGoat ec2.tf
  `aws_security_group.web-node` opens ports 22/80/all to `0.0.0.0/0`
  (Checkov CKV_AWS_24) → `PublicResourceExposure`.
- `vuln-overprivileged-user-policy` (TruePositive): TerraGoat iam.tf
  `aws_iam_user_policy.userpolicy` grants `ec2:*/s3:*/lambda:*/cloudwatch:*` on
  `Resource:*` → `OverPrivilegedPolicy`.
- `decoy-encrypted-private-logs-bucket` (TrueNegative): TerraGoat's `logs`
  bucket (private ACL + KMS encryption) — a real, correctly-configured resource.
- `decoy-least-privilege-policy` (TrueNegative): negative control — a scoped
  `s3:GetObject` policy on one ARN. **The credibility-critical cloud FP**:
  flagging a least-privilege policy as over-privileged.
- `decoy-internal-security-group` (TrueNegative): negative control — an SG whose
  only ingress is `10.0.0.0/8` (the open-SG vuln with the misconfig removed).

**Cloud scoring semantics (distinct from the HTTP scorers).** A static analysis
examines every resource, so "no finding for a resource" is a deliberate clean
verdict (`TrueNegative` for a decoy), NOT a "scan miss" `FalseNegative`. The
scorer (`bench_terragoat.rs`) encodes that confusion matrix and matches a finding
to a probe by `affected_resource`. It also surfaces `unmatched_findings`
(analyzer flags outside the curated ground truth) in run metadata so nothing is
silently hidden — observed count: 0.

**Real measured result** (`cargo run -p baloncore -- bench-terragoat`, offline):
```
vuln-open-security-group-web-node    TruePositive  (PublicResourceExposure)
vuln-overprivileged-user-policy      TruePositive  (OverPrivilegedPolicy)
decoy-encrypted-private-logs-bucket  TrueNegative  (not flagged)
decoy-least-privilege-policy         TrueNegative  (not flagged)
decoy-internal-security-group        TrueNegative  (not flagged)
```
Precision 100%, recall 100%, decoy false-positives 0/3, 0 stray findings.

**Tests added.**
- `cloud_providers::terraform_hcl::tests` (5): open-SG→public, private-SG→not,
  wildcard-inline-policy is linked + over-privileged, scoped-policy is NOT
  over-privileged, and an end-to-end `analyze()` that flags the two vulns and
  spares the two negative controls.
- `bench_terragoat.rs::tests` (9): happy path, FN when a vuln is missed, both
  decoy-flagged→FalsePositive cases, **`not_flagged_decoy_is_true_negative_not_false_negative`**
  (pins the cloud semantics), never-uses-expected-label, unmatched-findings
  surfaced, and the two CI-gate tests.
- `crates/baloncore-core/tests/bench_terragoat_lab.rs` — end-to-end offline test
  via the CLI; asserts 2×TP + 3×TN. Skips (NEEDS-HUMAN) when the corpus is not
  vendored.

**Mutation check.** Changed the cloud confusion-matrix rule
`(TrueNegative, flagged) => FalsePositive` to `=> TrueNegative` (i.e. flagging a
correctly-configured decoy no longer counts against precision) → both
decoy-FP tests and `ci_gate_fails_when_a_decoy_is_flagged` went RED. Restored
from `/tmp/bench_terragoat.rs.bak` → GREEN (9/9 scorer + 5/5 ingestor). Full
suite: core 565 lib + TerraGoat integration green; CLI 25 green.

**V0 verdict change.** P2.S3 (≥5 vendored external targets): PARTIAL → **PARTIAL,
+4 REAL** (VAmPI + DVGA + crAPI + TerraGoat). P2 cloud_iam vertical: the cloud
analyzer is now exercised end-to-end against a real external IaC corpus, offline,
with the decoy-FP rate (including a least-privilege negative control) measured at
0. New dependency: `hcl` (hcl-rs 0.19) added to baloncore-core for offline HCL
parsing. Cfngoat (static CloudFormation, offline) remains queued.

---

## P2.S3 (corpus #5) — Cfngoat external target, real OFFLINE CloudFormation scan + score

**Target.** `bridgecrewio/Cfngoat` — a static CloudFormation (YAML) corpus of
intentionally-misconfigured cloud resources. Fifth external corpus target; same
offline shape as TerraGoat but CloudFormation, not HCL.

**Provenance, checked not assumed — and a license finding.**
- Repo exists; pinned commit `0c09b69cfc3dbc6cb3ef01883415c35c588ced48`
  (2022-01-12).
- **License = NONE.** The Cfngoat repo has NO `LICENSE` file and the GitHub API
  reports `license: null`. The shortlist guessed "Apache-2.0, confirm" — that is
  WRONG. It is all-rights-reserved by default. Consequence:
  [`scripts/fetch_cfngoat.sh`](scripts/fetch_cfngoat.sh) is **fetch-only** — it
  clones into the gitignored `.baloncore/corpus/` at build time and the
  templates are NEVER committed to this repo (no redistribution). `case.toml`
  records `license = "NOASSERTION"` with the rationale, and the fetch script
  re-checks on each run that no license has appeared upstream. The only committed
  CloudFormation is our own negative-control template.

**Capability gaps closed (the "build it, don't fake around it" work).** The
shipped `cloud_providers::cloudformation` ingestor could NOT analyze real CFN
templates — three real gaps, all fixed (with regression tests):
1. **CFN short-form intrinsics.** `serde_yaml` errored ("invalid type: enum") on
   `!Ref`/`!Sub`/`!GetAtt`. Added `cfn_yaml_to_json`, which parses to
   `serde_yaml::Value` and collapses tagged nodes to canonical JSON
   (`!Ref X` → `{"Ref":"X"}`, etc.); literals (CidrIp, Action, Resource) pass
   through unchanged.
2. **Policy→principal linkage via `Users`/`Groups`.** `ingest_policy` linked only
   via `Roles`. Cfngoat's wildcard `excess_policy` attaches via `Users: [!Ref User]`,
   so the over-privileged finding never fired. Extended linkage to Roles + Users
   + Groups (name or `{Ref}` form).
3. **No security-group handler.** Added `ingest_security_group`, marking the SG
   public when an `ingress` rule allows `0.0.0.0/0` (or `::/0`).
Also added `ingest_files` to merge several templates (target + negative
controls) into one graph. Detection stays in the unchanged `IAMGraph::analyze()`.

**Case files** under
[`benchmarks/cases/cfngoat-iam/`](benchmarks/cases/cfngoat-iam/): `case.toml`
(license=NOASSERTION), `scope.toml` (offline / no-network), `ground_truth.json`,
and `negative_controls.yaml` (BALONCORE-authored decoys). 4 planted vulns (real
Cfngoat resources) + 2 decoys:
- `vuln-open-security-group-webnode` (TruePositive): `WebNodeSG` opens 0.0.0.0/0
  (CKV_AWS_24) → PublicResourceExposure.
- `vuln-overprivileged-user-policy` (TruePositive): `excess_policy`
  (ec2:*/s3:*/… on Resource:*, attached via Users) → OverPrivilegedPolicy.
- `vuln-overprivileged-lambda-execute` + `vuln-overprivileged-s3-object-delete`
  (TruePositive): the two inline policies on `CleanupRole` (logs:* / Resource:*)
  → OverPrivilegedPolicy.
- `decoy-least-privilege-policy` (TrueNegative): scoped s3:GetObject on one ARN —
  the credibility-critical over-privileged FP guard.
- `decoy-internal-security-group` (TrueNegative): SG ingress restricted to
  10.0.0.0/8.

**Real measured result** (`cargo run -p baloncore -- bench-cfngoat`, offline):
```
vuln-open-security-group-webnode      TruePositive  (PublicResourceExposure)
vuln-overprivileged-user-policy       TruePositive  (OverPrivilegedPolicy)
vuln-overprivileged-lambda-execute    TruePositive  (OverPrivilegedPolicy)
vuln-overprivileged-s3-object-delete  TruePositive  (OverPrivilegedPolicy)
decoy-least-privilege-policy          TrueNegative  (not flagged)
decoy-internal-security-group         TrueNegative  (not flagged)
```
Precision 100%, recall 100%, decoy false-positives 0/2, 0 stray findings.

**Tests added.**
- `cloud_providers::cloudformation::tests` (+3): intrinsics parse + open SG
  flagged; `Users`-attached wildcard policy linked + flagged; scoped policy +
  internal SG produce NO findings.
- `bench_cfngoat.rs::tests` (9): happy path (4 TP + 2 TN), FN when a vuln is
  missed, both decoy-flagged→FalsePositive, not-flagged-decoy-is-TN, never-uses-
  expected-label, unmatched-findings surfaced, and the two CI-gate tests.
- `crates/baloncore-core/tests/bench_cfngoat_lab.rs` — end-to-end offline test
  via the CLI; asserts 4×TP + 2×TN. Skips (NEEDS-HUMAN) when the corpus is not
  vendored.

**Mutation check.** Changed the cloud rule `(TrueNegative, flagged) =>
FalsePositive` to `=> TrueNegative` → both decoy-FP tests and
`ci_gate_fails_when_a_decoy_is_flagged` went RED. Restored from
`/tmp/bench_cfngoat.rs.bak` → GREEN (9/9 scorer + 7/7 ingestor). (The capability
fixes are independently guarded by the three new ingestor tests.) Full suite:
core 577 lib + Cfngoat integration green; CLI 25 green.

**V0 verdict change.** P2.S3 (≥5 vendored external targets): PARTIAL → **MET — 5
REAL** (VAmPI + DVGA + crAPI + TerraGoat + Cfngoat), spanning REST BOLA, GraphQL
auth bypass, multi-service BOLA, and offline IaC (Terraform HCL + CloudFormation).
The CloudFormation analyzer now actually parses real templates (intrinsics +
Users/Groups linkage + SG detection) — a real product capability gain, not just a
benchmark. Cfngoat's missing license is handled honestly: fetch-only, never
redistributed, recorded as NOASSERTION.

