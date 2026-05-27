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

