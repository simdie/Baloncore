# BALONCORE Vulnerable API Lab

This local lab intentionally contains a broken object-level authorization bug.

Run it with:

```bash
node labs/vulnerable-api/server.js
```

Default URL:

```text
http://127.0.0.1:3000
```

Test bearer tokens:

- `lab-user-a-token`
- `lab-user-b-token`
- `lab-admin-token`

The vulnerable endpoint is:

```text
GET /api/invoices/:id
GET /api/admin/reports/:id
```

The safe seed endpoint is:

```text
GET /api/invoices
GET /api/admin/reports
```

Expected behavior:

- `user_b` owns `inv_2002`
- `user_a` should not be able to read `inv_2002`
- the lab deliberately returns `inv_2002` to `user_a`

BALONCORE live validation:

```bash
cargo run -p baloncore -- validate-lab-idor --base-url http://127.0.0.1:3000
```

OpenAPI-driven matrix validation:

```bash
cargo run -p baloncore -- scan-openapi-bola \
  --base-url http://127.0.0.1:3000 \
  --openapi-url http://127.0.0.1:3000/openapi.json \
  --owner-profile user_b
```

The matrix command discovers `user_b`'s owned invoice from `GET /api/invoices`
before testing configured peer profiles. To prove the planted BFLA, run the same
command with `--owner-profile admin`; low-privilege profiles can incorrectly read
`GET /api/admin/reports/:id`.
BALONCORE uses resource-aware seed matching, so invoice seeds are skipped for
admin report endpoints and admin report seeds are skipped for invoice endpoints.
Reports include response-shape similarity, sensitive-field categories, and
impact severity so planted BOLA/BFLA findings show business impact, not only
HTTP status differences.
OpenAPI matrix scans also write `openapi_coverage.json` and
`coverage_report.md`, showing tested, skipped, seed-only, and not-eligible
endpoints.
Use `configs/baloncore.suppression-demo.toml` to see how a documented approved
access pattern is suppressed without deleting the underlying evidence.
Each scan writes a `run_report.md` executive summary that ranks findings by
impact and shows skipped resource mismatches.
Repeated scans update `.baloncore/findings/index.json`, so the report can show
new versus recurring findings.
Verified matrix findings also include `remediation.json` and `remediation.md`
inside the profile proof folder, with fix guidance and regression curl checks
that should pass after the authorization bug is repaired.
Run the remediation checks directly with:

```bash
cargo run -p baloncore -- run-regression .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/remediation.json
```

The current intentionally vulnerable lab should report `StillFailing`; after a
real fix, the same command should report `Fixed`.
In CI, add `--ci` so `StillFailing` exits nonzero and fails the job:

```bash
cargo run -p baloncore -- run-regression .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/remediation.json --ci
```

Generate a starter GitHub Actions workflow with:

```bash
cargo run -p baloncore -- export-regression-ci .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/remediation.json
```

Seal and verify the evidence bundle with:

```bash
cargo run -p baloncore -- seal-evidence .baloncore/runs/<run-id>/candidate-002-seed-001/user_a
cargo run -p baloncore -- verify-evidence .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/evidence_manifest.json
```

Sign the bundle with a local BALONCORE Ed25519 key:

```bash
cargo run -p baloncore -- init-signing-key
cargo run -p baloncore -- sign-evidence .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/evidence_manifest.json
cargo run -p baloncore -- trust-evidence-signer .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/evidence_signature.json
cargo run -p baloncore -- verify-evidence .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/evidence_manifest.json --require-signature
cargo run -p baloncore -- verify-evidence .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/evidence_manifest.json --trusted-only
cargo run -p baloncore -- verify-evidence-run .baloncore/runs/<run-id> --trusted-only --ci
```

Use `--out-dir <path>` to choose where evidence is written.

Full Stage 1 end-to-end run (scan, regression, signed/trusted evidence gates):

```bash
./scripts/stage1_e2e_demo.sh
./scripts/stage1_e2e_demo.sh --json
./scripts/stage1_e2e_demo.sh --fail-on-regression
```

The script defaults to `http://127.0.0.1:31337` to avoid conflicts with other
local services running on port 3000.
