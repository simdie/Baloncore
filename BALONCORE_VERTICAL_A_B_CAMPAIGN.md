# BALONCORE — Vertical A & B Capability Campaign (proof-gated, one class per session)

This is a long, ordered build campaign to take BALONCORE from "proves authorization
bugs" to "deep finder across Vertical A (web / web-app / API / GraphQL) and Vertical
B (web3 / smart contracts / DeFi)." It is NOT a do-it-all-now dump. Each session is
one focused build for Claude Code / Codex. Run them in order; do not start a session
until the previous one's proof gate is green.

## The proof gate (applies to EVERY session — this is the whole method)

A vuln-class finder is only DONE when ALL of these hold:
1. It does ACTIVE work and PROVES the finding with a deterministic signal — not
   "the payload reflected," but an actual proof (out-of-band callback, boolean/time
   differential, forged-token access, before/after state change). The model may
   PROPOSE; only the deterministic validator may mark Verified + seal evidence.
   (Same validator-firewall as web_api.rs's BolaValidator. Never shortcut it.)
2. It is proven on a REAL external benchmark target (from the corpus you're
   building) — it catches the planted bug.
3. It has held-out DECOYS that it must NOT flag (the false-positive measure).
4. It has a scorer test with a MUTATION CHECK (break the finder → test red →
   restore → green), logged in PROGRESS.md.
5. Low false positives win over coverage. A class that can't be made
   low-false-positive is marked NEEDS-WORK, not shipped.

Two invariants, unchanged: authorized scope only; model proposes, validator proves.

Grounding (verified in repo): finders live alongside web_api.rs (BolaValidator,
GraphQlBolaValidator, AuthorizationMatrixObservation, HttpRequestRunner) and
web3.rs / web3_parsers.rs. Active scans follow the bench_vampi.rs / bench_crapi.rs /
bench_dvga.rs runner pattern. Discovery/crawl scaffolding is in discovery.rs.
Evidence/lifecycle/proof in evidence.rs, lifecycle.rs, proof.rs.

================================================================================
# VERTICAL A — web / web-app / API / GraphQL (deep)
================================================================================

Current state: authorization family (BOLA, BFLA, tenant isolation, missing auth)
is REAL and proven on VAmPI/DVGA/crAPI. Everything below is new capability.

## A0 — Active-finding foundation: the Finder trait + out-of-band collaborator

```text
Read first: web_api.rs (BolaValidator, HttpRequestRunner, the Verified/Rejected
decision shape), bench_crapi.rs (runner pattern), evidence.rs, finding.rs.

Build the shared substrate every new finder needs, WITHOUT adding a vuln class yet:
- Define an ActiveFinder trait: given a target endpoint + auth profiles + a probe
  budget, it sends crafted requests via HttpRequestRunner and returns
  Verified(proof) | Rejected(reason) | Inconclusive — mirroring BolaValidator's
  contract so the firewall and evidence sealing work unchanged.
- Build an out-of-band (OOB) interaction collaborator: a small local HTTP/DNS
  sink BALONCORE controls, so finders that need to prove the SERVER reached an
  attacker-controlled destination (SSRF, blind injection, blind XXE) have a
  deterministic proof signal. Localhost-only by default; configurable host for
  authorized remote use. Record every interaction as evidence.
- A "differential prober" helper: send a control request and a test request,
  compare status/body/timing with stable thresholds, for boolean/time-based proofs.
- Per-probe and per-scan budgets (reuse the ModelBudget pattern); scope guard on
  every outbound request (never leave authorized scope, never hit the OOB sink
  from outside scope).

Acceptance: trait + OOB sink + differential prober compile and have unit tests
(OOB sink records a callback; differential prober flags a planted difference and
ignores noise). No vuln class yet. Mutation-check the differential threshold.
Verify: cargo fmt --check; cargo test.
```

## A1 — JWT / auth-token flaws (closest to what you've already exploited)

```text
You already exploited verify_signature=False in DVGA. Generalize it into a finder.

Build a JwtAuthFinder (ActiveFinder): given a valid token + a protected endpoint,
it attempts, each as a separate proof:
- unsigned / alg=none acceptance,
- signature stripped / not verified,
- weak-secret HMAC brute (small wordlist, bounded),
- alg confusion (RS256->HS256 with public key as secret) where a key is available,
- claim tampering (escalate identity/role) then re-access.
PROOF = the forged/tampered token successfully accesses a resource the original
identity could not (deterministic: 200 + owner/other-identity marker, vs the
control 401/403). Seal request/response evidence with the token redacted.

Prove on: DVGA (the verify_signature=False bug) AND VAmPI (its JWT weak-key bypass).
Decoys: a correctly-signed endpoint that rejects the forged token (must NOT flag),
and a public endpoint (anonymous also works → not an auth bypass).

Acceptance: real Verified on both targets; both decoys Rejected; mutation-check
(disable the forged-token-access guard → false positive → test red → restore).
Verify: cargo fmt --check; cargo test; bench run vs DVGA + VAmPI.
```

## A2 — Mass assignment / excessive data exposure

```text
Build a MassAssignmentFinder + ExcessiveDataFinder (ActiveFinder).
- Mass assignment: send extra/privileged fields (role, is_admin, owner_id,
  balance, verified) on create/update; PROOF = re-read the object and confirm the
  privileged field was actually written (before/after state diff), OR the response
  reflects an escalation. Not "the field was accepted" — the field must have TAKEN
  EFFECT.
- Excessive data exposure: compare the response to the documented/owner-scoped
  shape; PROOF = sensitive fields present that the principal should not receive
  (reuse SensitiveFieldFinding from web_api.rs).

Prove on: crAPI (mass-assignment challenge) and VAmPI (debug/data-exposure).
Decoys: an update where the privileged field is correctly ignored (re-read shows
no change → must NOT flag); a response whose extra fields are non-sensitive.

Acceptance: Verified on the planted bugs; decoys Rejected; mutation-check the
before/after diff (remove the re-read confirmation → accepted-but-not-effective
falsely flags → red → restore).
Verify: cargo fmt --check; cargo test; bench vs crAPI + VAmPI.
```

## A3 — SSRF (needs the A0 OOB collaborator)

```text
Build an SsrfFinder (ActiveFinder). For each parameter that takes a URL/host/file
ref, inject a reference to the A0 OOB sink. PROOF = the OOB sink records an inbound
request correlated to the probe (the SERVER fetched attacker-controlled URL). Cover
direct (response reflects fetched content) and BLIND (only the OOB callback proves
it). Bounded redirect/scheme set; never target anything outside the OOB sink and
authorized scope.

Prove on: crAPI (its SSRF challenge) — and add a tiny self-authored SSRF lab if
crAPI's variant isn't OOB-observable.
Decoys: a parameter that fetches but only allow-listed internal hosts (no OOB
callback → must NOT flag); a parameter that echoes the URL string without fetching.

Acceptance: Verified via a real OOB callback; decoys Rejected; mutation-check
(treat "URL reflected in response" as proof instead of requiring the callback →
the echo decoy falsely flags → red → restore the callback-required guard).
Verify: cargo fmt --check; cargo test; bench vs crAPI.
```

## A4 — Injection family: SQL / NoSQL (the hardest for false positives — go slow)

```text
Build an InjectionFinder (ActiveFinder) for SQLi + NoSQLi. PROOF must be one of:
- boolean-based differential (true-condition vs false-condition responses differ
  consistently across repeats),
- time-based (injected sleep measurably and repeatably delays the response vs a
  control, with a margin that survives jitter),
- out-of-band (A0 sink) for blind cases.
NEVER flag on error strings or reflection alone — those are the classic false
positives this finder must avoid. Require the proof to REPRODUCE (run it twice).

Prove on: VAmPI (its SQLi) and crAPI (NoSQLi where present).
Decoys: an input that returns a DB error but is NOT injectable (error-based false
positive — must NOT flag); a slow endpoint that is slow for everyone (time-based
false positive — must NOT flag).

Acceptance: Verified via reproduced boolean/time/OOB proof; both classic-FP decoys
Rejected; mutation-check (drop the reproduce-twice requirement → flaky FP → red →
restore). This is the class most likely to need NEEDS-WORK iterations — that's fine.
Verify: cargo fmt --check; cargo test; bench vs VAmPI + crAPI.
```

## A5 — Business-logic abuse (broaden beyond the one StateSkip case)

```text
Read first: business_logic.rs (the existing validator + the one wired StateSkip).
Add active scanners (not just library validators) for: price/quantity tamper
(client-supplied amount honored server-side — PROOF: order/charge created at the
tampered value, confirmed by re-read), workflow state-skip (already have one;
generalize), one-time-action replay (PROOF: double effect), and limit/quota bypass.
Drive each through the real runner against the SaaS lab + crAPI workflows.

Prove on: labs/vulnerable-saas (extend) + crAPI (coupon/order flows).
Decoys: a workflow that correctly rejects the tamper/replay (must NOT flag).

Acceptance: at least 3 logic abuses Verified with before/after evidence; decoys
Rejected; mutation-check the state-diff confirmation.
Verify: cargo fmt --check; cargo test; bench runs.
```

## A6 — Remaining web surface: file upload, CORS, open redirect, SSTI, path traversal

```text
Add finders for the medium-effort remaining classes, each with a deterministic
proof and decoys, in this priority order (do as separate sub-sessions, each its
own proof gate — do NOT batch them into one unproven blob):
- unrestricted file upload (PROOF: uploaded file becomes retrievable/executable),
- CORS misconfig (PROOF: cross-origin credentialed read succeeds with reflected
  origin — not just a permissive header present),
- open redirect (PROOF: redirect to attacker host honored),
- SSTI (PROOF: template expression evaluated, e.g. arithmetic rendered),
- path traversal / LFI (PROOF: out-of-scope file content retrieved, via A0 markers).
Each: real target where available (vAPI/crAPI/self-authored mini-lab), >=1 decoy,
mutation-check.

Acceptance: each sub-class Verified on a real or planted target with decoys held
out; anything that can't hit low-FP is logged NEEDS-WORK, not shipped green.
Verify: cargo fmt --check; cargo test per sub-class.
```

## A7 — Autonomous attack-surface discovery (what makes it XBOW-like, not point-and-shoot)

```text
Read first: discovery.rs. Today scans start from an OpenAPI/GraphQL spec. To hunt
real targets you must find your own surface.
Build: authenticated crawling (follow links/forms/XHR as each auth profile, within
scope), endpoint + parameter inventory from observed traffic (not just the spec),
auth-state mapping (which routes each role reaches), and feeding the discovered
surface into the A1-A6 finders automatically. Strict scope + rate limits + a
crawl budget; never wander off the authorized host.

Prove on: crAPI (crawl it WITHOUT giving the spec; confirm the crawler rediscovers
the vehicle-location BOLA surface that the spec-driven scan found).
Acceptance: crawler-discovered surface >= spec-driven surface on crAPI for the
known bug; scope never violated (test); mutation-check the scope guard.
Verify: cargo fmt --check; cargo test; crawl-driven bench vs crAPI.
```

## A8 — Vertical A consolidation + benchmark

```text
Add an aggregate web/API scan command that runs ALL Vertical A finders against a
target, dedupes, ranks by impact, and produces one report. Extend the benchmark to
score the FULL class set (authz + A1-A6) across VAmPI + crAPI + DVGA, with the
decoys from every class held out. Produce the Vertical-A leaderboard.
Acceptance: one command finds the full proven class set on the corpus; aggregate
precision/recall/decoy-FP reported; determinism locked on the fixture path.
Verify: full Vertical-A bench run; leaderboard generated.
```

================================================================================
# VERTICAL B — web3 / smart contracts / DeFi (deep)
================================================================================

Current state: web3.rs / web3_parsers.rs are parser-grade (Solidity parse + Slither
ingest + optional forge shell-out), classed FIXTURE in V0, NOT proven, NOT in the
benchmark. This vertical is harder than A: the proof is an EXECUTED EXPLOIT, not a
status code, and it needs real DeFi domain modeling. Budget B as the larger track.

## B0 — Real execution harness + Damn Vulnerable DeFi as the proof gate (do this FIRST)

```text
Read first: web3.rs, web3_parsers.rs, bench_crapi.rs (runner discipline:
spawn → exercise → score → teardown), the corpus targets file (Damn Vulnerable
DeFi @ theredguild, Foundry-native).

Before ANY new web3 analysis, build the execution + proof substrate:
- A Foundry execution harness: given a contract project + a written exploit/
  invariant test, run `forge test` and capture pass/fail + traces deterministically
  in a sandbox. This is web3's equivalent of HttpRequestRunner: it EXECUTES and
  the result is the proof.
- Vendor Damn Vulnerable DeFi (theredguild/damn-vulnerable-defi): pin a commit,
  CONFIRM the LICENSE (record SPDX in case.toml — confirm, don't assume),
  fetch script into the gitignored corpus dir.
- Wire ONE DVD challenge end-to-end as the first proof: BALONCORE produces (or is
  given) the invariant/exploit, runs it via the harness, and PROVES the exploit
  succeeds (the challenge's success condition is met) — sealed as web3 evidence
  in the same finding/lifecycle shape as web/API findings.
- A benign/patched contract as the DECOY: the same harness run must NOT report an
  exploit when the bug is fixed.

Acceptance: one DVD challenge Verified by REAL forge execution; patched decoy
Rejected; scorer test + mutation-check (make the harness report success on a
failing forge run → red → restore). web3 moves from FIXTURE to REAL for one class.
Verify: cargo fmt --check; cargo test; forge available (else explicit NEEDS-HUMAN,
never a fake pass); DVD bench run.
```

## B1 — Access-control / privileged-function exploits

```text
Build the finder for missing/incorrect access control on state-changing functions
(unprotected initialize, owner-only bypass, missing modifier). PROOF = a forge test
where a non-owner account executes a privileged action and the harness confirms the
state change (B0 harness). Generate the exploit test from the parsed contract +
model proposal; the EXECUTION is the proof.
Prove on: the relevant DVD challenge(s) + a self-authored minimal vulnerable
contract. Decoy: a correctly-guarded function (revert → not exploitable).
Acceptance: Verified by execution; decoy Rejected; mutation-check.
Verify: cargo fmt --check; cargo test; DVD bench.
```

## B2 — Reentrancy

```text
Finder for classic + cross-function + read-only reentrancy. PROOF = an executed
forge exploit with a malicious receiver that re-enters and the harness confirms
funds drained / invariant broken. Decoy: a checks-effects-interactions or
nonReentrant-guarded contract (exploit reverts → not flagged).
Prove on: the DVD reentrancy challenge + minimal lab. Mutation-check (count a
reverting exploit as success → red → restore).
Verify: cargo fmt --check; cargo test; DVD bench.
```

## B3 — Accounting / invariant violations (the DeFi core — domain-heavy)

```text
This is the heart of DeFi auditing and the hardest part. Build an invariant engine
that generates and EXECUTES property tests (Foundry invariant tests / Echidna /
Medusa) for accounting properties: total assets never decrease except via
authorized withdrawals; user can't withdraw more than their share; no bad-debt
creation; supply/balance conservation. PROOF = a fuzzing run finds a sequence that
breaks the invariant, reproduced as a concrete failing test.
- Integrate Echidna or Medusa (shell-out, like forge) for property fuzzing; capture
  the counterexample sequence as evidence.
Prove on: DVD challenges that hinge on accounting (e.g. the lending/pool ones) +
a minimal lab with a known accounting bug. Decoy: a contract whose invariant holds
under fuzzing (no counterexample → not flagged).
Acceptance: at least one accounting invariant violation found BY FUZZING and
reproduced; decoy holds; mutation-check (accept a non-reproducing counterexample →
red → restore the reproduce requirement).
Verify: cargo fmt --check; cargo test; echidna/medusa available else NEEDS-HUMAN;
DVD bench.
```

## B4 — Oracle / price manipulation & flash-loan abuse

```text
Finder for spot-price oracle reliance and flash-loan-amplified manipulation. PROOF
= an executed exploit (forge) that takes a flash loan, moves a manipulable price
source, and extracts value / breaks an invariant, with the harness confirming the
profit/violation. Decoy: a contract using a manipulation-resistant oracle (TWAP /
Chainlink) where the same exploit fails to profit.
Prove on: the DVD oracle/flash-loan challenges. Mutation-check the profit
confirmation.
Verify: cargo fmt --check; cargo test; DVD bench.
```

## B5 — Signature / replay & upgrade-path flaws

```text
Two finders:
- signature replay / malleability / missing-nonce / cross-chain replay (PROOF: a
  forge test reuses/forges a signature to perform an unauthorized action),
- upgradeability flaws (unprotected upgrade, uninitialized proxy, storage-collision)
  (PROOF: a test hijacks the implementation or corrupts storage).
Prove on: DVD challenges where applicable + minimal labs. Decoys: nonce-protected
signatures; correctly-guarded proxies. Mutation-check each.
Verify: cargo fmt --check; cargo test; DVD bench.
```

## B6 — Static + symbolic assist (raise recall without raising false positives)

```text
Now (not before — execution proof comes first) integrate static/symbolic tools as
HYPOTHESIS GENERATORS feeding the B1-B5 executable proofs: Slither (you have ingest),
and optionally a symbolic tool (Mythril/halmos) to PROPOSE candidate vulns. Critical:
a static/symbolic hit is a HYPOTHESIS only — it must be confirmed by an executed
exploit/invariant (B0 harness) before it becomes Verified. This keeps the firewall
intact and false positives down (static tools are noisy).
Acceptance: a Slither/symbolic-proposed bug is promoted ONLY after execution proof;
a static false-positive (flagged statically, not exploitable) is Rejected by the
executor. Mutation-check (let a static hit auto-verify → the static-FP decoy falsely
flags → red → restore the execution-required gate).
Verify: cargo fmt --check; cargo test; DVD bench.
```

## B7 — Vertical B consolidation + benchmark

```text
Aggregate web3 scan command running all B finders on a contract project; dedupe,
rank by recovered value / severity, produce a report with the reproducible exploit
test as the evidence centerpiece. Extend the benchmark to score the full B class
set across the DVD challenge suite + minimal labs, decoys held out. Vertical-B
leaderboard.
Acceptance: one command runs the full proven B set on DVD; aggregate
precision/recall/decoy-FP; the report's exploit tests actually re-run green.
Verify: full Vertical-B bench; leaderboard generated.
```

================================================================================
# Campaign rules & honest sequencing
================================================================================

- Order: finish your in-flight corpus first (it hardens the harness you reuse).
  Then A0 → A1 → ... → A8. Then B0 → B1 → ... → B7. B0 (execution harness + DVD
  proof gate) is mandatory before any other B work — without it web3 stays fixture.
- One session at a time. Do NOT let the agent batch classes. Each class passes its
  proof gate (real target + decoys + mutation check) before the next starts.
- YOU personally run the mutation check for at least the firewall-adjacent classes
  (A1, A4, B0, B3, B6) — break it, see red, restore, green.
- Get ONE real authorized bug-bounty finding using the BOLA capability you ALREADY
  have, early in the A campaign — do not wait for A8. That real finding teaches you
  more than any lab class and is the proof that funds the project.
- A4 (injection) and B3 (accounting invariants) are the hardest; expect multiple
  NEEDS-WORK iterations. Low false positives beat coverage every time — a class
  that floods false positives is worse than not having it.
- Nothing is "done" because it compiles or a test is green. It is done when it
  PROVES a real bug on a real external target and stays quiet on the decoys.
```