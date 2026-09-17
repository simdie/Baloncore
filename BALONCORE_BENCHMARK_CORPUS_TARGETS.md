# BALONCORE Benchmark Corpus — Verified Target Shortlist (for P2.S3)

Status as verified May 2026. Each entry lists the canonical repo, how it runs,
license status, and how it maps to a BALONCORE vertical. **The coding agent must
still open each LICENSE file and confirm before vendoring** — licenses can change
between this list and build time. Entries marked "CONFIRM" are the ones I could
not verify to the exact SPDX line and you should check first.

Two corrections vs. earlier drafts, both important:
- Damn Vulnerable DeFi's canonical repo MOVED from `tinchoabbate/...` to
  `theredguild/damn-vulnerable-defi`. Point Web3 cases at theredguild.
- The cloud vertical should use STATIC IaC corpora analyzed offline by
  `analyze-cloud-iam`, NOT live-deployed CloudGoat/AWSGoat. Live AWS targets cost
  money, need an AWS account, and break "a stranger can reproduce it." Feed the
  Terraform/CloudFormation/IAM-JSON files directly.

================================================================================
## Web / REST API authorization (P4's primary vertical, P2 web_api cases)
================================================================================

### crAPI — OWASP/crAPI
- Repo: https://github.com/OWASP/crAPI
- Runs: Docker Compose (microservices). Vulnerable by design; OWASP API Top 10.
- License: OWASP project — CONFIRM (expected Apache-2.0); check repo LICENSE.
- Why: real-world-style BOLA (GUID vehicle IDs), BFLA, JWT forgery, mass
  assignment, excessive data exposure. Strong flagship-finding material.
- Ground truth: OWASP publishes a challenges doc enumerating the planted bugs —
  use it to author ground_truth.json precisely.

### VAmPI — erev0s/VAmPI  (best false-positive / decoy source)
- Repo: https://github.com/erev0s/VAmPI
- Runs: `docker run -e vulnerable=1 -p 5000:5000 erev0s/vampi:latest`
- License: CONFIRM (repo has a LICENSE file; commonly GPL-3.0).
- Why it is special for P2: a global **vulnerable on/off switch**
  (`-e vulnerable=0` vs `1`). Run the SECURE build as your decoy/negative set and
  the VULNERABLE build as your positive set against the SAME endpoints. This is
  the cleanest possible way to measure false-positive rate — the same target,
  bugs toggled off, must produce ZERO findings. Ships OpenAPI3 + Postman.
- Documented bug set: SQLi, unauthorized password change, BOLA, mass assignment,
  debug-endpoint data exposure, user/password enumeration, RegexDoS, missing rate
  limiting, JWT weak-key bypass.

### vAPI — roottusk/vapi  (optional second REST case)
- Repo: https://github.com/roottusk/vapi
- Runs: Docker (PHP). OWASP API Top 10 as exercises. Postman collection provided.
- License: CONFIRM. Use as breadth if you want a second, different REST stack.

================================================================================
## GraphQL (P4.S2 GraphQL parity, P2 graphql cases)
================================================================================

### DVGA — dolevf/Damn-Vulnerable-GraphQL-Application
- Repo: https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application
- Runs: Docker; browse at http://localhost:5013.
- License: **MIT (verified in repo README).**
- Why: introspection on, injection, DoS, auth bypass, batching abuse. Has
  Beginner/Expert modes — use Expert as harder positives, and label benign
  operations as decoys. Public Postman collection to script repro.

================================================================================
## Web3 / smart contracts (P2 web3 cases, Stage 7 module)
================================================================================

### Damn Vulnerable DeFi — theredguild/damn-vulnerable-defi  (moved repo)
- Repo: https://github.com/theredguild/damn-vulnerable-defi
  (the old tinchoabbate URL now redirects here)
- Runs: Foundry-native (v3/v4). `forge test` per challenge.
- License: CONFIRM on the LICENSE file before vendoring (historically permissive;
  do not assume).
- Why: canonical DeFi exploit set — accounting desync, flash-loan abuse, reentrancy,
  oracle/price manipulation, access control. Maps directly to your invariant
  generator + Foundry proof-test generator. Each challenge has a known solution =
  ground truth; add benign contracts as decoys.
- Note: pin a specific version tag (e.g. v4.x) in case.toml so scores are stable.

### Your existing labs/vulnerable-protocol
- Keep as a small, fully-controlled case where YOU authored the planted bug and
  its decoys — useful as a determinism anchor.

================================================================================
## Cloud / IAM — STATIC IaC ONLY (P2 cloud_iam cases, Stage 6 module)
================================================================================

These feed `analyze-cloud-iam` as files. Do NOT deploy to AWS. This keeps the
benchmark offline, free, and reproducible.

### TerraGoat — bridgecrewio/terragoat  (primary cloud case)
- Repo: https://github.com/bridgecrewio/terragoat
- Use: vendor the Terraform (.tf) files; analyze offline. Intentionally
  misconfigured AWS/Azure/GCP resources (public storage, weak IAM, missing
  encryption, open security groups).
- License: **Apache-2.0 (Bridgecrew/Prisma org standard; confirm on LICENSE).**
- Why: dense, well-labeled misconfig set; Checkov maps each finding to a rule ID
  you can reuse for ground truth.

### Cfngoat — bridgecrewio/cfngoat  (CloudFormation parser path)
- Repo: https://github.com/bridgecrewio/cfngoat
- Use: vendor the CloudFormation templates; exercise your CloudFormation provider.
- License: Apache-2.0 expected — CONFIRM.

### IAM Vulnerable — BishopFox/iam-vulnerable  (privilege-escalation paths)
- Repo: https://github.com/BishopFox/iam-vulnerable
- Use: it deploys ~250 IAM resources and ~31 privesc paths via Terraform. For the
  OFFLINE benchmark, vendor the Terraform/IAM JSON and the documented privesc
  paths as ground truth for your IAM graph's principal→permission reachability —
  do not deploy.
- License: CONFIRM.

### CloudGoat extracts — RhinoSecurityLabs/cloudgoat  (optional)
- Repo: https://github.com/RhinoSecurityLabs/cloudgoat
- Use: ONLY the static `terraform/*.tf` and `policy.json` files as additional IAM
  graph fixtures. The full tool deploys live AWS (costs money) — skip that.
- License: CONFIRM.

### Your existing labs/cloud-iam/aws-risky.json
- Keep as a controlled, self-authored cloud case with known answer + decoys.

================================================================================
## Agent verification checklist before vendoring each target
================================================================================

For every case, the agent must confirm and record in case.toml:
1. Repo still exists at the URL and is not archived; pin a commit/tag hash.
2. Open the LICENSE file; record the SPDX id; confirm it permits redistribution
   OR vendor via a fetch script (download at build time) instead of copying.
3. Confirm the run method works (docker pull / forge build / file parse) in a
   clean environment.
4. Author ground_truth.json from the project's own documented bug list, AND add
   >=2 realistic decoys per case (for VAmPI/DVGA, use the secure mode / benign
   operations as decoys).
5. Record source_url, version/commit, and license in case.toml for reproducibility.

## Coverage summary
- Web/API: crAPI (flagship), VAmPI (decoy engine via on/off switch), vAPI (breadth)
- GraphQL: DVGA (MIT, verified)
- Web3: Damn Vulnerable DeFi @ theredguild (Foundry) + your protocol lab
- Cloud (offline IaC): TerraGoat (primary), Cfngoat, IAM Vulnerable, CloudGoat
  static extracts, + your aws-risky.json
This gives the benchmark at least 2 independent targets per vertical, with VAmPI
and DVGA providing clean toggle/mode-based negatives so your false-positive rate
is measured honestly — which is the number that separates BALONCORE from a noisy
scanner.