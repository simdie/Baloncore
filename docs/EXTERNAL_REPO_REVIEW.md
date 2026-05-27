# External Security Repo Review

## Purpose

This document records the review of public security projects and how their strongest ideas influenced BALONCORE.

Reviewed sources:

- `https://xbow.com/`
- `https://github.com/xbow-security`
- `https://x.com/RoundtableSpace/status/2057797373108122090`
- `https://github.com/forrestchang/andrej-karpathy-skills`
- `https://github.com/multica-ai/andrej-karpathy-skills`
- `https://github.com/elementalsouls/Claude-BugHunter`
- `https://github.com/shuvonsec/claude-bug-bounty`
- `https://github.com/0xSteph/pentest-ai-agents`
- `https://github.com/nullthrix/BugBounty-Methodology`
- `https://github.com/zakirkun/deep-eye`
- `https://github.com/vercel-labs/deepsec`
- `https://github.com/xdavidhu/awesome-google-vrp-writeups`

No source code was copied into BALONCORE. The import was conceptual and architectural.

The `RoundtableSpace` X post was not directly readable from the public web
session because X returned an inaccessible page. The related GitHub repositories
and public mirrors were reviewed directly.

## XBOW

Useful product signals:

- autonomous offensive security should still produce reproducible proof
- depth matters more than scanner breadth
- findings should be independently validated before customers see them
- human security teams should get leverage, not be replaced

BALONCORE impact:

- keep "proof before report" as the product promise
- keep deterministic validators as the center of the platform
- prioritize exploit-validated paths over theoretical warnings

## Claude-BugHunter

Useful ideas:

- skill-based vulnerability knowledge organized by bug class
- triage gates before reporting
- evidence hygiene and PII redaction discipline
- enterprise identity and cloud attack-chain matrices
- platform-ready reports for HackerOne, Bugcrowd, Intigriti, and Immunefi
- two-interface design: AI skill layer plus deterministic CLI helper
- engagement loop: scope, recon, hunt, validate, capture, report, remember
- validation outcomes: pass, downgrade, chain required, kill
- memory commands for resuming previous engagements and learning from patterns

BALONCORE imports:

- added `triage` agent spec
- added `evidence-hygiene` agent spec
- added triage gate primitives in Rust
- added redaction-aware evidence metadata
- added local workbench authorization gate before active scans
- added local repo inventory with redacted secret detection
- added artifact discovery so evidence, reports, and command logs remain visible
- kept the "kill false positives before reporting" rule as a product standard

## Karpathy-Inspired Skills

Useful ideas from `forrestchang/multica-ai/andrej-karpathy-skills`:

- think before coding and surface assumptions
- prefer simple, scoped implementation over speculative architecture
- avoid unrelated edits and drive-by refactors
- define success criteria and loop until verified
- package repeatable operating discipline as reusable skills

BALONCORE imports:

- added `docs/BUILD_RIGOR.md` to define what Stage-1-level rigor means
- updated the build rhythm: strategy and quality bar live in durable docs, while
  implementation continues as verifiable build steps
- added local workbench tests so the new product surface has an explicit success
  criterion, not just a visual shell
- reinforced "AI proposes, deterministic validators prove" as the product rule

## shuvonsec/claude-bug-bounty

Useful ideas:

- clear command surface for recon, report, scope, triage, autopilot, cloud recon, CI/CD scan
- separation between skills, agents, rules, tools, reports, and memory
- recon ranker and autonomous hunt loop concepts

BALONCORE impact:

- future CLI should expose clear verbs for recon, validate, report, triage, scope, and autopilot
- Stage 8 should include autonomous loop memory and target ranking

## pentest-ai-agents

Useful ideas:

- shared scope-guard prompt for execution-capable agents
- command noise levels: quiet, moderate, loud
- dual offensive and defensive output
- PoC validation agent that kills false positives
- detection engineer that turns attack behavior into SIEM and monitoring content

BALONCORE imports:

- added `detection-engineer` agent spec
- roadmap now tracks OPSEC/noise tagging and detection output
- safety model should add noise-level tracking before active testing

## BugBounty-Methodology

Useful ideas:

- classic recon playbooks and target expansion workflow
- tool checklists for subdomains, URLs, DNS, and content discovery
- practical bug bounty repetition loops

BALONCORE impact:

- useful as historical methodology input, but not imported directly
- recon module should support repeatable playbooks instead of one-off scans

## Deep Eye

Useful ideas:

- configuration-driven scanning
- plugin system for custom scanners
- multi-provider AI abstraction
- HTML/PDF/JSON reporting
- notification hooks

BALONCORE impact:

- plugin architecture stays on the roadmap
- reporting should support multiple output formats
- config-first runs should be reproducible

## DeepSec

Useful ideas:

- resumable stages: scan, process, revalidate, enrich, export
- append-only data records
- fast matcher stage before expensive AI processing
- custom matchers for organization-specific patterns
- revalidation as a first-class false-positive reducer
- diff/PR mode for CI
- cost and usage tracking

BALONCORE imports:

- added matcher/candidate primitives
- added append-only pipeline event primitives
- roadmap updated for candidate discovery, AI processing, revalidation, enrichment, export, and metrics

## awesome-google-vrp-writeups

Useful ideas:

- writeup corpora are a pattern source for real vulnerability classes
- cloud, OAuth, IDOR, SSRF, XSS, URL parsing, CI/CD, and service-account chains recur over time
- successful reports usually show a concrete chain from primitive to real impact

BALONCORE impact:

- future research corpus should classify public writeups by root cause, impact, prerequisites, proof shape, and defense
- attack-chain rules should be learned from validated writeups, not invented ad hoc

## Selected BALONCORE Feature Imports

- Triage gate before validation/reporting
- Evidence hygiene and redaction states
- Matcher/candidate model before expensive AI processing
- Append-only scan pipeline and run history
- Detection engineering output after verified findings
- Noise-level and OPSEC tracking for active commands
- Autopilot loop memory and recon ranking
- Writeup-derived attack-pattern corpus

## Deliberately Not Imported

- destructive exploitation guidance
- stealth/evasion as a product feature
- C2/post-exploitation workflows
- mass public-internet scanning
- code copied from third-party repositories

## Decision

BALONCORE should learn from the ecosystem without becoming a clone of any one project.

The product direction remains:

```text
Find candidates cheaply.
Use AI to reason deeply.
Validate deterministically.
Preserve clean evidence.
Generate defense.
Track everything append-only.
```
