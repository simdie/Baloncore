# BALONCORE Roadmap

## Purpose

BALONCORE is an AI-native security validation platform designed to help authorized teams find, prove, explain, and defend against real vulnerabilities across web, API, cloud, infrastructure, and Web3 systems.

The long-term goal is to build toward an XBOW-like class of product:

- autonomous or semi-autonomous security research
- agent-driven reconnaissance and hypothesis generation
- deterministic validation before reporting
- evidence-backed findings
- defensive guidance after proof
- company-grade SaaS and enterprise workflows

The operating principle is:

```text
AI proposes.
Validators prove or reject.
Evidence becomes the product.
Defense closes the loop.
```

BALONCORE must never become a tool that simply says "this might be vulnerable." The product must aim to prove what is real, reject weak hypotheses, and produce clear evidence that engineers, founders, auditors, and defenders can trust.

## Product North Star

BALONCORE should become a security validation platform that can answer:

```text
What can an attacker actually do?
How do we know?
What is the business impact?
How do we fix it?
How do we prevent it from coming back?
```

The platform should eventually support:

- Web and API pentesting
- SaaS authorization and tenant isolation testing
- Cloud and IAM attack-path validation
- Infrastructure and configuration review
- Web3 smart contract and protocol analysis
- CI/CD security gates
- AI-assisted reporting
- Defensive automation
- Enterprise evidence, audit, and compliance workflows

## Safety Boundary

BALONCORE is for authorized security work only.

Allowed targets include:

- systems owned by the user or customer
- client-authorized environments
- explicit bug bounty scopes
- open-source repositories
- local labs and intentionally vulnerable apps
- CTFs and training environments

Core safety principles:

- scope must be configured before active testing
- deny rules override allow rules
- findings require evidence
- destructive actions require explicit future policy support
- validators must stay inside authorized scope
- reports must distinguish verified findings from hypotheses

## Current Status

Current stage: **P7.S0 — BUILD_RIGOR Compliance Layer (IMPLEMENTED)**

The repository now contains a cross-cutting compliance proof system that answers all 7 BUILD_RIGOR questions with cryptographic evidence.

Completed P7.S0 work:

**BUILD_RIGOR compliance engine (crates/baloncore-core/src/rigor.rs):**

*1. Authorization — Scope Audit:*
- `ScopeAuditProof`: scope_contract_id, verified_at, total/allowed/blocked requests, host/URL allow/deny lists, SHA-256 verification hash, `passed()` check
- Proves every request was within authorized scope with cryptographically verifiable audit

*2. Evidence — Custody Chain:*
- `CustodyChain`: linked hash chain of `CustodyStep` entries — each step carries artifact_hash + previous_hash for tamper-evident continuity
- `add_step()` auto-derives artifact_hash from phase, description, actor, and artifact content
- `verify_continuity()` detects breaks by recomputing expected hashes
- `finalize()` sets `is_continuous` flag and root hash summary

*3. False-Positive Control — Decoy Verification:*
- `DecoyVerification`: total_decoys, correctly_rejected, incorrectly_accepted, rejection_rate, per-decoy results
- `DecoyResult`: decoy_id, endpoint, expected/actual result, rejected flag, evidence
- `passed` is true only when zero decoys were incorrectly accepted

*4. Customer Artifact — Report Integrity:*
- `ReportIntegrityCheck`: verifies that report finding IDs match evidence finding IDs exactly
- Computes set intersection, identifies unmatched entries in both directions, SHA-256 fingerprints both sets
- `is_consistent` is true only when there are zero unmatched entries in both directions

*5. Regression — Provenance:*
- `RegressionProvenanceEntry`: per-finding regression history with total_regressions, total_passes, total_failures, pass_rate, history of checkpoints
- `RegressionCheckpoint`: timestamp, verdict (Fixed/StillFailing), passed/total checks
- `currently_fixed` tracks whether the most recent regression passed

*6. Defense — Lineage:*
- `DefenseLineageEntry`: links finding_id + classification → defense artifact (sigma-rule, waf-rule, fix-template) with deterministically computed verification hash
- `verification_hash` is identical for the same (finding, classification, artifact_type, content) tuple
- Traces every defense artifact back to the finding and evidence that generated it

*7. Audit + Isolation — Integrity:*
- `AuditIntegrityRecord`: linked hash chain of `TamperEvidentEvent` entries
- Each event carries (actor, action, resource_type, resource_id, outcome, timestamp) with cryptographic event_hash and previous_hash chaining
- `verify()` recomputes every event's hash and confirms the chain has no breaks
- `seal()` finalizes the record with summary; any tampering after seal is detectable

**Unified Compliance Proof:**
- `ComplianceProof`: aggregates all 7 checks — `assemble()` creates everything from parameters, computes `all_passed` and auto-grade (A+ if all pass, B if scope+decoys pass, F otherwise)
- `to_markdown()`: full BUILD_RIGOR report with per-section tables and hash verification

**CLI command:**
- `rigor-proof --store --target --format markdown|json --output --json`: generates compliance proof with all 7 guarantees from evidence store

**17 new tests:**
- Scope audit pass/fail with blocked requests, custody chain continuity and tamper detection
- Decoy verification (all rejected, one accepted), report integrity (consistent, mismatch)
- Defense lineage deterministic hashes and content differentiation
- Audit integrity chain verification and tamper detection
- Regression provenance history tracking (mixed results, stay-fixed-on-pass)
- Full compliance proof assembly (A+ grade) and failure on blocked requests
- Compliance proof Markdown rendering includes all 7 sections

Total: 534 tests passing (502 core + 17 CLI + 15 API)

The repository now contains diligence history tracking, posture trend analysis, framework-specific reports, and CLI commands for generating diligence artifacts.

Completed P6.S1 work:

**Diligence history & trends (extended in crates/baloncore-core/src/diligence.rs):**
- `DiligenceHistory`: append-only history store with per-report entries; `append()` auto-computes posture_score, posture_grade, compliance_coverage, investment_readiness, fix/finding counts, critical_open/high_open; auto-trims to 100 entries; `save()`/`load()` persistence
- `DiligenceHistoryEntry`: timestamp, report_id, posture_score, posture_grade, compliance_coverage, investment_readiness, total_findings, fixed_findings, critical_open, high_open
- `compute_diligence_trend()`: linear regression over posture scores, fix rates, and compliance coverage; computes first→latest delta, direction (improving/declining/stable), per-report slope coefficients
- `DiligenceTrend`: first_score, latest_score, delta, direction, posture_slope, fix_rate_slope, coverage_slope, summary
- `linear_slope()`: simple linear regression (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x^2)
- `render_diligence_trend()`: Markdown report with posture-over-time table (date, score, grade, coverage, fix rate, critical open) and slope analysis

**Framework-specific reports:**
- `FrameworkSpecificReport`: framework, title, posture, coverage, evidence_summary, controls_detail, recommendations, summary; `to_markdown()` with controls table (control_id, status, evidence count, maturity)
- `for_soc2()`: extracts SOC 2 framework from full diligence report, filters for evidence/compliance recommendations
- `for_owasp()`: extracts OWASP API Top 10 framework, filters for remediation/compliance recommendations
- `vendor_security_review()`: combined vendor security review with posture, all controls, and operational summary recommendation

**CLI commands (crates/baloncore-cli/src/main.rs):**
- `diligence-report --store --target --format --output --json`: generates full diligence report (HTML/Markdown), auto-updates diligence history
- `diligence-compliance --store --framework soc2|owasp|vendor-review --target --output --json`: generates framework-specific compliance report
- `diligence-trend --history --json`: shows posture trend analysis with regression metrics
- `diligence-questionnaire --store --target --format markdown|json --output --json`: exports auto-answered vendor security questionnaire

**10 new tests:**
- History append with trend computation (improving, stable, declining)
- Trend insufficient data handling (1 entry = stable, delta=0)
- Declining trend detection (score drops > 0.05)
- History persist/reload roundtrip
- SOC2 report generation and Markdown rendering
- OWASP report generation and Markdown rendering
- Vendor security review generation
- Trend report includes posture-over-time and trend analysis
- Linear slope positive (y=x → slope=1) and negative (y=3-x → slope=-1)

**P6 summary — Diligence Package (both sub-stages complete):**

| Stage | Feature | Tests |
|-------|---------|-------|
| P6.S0 | Posture scoring, questionnaire, compliance coverage, diligence report | +14 |
| P6.S1 | History tracking, trend analysis, framework reports, CLI | +10 |
| **Total** | **~2334 lines in diligence.rs** | **517 tests (485+17+15)** |

The repository now contains a comprehensive security diligence engine that auto-answers vendor security questionnaires, computes security posture scores, maps findings to compliance frameworks, and produces investor-grade diligence reports.

Completed P6.S0 work:

**Security diligence engine (crates/baloncore-core/src/diligence.rs):**
- `SecurityDiligenceReport`: unified diligence report with overall posture, questionnaire, compliance coverage, risk heatmap, evidence quality, investment readiness, findings summary, and recommendations; `assemble()` computes everything from findings + metrics; `to_html()` and `to_markdown()` renderers
- `SecurityPosture`: score (0.0-1.0), grade (A+ through D), tier (Investment-Grade, Enterprise-Ready, Mature, Improving, Developing, Needs Attention), 6 component scores (fix_rate, severity_health, fp_reduction, defense_maturity, benchmark_performance, evidence_integrity) with weighted composite
- `SecurityPosture::compute()`: weighted formula — 25% fix_rate + 20% severity_health + 15% fp_reduction + 15% defense_maturity + 15% benchmark + 10% evidence_integrity
- Severity scoring with progressive penalties: critical×1.0, high×0.7, medium×0.3, low×0.1 of proportion
- `SecurityQuestionnaire`: 7 sections (Access Control, Tenant Isolation, API Security, Data Protection, Incident Response, CI/CD Security, Business Logic Security) with 22 auto-answered questions; each answer has confidence (high/medium), evidence description, and source attribution; tracks auto_answered_count and evidence_backed_count
- `ComplianceCoverageReport`: maps findings to 4 frameworks (OWASP API Top 10 — 10 controls, SOC 2 — 8 controls, AWS Well-Architected — 6 controls, GDPR — 5 controls, 29 controls total); per-framework coverage rate with per-control status; keyword-based matching from finding classifications
- `FrameworkCoverage`: per-framework coverage with `FrameworkControlStatus` (control_id, control_name, covered, evidence_classifications, evidence_count, maturity)
- `RiskHeatmap`: 6 categories (Access Control, Tenant Isolation, Business Logic, GraphQL Security, Authentication, Security Middleware) with severity, finding/fixed/open counts, risk_level
- `EvidenceQualityAssessment`: signed_count, encrypted_count, audit_trail_complete, redacted_properly, composite score (1.0 if all three, 0.8 if signed+redacted, 0.6 if signed only, 0.3 otherwise)
- `InvestmentReadinessScore`: 50% posture + 25% compliance + 25% evidence quality; strengths and gaps lists; grade mapping
- `DiligenceFindingSummary`: compact finding representation (finding_id, classification, severity, score, is_fixed, is_suppressed, endpoint, source)
- `DiligenceRecommendation`: category, priority, title, description, impact, effort — auto-generated from posture/compliance/evidence gaps
- `build_diligence_recommendations()`: generates recommendations for low fix rate, low compliance coverage, missing evidence signing, and high FP rates
- 14 new tests: posture scoring (empty, critical-laden, all-fixed), grade mapping, compliance coverage with findings and empty, questionnaire auto-answers, full report assembly, Markdown/HTML rendering, evidence quality scoring, risk heatmap categories, investment readiness gaps, recommendations for low fix rate

Total: 507 tests passing (475 core + 17 CLI + 15 API)

The repository now contains CI analytics with run history tracking, trend analysis, pass rate computation, and a CLI dashboard.

Completed P5.S4 work:

**CI analytics engine (crates/baloncore-core/src/ci_analytics.rs):**
- `CIPipelineHistory`: append-only history store with project, total_runs, per-run records; `append()` adds run and auto-trims to 500 entries; `save()`/`load()` persistence; `recent()` returns last N runs
- `CIPipelineRunRecord`: timestamp, project, passed, total_findings, new_findings, blocking_findings, suppressed_findings, duration_ms, stages (with per-stage pass/duration), notifications_sent/failed, summary/sarif paths, commit_sha, branch, pr_number
- `StageRecord`: name, passed, duration_ms
- `CIAnalytics`: total_runs/passes/failures, pass_rate, total_findings_seen, total_blocking_findings, avg_findings_per_run, avg_duration_ms, notification_delivery_rate, failure_rate_14d/30d, trend points, most_common_blocking classifications, stage_pass_rates, summary
- `RunTrendPoint`: period (1d/7d/14d/30d/90d), runs, passes, failures
- `BlockingClassCount`: classification, count — sorted by frequency
- `StagePassRate`: stage name, rate (passed/total), total — sorted by frequency
- `compute_ci_analytics()`: computes all metrics from history, handles empty history gracefully (returns zeros, not panics)
- `render_ci_dashboard()`: full Markdown dashboard with key metrics table, trend table, stage pass rates table, recent runs table with relative timestamps
- `render_ci_dashboard_compact()`: one-line summary for Slack/PR integration
- `format_timestamp_short()`: relative time formatting (Xs ago, Xm ago, Xh ago, Xd ago)

**CLI commands (crates/baloncore-cli/src/main.rs):**
- `ci-dashboard --history --recent --json`: loads history, computes analytics, renders full dashboard + compact summary
- `ci-pipeline-run` now auto-persists run results to `.baloncore/ci/pipeline_history.json` after each execution

**12 new tests:**
- History append/retrieve, auto-trim to 500 records
- History persist/reload roundtrip, load nonexistent returns empty
- Analytics pass rate computation (8/10 = 80%)
- Empty history analytics returns zeros gracefully
- Trend points generated for all time windows
- Relative timestamp formatting (seconds, hours, days)
- Dashboard rendering includes key metrics and recent runs
- Compact dashboard rendering
- Recent runs limited to requested count (last 10 of 50)
- Stage pass rates computed correctly

**P5 summary — CI/CD And GitHub Integration (all 5 sub-stages complete):**

| Stage | Feature | LoC | Tests |
|-------|---------|-----|-------|
| P5.S0 | Pipeline orchestration, GitHub Actions YAML, notifications | ~1010 | +17 |
| P5.S1 | GitHub API client, PR scanning, webhooks, revalidation planning | ~1324 | +23 |
| P5.S2 | CI provider detection, check runs, PR annotations | ~916 | +15 |
| P5.S3 | Revalidation execution, auto-fix lifecycle, CI presets | ~825 | +15 |
| P5.S4 | CI analytics, run history, trend analysis, dashboard | ~560 | +12 |
| **Total** | **~4635 lines across 5 modules** | **493 tests (461+17+15)** | |

The repository now contains a complete revalidation execution engine, auto-fix lifecycle transitions, and pre-configured CI pipeline templates for common deployment patterns.

Completed P5.S3 work:

**Revalidation execution (crates/baloncore-core/src/ci_revalidation.rs):**
- `RevalidationRunner`: takes a RevalidationPlan + FindingRecord list, iterates affected findings, runs regression via `HttpRequestRunner`, collects per-finding results with status and timing
- `RevalidationReport`: pr_number, started_at/finished_at timestamps, total_targets, fixed_count, still_failing_count, skipped_count, error_count, per-finding RevalidationResult list, summary
- `RevalidationResult`: finding_id, endpoint, classification, status, reason, remediation_path, regression_verdict, checks_passed/checks_total, duration_ms
- `RevalidationStatus` enum: Fixed, StillFailing, SkippedNoRemediation, SkippedAlreadyFixed, Error — each with `as_str()`
- Automatic remediation.json lookup from evidence store path: `.baloncore/evidence/runs/{scan_id}/{finding_id}/remediation.json`
- Skips findings already in `Fixed`/`Closed` state (checked before file existence to minimize false negatives)
- `try_run_regression()`: parses RemediationPlan from remediation.json, sends each RegressionCheck via HttpRequestRunner, collects passed/failed counts
- `RegressionVerdictSummary`: passed_checks, failed_checks, total_checks; `passed()` returns true only if failed_checks==0 AND total_checks>0; `verdict_str()` returns "Fixed"/"StillFailing"
- `bearer_token_from_auth()`: extracts bearer token from "Bearer ..." or "bearer ..." header prefix
- `render_revalidation_report()`: Markdown report with summary table (Fixed/Still Failing/Skipped/Errors counts), per-finding results table with status icons (+, x, ~, v, !)
- `generate_fix_lifecycle_transitions()`: produces `FixTransition` records for each Fixed finding (Verified → Fixed)
- `FixTransition`: finding_id, from_state, to_state, reason — ready for `record-finding-lifecycle` CLI

**CI pipeline presets:**
- `CIPreset` struct: id, name, description, stages (CIPipelineStage list), policy (PolicyConfig), scan_command, schedule_cron
- `rest-api` preset: OpenAPI-driven BOLA/BFLA scan with Gate, Sarif, Notify, Summary, Upload stages; fail_on_high=true; cron "0 6 * * 1-5"
- `graphql-api` preset: GraphQL introspection scan with Gate, Sarif, Notify, Revalidate stages; fail_on_critical/medium=true; cron "0 6 * * 1-5"
- `security-audit` preset: Comprehensive scan with all 6 stages (Gate, Sarif, Notify, Summary, Revalidate, Upload); fail_on_unsigned_evidence/untrusted_signer/anonymous_exposure/regression_failure=true; cron "0 2 * * 0"
- `CIPreset::all_presets()`, `CIPreset::by_id()`, `CIPreset::to_pipeline_config()` — lookup and conversion

**CLI commands (crates/baloncore-cli/src/main.rs):**
- `ci-revalidate --pr --scan --store --owner --repo --token-env --output --json`: executes revalidation from existing PR scan, posts PR comment with report, auto-generates lifecycle transitions via `record-finding-lifecycle`
- `ci-preset --preset --project --apply --json`: shows or applies a CI pipeline preset, writes pipeline_config.json when `--apply` is provided

**15 new tests:**
- RevalidationStatus enum naming, RegressionVerdictSummary passed/failed/empty edge cases
- Runner skips already-Fixed findings, skips missing findings, skips when no remediation.json
- Fix lifecycle transitions only include Fixed results
- Revalidation report Markdown rendering
- CI preset REST API (correct stages, policy), GraphQL (includes Revalidate), Security Audit (most comprehensive, all policy flags)
- Preset lookup by ID, preset to pipeline config conversion
- FixTransition serialization, unix_seconds sanity check

Total: 481 tests passing (449 core + 17 CLI + 15 API)

The repository now contains a CI provider auto-detection system, a CI runtime abstraction, GitHub Check Runs integration, and PR file-level annotation mapping.

Completed P5.S2 work:

**CI provider abstraction (crates/baloncore-core/src/ci_runtime.rs):**
- `CIProvider` enum: GitHubActions, GitLabCI, CircleCI, Jenkins, Buildkite, BitbucketPipelines, AzureDevOps, Local, Unknown — with `name()`, `is_ci()`, `detect()` via env var signature detection
- `CIRuntime`: auto-detected runtime context with provider, workspace, repository, branch, commit_sha, commit_message, pr_number, pr_branch, pr_base_branch, run_id, run_number, run_url, job_name, actor, is_pr, event_name
- Provider-specific detection: `from_github_actions()` (GITHUB_ACTIONS env, parses GITHUB_REF for PR numbers and branch names), `from_gitlab_ci()` (CI_PROJECT_*, CI_MERGE_REQUEST_* vars), `from_circle_ci()`, `from_jenkins()`, `from_buildkite()`, `from_bitbucket()`, `from_azure()`, `local()`, `unknown_ci()`
- `CIRuntime::detect()` auto-selects the right provider at runtime, reading provider-specific env vars to populate all fields
- `CIRuntime::summary()` renders human-readable runtime info (provider, repo, branch, commit, PR info, event, actor)
- `render_ci_status_markdown()` produces a CI status table for Slack/PR comments

**GitHub Check Runs integration:**
- `CICheckRun`: structured check run with name, head_sha, status (queued/in_progress/completed), conclusion (success/failure/neutral/cancelled/skipped/timed_out/action_required), title, summary, text, annotations, external_id
- `CheckRunStatus` and `CheckRunConclusion` enums with `as_str()` serialization
- `CICheckAnnotation`: file-level annotation with path, start_line, end_line, annotation_level (notice/warning/failure), message, title, raw_details
- `AnnotationLevel::from_severity()` maps finding severity (critical/high → failure, medium → warning, low → notice)
- `build_check_run_from_gate()`: converts a `CIGateResult` into a `CICheckRun` with per-finding annotations, extracting file paths from endpoint strings
- `create_github_check_run()`: POST /repos/{owner}/{repo}/check-runs via GitHub API (behind `live-models` feature), sends annotations array with file-level detail

**CI detection CLI command (`ci-detect`):**
- Prints current CI provider, repository, branch, commit, PR info, run ID, and actor
- `--json` flag for machine-readable output

**Check run CLI command (`ci-check-run`):**
- `ci-check-run --owner --repo --token-env --store --baseline --json`
- Runs CI gate, builds check run with annotations from blocking findings, creates GitHub Check Run via API
- Gracefully handles API failures with inline fallback output

**15 new tests:**
- Provider detection (Local when no env vars), provider naming, is_ci check, local runtime defaults
- Check run status/conclusion values, annotation level from severity (critical→failure, high→failure, medium→warning, low→notice)
- Build check run from passing gate (success conclusion, empty annotations, PR Review title)
- Build check run from failing gate (failure conclusion, annotations per blocking finding, CI Gate title for non-PR)
- Path extraction from endpoint strings
- CI status Markdown rendering
- Check run serialization roundtrip

Total: 466 tests passing (434 core + 17 CLI + 15 API)

The repository now contains GitHub API client code, PR-aware diff scanning for security-relevant changes, revalidation planning, and webhook handling.

Completed P5.S1 work:

**GitHub API client (crates/baloncore-core/src/github.rs):**
- `GitHubClient`: owner/repo/token_env configuration with `repo_url()` for API base URL construction
- `GitHubPR`: PR metadata (number, title, sha, branch, state, html_url, labels, draft, mergeable)
- `GitHubPRFile`: changed file in a PR (filename, status, additions/deletions/changes, patch) with security classification:
  - `is_security_relevant()`: combines api_spec + auth_config + middleware + endpoint checks
  - `is_api_spec()`: openapi, swagger, .graphql, schema files
  - `is_auth_config()`: auth, security, policy, permission, role, csrf files
  - `is_middleware()`: middleware, guard, interceptor files
  - `is_endpoint()`: route, controller, handler, endpoint files
  - `change_category()`: endpoint → middleware → api-spec → auth-config → other priority ordering
- `GitHubPRComment`, `GitHubReview`: typed comment/review structures
- `GitHubWebhookEvent`: parsed webhook event from JSON payload with event_type, action, pr_number, repo, sha/branch, sender, `is_pr_event()`, `should_scan()` (opened/synchronize/reopened only)
- `GitHubWebhookResponse`: action_taken, findings_blocking, review_posted
- `parse_github_webhook()`: parse webhook payload JSON with optional HMAC-SHA256 signature verification (gated behind `live-models` feature with `sha2`)

**Live API client functions (behind `live-models` feature):**
- `list_open_prs()`: GET /repos/{owner}/{repo}/pulls — fetch all open PRs
- `get_pr()`: GET /repos/{owner}/{repo}/pulls/{number} — fetch single PR
- `get_pr_files()`: GET /repos/{owner}/{repo}/pulls/{number}/files — fetch changed files with patches
- `post_pr_comment()`: POST /repos/{owner}/{repo}/issues/{number}/comments — post PR comment
- `post_pr_review()`: POST /repos/{owner}/{repo}/pulls/{number}/reviews — post formal review

**PR diff analysis:**
- `PRDiffAnalysis`: total_files, security_relevant_files (with category, additions, deletions), endpoint_changes (with path_hint, method_hint, auth_changed), auth_changes (with kind, description), summary
- `analyze_pr_diff()`: classifies all changed files, extracts endpoint paths and HTTP methods from patches, detects auth changes in diffs
- `extract_path_hint()`: finds API paths in patch lines by scanning for /api/, /v1/, etc. patterns
- `extract_method_hint()`: detects HTTP methods (GET/POST/PUT/PATCH/DELETE) in patch content via `.method(` patterns
- `summarize_patch()`: summarizes auth/middleware patch changes with line counts and role/csrf detection

**Revalidation:**
- `RevalidationPlan`: affected_endpoints, affected_findings (with reason: endpoint modified, file overlap, auth changes), retest_commands (CLI commands for re-running validators)
- `RevalidationTarget`: finding_id, endpoint, classification, reason
- `build_revalidation_plan()`: maps PR endpoint changes to existing Verified/Reported findings, generates retest commands
- `render_pr_review_comment()`: Markdown review comment with endpoint changes table, auth/middleware changes, revalidation plan with retest commands

**CLI commands (crates/baloncore-cli/src/main.rs):**
- `github-pr-scan --owner --repo --pr --token-env --store --output --json`: scans a PR for security-relevant changes, produces diff analysis + revalidation plan + review Markdown
- `github-post-review --owner --repo --pr --token-env --scan --event --commit-id --json`: posts a PR comment or review via GitHub API
- `github-webhook --event-type --payload-file --signature --webhook-secret-env --token-env --output --json`: handles incoming GitHub webhook events, auto-scans PRs on opened/synchronize/reopened, posts review comments

**23 new tests:**
- Client constructors, PR file classification (api_spec, auth_config, middleware, endpoint, non-security)
- Webhook event parsing (opened PR → scan, closed PR → skip, push → skip, synchronize → scan)
- PR diff analysis (detects security changes, empty returns zero)
- PR review comment rendering (endpoints, methods, auth_changed, findings, retest commands)
- Revalidation plan (affected findings, rejected findings excluded)
- Webhook parse invalid JSON, custom API base URL
- Path hint extraction from patch, method hint extraction (GET, POST, no method)

Total: 451 tests passing (419 core + 17 CLI + 15 API)

The repository now contains a declarative CI pipeline orchestration layer with configurable stages, notification delivery, and GitHub Actions workflow generation.

Completed P5.S0 work:

**CI pipeline configuration and orchestration (crates/baloncore-core/src/ci_pipeline.rs):**
- `CIPipelineConfig`: declarative pipeline configuration with version, project, stages, policy, notifications, and GitHub Actions settings; `validate()` with project name, adapter, and URL checks; `save()`/`load()` roundtrip
- `CIPipelineStage` enum: Gate, Sarif, Notify, Summary, Revalidate, Upload — each stage represents a discrete pipeline step
- `NotificationTarget`: configurable notification target with adapter type (slack/linear/jira), URL, secret_env for credential injection, enabled flag, max_retries, retry_delay_ms, extra_headers; constructors `slack()`, `linear()`, `jira()`
- `GitHubActionsConfig`: repository, branch, workflow_name, schedule_cron, upload_sarif, post_pr_comment, baloncore_version, extra_env; `to_workflow_yaml()` generates complete GitHub Actions workflow YAML with checkout, BALONCORE scan, CI gate, SARIF upload via `github/codeql-action/upload-sarif@v3`, Slack notification step, PR comment via `actions/github-script@v7`, revalidation, and artifact upload
- `generate_github_actions_workflow()`: produces a production-ready GitHub Actions YAML from pipeline config, with proper triggers (push, PR, schedule, workflow_dispatch), permissions (contents:read, security-events:write, pull-requests:write), and per-stage steps
- `CIPipelineRunner`: orchestrates stages in sequence — Gate runs `evaluate_ci_gate()`, Sarif writes SARIF to disk, Notify delivers notifications with retry, Summary writes `pr_summary.md`; collects `CIPipelineResult` with per-stage status and timing
- `deliver_notification()`: real HTTP delivery with retry logic (configurable max_retries, retry_delay_ms); reads secrets from environment variables; builds adapter-specific payloads (Slack blocks, Linear issue, Jira ticket); returns `NotificationResult` with delivered status, HTTP status code, error message, and retry count
- `render_ci_pipeline_summary()`: Markdown pipeline report with evidence gate results, blocking findings, and notification delivery status
- `CIPipelineResult`: passed/failed, project, stages (each with name/passed/message/duration_ms), gate result, notification results, summary and SARIF paths
- 17 new tests: config roundtrip, validation (empty project, bad adapter, valid Slack), save/load, GitHub Actions workflow generation (all stages present, no disabled notifications, disabled skipped), stage names, notification target constructors, payload format for Slack/Linear/Jira, pipeline result serialization, config validation for empty repo, pipeline with no notifications, render pipeline summary

**CLI commands (crates/baloncore-cli/src/main.rs):**
- `ci-pipeline-run --config --store --baseline --generate-workflow --json`: runs full CI pipeline from declarative config; optionally generates GitHub Actions workflow YAML
- `ci-pipeline-workflow --config --output`: generates and writes GitHub Actions workflow YAML from pipeline config
- `ci-pipeline-notify --adapter --url --summary --secret-env --json`: sends a single notification to a configured adapter with retry and error reporting

Total: 431 tests passing (399 core + 17 CLI + 15 API)

The repository now contains a working local/backend pass across Stages 2-10, P2 evaluation/benchmark infrastructure, P3.S0-S4 metrics/traceability, P3.S3 dashboard, P4.S0 auth scheme expansion, P4.S1 tenant isolation, P4.S2 GraphQL active validation, P4.S3 business-logic validation, P4.S4 flagship customer report, and P5.S0 CI/CD pipeline orchestration.

The repository now contains a flagship customer-grade security report that combines BOLA and business-logic findings into a single evidence-backed, VC-ready deliverable with HTML and Markdown rendering, redaction, reproduction steps, and fix guidance.

Completed P4.S4 work:

**Flagship report types (crates/baloncore-core/src/flagship_report.rs):**
- `FlagshipReport`: title, generated_at, target, findings, executive_summary, severity_rationale, blast_radius
- `FlagshipFinding`: finding_id, classification, vulnerability_class, title, severity, score, security_property, description, business_impact, reproduction_steps, evidence, fix, regression_test, detection_rule
- `ReproductionStep`: step number, action, method, URL, headers, body, expected_status, expected_behavior
- `EvidenceEntry`: exchange_id, profile, method, url, status, response_body_redacted, markers
- `FixGuidance`: title, description, before_code, after_code, language, framework
- `FlagshipReport::from_bola_and_business_logic()`: combines BOLA + business-logic findings into unified report with executive summary, severity rationale, blast radius, per-finding reproduction, evidence, fix, regression, and detection
- `to_html()`: self-contained dark-themed HTML report with CSS variables, severity badges, evidence entries, code blocks
- `to_markdown()`: Markdown equivalent with headings, tables, code blocks
- `redact_secrets()`: regex-based stripping of token/bearer_token/api_key/password/session/secret values
- `html_escape()`: HTML entity encoding for safe rendering
- `severity_for_score()`: maps score → critical/high/medium/low
- `format_timestamp()`: epoch → approximate UTC date rendering (no chrono dependency)
- `AuthorizationClass::score()`: maps BOLA=58, BFLA=68, MissingAuth=72, TenantIsolation=62, non-findings=0
- 4 new tests: HTML render, Markdown render, redaction, severity scoring

**CLI command `export-flagship-report` (crates/baloncore-cli/src/main.rs):**
- `export-flagship-report --run-dir <dir> --format html|markdown --target <target> --output <path> --json`
- Reads `decision.json` + `validation_case.json` + `classification.json` from run directory
- Optionally reads `business_logic_case.json` + `business_logic_finding.json` for BL data; synthesizes defaults if absent
- Generates `FlagshipReport` via `from_bola_and_business_logic()` and writes HTML or Markdown output
- Rejects with clear error if BOLA validation was rejected (no flagship report possible)

Total: 414 tests passing (382 core + 17 CLI + 15 API)

The repository now contains a working local/backend pass across Stages 2-10, P2 evaluation/benchmark infrastructure, P3.S0-S4 metrics/traceability, P3.S3 dashboard, P4.S0 auth scheme expansion, P4.S1 tenant isolation, P4.S2 GraphQL active validation, P4.S3 business-logic validation, and P4.S4 flagship customer report.

**Business-logic validation types and validator (crates/baloncore-core/src/business_logic.rs):**
- `BusinessLogicAbuse` enum: PriceTamper, StateSkip, Replay, QuantityLimitBypass — each with `as_str()`, `title()`, `security_property()`, `vulnerability_class()`, `score()`
- `WorkflowStep`: step name, method, URL template, body template, expected status, preconditions, state fields
- `WorkflowInvariant`: abuse type, description, steps, invariant field, tampered/legitimate values, prerequisite step
- `BusinessLogicValidationCase`: full validation case with abuse type, before/after state, before/after exchanges, tampered field and values, profile, object_id
- `WorkflowState`: status, body excerpt, state fields (key-value pairs)
- `WorkflowExchange`: request/response pair for a workflow step
- `BusinessLogicValidator::validate()`: dispatches to type-specific validator
- `validate_price_tamper()`: verifies tampered price overrides legitimate price; rejects if server validates; rejects if request fails
- `validate_state_skip()`: verifies forbidden state transition achieved; rejects if state doesn't change or changes to legitimate value; verifies via state_fields or body content
- `validate_replay()`: verifies duplicate effect from replayed request; checks state_fields (count/total/quantity/status changes); rejects if server detects duplicate ("duplicate", "already_processed", "idempotency", "conflict" keywords)
- `validate_quantity_limit_bypass()`: verifies tampered quantity overrides legitimate limit; rejects if server validates
- `VerifiedBusinessLogicFinding`: full proof with title, abuse_type, vulnerability_class, workflow_name, object_id, evidence exchanges, evidence markers, before/after state summaries, security property, score
- `RejectedBusinessLogicHypothesis`: reason and observations for rejected proposals
- `summarize_state()`: render workflow state summary for reports

**Validator registration (crates/baloncore-core/src/research_engine.rs + agent.rs):**
- `workflow-invariant-validator` moved from `planned_validator()` to `registered_validator()` — now eligible for deterministic validation
- `validator_for_classification("BusinessLogicWorkflowBypass")` routes to `"workflow-invariant-validator"` (was falling to `"manual-review"`)

**Vulnerable SaaS lab business-logic endpoints (labs/vulnerable-saas/server.js):**
- `POST /api/orders` — create order with `product_id`, `quantity`, `total_usd`. **Planted vulnerability**: client-supplied `total_usd` overrides product price (price tamper). Quantity above limit accepted (quantity bypass)
- `GET /api/orders` — list current user's orders
- `GET /api/orders/:id` — get order by ID
- `POST /api/orders/:id/pay` — pay for order. **Decoy**: validates `total_usd` matches `unit_price_usd * quantity`; rejects with lab_note for tampered amounts
- `POST /api/orders/:id/ship` — ship order. **Planted vulnerability**: allows shipping without payment (state-skip bypass); returns `lab_note: "intentional state-skip: order shipped without payment requirement"`
- Product catalog: Alpha License ($29.99), Beta Subscription ($99.00), Gamma Add-on ($4.99)

**11 new tests in `business_logic::tests` module:**
- `price_tamper_verified_when_tampered_price_overrides`: tampered price overrides legitimate price → Verified
- `price_tamper_rejected_when_server_validates`: server rejects tampered price → Rejected
- `price_tamper_rejected_when_server_rejects_request`: server returns 400 → Rejected
- `state_skip_verified_when_forbidden_state_reached`: draft→shipped without payment → Verified
- `state_skip_rejected_when_state_does_not_change`: state stays the same → Rejected
- `replay_verified_when_duplicate_effect_observed`: charge_count goes 1→2 → Verified
- `replay_rejected_when_server_detects_duplicate`: server returns "duplicate" → Rejected
- `quantity_limit_bypass_verified_when_tampered_quantity_overrides`: quantity=9999 accepted → Verified
- `quantity_limit_bypass_rejected_when_server_enforces`: server rejects quantity → Rejected
- `abuse_type_properties`: as_str, score, security_property, vulnerability_class for all 4 abuse types
- `decoy_workflow_not_flagged`: server rejects tampered request (400) → Rejected

Total: 410 tests passing (378 core + 17 CLI + 15 API)

The repository now contains a working local/backend pass across Stages 2-10, P2 evaluation/benchmark infrastructure, P3.S0-S4 metrics/traceability, P3.S3 dashboard, P4.S0 auth scheme expansion, P4.S1 tenant isolation, P4.S2 GraphQL active validation, and P4.S3 business-logic validation.

**GraphQL introspection and inventory (crates/baloncore-core/src/web_api.rs):**
- `GraphQlFieldType`: represents a GraphQL type with name, kind (OBJECT, LIST, NON_NULL, SCALAR, etc.), and ofType for wrapper types
- `GraphQlField`: individual field with name, return type, args, description, isDeprecated
- `GraphQlArg`: operation argument with name, type, and defaultValue — `looks_like_object_id()` detects id-like arguments (id, *_id, uuid, slug, key)
- `GraphQlType`: parsed type from introspection with name, kind, and fields
- `GraphQlOperation`: query or mutation with operation_type, name, return_type, args, description, is_deprecated — `has_id_argument()` finds the ID arg, `minimal_query()` generates a query document for a given id value
- `GraphQlOperationType` enum: Query, Mutation
- `GraphQlInventory`: parsed schema with source_url, schema_types, queries, mutations, endpoints, and bola_candidates
- `GraphQlInventory::from_introspection_json()`: parses a full introspection response, extracts query/mutation types, builds per-operation `ApiEndpoint` entries with `EndpointSource::GraphQl`, and generates BOLA candidates
- `GraphQlInventory::introspection_query()`: returns the standard introspection query document for sending to a GraphQL endpoint
- `GraphQlBolaCandidate`: candidate with endpoint, operation_type, operation_name, id_argument, return_type_name, confidence, rationale — generated from operations that have ID-like arguments and return object types
- `GraphQlBolaCandidate::from_operations()`: confidence scoring based on operation name (object terms), id argument name, and mutation bonus
- `GraphQlBolaValidationCase`: full validation case with endpoint, operation_name, operation_type, id_argument, object_id, owner/attacker profiles and exchanges, tenant fields
- `GraphQlBolaValidator::validate()`: deterministic validator identical in structure to `BolaValidator` — verifies owner baseline success, rejects blocked access, rejects anonymous bypass, checks evidence markers and body similarity, returns `GraphQlBolaDecision::Verified(GraphQlVerifiedFinding)` or `Rejected`
- `GraphQlVerifiedFinding`: proof with title, endpoint_id, operation_name, object_id, profiles, evidence markers, body similarity, security property
- `GraphQlInventoryError`: Parse, MissingSchema, IntrospectionErrors
- `graphql_fields_for_type()`: heuristic field selector that picks idiomatic fields per return type (user→email/name/org_id/role, project→name/org_id/owner_id/status, etc.)
- `value_to_graphql_literal()`: converts serde_json Values to GraphQL literal format
- 11 new tests: schema parsing, BOLA candidate extraction, error rejection (no schema, introspection errors), mutations, id-argument detection, non-object query skipping, endpoint generation, cross-user verification, blocked decoy rejection, anonymous bypass rejection

**GraphQL validator registration (crates/baloncore-core/src/research_engine.rs + agent.rs):**
- `graphql-auth-validator` moved from `planned_validator()` to `registered_validator()` — now eligible for deterministic validation
- `validator_for_classification("GraphQLFieldAuthorization")` routes to `"graphql-auth-validator"` (was falling to `"manual-review"`)

**Vulnerable SaaS lab GraphQL endpoint (labs/vulnerable-saas/server.js):**
- `POST /graphql` — full GraphQL endpoint with introspection support
- `GET /graphql` — info endpoint
- Queries: `me`, `project(id: ID!)`, `projects(orgId: ID!)`, `organization(id: ID!)`
- Types: `Query`, `Project`, `User`, `Organization`
- **Planted cross-tenant BOLA over GraphQL**: Org A member queries `project(id: "proj-b-001")` → returns 200 with `cross_tenant: true` (same vulnerability as REST)
- **Correctly blocked decoy over GraphQL**: `project(id: "proj-b-secret")` → returns `{ project: null }` with `errors: [{ message: "access denied", lab_note: "decoy: correctly protected" }]`
- Introspection requires authentication (401 if anonymous)
- Auth: Bearer, cookie/session, API key all supported
- OpenAPI spec still serves REST endpoints; GraphQL is discovered via introspection

Total: 399 tests passing (367 core + 17 CLI + 15 API)

The repository now contains a working local/backend pass across Stages 2-10, P2 evaluation/benchmark infrastructure, P3.S0-S4 metrics/traceability, P3.S3 dashboard, P4.S0 auth scheme expansion, P4.S1 tenant isolation, and P4.S2 GraphQL active validation.

**Core auth expansion (crates/baloncore-core):**
- `AuthCredentialRef` extended with `api_key_header`, `cookie_session`, `oauth2`, `extra_headers`, `extra_cookies` fields
- `ApiKeyHeaderRef`: header_name + header_value_env/header_value for API key authentication
- `CookieSessionRef`: cookie_name/cookie_value + CSRF token header/value + login_endpoint/login_body for session auth
- `OAuth2Ref`: grant_type (ClientCredentials/AuthorizationCode), token_endpoint, client_id/secret (env var or inline), scope, resource
- `TemplateHeader` and `TemplateCookie`: per-profile header/cookie templating for matrix replay
- `AuthScheme` enum: None, Bearer, ApiKey, CookieSession, OAuth2
- `ResolvedCredential`: unified credential type with bearer_token, api_key_header, cookies, csrf_token_header, csrf_token, extra_headers, extra_cookies, reproduction_hint
- `resolve_credential_from_profile()`: resolves any AuthProfile into a ResolvedCredential with env var lookup and lab defaults for each scheme
- `AuthProfile::auth_scheme()`: detects the auth scheme from profile configuration
- `AuthCredentialRef::is_bearer_only()`: backward-compatible check
- `HttpRequestSpec` extended with `cookies`, `headers`, `csrf_token_header`, `csrf_token` fields
- `HttpRequestRunner::send()` now applies cookies (Cookie header), API key headers, CSRF tokens, and supports all HTTP methods (POST/PUT/PATCH/DELETE/OPTIONS added)
- `ResolvedCredential::apply_to_spec()`: merges any resolved credential into an HttpRequestSpec
- Lab default fallback functions for cookie, API key, and bearer env vars
- `BaloncoreConfig::example()` includes `cookie_user_a` (CookieSession) and `apikey_user_b` (ApiKey) profiles
- 8 new auth scheme tests: scheme detection (None/Bearer/ApiKey/CookieSession/OAuth2), resolve_credential for each scheme, apply_to_spec for bearer/api_key/cookie_session

**Lab server cookie/session + API key support (labs/vulnerable-api):**
- `usersByCookie` map with session tokens (lab-session-user-a, lab-session-user-b, lab-session-admin)
- `usersByApiKey` map with API key tokens
- `currentUser()` now checks Authorization Bearer, Cookie session, and X-API-Key header
- `POST /auth/login` endpoint: accepts `{username, password}`, returns Set-Cookie + X-CSRF-Token
- `GET /auth/csrf-token` endpoint: returns CSRF token for current session
- OpenAPI spec updated: security schemes now include `bearerAuth`, `cookieAuth`, `apiKeyAuth`
- All endpoints accept all three auth schemes

Total: 385 tests passing (353 core + 17 CLI + 15 API)

The repository now contains a working local/backend pass across Stages 2-10, P2 evaluation/benchmark infrastructure, P3.S0-S3 metrics/API/dashboard, and P3.S4 traceability and anti-gaming tests.

Completed P3.S4 work:

- 9 new integration tests in `metrics::p3s4_traceability_anti_gaming` module:
  - `traceability_metrics_equal_independent_recomputation`: every field of MetricsSummary verified against independent recomputation from raw ScanRecord/FindingRecord (verified_findings, rejected, suppressed, total, vfps, FP reduction, retest rate, CI blocked, model calls, tokens, per-vuln-class breakdown, trace provenance)
  - `traceability_rollup_cumulative_matches_compute`: rollup cumulative matches direct `compute_metrics_summary()` call
  - `traceability_persistence_roundtrip_preserves_values`: save/load roundtrip preserves all metric values
  - `anti_gaming_hypothesis_not_counted_as_verified`: pure Hypothesis findings produce 0 verified, 0 rejected, 0 suppressed
  - `anti_gaming_rejected_not_counted_as_verified`: only Rejected findings produce 0 verified, 2 rejected
  - `anti_gaming_suppressed_not_counted_as_verified`: NeedsMoreEvidence findings produce 0 verified, 0 rejected, 2 suppressed
  - `anti_gaming_mixed_states_only_verified_counted`: 9 findings across all states; only Verified/Reported/Fixed/Retested/Closed counted as verified
  - `anti_gaming_rollup_excludes_unverified_from_cumulative`: rollup with Hypothesis/Rejected/NeedsMoreEvidence produces 0 cumulative verified
  - `anti_gaming_no_false_positive_inflation`: FP reduction rate is positive when rejections exist, never exceeds 1.0
- All 377 tests passing (345 core + 17 CLI + 15 API)

The repository now contains a working local/backend pass across Stages 2-10, P2 evaluation/benchmark infrastructure, P3.S0-S2 metrics/API, and P3.S3 dashboard.

Completed P3.S3 work:

- `apps/web/app/health/page.tsx`: full Program Health page with headline cards, time-series trends, drill-down, vulnerability class breakdown, model efficiency metrics
- Headline cards: verified findings/scan, FP reduction rate, median time-to-proof, retest success rate, CI-blocked criticals — every number clickable and routes to drill-down
- Time-series trend section with metric selector (verified_findings, rejected_hypotheses, suppressed_findings, total_candidates) and bucket selector (hour/day/week/month)
- Drill-down section: clicking any headline metric calls `/api/metrics/drilldown` and shows source run/finding entries
- Time-to-proof distribution panel (min/median/p90/max)
- Vulnerability class breakdown table (verified/rejected/suppressed/FP rate/time-to-proof per class)
- Model efficiency section (model calls per verified, tokens per verified, total scans, total findings)
- Empty/loading/error states for every card: "No metrics data yet" when no data, loading spinner on fetch, error banner on connection failure
- Numbers that cannot be drilled into show "—" instead of misleading zeros
- `apps/web/lib/baloncore.ts`: added `MetricsSummary`, `MetricsTrendPoint`, `MetricsTrend`, `MetricsDrilldownEntry`, `MetricsDrilldown` types
- CSS additions: trend-empty, trend-value, time-bar-grid, time-bar-row, stat-card disabled state, responsive breakpoints
- Dashboard sidebar updated with Health link
- Next.js build + TypeScript typecheck pass with zero errors
- All 336 core + 17 CLI + 15 API tests passing

The repository now contains a working local/backend pass across Stages 2-10, P2 evaluation/benchmark infrastructure, P3.S0-S1 metrics, and P3.S2 API endpoints.

Completed P3.S2 work:

- `GET /api/metrics/summary`: returns full MetricsSummary JSON from the rollup; returns zeros when no data exists (not an error)
- `GET /api/metrics/trend?metric=&bucket=`: returns time-series trend points; supports verified_findings, rejected_hypotheses, suppressed_findings, total_candidates; bucket: hour/day/week/month
- `GET /api/metrics/drilldown?metric=&period=`: returns per-scan entries with source findings for drill-down; period filter optional
- `metrics_path()` and `evidence_store_path()` helpers resolve from `config.repo_root`
- All three endpoints return empty series/zero values for missing data (acceptance: "a request for a metric with no data returns an explicit empty series, not an error")
- 7 new P3.S2 API tests: summary returns rollup data, summary returns empty on no data, trend returns series, trend returns empty, drilldown returns entries, drilldown returns empty, endpoints wired in router
- All 336 core + 17 CLI + 15 API = 368 tests passing

- `MetricsRollup` struct: version, total_scans_indexed, last_scan_id, last_updated_at, cumulative MetricsSummary, per_scan Vec<ScanMetricsEntry>
- `ScanMetricsEntry` struct: scan_id, verified_findings, rejected_hypotheses, suppressed_findings, total_candidates, started_at, computed_at
- `MetricsRollup::add_scan()`: incremental update — adds scan entry to per_scan list, recomputes cumulative MetricsSummary from all scans+findings+model budget
- `MetricsRollup::new()`: creates empty rollup with zeroed metrics
- `save_metrics_rollup()` / `load_metrics_rollup()`: persist/retrieve `.baloncore/evidence/metrics.json`; load returns empty rollup for nonexistent files
- `MetricsTrendPoint` struct: period, metric, value, sample_count
- `compute_metrics_trend()`: bucketed time-series trend for any metric (verified_findings, rejected_hypotheses, etc.) with hour/day/week/month bucket support
- `render_metrics_trend()`: Markdown trend table
- `render_metrics_rollup()`: Markdown rollup rendering with full metrics summary + rollup metadata
- CLI `metrics-summary --store --json`: loads and renders the metrics rollup
- CLI `metrics-trend --store --metric --bucket --json`: computes and renders time-series trend
- `index-evidence-run` now auto-computes and persists metrics rollup to `.baloncore/evidence/metrics.json`
- 11 new P3.S1 tests (rollup new/add/incremental/multiple/persist/trend/hand-computation/render)
- All 336 core tests + 17 CLI tests passing with zero warnings

Completed P3.S0 work:

- `crates/baloncore-core/src/metrics.rs`: new module with pure functions over already-loaded data structures (no I/O), fully unit-testable
- `MetricPoint` struct: every number traces to source run/finding IDs for drillability
- `MetricsSummary` struct: holds all metrics plus per-vuln-class breakdown and trace provenance
- `VulnClassMetricsSummary`: per-vulnerability-class verified/rejected/suppressed counts, FP reduction rate, time-to-proof
- `TimeToProofMetrics`: mean, median, p90, min, max, sample_count for time-to-proof aggregation
- `TimeToFixMetrics`: mean, median, p90, min, max, sample_count for verified→Fixed transition delta
- `ScanVolumePoint`: time-bucketed scan volume with verified/rejected counts
- `verified_findings_per_scan()`: verified findings / total scans (0 for empty)
- `false_positive_reduction_rate()`: (suppressed + rejected) / total candidates
- `false_positive_reduction_rate_from_store()`: FP reduction using lifecycle states
- `time_to_proof()`: first Verified transition ts - first_seen_at, with mean/median/p90
- `time_to_fix()`: Verified→Fixed transition delta with mean/median/p90
- `retest_success_rate()`: retested-pass / (Fixed that were retested)
- `retest_success_rate_simple()`: simplified version using FindingState enum
- `ci_blocked_criticals()`: sum of verified_findings across scans
- `scan_volume_over_time()`: bucketed (hour/day/week/month) scan volume
- `model_calls_per_verified()`: model_calls / total_verified
- `tokens_per_verified()`: total_tokens / total_verified
- `vuln_class_breakdown()`: per-class metrics from finding records
- `compute_metrics_summary()`: assembles all metrics from scans, findings, model budget
- `render_metrics_summary()`: Markdown rendering of MetricsSummary
- 31 exhaustive unit tests covering empty-input edge cases, literal value assertions, mixed inputs
- All 325 core tests + 17 CLI tests passing with zero warnings

Completed P2.S7 work:

- `benchmarks/METHODOLOGY.md`: complete methodology doc with corpus, ground truth, scoring, difficulty weighting, grades, authorization, reproduction, and honest limitations
- `docs/DILIGENCE/BENCHMARK.md`: diligence-facing doc with executive summary, verification command, results table, eval gate thresholds, attribution, and limitations
- `generate_methodology_doc()`: auto-generates METHODOLOGY.md from current benchmark suites/runs with headline numbers from actual scorecards
- `generate_benchmark_doc()`: auto-generates BENCHMARK.md with results, decoy FP counts, eval gate thresholds, and attribution
- Both generators auto-quote headline numbers (accuracy, precision, recall, F1, grade) directly from live benchmark data — docs never drift from real results
- CLI `generate-methodology-doc` command: generates methodology markdown with `--output` and `--json` flags
- CLI `generate-benchmark-doc` command: generates diligence markdown with `--output` and `--json` flags
- 4 new P2.S7 tests (methodology headline numbers, benchmark results, scorecard matching, attribution)
- All 298 core tests + 17 CLI tests passing with zero warnings

Completed P2.S6 work:

- `EvalGateResult` struct: passed, current_grade, current_metrics, baseline_comparison, threshold_checks, decoy_false_positive_count, decoy_false_positive_violations, recall_drop_violations, summary
- `ThresholdCheck` struct: metric, value, threshold, passed, comparison string
- `eval_gate()`: precision threshold, decoy false-positive threshold, recall-drop detection against baseline, baseline comparison with per-metric deltas
- `render_eval_gate_result()`: Markdown report with threshold checks table, decoy FP section, recall drop section, baseline comparison with improvements/regressions
- `save/load_eval_gate_result()` — JSON persistence
- CLI `eval-gate` command: `--suite`, `--domain`, `--min-precision`, `--max-decoy-fp`, `--max-recall-drop`, `--baseline`, `--output`, `--json`; exits nonzero on gate failure
- `.github/workflows/benchmark-ci.yml`: GitHub Actions workflow that runs determinism check, eval gate across all 4 suites, and benchmark CI on every PR
- Eval gate deliberately fails when a decoy is flagged (max_decoy_fp=0) or precision drops below threshold
- 8 new P2.S6 tests (gate pass, gate fail on precision, decoy FP detection, recall drop vs baseline, render, render with baseline, persistence, precision threshold)
- All 294 core tests + 17 CLI tests passing with zero warnings

Completed P2.S5 work:

- `DeterminismCheckResult` struct: runs_compared, scores_identical, byte_identical_json, per-metric match vectors, run_ids, details
- `verify_determinism()`: runs K golden baseline evaluations and asserts BYTE-IDENTICAL aggregate scores across all runs
- `render_determinism_check()`: Markdown report showing per-run comparison vs baseline with ✓/✗ per metric
- `MetricStatistics` struct: mean, stddev, min, max, sample_count for K-repetition analysis
- `BenchmarkRepetitionResult` struct: K-sample mean±stddev across accuracy, precision, recall, F1, FPR, FNR, mean time, weighted accuracy, evidence coverage; `deterministic` boolean flag
- `compute_repetition_stats()`: computes mean/stddev/min/max for all metrics across K runs, flags deterministic if all metric pairs match
- `render_repetition_result()`: Markdown report with provider/model attribution, K-repetitions, metric statistics table (mean±stddev), deterministic/Non-deterministic verdict
- `save_determinism_check()` / `load_determinism_check()` — JSON persistence
- `save_repetition_result()` / `load_repetition_result()` — JSON persistence
- `BenchmarkConfig` extended with `provider`, `model`, `prompt_version`, `git_commit`, `corpus_hash` for run attribution
- CLI `benchmark-determinism` command: `--suite`, `--domain`, `--k`, `--output`, `--json`; exits with error on determinism failure
- CLI `benchmark-repetition` command: `--suite`, `--domain`, `--k`, `--output`, `--json`; K repetitions with mean±stddev reporting
- `scripts/run_benchmarks.sh` now supports `--check-determinism` and `--determinism-k` flags
- 9 new P2.S5 tests (determinism 2/3-run, insufficient runs, render, repetition 3-run, variance detection, render, persistence x2)
- All 286 core tests + 17 CLI tests passing with zero warnings

Completed P2.S4 work:

- `LeaderboardReport` struct with per-run entries, aggregate metrics, per-case results, per-vuln-class breakdown, and full attribution (provider/model/prompt_version/engine_version/git_commit/corpus_hash)
- `LeaderboardRunEntry` captures run_id, suite_id, domain, grade, accuracy, precision, recall, F1
- `PerCaseResult` struct with case-level detail: ground truth, prediction, correct flag, confidence, time, difficulty, vuln_class
- `VulnClassMetrics` struct: per-vulnerability-class precision/recall/F1/median time
- `LeaderboardAttribution` struct: provider, model, prompt_version, engine_version, git_commit, corpus_hash
- `BenchmarkConfig` extended with `provider`, `model`, `prompt_version`, `git_commit`, `corpus_hash` fields for run attribution
- `generate_leaderboard()` aggregates across suites/runs, computes per-vuln-class breakdown, populates per-case results
- `render_leaderboard()` produces full Markdown leaderboard: attribution block, aggregate metrics table, per-run table, per-vuln-class table, per-case results table
- `render_run_diff()` renders Markdown diff between two leaderboard reports with per-metric deltas (▲/▼/— arrows), case-level improved/regressed lists, per-vuln-class delta table
- `save_leaderboard()` / `load_leaderboard()` for JSON persistence
- CLI `leaderboard` command: takes `--runs` files, outputs JSON + Markdown leaderboard
- CLI `leaderboard-diff` command: compares baseline vs current leaderboard, outputs diff
- `scripts/run_benchmarks.sh` now generates leaderboard when multiple suites run
- 9 new P2.S4 tests (leaderboard generation, aggregation, per-case, vuln-class, rendering, diff, attribution, persistence, regression detection)
- All 277 core tests + 17 CLI tests passing with zero warnings

Completed P2.S3 work:

- `BenchmarkHistory` struct for tracking benchmark runs over time with per-run metrics and engine version
- `HistoryEntry` captures run_id, timestamp, grade, accuracy, precision, recall, F1, FPR, FNR, engine_version, validator_config
- `detect_drift()` compares current metrics against history baseline with configurable drift threshold
- `DriftReport` with per-dimension drift values (accuracy, precision, recall, F1, FPR, FNR) and degraded/improved/warning classification
- `render_drift_report()` produces Markdown drift report with per-dimension status table
- `CrossDomainCorrelation` struct with domain pair correlations, overall health, strongest/weakest domain
- `compute_cross_domain_correlation()` compares accuracy across all benchmark domains
- `HistoryEntry` trend analysis: `latest()`, `best_accuracy()`, `trend()`, `last_n()`
- `append_to_history()` auto-creates history if missing, appends run metrics and grade
- `save_history()` / `load_history()` for persisting benchmark history to JSON
- `render_history()` produces Markdown history table per domain
- CLI `benchmark-history` command: display history, append runs via `--append-run`
- CLI `drift-report` command: detect drift against history with `--drift-threshold`
- CLI `cross-domain` command: compute cross-domain correlation across multiple run files
- `scripts/run_benchmarks.sh`: added `--track-history`, `--check-drift`, `--drift-threshold` flags
- Cross-domain correlation auto-reported when multiple suites are evaluated
- 12 new P2.S3 tests (history, drift detection, correlation, persistence, rendering)
- All 268 core tests + 17 CLI tests passing with zero warnings

Completed P2.S2 work:

- `generate_golden_baseline()` produces known-perfect benchmark results for each suite
- `save_golden_baseline()` and `load_golden_baseline()` persist/retrieve golden reference files from `.baloncore/benchmark/golden/`
- `benchmark_ci_gate()` combines evaluation metrics with configurable thresholds (accuracy, precision, recall, F1, FPR) into a `BenchmarkCIGateResult`
- `render_ci_gate_result()` produces Markdown CI gate reports with pass/fail status per threshold
- `evaluate_web_api_run()` matches real scan validations to benchmark cases using path pattern matching (`/api/invoices/{id}` matches `/api/invoices/inv_2002`)
- `evaluate_cloud_iam_findings()` maps Cloud IAM analysis findings to benchmark cases
- `evaluate_web3_findings()` maps Web3 analysis findings to benchmark cases
- `evaluate_evidence_integrity()` maps evidence integrity checks to benchmark cases
- CLI `benchmark-ci` command: runs evaluation + CI gate in one pass, supports `--save-golden`, `--json`, configurable thresholds
- CLI `evaluate-benchmark` command: evaluates suites against real scan data or ground-truth baseline
- CLI `benchmark-regression` command: CI-friendly gate that fails on score regression
- `scripts/run_benchmarks.sh`: runs all 4 benchmark suites, generates golden baselines, evaluates, and reports pass/fail
- Golden baseline files for all 4 suites stored in `.baloncore/benchmark/golden/`
- 10 new executor tests (WebAPI mapping, CloudIAM findings, Web3 findings, evidence integrity, golden baseline generation, CI gate pass/fail, rendering)
- All 256 core tests + 17 CLI tests passing with zero warnings

Completed P2.S1 work:

- benchmark executor module in `evaluation.rs` that consumes real scan outputs and produces evaluated `BenchmarkResult` entries
- `evaluate_web_api_run()`: reads matrix_summary.json validations and maps them to Web/API benchmark cases
- `evaluate_cloud_iam_findings()`: reads cloud_iam_analysis.json and maps CloudFindings to Cloud IAM benchmark cases
- `evaluate_web3_findings()`: reads web3_analysis.json and maps Web3Findings to Web3 benchmark cases
- `evaluate_evidence_integrity()`: reads finding store evidence and maps to Evidence benchmark cases
- `create_benchmark_run_from_results()`: assembles results into a timestamped BenchmarkRun
- CLI `evaluate-benchmark` command: selects suite by ID or domain, reads live scan data or falls back to ground-truth baseline, produces a evaluated benchmark run and scorecard
- CLI `benchmark-regression` command: CI-friendly check that fails if accuracy, precision, or recall drop below configurable thresholds
- automatic recommendation engine that fires on low metrics (precision, recall, FPR, evidence coverage, etc.)
- JSON and human-readable output for all commands
- all 246 core tests + 17 CLI tests passing

Completed P2.S0 work:

- evaluation framework module (`baloncore-core/src/evaluation.rs`) with benchmark suite definitions, ground truth labels, difficulty levels, and tag-based breakdowns
- four golden benchmark suites: Web/API (10 cases), Cloud IAM (5 cases), Web3 (5 cases), Evidence Lifecycle (4 cases)
- ground truth labels: TruePositive, FalsePositive, TrueNegative, FalseNegative, Inconclusive
- difficulty levels: Trivial, Basic, Moderate, Advanced, Expert with weighted accuracy scoring
- evaluation metrics: precision, recall, F1, accuracy, FPR, FNR, mean/median time-to-proof, classification accuracy, severity accuracy, evidence coverage, difficulty-weighted accuracy
- evaluation grades: A+ through F based on accuracy thresholds
- benchmark run comparison with per-case delta tracking, improvement/regression counts
- recommendation engine that fires on low precision, high FPR, slow proof times, low evidence coverage
- Markdown scorecard rendering with summary metrics, difficulty/tag breakdowns, comparison deltas
- CLI commands: `list-benchmarks`, `run-benchmark`, `compare-benchmark`
- JSON and human-readable output for all commands
- persistence: load/save benchmark suites, runs, and scorecards as JSON files
- 18 dedicated evaluation tests

Completed Stage 2-10 product pass:

- `index-evidence-run` command for normalizing Stage 1 run artifacts into a durable local evidence store
- `.baloncore/evidence/index.json` store with scan, finding, hypothesis, report, policy, coverage, verification, and evidence bundle records
- per-scan evidence records under `.baloncore/evidence/scans/`
- `record-finding-lifecycle` command for append-only finding lifecycle transitions
- lifecycle state enforcement for `Hypothesis`, `Rejected`, `NeedsMoreEvidence`, `Verified`, `Reported`, `Fixed`, `Retested`, and `Closed`
- finding lifecycle events embedded in both global and per-scan evidence records
- imported GLM lifecycle store primitives as a separate `FindingStore` for cross-domain findings, scan history, upsert, and state transitions
- imported CI baseline and policy gate primitives with severity-based blocking logic
- imported SARIF export primitives for GitHub/code-scanning style evidence output
- added `export-evidence-sarif`, `ci-evidence-gate`, and `baseline-evidence` commands on top of the Stage 2 evidence index
- imported defense recommendation engine with remediation, detection, regression-test, WAF, least-privilege, and threat-model guidance
- added `defense-report` command for classification-based defensive reporting
- imported cloud IAM graph and provider parsers for AWS, GCP, Azure, Kubernetes, Terraform state, and CloudFormation
- added `analyze-cloud-iam` command with offline artifacts and lifecycle finding-store export
- imported Web3/Solidity analysis, Solidity parser, Slither JSON ingestion, Foundry invariant generation, and fuzz-output parsing primitives
- added `analyze-web3` command with local Web3 artifacts and lifecycle finding-store export
- added local authorized labs for cloud IAM and Web3 analysis under `labs/cloud-iam/` and `labs/vulnerable-protocol/`
- Stage 2 customer-grade evidence report export for HTML, Markdown, and JSON
- Stage 2 export-blocking sensitive evidence check plus redaction command
- Stage 3 versioned agent prompt/contract registry and deterministic fixture agent runner
- Stage 3 verifier challenge loop and validator bridge that prevents model claims from becoming findings
- Stage 3 CLI commands: `show-agent`, `run-agent-dry-run`, `validate-agent-output`, and `agent-pipeline`
- Stage 4 self-contained local dashboard export with scan history, findings, evidence integrity, hypotheses, redaction blockers, and report links
- Stage 5 combined `ci-run` suite for evidence gating, SARIF, PR Markdown summaries, evidence bundle policy, and redaction checks
- Stage 5 OpenAPI diff command and Slack/Linear/Jira dry-run notification payload exporter
- Stage 6 cloud reachability proof artifacts and cloud defense plan output
- Stage 7 Web3 generated Foundry proof-test manifest and generated `foundry-tests/*.t.sol` artifacts
- Stage 8 bounded autonomous orchestration loop with recon, hypothesis, validator bridge, reporting, budgets, noise policy, and approval gates
- Stage 9 defense bundle export with prevention, detection, regression-test snippets, and retest plans
- Stage 10 local platform model with organizations, workspaces, users, RBAC, billing, audit log, compliance mapping, onboarding, usage metrics, and access checks

GLM copy assessment:

- GLM reached broad **Stage 2 and early Stage 3/4/5 scaffolding**, plus some Stage 6, Stage 7, and Stage 8 sketches.
- The useful, test-passing backend pieces were ported selectively.
- The dashboard, API server, fixture-only agents, autonomous pentest scaffold, and tenant/SaaS layer were not ported because they were not mature enough for the main branch yet.

Completed foundation work:

- Rust workspace
- `baloncore-core` crate
- `baloncore` CLI crate
- config format
- scope guard
- evidence model
- finding model
- proof package model
- blast-radius safety policy
- schema discovery probe registry
- attack-chain rule registry
- built-in agent specs
- safety documentation
- architecture documentation
- SimdiaScanAI review and feature import notes
- initial unit tests

Completed Stage 1 work:

- endpoint inventory model
- HTTP method and endpoint source model
- HTTP exchange model
- two-user auth profile setup in `baloncore.toml`
- deterministic BOLA/IDOR validator
- synthetic BOLA proof demo CLI
- blast-radius estimate CLI
- triage gate primitives
- redaction-aware evidence metadata
- matcher/candidate primitives
- append-only pipeline event primitives
- local vulnerable API lab
- scoped live HTTP request runner
- live `validate-lab-idor` command
- local artifact writer for exchanges, decisions, proof packages, and Markdown report
- OpenAPI JSON endpoint inventory importer
- live multi-schema discovery runner for OpenAPI, GraphQL, Postman, WSDL, and gRPC reflection probes
- discovered-schema candidate generation for actively validatable non-OpenAPI endpoints
- safe collection endpoint seed candidate selector
- object seed extraction from owner-authenticated JSON responses
- `--seed-file` and manual `--object-id` seed support
- authenticated object-endpoint candidate selector
- `scan-openapi-bola` command for owner/profile/anonymous auth-profile matrix validation
- multi-profile matrix defaults across all non-owner configured profiles
- explicit anonymous validation records for missing-authentication detection with impact/remediation artifacts
- CI policy gate `scan-openapi-bola --ci-anonymous-exposure` for protected endpoint anonymous exposure
- configurable active-check noise mode (`quiet`, `moderate`, `loud`) with per-validation noise tagging
- hard active-request budget enforcement with `--max-active-requests`
- authorization classification for BOLA, BFLA, missing authentication, intended privileged access, intended owner access, and blocked-as-expected cases
- resource-aware seed/candidate matching to avoid unrelated endpoint/object probes
- explicit `resource_mismatch` skip records in matrix summaries
- response-shape comparison for owner/tested responses
- sensitive-field detection for email, financial, ownership, credential, and privileged business data
- impact severity scoring and `impact.json` artifacts
- executive `run_report.md` aggregation with severity-ranked findings and coverage/noise-control counts
- OpenAPI coverage artifacts with tested, skipped, seed-only, and not-eligible endpoint status
- `openapi_coverage.json` and `coverage_report.md`
- workflow family and state-transition mapping artifacts from discovered endpoints
- explicit hypothesis lifecycle ledger (`hypothesis_ledger.json`) with proposed/promoted/rejected/suppressed traces
- persistent hypothesis memory in `.baloncore/hypotheses/index.json`
- config-driven suppression rules for approved access patterns
- suppressed-finding accounting plus `suppression.json` evidence artifacts
- one-command Stage 1 E2E runner: `scripts/stage1_e2e_demo.sh`
- Stage 1 E2E runner defaults to dedicated local demo port `31337`
- Stage 1 E2E runner supports `--json` summaries and `--fail-on-regression` policy gating
- persistent local finding memory in `.baloncore/findings/index.json`
- stable finding fingerprints with new/recurring status in run reports
- remediation plans for verified authorization findings
- replayable regression checks for owner, tested-profile, and anonymous access
- `remediation.json` and `remediation.md` artifacts in proof folders
- executable `run-regression` command for remediation plans
- `regression_result.json` and `regression_result.md` fixed-state verdict artifacts
- `run-regression --ci` pipeline mode that fails builds on `StillFailing`
- `export-regression-ci` GitHub Actions workflow generation
- tamper-evident `evidence_manifest.json` bundles with SHA-256 file hashes
- `seal-evidence` and `verify-evidence` commands for evidence integrity checks
- local Ed25519 signing key generation with `init-signing-key`
- `sign-evidence` command that writes `evidence_signature.json`
- signature-aware `verify-evidence --require-signature`
- signer trust registry with `trust-evidence-signer`
- trusted-only evidence verification with `verify-evidence --trusted-only`
- batch run verification with `verify-evidence-run`
- CI evidence gate with `verify-evidence-run --trusted-only --ci`
- tamper-negative tests for modified evidence files and modified signatures
- per-candidate/per-seed proof folders, `object_seeds.json`, and `matrix_summary.json`
- BOLA validator tests for verified, blocked, public-object, and unrelated-response cases
- OpenAPI inventory unit test
- object seed extraction unit test
- authorization matrix classification tests for BOLA, BFLA, and intended admin access
- resource matching tests for matched, mismatched, and manual seed cases
- response impact tests for sensitive BOLA and privileged BFLA findings
- remediation-plan unit test for verified BOLA findings
- regression verdict unit test for fixed and still-failing patch states

Stage 1 exit criteria status:

- local lab API scanning: complete
- intentionally planted IDOR/BOLA proof: complete
- false-positive and resource-mismatch rejection: complete
- evidence storage for verified results: complete
- signed evidence and CI gates: complete
- schema discovery, workflow mapping, noise policy, and hypothesis lifecycle hardening: complete enough to graduate to Stage 2

Working commands:

```bash
cargo run -p baloncore -- init
cargo run -p baloncore -- check-config baloncore.toml
cargo run -p baloncore -- check-scope http://localhost:3000/api/users
cargo run -p baloncore -- explain-agents
cargo run -p baloncore -- estimate-blast-radius --endpoints 50 --params 4 --variants 10 --depth medium --authenticated
cargo run -p baloncore -- demo-idor
cargo run -p baloncore -- validate-lab-idor --base-url http://127.0.0.1:3000
cargo run -p baloncore -- scan-openapi-bola
cargo run -p baloncore -- run-regression .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/remediation.json
cargo run -p baloncore -- run-regression .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/remediation.json --ci
cargo run -p baloncore -- export-regression-ci .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/remediation.json
cargo run -p baloncore -- seal-evidence .baloncore/runs/<run-id>/candidate-002-seed-001/user_a
cargo run -p baloncore -- init-signing-key
cargo run -p baloncore -- sign-evidence .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/evidence_manifest.json
cargo run -p baloncore -- trust-evidence-signer .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/evidence_signature.json
cargo run -p baloncore -- verify-evidence .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/evidence_manifest.json
cargo run -p baloncore -- verify-evidence .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/evidence_manifest.json --require-signature
cargo run -p baloncore -- verify-evidence .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/evidence_manifest.json --trusted-only
cargo run -p baloncore -- verify-evidence-run .baloncore/runs/<run-id> --trusted-only --ci
cargo run -p baloncore -- index-evidence-run .baloncore/runs/<run-id>
cargo run -p baloncore -- record-finding-lifecycle <scan-id> <finding-id> --state Reported --reason "Included in customer report."
cargo run -p baloncore -- export-evidence-sarif --output .baloncore/evidence/report.sarif
cargo run -p baloncore -- ci-evidence-gate --ci
cargo run -p baloncore -- baseline-evidence
cargo run -p baloncore -- defense-report BrokenObjectLevelAuthorization --output .baloncore/defense/bola.md
cargo run -p baloncore -- analyze-cloud-iam aws labs/cloud-iam/aws-risky.json
cargo run -p baloncore -- analyze-web3 labs/vulnerable-protocol
cargo run -p baloncore -- export-evidence-report --format html --output .baloncore/evidence/evidence_report.html --allow-sensitive
cargo run -p baloncore -- check-evidence-export .baloncore/runs/<run-id>
cargo run -p baloncore -- redact-evidence-file .baloncore/runs/<run-id>/candidate-002-seed-001/user_a/tested_exchange.json
cargo run -p baloncore -- show-agent api-auth --json
cargo run -p baloncore -- agent-pipeline api-auth --scan-dir .baloncore/runs/<run-id>
cargo run -p baloncore -- validate-agent-output api-auth .baloncore/agents/<artifact>.json
cargo run -p baloncore -- export-dashboard --store .baloncore/evidence/index.json
cargo run -p baloncore -- ci-run --check-redaction --sarif-output .baloncore/ci/baloncore.sarif
cargo run -p baloncore -- diff-openapi current-openapi.json previous-openapi.json --json
cargo run -p baloncore -- export-notification-dry-run .baloncore/ci/pr_summary.md --adapter slack
cargo run -p baloncore -- autonomous-run --scan-dir .baloncore/runs/<run-id>
cargo run -p baloncore -- export-defense-bundle --evidence-store .baloncore/evidence/index.json
cargo run -p baloncore -- platform-bootstrap
cargo run -p baloncore -- platform-check-access --user user-owner-example-test --workspace ws-production --permission export-report
cargo run -p baloncore -- list-benchmarks
cargo run -p baloncore -- list-benchmarks --domain web_api --json
cargo run -p baloncore -- run-benchmark --suite baloncore-web-api-v1
cargo run -p baloncore -- run-benchmark --domain cloud_iam --json
cargo run -p baloncore -- compare-benchmark .baloncore/benchmark/run.json .baloncore/benchmark/run2.json
cargo run -p baloncore -- evaluate-benchmark --suite baloncore-web-api-v1
cargo run -p baloncore -- evaluate-benchmark --domain cloud_iam
cargo run -p baloncore -- benchmark-regression --baseline .baloncore/benchmark/run.json --min-accuracy 0.80
cargo run -p baloncore -- benchmark-ci --suite baloncore-web-api-v1 --save-golden
cargo run -p baloncore -- benchmark-ci --domain web3 --min-accuracy 0.80 --min-f1 0.70 --json
./scripts/run_benchmarks.sh
./scripts/run_benchmarks.sh --fail-on-regression
```

Verified:

```bash
cargo fmt --check
cargo test
```

## SimdiaScanAI Feature Import

Before continuing into Stage 1, the legacy `SimdiaScanAI` folder was reviewed for ideas worth preserving.

Useful concepts imported into BALONCORE:

- proof packages for reproduction-ready evidence
- blast-radius estimation before active testing
- schema discovery for OpenAPI, GraphQL, Postman, WSDL, and gRPC
- attack-chain reasoning from verified atomic findings
- business-logic mapping for user flows and state transitions
- methodology/checklist thinking for later guided scan modes

Ideas deliberately not imported directly:

- generated certificates and keys
- `.venv`, `node_modules`, `dist`, and cache folders
- old Python service stack
- stealth or WAF-bypass modules
- monetization and negotiation automation
- large frontend implementation

Decision:

```text
Keep the best concepts.
Do not inherit the old architecture.
BALONCORE is the cleaner Rust-first successor.
```

Detailed review:

```text
docs/SIMDIASCANAI_REVIEW.md
```

## External Repo Review

The following public security projects were reviewed before continuing Stage 1:

- `https://xbow.com/`
- `https://github.com/xbow-security`
- `https://github.com/elementalsouls/Claude-BugHunter`
- `https://github.com/shuvonsec/claude-bug-bounty`
- `https://github.com/0xSteph/pentest-ai-agents`
- `https://github.com/nullthrix/BugBounty-Methodology`
- `https://github.com/zakirkun/deep-eye`
- `https://github.com/vercel-labs/deepsec`
- `https://github.com/xdavidhu/awesome-google-vrp-writeups`

Imported BALONCORE-native ideas:

- triage gate before validation/reporting
- evidence hygiene and redaction states
- matcher/candidate model before expensive AI processing
- append-only scan pipeline and run history
- detection engineering output after verified findings
- noise-level and OPSEC tracking for active commands
- autonomous loop memory and recon ranking
- writeup-derived attack-pattern corpus

No third-party source code was copied into BALONCORE. The import was conceptual and architectural.

Detailed review:

```text
docs/EXTERNAL_REPO_REVIEW.md
```

## Architecture Vision

### Rust Kernel

Rust should own the reliable core:

- target model
- scope enforcement
- evidence model
- finding lifecycle
- validator orchestration
- attack graph primitives
- CLI workflows
- local scan runner
- high-performance parsing where needed

### TypeScript Layer

TypeScript should own product and browser-heavy work:

- dashboard
- user interface
- Playwright browser automation
- GitHub, Slack, Linear, Jira integrations
- SaaS API layer if needed

### Python Layer

Python can support research and tool glue:

- AI orchestration experiments
- wrappers around existing security tools
- report experiments
- vulnerability lab utilities
- ML or heuristic prototypes

### Agent Layer

Agents should be versioned modules with strict contracts:

- mission
- inputs
- forbidden actions
- output schema
- confidence rules
- validation requirement

Agents should not directly create final findings unless the finding is backed by validator evidence.

### Legacy-Derived Product Principles

The SimdiaScanAI review reinforced five product principles:

- proof packages should be generated for every verified finding
- scan impact must be estimated before active testing
- API schemas should be discovered before fuzzing or authorization checks
- business workflows are first-class attack surface
- attack chains must be built from verified atomic findings, not model guesses

## Stage 0 - Foundation

### Goal

Create the serious base for the product so future modules can plug into a consistent kernel.

### Core Capabilities

- repository structure
- Rust workspace
- config format
- scope model
- safety policy
- evidence model
- finding model
- agent specs
- basic CLI
- tests

### Deliverables

- `README.md`
- `docs/BLUEPRINT.md`
- `docs/ARCHITECTURE.md`
- `docs/SAFETY.md`
- `Baloncore_roadmap.md`
- `baloncore.toml`
- `crates/baloncore-core`
- `crates/baloncore-cli`
- `agents/recon.md`
- `agents/api-auth.md`
- `agents/verifier.md`
- `agents/reporter.md`

### Exit Criteria

- project builds
- config can be generated and validated
- scope decisions can be checked
- agent specs can be listed
- tests pass

### Status

Complete enough to support Stage 1 development. The kernel remains intentionally small, but it now includes the first Web/API validation primitives.

## Stage 1 - Web/API Validation MVP

### Goal

Build the first useful security engine: web and API authorization validation for authorized targets.

This is the first product wedge because it is valuable, understandable, demo-friendly, and relevant to startups, SaaS companies, and internal engineering teams.

### Target Vulnerability Classes

- broken object-level authorization
- IDOR
- broken function-level authorization
- missing authentication
- tenant isolation failure
- role confusion
- unsafe direct object references
- schema and implementation mismatch
- sensitive endpoint exposure

### Core Features

- target URL intake
- scope enforcement on every request
- triage gate before expensive validation
- endpoint inventory
- schema discovery for OpenAPI, GraphQL, Postman, WSDL, and gRPC
- matcher/candidate discovery for source and endpoint signals
- HTTP request and response capture
- auth profile model
- anonymous, user A, user B, admin profiles
- object identifier extraction
- replay request under alternate users
- compare response status, body shape, and sensitive fields
- business-logic flow inventory
- state-transition and workflow-order mapping
- blast-radius estimate before active validation
- quiet/moderate/loud noise tagging for active checks
- generate hypothesis records
- promote only reproducible findings

### First "Wow" Feature

BALONCORE should create or use multiple authorized test users, map their accessible objects, replay object requests across roles, and prove when user A can access user B's data.

Example proof:

```text
User A requested /api/invoices/inv_2002.
The invoice belongs to User B.
The server returned HTTP 200 with User B's invoice details.
BALONCORE captured both the baseline and attack request.
```

### Deliverables

- endpoint model - started
- auth profile model
- schema discovery model
- business workflow model
- blast-radius gate - started
- triage gate - started
- matcher/candidate model - started
- HTTP exchange evidence type - started
- request runner - started
- response comparator
- BOLA validator - started
- missing-auth validator
- initial JSON or Markdown report

### Exit Criteria

- BALONCORE can scan a local lab API
- it can prove at least one intentionally planted IDOR
- it can reject at least one false positive
- it stores evidence for each verified result

## Stage 2 - Evidence And Reporting Engine

### Goal

Turn raw validation into reports that customers, founders, engineers, auditors, and investors can trust.

### Core Features

- evidence database
- append-only run history
- proof package generator
- proof package JSON output - started
- scan IDs
- finding IDs
- finding lifecycle
- hypothesis status
- rejected hypothesis records
- verified finding records
- HTTP exchange viewer data
- reproduction-ready curl command
- optional screenshot, video, timing, and OOB callback evidence
- evidence sensitivity labels
- redaction status and export blocking when redaction is required
- severity scoring
- Markdown report export
- first Markdown report output - started
- HTML report export
- executive summary
- engineering fix guidance
- regression test suggestions

### Finding Lifecycle

```text
Hypothesis
Rejected
Needs More Evidence
Verified
Reported
Fixed
Retested
Closed
```

### Deliverables

- evidence storage
- proof package storage
- report renderer
- severity model
- finding state machine
- sample reports
- report templates

### Exit Criteria

- every finding links to evidence
- unverified hypotheses are excluded from final reports
- reports can be shared with a technical team
- reports include reproduction, impact, and fix guidance

## Stage 3 - AI Agent Layer

### Goal

Add intelligence while preventing hallucinated findings.

### Agent Types

- Recon Agent
- Schema Discovery Agent
- API Auth Agent
- Business Logic Agent
- Attack Chain Agent
- Triage Agent
- Evidence Hygiene Agent
- Matcher Author Agent
- Verifier Agent
- Revalidation Agent
- Detection Engineer Agent
- Reporter Agent
- Fix Guidance Agent
- Defense Agent

### Core Features

- versioned prompts
- strict output schemas
- model-independent agent contracts
- shared scope guard for execution-capable agents
- hypothesis generation
- schema-aware endpoint reasoning
- business-flow reasoning
- attack-chain hypothesis generation from verified findings
- reasoning over endpoint inventory
- finding explanation
- false-positive challenge
- evidence summarization
- refusal and skipped-work tracking

### Critical Rule

AI can propose a vulnerability path, but only validators can promote it into a verified finding.

### Deliverables

- agent runner
- structured agent I/O
- prompt registry
- JSON schema validation
- model configuration
- verifier challenge loop

### Exit Criteria

- AI can generate useful hypotheses from endpoint data
- AI can use schema discovery results to prioritize tests
- AI can propose business-logic validation plans without executing unsafe actions
- weak hypotheses are rejected
- final reports cite evidence instead of model claims
- agent outputs are repeatable enough for product use

## Stage 4 - Dashboard

### Goal

Make BALONCORE usable, demoable, and product-grade.

### Core Views

- scan creation
- scope editor
- auth profile manager
- endpoint inventory
- attack surface map
- findings list
- evidence viewer
- report preview
- scan history
- system settings

### Design Direction

BALONCORE should feel like a serious security operations product:

- dense but clear
- evidence-first
- fast to scan
- restrained visual style
- strong information hierarchy
- no unnecessary marketing surface inside the app

### Deliverables

- web dashboard
- API service
- scan detail page
- evidence viewer
- finding detail page
- report export controls

### Exit Criteria

- a user can run and inspect a scan without the CLI
- evidence is easy to review
- findings are clearly separated by status
- the product can be demoed to a founder or investor

## Stage 5 - CI/CD And GitHub Integration

### Goal

Make BALONCORE useful before code reaches production.

### Core Features

- GitHub repository connection
- pull request scans
- GitHub Actions integration
- SARIF output
- diff-only candidate discovery
- append-only file and endpoint records
- revalidation of existing findings after code changes
- release-blocking policies
- Slack notifications
- Linear or Jira ticket creation
- baseline comparisons
- retest fixed findings

### Use Cases

- block a release when a verified authorization bug is introduced
- comment on pull requests with evidence
- generate regression tests for confirmed bugs
- track fixed versus unresolved issues

### Deliverables

- GitHub integration
- CI command mode
- SARIF exporter
- policy config
- notification adapters

### Exit Criteria

- BALONCORE can run in CI
- results can appear in GitHub security tooling
- teams can distinguish new findings from existing findings
- verified critical issues can fail a build

## Stage 6 - Cloud/IAM Attack Path Module

### Goal

Expand into cloud and infrastructure defense by proving risky cloud relationships and privilege paths.

### Target Areas

- AWS IAM
- GCP IAM
- Azure IAM
- Terraform
- CloudFormation
- Kubernetes
- GitHub Actions to cloud trust
- public storage exposure
- dangerous role assumptions
- over-permissive service accounts

### Core Features

- cloud config ingestion
- IaC scanning
- IAM graph model
- principal-to-permission path analysis
- public exposure checks
- CI/CD identity checks
- cloud evidence records
- remediation guidance

### Example "Wow" Finding

```text
This GitHub Actions workflow can request an OIDC token.
The token can assume AWS role DeployRole.
DeployRole can pass AdminRole to a compute service.
That path gives effective administrative control.
```

### Deliverables

- IAM graph engine
- Terraform adapter
- Checkov or similar integration
- Prowler or similar integration
- attack-path report format

### Exit Criteria

- BALONCORE can explain at least one real privilege path
- it can distinguish theoretical permission from reachable permission
- cloud findings include exact identity chain evidence

## Stage 7 - Web3 Smart Contract Module

### Goal

Expand into crypto protocol security with invariant generation and exploit validation.

### Target Areas

- Solidity
- Foundry
- Hardhat
- DeFi accounting
- oracle usage
- liquidation logic
- bridge/message-passing logic
- signature replay
- upgradeability
- access control
- reentrancy
- rounding and decimal mismatches

### Core Features

- Foundry and Hardhat ingestion
- Slither integration
- invariant generation
- fuzzing orchestration
- property-based tests
- symbolic or heuristic path discovery
- exploit proof tests
- protocol-specific report templates

### Example "Wow" Finding

```text
BALONCORE generated an invariant for total share accounting.
The fuzzer found a sequence where withdraw and donate operations desynchronize assets and shares.
BALONCORE produced a Foundry test that reproduces the issue.
```

### Deliverables

- Web3 project adapter
- Slither adapter
- Foundry test generator
- invariant template library
- fuzz runner
- Web3 finding model extensions

### Exit Criteria

- BALONCORE can run against a local vulnerable protocol
- it can generate at least one useful invariant
- it can produce a reproducible Foundry test for a confirmed issue

## Stage 8 - Autonomous Multi-Agent Pentest Mode

### Goal

Move toward the XBOW-like experience: scoped autonomous research loops with validation and reporting.

### Agent Roles

- Planner Agent
- Recon Agent
- Tool Agent
- Web/API Agent
- Cloud Agent
- Web3 Agent
- Exploit Validation Agent
- Verifier Agent
- Reporter Agent
- Defense Agent

### Core Features

- task planning
- tool selection
- scan memory
- candidate memory
- run history
- attack graph memory
- verified atomic finding graph
- chain-edge confidence and assumptions
- automatic retesting
- hypothesis prioritization
- recon ranking
- false-positive courtroom
- bounded autonomous execution
- human approval gates for risky actions

### Autonomous Loop

```text
Plan
Recon
Hypothesize
Validate
Reject or Verify
Collect Evidence
Report
Defend
Retest
```

### Deliverables

- agent orchestrator
- task queue
- memory store
- attack graph
- validator registry
- human approval controls

### Exit Criteria

- BALONCORE can run a scoped pentest workflow
- it can choose between multiple validators
- it can explain why a path was abandoned
- it can produce verified findings without manual report writing

## Stage 9 - Defensive Automation

### Goal

Make BALONCORE a defense platform, not only an offensive testing tool.

### Core Features

- fix guidance
- secure code patch suggestions
- regression test generation
- WAF rule suggestions
- SIEM query suggestions
- Sigma-style rule output
- cloud audit-log detection guidance
- logging recommendations
- IAM least-privilege suggestions
- detection logic
- threat model updates
- retest workflows

### Defensive Output Examples

- unit test or integration test for the bug
- route-level authorization check recommendation
- tenant isolation regression test
- IAM policy reduction
- cloud alert rule
- log event to monitor future abuse

### Deliverables

- defense recommendation engine
- regression test generator
- detection rule templates
- remediation tracking
- retest scheduler

### Exit Criteria

- every verified finding includes prevention guidance
- every major finding includes detection guidance where applicable
- fixed findings can be retested
- teams can prove that a bug did not return

## Stage 10 - Company-Grade Platform

### Goal

Turn BALONCORE into a fundable and sellable product.

### Core Features

- multi-tenant SaaS
- user accounts
- organizations and teams
- RBAC
- enterprise SSO
- encrypted evidence storage
- audit logs
- billing
- usage limits
- onboarding flows
- deployment options
- customer workspaces
- compliance mapping
- support and admin tools

### Commercial Positioning

BALONCORE should be positioned as:

```text
AI security validation that proves real risk and helps teams defend.
```

Target customers:

- startups shipping APIs quickly
- SaaS companies with tenant isolation risk
- Web3 protocols and audit teams
- cloud-heavy engineering teams
- security teams that need validated findings, not scanner noise
- founders who need pre-production security assurance

### Investor-Grade Metrics

- verified findings per scan
- false-positive reduction rate
- time to proof
- time to fix
- retest success rate
- number of CI-blocked critical issues
- customer adoption
- scan volume
- recurring usage
- expansion across modules

### Exit Criteria

- customers can onboard without manual setup
- teams can run repeatable scans
- reports are trusted by engineering teams
- product has a clear paid use case
- the platform can support multiple customers securely

## Release Milestones

### v0.1 - Kernel

- CLI
- config
- scope guard
- evidence model
- finding model
- agent specs

### v0.2 - Local Web/API Validator

- endpoint inventory
- matcher/candidate model
- auth profiles
- HTTP exchange capture
- triage gate
- blast-radius estimate
- BOLA/IDOR checks
- local report output

### v0.3 - Evidence Reports

- finding lifecycle
- append-only run history
- evidence database
- evidence redaction/hygiene
- Markdown and HTML reports
- fix guidance

### v0.4 - AI Hypothesis Engine

- structured agent runner
- recon and API auth agents
- schema-discovery, business-logic, triage, and evidence-hygiene agents
- verifier challenge loop
- schema-constrained outputs

### v0.5 - Dashboard

- scan UI
- evidence viewer
- findings UI
- reports UI

### v0.6 - CI/GitHub

- GitHub Actions mode
- SARIF export
- pull request comments
- baseline comparisons

### v0.7 - Cloud/IAM

- IaC ingestion
- IAM graph
- cloud attack paths

### v0.8 - Web3

- Foundry/Hardhat ingestion
- Slither integration
- invariant generation
- fuzzing workflow

### v0.9 - Autonomous Pentest Mode

- multi-agent planner
- memory
- attack graph reasoning
- validator registry

### v1.0 - Company Platform

- SaaS dashboard
- teams
- RBAC
- encrypted evidence storage
- billing-ready product shape

## What We Build Next

The current work is **Stage 1 - Web/API Validation MVP**.

Immediate implementation plan:

1. Add endpoint inventory types. Done.
2. Add HTTP request and response evidence records. Started.
3. Add auth profile details for test users. Done.
4. Add a blast-radius gate for active validation. Started.
5. Implement a first BOLA/IDOR validator. Started.
6. Add triage gate and redaction-aware evidence. Done.
7. Add matcher/candidate and append-only pipeline primitives. Done.
8. Build a local vulnerable lab API. Done.
9. Build a scoped request runner. Started.
10. Add schema discovery execution for OpenAPI, GraphQL, Postman, WSDL, and gRPC sources.
11. Add proof package records to verified findings. Started.
12. Store verified and rejected results. Started.
13. Generate a first Markdown report. Started.

The first concrete success target:

```text
BALONCORE scans a local lab API and proves one intentionally planted IDOR with request and response evidence.
```

That is the point where BALONCORE stops being only architecture and starts becoming a security product.
