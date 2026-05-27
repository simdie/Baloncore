use serde::{Deserialize, Serialize};

use crate::business_logic::VerifiedBusinessLogicFinding;
use crate::defense::recommend;
use crate::web_api::{AuthorizationClass, BolaValidationCase, VerifiedBolaFinding};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagshipReport {
    pub title: String,
    pub generated_at: u64,
    pub target: String,
    pub findings: Vec<FlagshipFinding>,
    pub executive_summary: String,
    pub severity_rationale: String,
    pub blast_radius: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagshipFinding {
    pub finding_id: String,
    pub classification: String,
    pub vulnerability_class: String,
    pub title: String,
    pub severity: String,
    pub score: u8,
    pub security_property: String,
    pub description: String,
    pub business_impact: String,
    pub reproduction_steps: Vec<ReproductionStep>,
    pub evidence: Vec<EvidenceEntry>,
    pub fix: FixGuidance,
    pub regression_test: String,
    pub detection_rule: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproductionStep {
    pub step: usize,
    pub action: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub expected_status: u16,
    pub expected_behavior: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEntry {
    pub exchange_id: String,
    pub profile: String,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub response_body_redacted: String,
    pub markers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixGuidance {
    pub title: String,
    pub description: String,
    pub before_code: String,
    pub after_code: String,
    pub language: String,
    pub framework: String,
}

impl FlagshipReport {
    pub fn from_bola_and_business_logic(
        target: &str,
        bola_case: &BolaValidationCase,
        bola_finding: &VerifiedBolaFinding,
        bola_class: &AuthorizationClass,
        bl_case: &crate::business_logic::BusinessLogicValidationCase,
        bl_finding: &VerifiedBusinessLogicFinding,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let tenant_note = if matches!(bola_class, AuthorizationClass::TenantIsolationViolation) {
            " This is a tenant isolation violation — a cross-tenant data leak."
        } else {
            ""
        };

        let executive_summary = format!(
            "BALONCORE discovered two verified security findings against {}: \
             (1) a {} allowing unauthorized cross-principal data access, and \
             (2) a business-logic abuse ({}) allowing {}.{} \
             Both findings were proven with deterministic evidence — \
             no hypothesis was reported without a reproducible proof.",
            target,
            bola_class.vulnerability_class(),
            bl_finding.abuse_type,
            bl_finding.security_property.to_ascii_lowercase(),
            tenant_note,
        );

        let severity_rationale = format!(
            "The {} finding scores {} on the BALONCORE impact scale, \
             and the {} finding scores {}. Both are verified with evidence \
             markers and body similarity checks, eliminating false positives.",
            bola_class.vulnerability_class(),
            bola_class.score(),
            bl_finding.abuse_type,
            bl_finding.score,
        );

        let blast_radius = format!(
            "The {} vulnerability affects the `{}` endpoint ({}, object `{}`), \
              where profile `{}` accessed data belonging to profile `{}`. \
              The {} vulnerability affects the `{}` workflow ({}, object `{}`), \
              where field `{}` was tampered from `{}` to `{}`. \
              In production, these patterns affect all users and objects \
              that share the same authorization boundary.",
            bola_class.vulnerability_class(),
            bola_finding.endpoint_id,
            bola_finding.security_property,
            bola_finding.object_id,
            bola_finding.attacker_profile,
            bola_finding.owner_profile,
            bl_finding.abuse_type,
            bl_finding.workflow_name,
            bl_finding.security_property,
            bl_finding.object_id,
            bl_finding.tampered_field,
            bl_finding.legitimate_value,
            bl_finding.tampered_value,
        );

        let defense = recommend(bola_class.vulnerability_class());

        let bola_finding_entry = FlagshipFinding {
            finding_id: format!("FF-001-{}", bola_class.vulnerability_class()),
            classification: format!("{:?}", bola_class),
            vulnerability_class: bola_class.vulnerability_class().to_string(),
            title: bola_finding.title.clone(),
            severity: severity_for_score(bola_class.score()),
            score: bola_class.score(),
            security_property: bola_finding.security_property.clone(),
            description: format!(
                "Profile `{}` accessed object `{}` belonging to profile `{}` on endpoint `{}`, \
                 violating the security property: \"{}\".",
                bola_finding.attacker_profile,
                bola_finding.object_id,
                bola_finding.owner_profile,
                bola_finding.endpoint_id,
                bola_finding.security_property,
            ),
            business_impact: format!(
                "An attacker with the `{}` profile can read or modify any object accessible \
                 through the `{}` endpoint, across all tenants and organizations. \
                 This enables data exfiltration, privilege escalation, and compliance violations.",
                bola_finding.attacker_profile, bola_finding.endpoint_id,
            ),
            reproduction_steps: vec![
                ReproductionStep {
                    step: 1,
                    action: "Owner profile requests their own object".to_string(),
                    method: "GET".to_string(),
                    url: format!("{}{{object_id}}", bola_case.endpoint.url_template),
                    headers: vec![(
                        "Authorization".to_string(),
                        format!("Bearer <{}_token>", bola_finding.owner_profile),
                    )],
                    body: None,
                    expected_status: 200,
                    expected_behavior: format!(
                        "Returns object `{}` belonging to `{}`",
                        bola_finding.object_id, bola_finding.owner_profile
                    ),
                },
                ReproductionStep {
                    step: 2,
                    action: "Attacker profile requests the same object".to_string(),
                    method: "GET".to_string(),
                    url: format!("{}{{object_id}}", bola_case.endpoint.url_template),
                    headers: vec![(
                        "Authorization".to_string(),
                        format!("Bearer <{}_token>", bola_finding.attacker_profile),
                    )],
                    body: None,
                    expected_status: 200,
                    expected_behavior: format!(
                        "Returns object `{}` — this should be 403, not 200",
                        bola_finding.object_id
                    ),
                },
            ],
            evidence: vec![
                EvidenceEntry {
                    exchange_id: bola_finding
                        .evidence_exchange_ids
                        .first()
                        .cloned()
                        .unwrap_or_default(),
                    profile: bola_finding.owner_profile.clone(),
                    method: "GET".to_string(),
                    url: bola_case.endpoint.url_template.clone(),
                    status: 200,
                    response_body_redacted: redact_secrets(
                        &bola_case.owner_exchange.response_body_excerpt,
                    ),
                    markers: bola_finding.evidence_markers.clone(),
                },
                EvidenceEntry {
                    exchange_id: bola_finding
                        .evidence_exchange_ids
                        .get(1)
                        .cloned()
                        .unwrap_or_default(),
                    profile: bola_finding.attacker_profile.clone(),
                    method: "GET".to_string(),
                    url: bola_case.endpoint.url_template.clone(),
                    status: 200,
                    response_body_redacted: redact_secrets(
                        &bola_case.attacker_exchange.response_body_excerpt,
                    ),
                    markers: bola_finding.evidence_markers.clone(),
                },
            ],
            fix: FixGuidance {
                title: defense.prevention_guidance.first().map_or_else(
                    || "Implement authorization checks".to_string(),
                    |g| g.title.clone(),
                ),
                description: defense.prevention_guidance.first().map_or_else(
                    || "Add object-level authorization".to_string(),
                    |g| g.description.clone(),
                ),
                before_code: defense
                    .fix_template
                    .as_ref()
                    .map_or_else(String::new, |f| f.before.clone()),
                after_code: defense
                    .fix_template
                    .as_ref()
                    .map_or_else(String::new, |f| f.after.clone()),
                language: defense
                    .fix_template
                    .as_ref()
                    .map_or_else(String::new, |f| f.language.clone()),
                framework: defense
                    .fix_template
                    .as_ref()
                    .map_or_else(String::new, |f| f.framework.clone()),
            },
            regression_test: defense
                .regression_tests
                .first()
                .map_or_else(String::new, |t| t.code.clone()),
            detection_rule: defense
                .detection_guidance
                .first()
                .map_or_else(String::new, |r| r.rule_content.clone()),
        };

        let bl_defense = recommend(&bl_finding.vulnerability_class);
        let abuse_impact = match bl_finding.abuse_type.as_ref() {
            "price_tamper" => "purchase goods at a fraction of the legitimate price",
            "state_skip" => "skip required workflow steps such as payment before shipping",
            "replay" => "duplicate one-time actions such as submitting the same payment twice",
            "quantity_limit_bypass" => "exceed configured quantity or rate limits",
            _ => "bypass intended business constraints",
        };

        let bl_finding_entry = FlagshipFinding {
            finding_id: format!("FF-002-{}", bl_finding.vulnerability_class),
            classification: format!("BusinessLogic_{}", bl_finding.abuse_type),
            vulnerability_class: bl_finding.vulnerability_class.clone(),
            title: bl_finding.title.clone(),
            severity: severity_for_score(bl_finding.score),
            score: bl_finding.score,
            security_property: bl_finding.security_property.clone(),
            description: format!(
                "Profile `{}` exploited `{}` in the `{}` workflow on object `{}`, \
                 tampering field `{}` from `{}` to `{}`. \
                 Security property: \"{}\".",
                bl_finding.profile,
                bl_finding.abuse_type,
                bl_finding.workflow_name,
                bl_finding.object_id,
                bl_finding.tampered_field,
                bl_finding.legitimate_value,
                bl_finding.tampered_value,
                bl_finding.security_property,
            ),
            business_impact: format!(
                "An attacker can exploit the `{}` business-logic flaw to \
                 {}, affecting all `{}` workflows. \
                 This bypasses intended business constraints and can lead to \
                 financial loss, data corruption, or unauthorized state transitions.",
                bl_finding.abuse_type, abuse_impact, bl_finding.workflow_name,
            ),
            reproduction_steps: vec![
                ReproductionStep {
                    step: 1,
                    action: format!("Record baseline state before {}", bl_finding.abuse_type),
                    method: bl_case
                        .before_exchange
                        .as_ref()
                        .map_or_else(|| "GET".to_string(), |e| e.method.clone()),
                    url: bl_case
                        .before_exchange
                        .as_ref()
                        .map_or_else(String::new, |e| e.url.clone()),
                    headers: vec![(
                        "Authorization".to_string(),
                        format!("Bearer <{}_token>", bl_finding.profile),
                    )],
                    body: None,
                    expected_status: 200,
                    expected_behavior: format!("Before state: {}", bl_finding.before_state_summary),
                },
                ReproductionStep {
                    step: 2,
                    action: format!(
                        "Execute {} with tampered {}",
                        bl_finding.abuse_type, bl_finding.tampered_field
                    ),
                    method: bl_case.after_exchange.method.clone(),
                    url: bl_case.after_exchange.url.clone(),
                    headers: vec![(
                        "Authorization".to_string(),
                        format!("Bearer <{}_token>", bl_finding.profile),
                    )],
                    body: Some(format!(
                        "{{ \"{}\": \"{}\" }}",
                        bl_finding.tampered_field, bl_finding.tampered_value
                    )),
                    expected_status: 200,
                    expected_behavior: format!(
                        "After state: {} — this should be rejected, not accepted",
                        bl_finding.after_state_summary
                    ),
                },
            ],
            evidence: vec![
                EvidenceEntry {
                    exchange_id: bl_finding
                        .evidence_exchange_ids
                        .first()
                        .cloned()
                        .unwrap_or_default(),
                    profile: bl_finding.profile.clone(),
                    method: bl_case
                        .before_exchange
                        .as_ref()
                        .map_or_else(|| "GET".to_string(), |e| e.method.clone()),
                    url: bl_case
                        .before_exchange
                        .as_ref()
                        .map_or_else(String::new, |e| e.url.clone()),
                    status: bl_case.before_state.status,
                    response_body_redacted: redact_secrets(&bl_case.before_state.body_excerpt),
                    markers: vec![format!("before: {}", bl_finding.before_state_summary)],
                },
                EvidenceEntry {
                    exchange_id: bl_finding
                        .evidence_exchange_ids
                        .get(1)
                        .cloned()
                        .unwrap_or_default(),
                    profile: bl_finding.profile.clone(),
                    method: bl_case.after_exchange.method.clone(),
                    url: bl_case.after_exchange.url.clone(),
                    status: bl_case.after_state.status,
                    response_body_redacted: redact_secrets(&bl_case.after_state.body_excerpt),
                    markers: bl_finding.evidence_markers.clone(),
                },
            ],
            fix: FixGuidance {
                title: bl_defense.prevention_guidance.first().map_or_else(
                    || "Validate business logic server-side".to_string(),
                    |g| g.title.clone(),
                ),
                description: bl_defense.prevention_guidance.first().map_or_else(
                    || "Add server-side validation".to_string(),
                    |g| g.description.clone(),
                ),
                before_code: bl_defense
                    .fix_template
                    .as_ref()
                    .map_or_else(String::new, |f| f.before.clone()),
                after_code: bl_defense
                    .fix_template
                    .as_ref()
                    .map_or_else(String::new, |f| f.after.clone()),
                language: bl_defense
                    .fix_template
                    .as_ref()
                    .map_or_else(String::new, |f| f.language.clone()),
                framework: bl_defense
                    .fix_template
                    .as_ref()
                    .map_or_else(String::new, |f| f.framework.clone()),
            },
            regression_test: bl_defense
                .regression_tests
                .first()
                .map_or_else(String::new, |t| t.code.clone()),
            detection_rule: bl_defense
                .detection_guidance
                .first()
                .map_or_else(String::new, |r| r.rule_content.clone()),
        };

        Self {
            title: format!("BALONCORE Security Validation Report — {}", target),
            generated_at: now,
            target: target.to_string(),
            findings: vec![bola_finding_entry, bl_finding_entry],
            executive_summary,
            severity_rationale,
            blast_radius,
        }
    }

    pub fn to_html(&self) -> String {
        render_flagship_html(self)
    }

    pub fn to_markdown(&self) -> String {
        render_flagship_markdown(self)
    }
}

fn severity_for_score(score: u8) -> String {
    match score {
        s if s >= 80 => "critical".to_string(),
        s if s >= 68 => "high".to_string(),
        s if s >= 50 => "medium".to_string(),
        _ => "low".to_string(),
    }
}

fn redact_secrets(body: &str) -> String {
    let mut redacted = body.to_string();
    let patterns = [
        (r#""token"\s*:\s*"[^"]*""#, r#""token":"[REDACTED]""#),
        (
            r#""bearer_token"\s*:\s*"[^"]*""#,
            r#""bearer_token":"[REDACTED]""#,
        ),
        (r#""api_key"\s*:\s*"[^"]*""#, r#""api_key":"[REDACTED]""#),
        (r#""password"\s*:\s*"[^"]*""#, r#""password":"[REDACTED]""#),
        (r#""session"\s*:\s*"[^"]*""#, r#""session":"[REDACTED]""#),
        (r#""secret"\s*:\s*"[^"]*""#, r#""secret":"[REDACTED]""#),
    ];
    for (pattern, replacement) in patterns {
        if let Ok(re) = regex_lite::Regex::new(pattern) {
            redacted = re.replace_all(&redacted, replacement).to_string();
        }
    }
    redacted
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn render_flagship_html(report: &FlagshipReport) -> String {
    let mut findings_html = String::new();
    for f in &report.findings {
        let mut steps_html = String::new();
        for s in &f.reproduction_steps {
            let mut headers_parts = Vec::new();
            for (k, v) in &s.headers {
                if v.contains("token") || v.contains("Token") || v.contains("REDACTED") {
                    headers_parts.push(format!("<code>{}: [REDACTED]</code>", html_escape(k)));
                } else {
                    headers_parts.push(format!(
                        "<code>{}: {}</code>",
                        html_escape(k),
                        html_escape(v)
                    ));
                }
            }
            let headers_str = headers_parts.join("<br>");
            let body_html = s.body.as_ref().map_or_else(
                || "None".to_string(),
                |b| format!("<pre><code>{}</code></pre>", html_escape(b)),
            );

            steps_html.push_str(&format!(
                r##"<div class="step">
                    <h4>Step {}: {}</h4>
                    <div class="step-detail">
                        <div><span class="label">Method:</span> <code>{}</code></div>
                        <div><span class="label">URL:</span> <code>{}</code></div>
                        <div><span class="label">Headers:</span> {}</div>
                        <div><span class="label">Body:</span> {}</div>
                        <div><span class="label">Expected Status:</span> {}</div>
                        <div><span class="label">Expected Behavior:</span> {}</div>
                    </div>
                </div>"##,
                s.step,
                html_escape(&s.action),
                html_escape(&s.method),
                html_escape(&s.url),
                headers_str,
                body_html,
                s.expected_status,
                html_escape(&s.expected_behavior),
            ));
        }

        let mut evidence_html = String::new();
        for e in &f.evidence {
            let status_class = if e.status >= 200 && e.status < 300 {
                "status-success"
            } else {
                "status-error"
            };
            let mut markers_items = String::new();
            for m in &e.markers {
                markers_items.push_str(&format!("<li>{}</li>", html_escape(m)));
            }
            evidence_html.push_str(&format!(
                r##"<div class="evidence-entry">
                    <div class="evidence-header">
                        <span class="evidence-id">{}</span>
                        <span class="evidence-profile">Profile: {}</span>
                        <span class="evidence-method">{}</span>
                        <span class="evidence-status {}">{}</span>
                    </div>
                    <div class="evidence-url"><code>{}</code></div>
                    <div class="evidence-body">
                        <pre><code>{}</code></pre>
                    </div>
                    <div class="evidence-markers">
                        <ul>{}</ul>
                    </div>
                </div>"##,
                html_escape(&e.exchange_id),
                html_escape(&e.profile),
                html_escape(&e.method),
                status_class,
                e.status,
                html_escape(&e.url),
                html_escape(&e.response_body_redacted),
                markers_items,
            ));
        }

        let fix_html = if f.fix.after_code.is_empty() {
            String::new()
        } else {
            format!(
                r##"<div class="fix-guidance">
                    <h4>Vulnerable Code ({})</h4>
                    <pre><code class="language-{}">{}</code></pre>
                    <h4>Fixed Code ({})</h4>
                    <pre><code class="language-{}">{}</code></pre>
                    <p class="fix-description">{}</p>
                </div>"##,
                html_escape(&f.fix.framework),
                html_escape(&f.fix.language),
                html_escape(&f.fix.before_code),
                html_escape(&f.fix.framework),
                html_escape(&f.fix.language),
                html_escape(&f.fix.after_code),
                html_escape(&f.fix.description),
            )
        };

        let regression_html = if f.regression_test.is_empty() {
            String::new()
        } else {
            format!(
                r##"<div class="regression-test">
                    <h4>Executable Regression Test</h4>
                    <pre><code class="language-typescript">{}</code></pre>
                </div>"##,
                html_escape(&f.regression_test),
            )
        };

        let detection_html = if f.detection_rule.is_empty() {
            String::new()
        } else {
            format!(
                r##"<div class="detection-rule">
                    <h4>Detection Rule (SIGMA)</h4>
                    <pre><code class="language-yaml">{}</code></pre>
                </div>"##,
                html_escape(&f.detection_rule),
            )
        };

        let severity_class = match f.severity.as_str() {
            "critical" => "severity-critical",
            "high" => "severity-high",
            "medium" => "severity-medium",
            _ => "severity-low",
        };

        findings_html.push_str(&format!(
            r##"<div class="finding">
                <div class="finding-header">
                    <h3 class="finding-title">{}</h3>
                    <div class="finding-meta">
                        <span class="finding-id">{}</span>
                        <span class="severity-badge {}">{} (score: {})</span>
                        <span class="vuln-class">{}</span>
                    </div>
                </div>
                <div class="finding-body">
                    <div class="security-property">
                        <strong>Security Property:</strong> "{}"
                    </div>
                    <div class="description">
                        <p>{}</p>
                    </div>
                    <div class="business-impact">
                        <h4>Business Impact</h4>
                        <p>{}</p>
                    </div>
                    <div class="reproduction">
                        <h4>Exact Reproduction Steps</h4>
                        {}
                    </div>
                    <div class="evidence">
                        <h4>Evidence</h4>
                        {}
                    </div>
                    {}
                    {}
                    {}
                </div>
            </div>"##,
            html_escape(&f.title),
            html_escape(&f.finding_id),
            severity_class,
            html_escape(&f.severity),
            f.score,
            html_escape(&f.vulnerability_class),
            html_escape(&f.security_property),
            html_escape(&f.description),
            html_escape(&f.business_impact),
            steps_html,
            evidence_html,
            fix_html,
            regression_html,
            detection_html,
        ));
    }

    let generated_str = format_timestamp(report.generated_at);

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{}</title>
    <style>
        :root {{
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #d97706;
            --low: #65a30d;
            --bg: #0f172a;
            --card-bg: #1e293b;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
            --border: #334155;
            --accent: #3b82f6;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }}
        .report {{ max-width: 960px; margin: 0 auto; }}
        .header {{ text-align: center; padding: 2rem 0; border-bottom: 2px solid var(--border); margin-bottom: 2rem; }}
        .header h1 {{ font-size: 1.8rem; color: var(--accent); }}
        .header .subtitle {{ color: var(--text-muted); margin-top: 0.5rem; }}
        .header .target {{ color: var(--text); font-weight: 600; }}
        .section {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
        .section h2 {{ font-size: 1.3rem; color: var(--accent); margin-bottom: 1rem; }}
        .section p {{ color: var(--text); }}
        .finding {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; }}
        .finding-header {{ margin-bottom: 1rem; }}
        .finding-title {{ font-size: 1.2rem; color: var(--text); }}
        .finding-meta {{ display: flex; gap: 1rem; align-items: center; margin-top: 0.5rem; flex-wrap: wrap; }}
        .finding-id {{ color: var(--text-muted); font-family: monospace; font-size: 0.85rem; }}
        .severity-badge {{ padding: 0.25rem 0.75rem; border-radius: 4px; font-weight: 600; font-size: 0.85rem; color: white; }}
        .severity-critical {{ background: var(--critical); }}
        .severity-high {{ background: var(--high); }}
        .severity-medium {{ background: var(--medium); }}
        .severity-low {{ background: var(--low); }}
        .vuln-class {{ color: var(--text-muted); font-family: monospace; font-size: 0.85rem; }}
        .security-property {{ background: rgba(59,130,246,0.1); border-left: 3px solid var(--accent); padding: 0.75rem 1rem; margin: 1rem 0; font-style: italic; }}
        .description, .business-impact {{ margin: 1rem 0; }}
        .business-impact h4 {{ color: var(--critical); }}
        .reproduction h4, .evidence h4, .fix-guidance h4, .regression-test h4, .detection-rule h4 {{ color: var(--accent); margin-bottom: 0.5rem; }}
        .step {{ background: rgba(0,0,0,0.2); border-radius: 6px; padding: 1rem; margin-bottom: 0.75rem; }}
        .step h4 {{ color: var(--text); margin-bottom: 0.5rem; }}
        .step-detail {{ font-size: 0.9rem; }}
        .step-detail div {{ margin-bottom: 0.25rem; }}
        .label {{ color: var(--text-muted); font-weight: 600; }}
        .evidence-entry {{ background: rgba(0,0,0,0.3); border-radius: 6px; padding: 1rem; margin-bottom: 0.75rem; }}
        .evidence-header {{ display: flex; gap: 1rem; align-items: center; flex-wrap: wrap; margin-bottom: 0.5rem; }}
        .evidence-profile {{ color: var(--text-muted); }}
        .evidence-method {{ color: var(--accent); font-weight: 600; }}
        .status-success {{ background: rgba(34,197,94,0.2); padding: 0.25rem 0.5rem; border-radius: 4px; color: #22c55e; }}
        .status-error {{ background: rgba(239,68,68,0.2); padding: 0.25rem 0.5rem; border-radius: 4px; color: #ef4444; }}
        .evidence-url {{ font-family: monospace; font-size: 0.85rem; margin-bottom: 0.5rem; }}
        .evidence-body pre {{ background: rgba(0,0,0,0.3); padding: 0.75rem; border-radius: 4px; overflow-x: auto; font-size: 0.85rem; max-height: 200px; }}
        .evidence-markers ul {{ list-style: none; padding: 0; }}
        .evidence-markers li {{ color: var(--accent); font-family: monospace; font-size: 0.85rem; padding: 0.125rem 0; }}
        pre code {{ white-space: pre-wrap; word-wrap: break-word; }}
        .fix-guidance pre, .regression-test pre, .detection-rule pre {{ background: rgba(0,0,0,0.3); padding: 1rem; border-radius: 4px; overflow-x: auto; font-size: 0.85rem; }}
        .fix-description {{ margin-top: 0.5rem; color: var(--text-muted); }}
        .footer {{ text-align: center; color: var(--text-muted); font-size: 0.85rem; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border); }}
    </style>
</head>
<body>
    <div class="report">
        <div class="header">
            <h1>{}</h1>
            <div class="subtitle">BALONCORE Security Validation Report</div>
            <div class="target">Target: {}</div>
            <div class="subtitle">Generated: {}</div>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <p>{}</p>
        </div>

        <div class="section">
            <h2>Severity Rationale</h2>
            <p>{}</p>
        </div>

        <div class="section">
            <h2>Blast Radius</h2>
            <p>{}</p>
        </div>

        <h2>Findings</h2>
        {}

        <div class="footer">
            <p>BALONCORE — AI proposes. Validators prove. Evidence becomes the product.</p>
            <p>Report generated at epoch {}. All claims link to deterministic evidence.</p>
        </div>
    </div>
</body>
</html>"##,
        html_escape(&report.title),
        html_escape(&report.title),
        html_escape(&report.target),
        html_escape(&generated_str),
        html_escape(&report.executive_summary),
        html_escape(&report.severity_rationale),
        html_escape(&report.blast_radius),
        findings_html,
        report.generated_at,
    )
}

fn render_flagship_markdown(report: &FlagshipReport) -> String {
    let mut md = String::new();
    md.push_str(&format!("# {}\n\n", report.title));
    md.push_str(&format!("**Target:** {}\n\n", report.target));
    md.push_str(&format!(
        "**Generated:** {}\n\n",
        format_timestamp(report.generated_at)
    ));

    md.push_str("## Executive Summary\n\n");
    md.push_str(&report.executive_summary);
    md.push_str("\n\n");

    md.push_str("## Severity Rationale\n\n");
    md.push_str(&report.severity_rationale);
    md.push_str("\n\n");

    md.push_str("## Blast Radius\n\n");
    md.push_str(&report.blast_radius);
    md.push_str("\n\n");

    for f in &report.findings {
        md.push_str(&format!("## {} — {}\n\n", f.finding_id, f.title));
        md.push_str(&format!("- **Classification:** {}\n", f.classification));
        md.push_str(&format!(
            "- **Vulnerability Class:** {}\n",
            f.vulnerability_class
        ));
        md.push_str(&format!(
            "- **Severity:** {} (score: {})\n",
            f.severity, f.score
        ));
        md.push_str(&format!(
            "- **Security Property:** \"{}\"\n\n",
            f.security_property
        ));

        md.push_str(&f.description);
        md.push_str("\n\n### Business Impact\n\n");
        md.push_str(&f.business_impact);
        md.push_str("\n\n### Exact Reproduction Steps\n\n");

        for s in &f.reproduction_steps {
            md.push_str(&format!("**Step {}: {}**\n\n", s.step, s.action));
            md.push_str(&format!("- **Method:** {}\n", s.method));
            md.push_str(&format!("- **URL:** `{}`\n", s.url));
            for (k, v) in &s.headers {
                let v_redacted =
                    if v.contains("token") || v.contains("Token") || v.contains("REDACTED") {
                        "[REDACTED]"
                    } else {
                        v.as_str()
                    };
                md.push_str(&format!("- **Header:** `{}: {}`\n", k, v_redacted));
            }
            if let Some(body) = &s.body {
                md.push_str(&format!("- **Body:** `{}`\n", body));
            }
            md.push_str(&format!("- **Expected Status:** {}\n", s.expected_status));
            md.push_str(&format!(
                "- **Expected Behavior:** {}\n\n",
                s.expected_behavior
            ));
        }

        md.push_str("### Evidence\n\n");
        for e in &f.evidence {
            md.push_str(&format!(
                "**Exchange:** `{}` | Profile: `{}` | {} `{}` → {}\n\n",
                e.exchange_id, e.profile, e.method, e.url, e.status
            ));
            md.push_str(&format!("```\n{}\n```\n\n", e.response_body_redacted));
            if !e.markers.is_empty() {
                md.push_str("Markers:\n");
                for m in &e.markers {
                    md.push_str(&format!("- {}\n", m));
                }
                md.push_str("\n");
            }
        }

        if !f.fix.after_code.is_empty() {
            md.push_str(&format!("### Fix: {}\n\n", f.fix.title));
            md.push_str(&f.fix.description);
            md.push_str("\n\n**Vulnerable code:**\n\n");
            md.push_str(&format!(
                "```{}\n{}\n```\n\n",
                f.fix.language, f.fix.before_code
            ));
            md.push_str("**Fixed code:**\n\n");
            md.push_str(&format!(
                "```{}\n{}\n```\n\n",
                f.fix.language, f.fix.after_code
            ));
        }

        if !f.regression_test.is_empty() {
            md.push_str("### Regression Test\n\n");
            md.push_str(&format!("```typescript\n{}\n```\n\n", f.regression_test));
        }

        if !f.detection_rule.is_empty() {
            md.push_str("### Detection Rule (SIGMA)\n\n");
            md.push_str(&format!("```yaml\n{}\n```\n\n", f.detection_rule));
        }
    }

    md.push_str("---\n\n");
    md.push_str("*BALONCORE — AI proposes. Validators prove. Evidence becomes the product.*\n");

    md
}

fn format_timestamp(epoch: u64) -> String {
    format!(
        "{}s since UNIX epoch ({}-{:02}-{:02} UTC)",
        epoch,
        1970 + (epoch / (365 * 24 * 3600)) as u64,
        ((epoch % (365 * 24 * 3600)) / (30 * 24 * 3600)) as u64 + 1,
        ((epoch % (30 * 24 * 3600)) / (24 * 3600)) as u64 + 1
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web_api::{ApiEndpoint, EndpointSource, HttpMethod};

    fn make_bola_case() -> BolaValidationCase {
        BolaValidationCase {
            endpoint: ApiEndpoint {
                id: "GET-/api/orgs/{orgId}/projects/{projectId}".to_string(),
                method: HttpMethod::Get,
                url_template: "/api/orgs/{orgId}/projects/{projectId}".to_string(),
                source: EndpointSource::OpenApi,
                requires_auth: Some(true),
                path_parameters: vec!["orgId".to_string(), "projectId".to_string()],
                tags: vec!["tenant-isolation".to_string()],
            },
            object_id: "proj-b-001".to_string(),
            owner_profile: "org_b_member".to_string(),
            attacker_profile: "org_a_member".to_string(),
            owner_markers: vec!["org-b".to_string()],
            owner_exchange: crate::web_api::HttpExchange {
                id: "owner-bola".to_string(),
                profile: "org_b_member".to_string(),
                method: HttpMethod::Get,
                url: "http://localhost/api/orgs/org-b/projects/proj-b-001".to_string(),
                status: 200,
                response_headers: vec![],
                response_body_excerpt: r#"{"id":"proj-b-001","org_id":"org-b","name":"Beta Mobile App"}"#.to_string(),
            },
            attacker_exchange: crate::web_api::HttpExchange {
                id: "attacker-bola".to_string(),
                profile: "org_a_member".to_string(),
                method: HttpMethod::Get,
                url: "http://localhost/api/orgs/org-b/projects/proj-b-001".to_string(),
                status: 200,
                response_headers: vec![],
                response_body_excerpt: r#"{"id":"proj-b-001","org_id":"org-b","name":"Beta Mobile App","cross_tenant":true}"#.to_string(),
            },
            anonymous_exchange: Some(crate::web_api::HttpExchange {
                id: "anon-bola".to_string(),
                profile: "anonymous".to_string(),
                method: HttpMethod::Get,
                url: "http://localhost/api/orgs/org-b/projects/proj-b-001".to_string(),
                status: 401,
                response_headers: vec![],
                response_body_excerpt: r#"{"error":"authentication required"}"#.to_string(),
            }),
        }
    }

    #[test]
    fn flagship_report_renders_html() {
        let bola_case = make_bola_case();
        let bola_finding = VerifiedBolaFinding {
            title: "Broken object-level authorization".to_string(),
            endpoint_id: "GET-/api/orgs/{orgId}/projects/{projectId}".to_string(),
            object_id: "proj-b-001".to_string(),
            owner_profile: "org_b_member".to_string(),
            attacker_profile: "org_a_member".to_string(),
            evidence_exchange_ids: vec!["owner-bola".to_string(), "attacker-bola".to_string()],
            evidence_markers: vec!["object_id:proj-b-001".to_string(), "owner_marker:org-b".to_string()],
            body_similarity: 0.92,
            security_property: "A principal must not access an object owned by a different principal without explicit authorization.".to_string(),
        };
        let bl_case = crate::business_logic::BusinessLogicValidationCase {
            abuse_type: crate::business_logic::BusinessLogicAbuse::PriceTamper,
            workflow_name: "order_creation".to_string(),
            invariant_description: "Server must not accept client-supplied price".to_string(),
            before_state: crate::business_logic::WorkflowState {
                status: 200,
                body_excerpt: r#"{"id":"ord-1","total_usd":"29.99"}"#.to_string(),
                state_fields: vec![("total_usd".to_string(), "29.99".to_string())],
            },
            after_state: crate::business_logic::WorkflowState {
                status: 200,
                body_excerpt: r#"{"id":"ord-1","total_usd":"0.01"}"#.to_string(),
                state_fields: vec![("total_usd".to_string(), "0.01".to_string())],
            },
            before_exchange: Some(crate::business_logic::WorkflowExchange {
                id: "step-create".to_string(),
                step_name: "create_order".to_string(),
                profile: "member_a".to_string(),
                method: "POST".to_string(),
                url: "http://localhost:3010/api/orders".to_string(),
                request_body_excerpt: r#"{"product_id":"prod-alpha","quantity":1}"#.to_string(),
                response_status: 201,
                response_body_excerpt: r#"{"id":"ord-1","total_usd":"29.99"}"#.to_string(),
            }),
            after_exchange: crate::business_logic::WorkflowExchange {
                id: "step-tamper".to_string(),
                step_name: "tamper_price".to_string(),
                profile: "member_a".to_string(),
                method: "POST".to_string(),
                url: "http://localhost:3010/api/orders".to_string(),
                request_body_excerpt:
                    r#"{"product_id":"prod-alpha","quantity":1,"total_usd":0.01}"#.to_string(),
                response_status: 201,
                response_body_excerpt: r#"{"id":"ord-1","total_usd":"0.01"}"#.to_string(),
            },
            tampered_field: "total_usd".to_string(),
            legitimate_value: "29.99".to_string(),
            tampered_value: "0.01".to_string(),
            profile: "member_a".to_string(),
            object_id: "ord-1".to_string(),
            security_property: crate::business_logic::BusinessLogicAbuse::PriceTamper
                .security_property()
                .to_string(),
        };
        let bl_finding = crate::business_logic::VerifiedBusinessLogicFinding {
            title: "Business logic: price tampering".to_string(),
            abuse_type: "price_tamper".to_string(),
            vulnerability_class: "business_logic_price_tamper".to_string(),
            workflow_name: "order_creation".to_string(),
            object_id: "ord-1".to_string(),
            profile: "member_a".to_string(),
            tampered_field: "total_usd".to_string(),
            legitimate_value: "29.99".to_string(),
            tampered_value: "0.01".to_string(),
            evidence_exchange_ids: vec!["step-create".to_string(), "step-tamper".to_string()],
            evidence_markers: vec!["total_usd: tampered 29.99 -> 0.01".to_string()],
            before_state_summary: "status_200 {total_usd=29.99}".to_string(),
            after_state_summary: "status_200 {total_usd=0.01}".to_string(),
            security_property: crate::business_logic::BusinessLogicAbuse::PriceTamper
                .security_property()
                .to_string(),
            score: 70,
        };
        let report = FlagshipReport::from_bola_and_business_logic(
            "https://saas.example.com",
            &bola_case,
            &bola_finding,
            &AuthorizationClass::TenantIsolationViolation,
            &bl_case,
            &bl_finding,
        );
        let html = report.to_html();
        assert!(html.contains("Executive Summary"));
        assert!(html.contains("tenant_isolation_violation"));
        assert!(html.contains("price_tamper"));
        assert!(html.contains("Reproduction"));
        assert!(html.contains("Evidence"));
        assert!(html.contains("Regression"));
    }

    #[test]
    fn flagship_report_renders_markdown() {
        let bola_case = make_bola_case();
        let bola_finding = VerifiedBolaFinding {
            title: "Broken object-level authorization".to_string(),
            endpoint_id: "GET-/api/orgs/{orgId}/projects/{projectId}".to_string(),
            object_id: "proj-b-001".to_string(),
            owner_profile: "org_b_member".to_string(),
            attacker_profile: "org_a_member".to_string(),
            evidence_exchange_ids: vec!["owner-bola".to_string(), "attacker-bola".to_string()],
            evidence_markers: vec!["object_id:proj-b-001".to_string()],
            body_similarity: 0.92,
            security_property:
                "A principal must not access an object owned by a different principal.".to_string(),
        };
        let bl_case = crate::business_logic::BusinessLogicValidationCase {
            abuse_type: crate::business_logic::BusinessLogicAbuse::StateSkip,
            workflow_name: "order_fulfillment".to_string(),
            invariant_description: "Must complete payment before shipping".to_string(),
            before_state: crate::business_logic::WorkflowState {
                status: 200,
                body_excerpt: r#"{"id":"ord-4","status":"draft"}"#.to_string(),
                state_fields: vec![("status".to_string(), "draft".to_string())],
            },
            after_state: crate::business_logic::WorkflowState {
                status: 200,
                body_excerpt: r#"{"id":"ord-4","status":"shipped"}"#.to_string(),
                state_fields: vec![("status".to_string(), "shipped".to_string())],
            },
            before_exchange: Some(crate::business_logic::WorkflowExchange {
                id: "step-submit".to_string(),
                step_name: "submit_order".to_string(),
                profile: "member_a".to_string(),
                method: "POST".to_string(),
                url: "http://localhost:3010/api/orders/ord-4/ship".to_string(),
                request_body_excerpt: "{}".to_string(),
                response_status: 200,
                response_body_excerpt: r#"{"id":"ord-4","status":"draft"}"#.to_string(),
            }),
            after_exchange: crate::business_logic::WorkflowExchange {
                id: "step-skip".to_string(),
                step_name: "ship_without_payment".to_string(),
                profile: "member_a".to_string(),
                method: "POST".to_string(),
                url: "http://localhost:3010/api/orders/ord-4/ship".to_string(),
                request_body_excerpt: "{}".to_string(),
                response_status: 200,
                response_body_excerpt: r#"{"id":"ord-4","status":"shipped"}"#.to_string(),
            },
            tampered_field: "status".to_string(),
            legitimate_value: "paid".to_string(),
            tampered_value: "shipped".to_string(),
            profile: "member_a".to_string(),
            object_id: "ord-4".to_string(),
            security_property: crate::business_logic::BusinessLogicAbuse::StateSkip
                .security_property()
                .to_string(),
        };
        let bl_finding = crate::business_logic::VerifiedBusinessLogicFinding {
            title: "Business logic: state-skip bypass".to_string(),
            abuse_type: "state_skip".to_string(),
            vulnerability_class: "business_logic_state_skip".to_string(),
            workflow_name: "order_fulfillment".to_string(),
            object_id: "ord-4".to_string(),
            profile: "member_a".to_string(),
            tampered_field: "status".to_string(),
            legitimate_value: "draft".to_string(),
            tampered_value: "shipped".to_string(),
            evidence_exchange_ids: vec!["step-submit".to_string(), "step-skip".to_string()],
            evidence_markers: vec!["status: state skipped from draft to shipped".to_string()],
            before_state_summary: "status_200 {status=draft}".to_string(),
            after_state_summary: "status_200 {status=shipped}".to_string(),
            security_property: crate::business_logic::BusinessLogicAbuse::StateSkip
                .security_property()
                .to_string(),
            score: 72,
        };
        let report = FlagshipReport::from_bola_and_business_logic(
            "https://saas.example.com",
            &bola_case,
            &bola_finding,
            &AuthorizationClass::BrokenObjectLevelAuthorization,
            &bl_case,
            &bl_finding,
        );
        let md = report.to_markdown();
        assert!(md.contains("# "));
        assert!(md.contains("Executive Summary"));
        assert!(md.contains("state_skip"));
        assert!(md.contains("Reproduction"));
        assert!(md.contains("Evidence"));
    }

    #[test]
    fn redaction_removes_secrets() {
        let body = r#"{"token":"sk-1234567890","bearer_token":"abc123","password":"hunter2","api_key":"key-xyz","session":"sess-abc","secret":"my-secret"}"#;
        let redacted = redact_secrets(body);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("sk-1234567890"));
        assert!(!redacted.contains("abc123"));
        assert!(!redacted.contains("hunter2"));
        assert!(!redacted.contains("key-xyz"));
        assert!(!redacted.contains("sess-abc"));
        assert!(!redacted.contains("my-secret"));
    }

    #[test]
    fn severity_for_score_works() {
        assert_eq!(severity_for_score(90), "critical");
        assert_eq!(severity_for_score(72), "high");
        assert_eq!(severity_for_score(55), "medium");
        assert_eq!(severity_for_score(30), "low");
    }
}
