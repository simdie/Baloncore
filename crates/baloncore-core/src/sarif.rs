use crate::lifecycle::FindingRecord;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    pub short_description: SarifMessage,
    pub properties: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifResult {
    pub rule_id: String,
    pub rule_index: usize,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    pub fingerprints: Option<serde_json::Value>,
    pub properties: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifLocation {
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifPhysicalLocation {
    pub artifact_location: SarifArtifactLocation,
    pub region: Option<SarifRegion>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifRegion {
    pub start_line: Option<u32>,
}

fn severity_to_sarif_level(severity: &str) -> String {
    match severity.to_lowercase().as_str() {
        "critical" => "error".to_string(),
        "high" => "error".to_string(),
        "medium" => "warning".to_string(),
        "low" => "note".to_string(),
        "info" => "note".to_string(),
        _ => "warning".to_string(),
    }
}

fn classification_to_rule_id(classification: &str) -> String {
    classification
        .to_lowercase()
        .replace(' ', "-")
        .replace('/', "-")
}

pub fn findings_to_sarif(findings: &[FindingRecord]) -> SarifReport {
    let mut rules: Vec<SarifRule> = vec![];
    let mut rule_ids: Vec<String> = vec![];

    for f in findings {
        let rule_id = classification_to_rule_id(&f.classification);
        if !rule_ids.contains(&rule_id) {
            rule_ids.push(rule_id.clone());
            rules.push(SarifRule {
                id: rule_id,
                name: f.classification.clone(),
                short_description: SarifMessage {
                    text: format!("{} vulnerability", f.classification),
                },
                properties: None,
            });
        }
    }

    let results: Vec<SarifResult> = findings
        .iter()
        .filter(|f| {
            f.state == crate::lifecycle::FindingState::Reported
                || f.state == crate::lifecycle::FindingState::Verified
        })
        .map(|f| {
            let rule_id = classification_to_rule_id(&f.classification);
            let rule_index = rule_ids.iter().position(|r| r == &rule_id).unwrap_or(0);

            SarifResult {
                rule_id,
                rule_index,
                level: severity_to_sarif_level(&f.severity),
                message: SarifMessage {
                    text: format!(
                        "{} on {} (tested as {}, owned by {}): {} score={}",
                        f.classification,
                        f.endpoint,
                        f.tested_profile,
                        f.owner_profile,
                        f.severity,
                        f.score
                    ),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: f.endpoint.clone(),
                        },
                        region: None,
                    },
                }],
                fingerprints: Some(serde_json::json!({
                    "primaryLocationLineHash": f.fingerprint,
                })),
                properties: Some(serde_json::json!({
                    "baloncore.finding_id": f.finding_id,
                    "baloncore.state": f.state.as_str(),
                    "baloncore.score": f.score,
                    "baloncore.tested_profile": f.tested_profile,
                    "baloncore.owner_profile": f.owner_profile,
                    "baloncore.object_id": f.object_id,
                    "baloncore.seen_count": f.seen_count,
                })),
            }
        })
        .collect();

    SarifReport {
        schema: "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "BALONCORE".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://baloncore.ai".to_string(),
                    rules,
                },
            },
            results,
        }],
    }
}

pub fn sarif_to_string(findings: &[FindingRecord]) -> Result<String, String> {
    let report = findings_to_sarif(findings);
    serde_json::to_string_pretty(&report).map_err(|e| format!("failed to serialize SARIF: {e}"))
}

pub fn sarif_to_file(findings: &[FindingRecord], path: &std::path::Path) -> Result<(), String> {
    let content = sarif_to_string(findings)?;
    std::fs::write(path, content).map_err(|e| format!("failed to write SARIF file: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::{FindingState, FindingTransition};

    fn test_finding(
        id: &str,
        classification: &str,
        severity: &str,
        state: FindingState,
    ) -> FindingRecord {
        FindingRecord {
            finding_id: id.to_string(),
            scan_id: "test-scan".to_string(),
            fingerprint: format!("fp-{}", id),
            classification: classification.to_string(),
            vulnerability_class: classification.to_string(),
            endpoint: "GET /api/invoices/{id}".to_string(),
            object_id: "inv_123".to_string(),
            owner_profile: "user_b".to_string(),
            tested_profile: "user_a".to_string(),
            severity: severity.to_string(),
            score: 80,
            state: state.clone(),
            first_seen_run: "run-1".to_string(),
            last_seen_run: "run-1".to_string(),
            first_seen_at: 1000,
            last_seen_at: 1000,
            seen_count: 1,
            latest_artifacts: "artifacts".to_string(),
            latest_evidence_dir: ".baloncore/runs/test".to_string(),
            transitions: vec![FindingTransition {
                from_state: "Hypothesis".to_string(),
                to_state: state.as_str().to_string(),
                reason: "validator confirmed".to_string(),
                at: 1000,
                actor: "api-auth".to_string(),
            }],
            defense_classifications: vec![],
        }
    }

    #[test]
    fn sarif_report_structure_is_valid() {
        let findings = vec![
            test_finding("f1", "BOLA", "high", FindingState::Reported),
            test_finding("f2", "BFLA", "medium", FindingState::Verified),
        ];
        let report = findings_to_sarif(&findings);
        assert_eq!(report.version, "2.1.0");
        assert_eq!(report.runs.len(), 1);
        assert_eq!(report.runs[0].results.len(), 2);
        assert_eq!(report.runs[0].tool.driver.name, "BALONCORE");
        assert!(report.runs[0].tool.driver.rules.len() >= 2);
    }

    #[test]
    fn sarif_excludes_rejected_findings() {
        let findings = vec![
            test_finding("f1", "BOLA", "high", FindingState::Reported),
            test_finding("f2", "BFLA", "medium", FindingState::Rejected),
        ];
        let report = findings_to_sarif(&findings);
        assert_eq!(report.runs[0].results.len(), 1);
    }

    #[test]
    fn sarif_severity_mapping() {
        assert_eq!(severity_to_sarif_level("critical"), "error");
        assert_eq!(severity_to_sarif_level("high"), "error");
        assert_eq!(severity_to_sarif_level("medium"), "warning");
        assert_eq!(severity_to_sarif_level("low"), "note");
        assert_eq!(severity_to_sarif_level("info"), "note");
    }

    #[test]
    fn sarif_serialization_roundtrip() {
        let findings = vec![test_finding(
            "f1",
            "BOLA",
            "critical",
            FindingState::Reported,
        )];
        let json = sarif_to_string(&findings).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["$schema"], "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json");
        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["results"][0]["level"], "error");
    }

    #[test]
    fn sarif_includes_finding_properties() {
        let findings = vec![test_finding(
            "f-bola-1",
            "BOLA",
            "high",
            FindingState::Reported,
        )];
        let report = findings_to_sarif(&findings);
        let result = &report.runs[0].results[0];
        assert_eq!(result.rule_id, "bola");
        assert!(result.properties.is_some());
        let props = result.properties.as_ref().unwrap();
        assert_eq!(props["baloncore.finding_id"], "f-bola-1");
        assert_eq!(props["baloncore.score"], 80);
    }
}
