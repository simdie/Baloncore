use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingRecord {
    pub finding_id: String,
    pub scan_id: String,
    pub fingerprint: String,
    pub classification: String,
    pub vulnerability_class: String,
    pub endpoint: String,
    pub object_id: String,
    pub owner_profile: String,
    pub tested_profile: String,
    pub severity: String,
    pub score: u64,
    pub state: FindingState,
    pub first_seen_run: String,
    pub last_seen_run: String,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
    pub seen_count: u64,
    pub latest_artifacts: String,
    pub latest_evidence_dir: String,
    pub transitions: Vec<FindingTransition>,
    #[serde(default)]
    pub defense_classifications: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingState {
    Hypothesis,
    Rejected,
    NeedsMoreEvidence,
    Verified,
    Reported,
    Fixed,
    Retested,
    Closed,
}

impl FindingRecord {
    pub fn defense_classification_keys(&self) -> Vec<String> {
        if !self.defense_classifications.is_empty() {
            return self.defense_classifications.clone();
        }
        let mut keys = vec![self.vulnerability_class.clone()];
        for class in &self.classification_to_defense_keys() {
            if !keys.contains(class) {
                keys.push(class.clone());
            }
        }
        keys
    }

    fn classification_to_defense_keys(&self) -> Vec<String> {
        let lower = self.classification.to_ascii_lowercase().replace(' ', "_");
        match lower.as_str() {
            "brokenobjectlevelauthorization" | "broken_object_level_authorization" => {
                vec![
                    "idor".to_string(),
                    "broken_object_level_authorization".to_string(),
                ]
            }
            "brokenfunctionlevelauthorization" | "broken_function_level_authorization" => {
                vec!["access_control".to_string()]
            }
            "missinauthentication" | "missing_authentication" => {
                vec![
                    "access_control".to_string(),
                    "broken_authentication".to_string(),
                ]
            }
            _ => vec![],
        }
    }
}

impl FindingState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hypothesis => "hypothesis",
            Self::Rejected => "rejected",
            Self::NeedsMoreEvidence => "needs_more_evidence",
            Self::Verified => "verified",
            Self::Reported => "reported",
            Self::Fixed => "fixed",
            Self::Retested => "retested",
            Self::Closed => "closed",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "hypothesis" => Self::Hypothesis,
            "rejected" => Self::Rejected,
            "needs_more_evidence" => Self::NeedsMoreEvidence,
            "verified" => Self::Verified,
            "reported" => Self::Reported,
            "fixed" => Self::Fixed,
            "retested" => Self::Retested,
            "closed" => Self::Closed,
            _ => Self::Hypothesis,
        }
    }

    pub fn can_transition_to(&self, next: &FindingState) -> bool {
        match (self, next) {
            (Self::Hypothesis, Self::Verified) => true,
            (Self::Hypothesis, Self::Rejected) => true,
            (Self::Hypothesis, Self::NeedsMoreEvidence) => true,
            (Self::NeedsMoreEvidence, Self::Verified) => true,
            (Self::NeedsMoreEvidence, Self::Rejected) => true,
            (Self::Verified, Self::Reported) => true,
            (Self::Verified, Self::Rejected) => true,
            (Self::Reported, Self::Fixed) => true,
            (Self::Reported, Self::Verified) => true,
            (Self::Fixed, Self::Retested) => true,
            (Self::Fixed, Self::Reported) => true,
            (Self::Retested, Self::Closed) => true,
            (Self::Retested, Self::Reported) => true,
            (Self::Closed, Self::Reported) => true,
            _ => false,
        }
    }

    pub fn is_actionable(&self) -> bool {
        matches!(
            self,
            Self::Hypothesis
                | Self::NeedsMoreEvidence
                | Self::Verified
                | Self::Reported
                | Self::Fixed
                | Self::Retested
        )
    }

    pub fn is_reportable(&self) -> bool {
        matches!(
            self,
            Self::Verified | Self::Reported | Self::Fixed | Self::Retested | Self::Closed
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingTransition {
    pub from_state: String,
    pub to_state: String,
    pub reason: String,
    pub at: u64,
    pub actor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanRecord {
    pub scan_id: String,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub scan_type: String,
    pub base_url: String,
    pub owner_profile: String,
    pub matrix_profiles: Vec<String>,
    pub endpoints_imported: usize,
    pub candidates_considered: usize,
    pub validated_count: usize,
    pub verified_findings: usize,
    pub rejected_hypotheses: usize,
    pub suppressed_findings: usize,
    pub noise_mode: String,
    pub run_dir: String,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FindingStore {
    pub version: u32,
    pub findings: Vec<FindingRecord>,
    pub scans: Vec<ScanRecord>,
}

impl FindingStore {
    pub fn new() -> Self {
        Self {
            version: 2,
            findings: Vec::new(),
            scans: Vec::new(),
        }
    }

    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let raw =
            std::fs::read_to_string(path).map_err(|e| format!("failed to read store: {e}"))?;
        serde_json::from_str::<FindingStore>(&raw)
            .map_err(|e| format!("failed to parse store: {e}"))
    }

    pub fn save(&self, path: &std::path::Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create store dir: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize store: {e}"))?;
        std::fs::write(path, json).map_err(|e| format!("failed to write store: {e}"))
    }

    pub fn upsert_finding(&mut self, finding: FindingRecord) {
        if let Some(existing) = self
            .findings
            .iter_mut()
            .find(|f| f.finding_id == finding.finding_id)
        {
            existing.seen_count = finding.seen_count;
            existing.last_seen_run = finding.last_seen_run.clone();
            existing.last_seen_at = finding.last_seen_at;
            existing.latest_artifacts = finding.latest_artifacts.clone();
            existing.latest_evidence_dir = finding.latest_evidence_dir.clone();
            existing.severity = finding.severity.clone();
            existing.score = finding.score;
            existing.transitions.extend(finding.transitions);
        } else {
            self.findings.push(finding);
        }
        self.findings.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| a.finding_id.cmp(&b.finding_id))
        });
    }

    pub fn transition_finding(
        &mut self,
        finding_id: &str,
        new_state: FindingState,
        reason: &str,
        actor: &str,
        at: u64,
    ) -> Result<&FindingRecord, String> {
        let finding = self
            .findings
            .iter_mut()
            .find(|f| f.finding_id == finding_id)
            .ok_or_else(|| format!("finding `{finding_id}` not found"))?;
        let old_state = finding.state.clone();
        if !old_state.can_transition_to(&new_state) {
            return Err(format!(
                "invalid transition from {} to {}",
                old_state.as_str(),
                new_state.as_str()
            ));
        }
        finding.transitions.push(FindingTransition {
            from_state: old_state.as_str().to_string(),
            to_state: new_state.as_str().to_string(),
            reason: reason.to_string(),
            at,
            actor: actor.to_string(),
        });
        finding.state = new_state.clone();
        if new_state == FindingState::Verified && finding.defense_classifications.is_empty() {
            finding.defense_classifications = finding.defense_classification_keys();
        }
        Ok(finding)
    }

    pub fn find_by_fingerprint(&self, fingerprint: &str) -> Option<&FindingRecord> {
        self.findings.iter().find(|f| f.fingerprint == fingerprint)
    }

    pub fn actionable_findings(&self) -> Vec<&FindingRecord> {
        self.findings
            .iter()
            .filter(|f| f.state.is_actionable())
            .collect()
    }

    pub fn reportable_findings(&self) -> Vec<&FindingRecord> {
        self.findings
            .iter()
            .filter(|f| f.state.is_reportable())
            .collect()
    }

    pub fn add_scan(&mut self, scan: ScanRecord) {
        self.scans.push(scan);
    }

    pub fn scan_by_id(&self, scan_id: &str) -> Option<&ScanRecord> {
        self.scans.iter().find(|s| s.scan_id == scan_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_finding() -> FindingRecord {
        FindingRecord {
            finding_id: "bola-user_a-inv_2002".to_string(),
            scan_id: "openapi-bola-1000000000".to_string(),
            fingerprint: "broken-object-level-authorization-get-api-invoices-id-user-a-inv-2002"
                .to_string(),
            classification: "BrokenObjectLevelAuthorization".to_string(),
            vulnerability_class: "broken_object_level_authorization".to_string(),
            endpoint: "GET /api/invoices/{id}".to_string(),
            object_id: "inv_2002".to_string(),
            owner_profile: "user_b".to_string(),
            tested_profile: "user_a".to_string(),
            severity: "high".to_string(),
            score: 7,
            state: FindingState::Verified,
            first_seen_run: "openapi-bola-1000000000".to_string(),
            last_seen_run: "openapi-bola-1000000000".to_string(),
            first_seen_at: 1000000000,
            last_seen_at: 1000000000,
            seen_count: 1,
            latest_artifacts: ".baloncore/runs/openapi-bola-1000000000".to_string(),
            latest_evidence_dir: ".baloncore/runs/openapi-bola-1000000000".to_string(),
            transitions: vec![FindingTransition {
                from_state: "hypothesis".to_string(),
                to_state: "verified".to_string(),
                reason: "promoted by validator".to_string(),
                at: 1000000000,
                actor: "bola-validator".to_string(),
            }],
            defense_classifications: vec![],
        }
    }

    #[test]
    fn finding_state_transitions() {
        assert!(FindingState::Hypothesis.can_transition_to(&FindingState::Verified));
        assert!(FindingState::Hypothesis.can_transition_to(&FindingState::Rejected));
        assert!(FindingState::Verified.can_transition_to(&FindingState::Reported));
        assert!(FindingState::Reported.can_transition_to(&FindingState::Fixed));
        assert!(FindingState::Fixed.can_transition_to(&FindingState::Retested));
        assert!(FindingState::Retested.can_transition_to(&FindingState::Closed));
        assert!(!FindingState::Closed.can_transition_to(&FindingState::Hypothesis));
        assert!(!FindingState::Rejected.can_transition_to(&FindingState::Verified));
    }

    #[test]
    fn store_upsert_and_find() {
        let mut store = FindingStore::new();
        let finding = test_finding();
        store.upsert_finding(finding.clone());
        assert_eq!(store.findings.len(), 1);
        let found = store.find_by_fingerprint(&finding.fingerprint).unwrap();
        assert_eq!(found.finding_id, finding.finding_id);
    }

    #[test]
    fn store_transition_finding() {
        let mut store = FindingStore::new();
        let finding = test_finding();
        store.upsert_finding(finding);
        let result = store.transition_finding(
            "bola-user_a-inv_2002",
            FindingState::Reported,
            "moved to reported after review",
            "analyst",
            2000000000,
        );
        assert!(result.is_ok());
        let found = store
            .find_by_fingerprint(
                "broken-object-level-authorization-get-api-invoices-id-user-a-inv-2002",
            )
            .unwrap();
        assert_eq!(found.state, FindingState::Reported);
        assert_eq!(found.transitions.len(), 2);
    }

    #[test]
    fn store_rejects_invalid_transition() {
        let mut store = FindingStore::new();
        let finding = test_finding();
        store.upsert_finding(finding);
        let result = store.transition_finding(
            "bola-user_a-inv_2002",
            FindingState::Hypothesis,
            "invalid backtrack",
            "bad-actor",
            2000000000,
        );
        assert!(result.is_err());
    }

    #[test]
    fn store_actionable_and_reportable_filters() {
        let mut store = FindingStore::new();
        let mut verified = test_finding();
        verified.state = FindingState::Verified;
        store.upsert_finding(verified);
        let mut rejected = test_finding();
        rejected.finding_id = "rejected-1".to_string();
        rejected.fingerprint = "rejected-fp-1".to_string();
        rejected.state = FindingState::Rejected;
        rejected.defense_classifications = vec![];
        store.upsert_finding(rejected);
        assert_eq!(store.actionable_findings().len(), 1);
        assert_eq!(store.reportable_findings().len(), 1);
    }

    #[test]
    fn store_add_scan_and_lookup() {
        let mut store = FindingStore::new();
        let scan = ScanRecord {
            scan_id: "scan-1".to_string(),
            started_at: 1000,
            finished_at: Some(2000),
            scan_type: "openapi-bola".to_string(),
            base_url: "http://127.0.0.1:3000".to_string(),
            owner_profile: "user_b".to_string(),
            matrix_profiles: vec!["user_a".to_string()],
            endpoints_imported: 5,
            candidates_considered: 2,
            validated_count: 4,
            verified_findings: 1,
            rejected_hypotheses: 3,
            suppressed_findings: 0,
            noise_mode: "moderate".to_string(),
            run_dir: ".baloncore/runs/scan-1".to_string(),
            findings: vec!["bola-user_a-inv_2002".to_string()],
        };
        store.add_scan(scan);
        assert!(store.scan_by_id("scan-1").is_some());
        assert!(store.scan_by_id("nonexistent").is_none());
    }

    #[test]
    fn defense_classifications_auto_attached_on_verified() {
        let mut store = FindingStore::new();
        let mut finding = test_finding();
        finding.state = FindingState::Hypothesis;
        finding.defense_classifications = vec![];
        store.upsert_finding(finding);
        let result = store.transition_finding(
            "bola-user_a-inv_2002",
            FindingState::Verified,
            "promoted by validator",
            "bola-validator",
            1000000000,
        );
        assert!(result.is_ok());
        let found = store
            .find_by_fingerprint(
                "broken-object-level-authorization-get-api-invoices-id-user-a-inv-2002",
            )
            .unwrap();
        assert!(!found.defense_classifications.is_empty());
        assert!(found
            .defense_classifications
            .contains(&"broken_object_level_authorization".to_string()));
    }

    #[test]
    fn defense_classification_keys_from_vulnerability_class() {
        let mut finding = test_finding();
        finding.vulnerability_class = "idor".to_string();
        finding.classification = "BrokenObjectLevelAuthorization".to_string();
        finding.defense_classifications = vec![];
        let keys = finding.defense_classification_keys();
        assert!(keys.contains(&"idor".to_string()));
    }
}
