use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScanStage {
    Intake,
    ScopeCheck,
    CandidateDiscovery,
    AiProcess,
    DeterministicValidate,
    Revalidate,
    Enrich,
    Report,
    Defend,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingLifecycle {
    Candidate,
    Hypothesis,
    Rejected,
    NeedsMoreEvidence,
    NeedsChain,
    Verified,
    RevalidatedTruePositive,
    RevalidatedFalsePositive,
    Fixed,
    Reported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PipelineEvent {
    pub run_id: String,
    pub stage: ScanStage,
    pub subject: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnalysisRecord {
    pub subject: String,
    pub lifecycle: FindingLifecycle,
    pub events: Vec<PipelineEvent>,
}

impl AnalysisRecord {
    pub fn append_event(&mut self, event: PipelineEvent) {
        self.events.push(event);
    }
}
