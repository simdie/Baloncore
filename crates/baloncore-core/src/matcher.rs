use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatcherSpec {
    pub slug: String,
    pub title: String,
    pub noise_tier: NoiseTier,
    pub file_patterns: Vec<String>,
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NoiseTier {
    Precise,
    Normal,
    Noisy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CandidateMatch {
    pub matcher_slug: String,
    pub target_ref: String,
    pub line_numbers: Vec<u32>,
    pub snippet: String,
    pub matched_label: String,
}

impl MatcherSpec {
    pub fn should_prioritize_before(&self, other: &Self) -> bool {
        self.noise_tier.priority() < other.noise_tier.priority()
    }
}

impl NoiseTier {
    fn priority(&self) -> u8 {
        match self {
            NoiseTier::Precise => 0,
            NoiseTier::Normal => 1,
            NoiseTier::Noisy => 2,
        }
    }
}
