use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlastRadiusPolicy {
    pub max_requests: u32,
    pub max_response_data_mb: f32,
    pub max_storage_writes_mb: f32,
    pub max_concurrent_connections: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanImpactEstimate {
    pub estimated_requests: u32,
    pub estimated_response_data_mb: f32,
    pub estimated_storage_writes_mb: f32,
    pub estimated_duration_minutes: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScanDepth {
    Light,
    Medium,
    Deep,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanImpactInput {
    pub endpoints: u32,
    pub average_parameters: u32,
    pub payload_variants: u32,
    pub average_response_kb: u32,
    pub depth: ScanDepth,
    pub authenticated: bool,
    pub tests_file_uploads: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlastRadiusDecision {
    pub approved: bool,
    pub estimate: ScanImpactEstimate,
    pub violations: Vec<String>,
    pub recommended_depth: ScanDepth,
}

impl Default for BlastRadiusPolicy {
    fn default() -> Self {
        Self {
            max_requests: 50_000,
            max_response_data_mb: 1_000.0,
            max_storage_writes_mb: 100.0,
            max_concurrent_connections: 100,
        }
    }
}

impl BlastRadiusPolicy {
    pub fn evaluate(&self, input: &ScanImpactInput) -> BlastRadiusDecision {
        let depth_multiplier = match input.depth {
            ScanDepth::Light => 0.3,
            ScanDepth::Medium => 1.0,
            ScanDepth::Deep => 3.0,
        };

        let auth_multiplier = if input.authenticated { 1.5 } else { 1.0 };
        let estimated_requests =
            ((input.endpoints * input.average_parameters * input.payload_variants) as f32
                * depth_multiplier
                * auth_multiplier)
                .ceil() as u32;

        let estimated_response_data_mb =
            estimated_requests as f32 * input.average_response_kb as f32 / 1024.0;
        let estimated_storage_writes_mb = if input.tests_file_uploads {
            input.endpoints as f32 * 0.5 * depth_multiplier
        } else {
            0.0
        };

        let estimate = ScanImpactEstimate {
            estimated_requests,
            estimated_response_data_mb: round_one(estimated_response_data_mb),
            estimated_storage_writes_mb: round_one(estimated_storage_writes_mb),
            estimated_duration_minutes: round_one(estimated_requests as f32 / 300.0),
        };

        let mut violations = Vec::new();
        if estimate.estimated_requests > self.max_requests {
            violations.push("estimated request count exceeds policy".to_string());
        }
        if estimate.estimated_response_data_mb > self.max_response_data_mb {
            violations.push("estimated response data exceeds policy".to_string());
        }
        if estimate.estimated_storage_writes_mb > self.max_storage_writes_mb {
            violations.push("estimated storage writes exceed policy".to_string());
        }

        let approved = violations.is_empty();
        let recommended_depth = if approved {
            input.depth.clone()
        } else {
            match input.depth {
                ScanDepth::Deep => ScanDepth::Medium,
                ScanDepth::Medium | ScanDepth::Light => ScanDepth::Light,
            }
        };

        BlastRadiusDecision {
            approved,
            estimate,
            violations,
            recommended_depth,
        }
    }
}

fn round_one(value: f32) -> f32 {
    (value * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approves_small_light_scans() {
        let decision = BlastRadiusPolicy::default().evaluate(&ScanImpactInput {
            endpoints: 10,
            average_parameters: 3,
            payload_variants: 5,
            average_response_kb: 20,
            depth: ScanDepth::Light,
            authenticated: false,
            tests_file_uploads: false,
        });

        assert!(decision.approved);
        assert!(decision.estimate.estimated_requests < 100);
    }

    #[test]
    fn reduces_depth_when_policy_is_exceeded() {
        let decision = BlastRadiusPolicy::default().evaluate(&ScanImpactInput {
            endpoints: 5_000,
            average_parameters: 10,
            payload_variants: 10,
            average_response_kb: 50,
            depth: ScanDepth::Deep,
            authenticated: true,
            tests_file_uploads: true,
        });

        assert!(!decision.approved);
        assert_eq!(decision.recommended_depth, ScanDepth::Medium);
    }
}
