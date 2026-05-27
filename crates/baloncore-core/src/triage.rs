use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TriageGateInput {
    pub has_reproducible_request: bool,
    pub impact_is_accepted: bool,
    pub asset_is_in_scope: bool,
    pub attacker_access_is_realistic: bool,
    pub known_duplicate_or_intended_behavior: bool,
    pub impact_proven_beyond_technical_possibility: bool,
    pub matches_never_submit_class: bool,
    pub requires_chain: bool,
    pub chain_is_proven: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TriageVerdict {
    ReadyForValidation,
    NeedsMoreEvidence,
    NeedsChain,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TriageDecision {
    pub verdict: TriageVerdict,
    pub failed_gate: Option<&'static str>,
    pub reason: String,
}

pub fn seven_question_gate(input: &TriageGateInput) -> TriageDecision {
    if !input.has_reproducible_request {
        return reject(
            "q1_reproducible_request",
            "no copy-pasteable proof request exists",
        );
    }
    if !input.impact_is_accepted {
        return reject(
            "q2_accepted_impact",
            "impact is excluded or not accepted by the program",
        );
    }
    if !input.asset_is_in_scope {
        return reject("q3_scope", "affected asset is outside configured scope");
    }
    if !input.attacker_access_is_realistic {
        return reject(
            "q4_realistic_access",
            "required privileges or preconditions are not attacker-realistic",
        );
    }
    if input.known_duplicate_or_intended_behavior {
        return reject(
            "q5_duplicate_or_intended",
            "behavior appears known, duplicate, or intentionally documented",
        );
    }
    if !input.impact_proven_beyond_technical_possibility {
        return TriageDecision {
            verdict: TriageVerdict::NeedsMoreEvidence,
            failed_gate: Some("q6_impact_proof"),
            reason: "technical behavior exists, but concrete security impact is not proven"
                .to_string(),
        };
    }
    if input.matches_never_submit_class && !input.chain_is_proven {
        return reject(
            "q7_never_submit",
            "finding class is normally invalid unless chained to concrete impact",
        );
    }
    if input.requires_chain && !input.chain_is_proven {
        return TriageDecision {
            verdict: TriageVerdict::NeedsChain,
            failed_gate: Some("chain_required"),
            reason: "finding needs a proven chain before it can become reportable".to_string(),
        };
    }

    TriageDecision {
        verdict: TriageVerdict::ReadyForValidation,
        failed_gate: None,
        reason: "finding passed triage and should enter deterministic validation".to_string(),
    }
}

fn reject(failed_gate: &'static str, reason: &str) -> TriageDecision {
    TriageDecision {
        verdict: TriageVerdict::Reject,
        failed_gate: Some(failed_gate),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_input() -> TriageGateInput {
        TriageGateInput {
            has_reproducible_request: true,
            impact_is_accepted: true,
            asset_is_in_scope: true,
            attacker_access_is_realistic: true,
            known_duplicate_or_intended_behavior: false,
            impact_proven_beyond_technical_possibility: true,
            matches_never_submit_class: false,
            requires_chain: false,
            chain_is_proven: false,
        }
    }

    #[test]
    fn promotes_valid_findings_to_validation() {
        let decision = seven_question_gate(&valid_input());
        assert_eq!(decision.verdict, TriageVerdict::ReadyForValidation);
    }

    #[test]
    fn rejects_out_of_scope_assets() {
        let mut input = valid_input();
        input.asset_is_in_scope = false;
        let decision = seven_question_gate(&input);
        assert_eq!(decision.verdict, TriageVerdict::Reject);
        assert_eq!(decision.failed_gate, Some("q3_scope"));
    }

    #[test]
    fn asks_for_chain_when_standalone_impact_is_weak() {
        let mut input = valid_input();
        input.requires_chain = true;
        input.chain_is_proven = false;
        let decision = seven_question_gate(&input);
        assert_eq!(decision.verdict, TriageVerdict::NeedsChain);
    }
}
