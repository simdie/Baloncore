use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BusinessLogicAbuse {
    PriceTamper,
    StateSkip,
    Replay,
    QuantityLimitBypass,
}

impl BusinessLogicAbuse {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PriceTamper => "price_tamper",
            Self::StateSkip => "state_skip",
            Self::Replay => "replay",
            Self::QuantityLimitBypass => "quantity_limit_bypass",
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            Self::PriceTamper => "Business logic: price tampering",
            Self::StateSkip => "Business logic: state-skip bypass",
            Self::Replay => "Business logic: replay attack",
            Self::QuantityLimitBypass => "Business logic: quantity/limit bypass",
        }
    }

    pub fn security_property(&self) -> &'static str {
        match self {
            Self::PriceTamper => "A server must not accept a client-supplied price that differs from the authoritative price without explicit authorization.",
            Self::StateSkip => "A workflow must not allow skipping required prerequisite steps (e.g., paying before order is submitted).",
            Self::Replay => "A one-time action must not produce a duplicate effect when replayed with the same credentials.",
            Self::QuantityLimitBypass => "A server must not allow a client to exceed configured quantity or rate limits.",
        }
    }

    pub fn vulnerability_class(&self) -> &'static str {
        match self {
            Self::PriceTamper => "business_logic_price_tamper",
            Self::StateSkip => "business_logic_state_skip",
            Self::Replay => "business_logic_replay",
            Self::QuantityLimitBypass => "business_logic_quantity_limit_bypass",
        }
    }

    pub fn score(&self) -> u8 {
        match self {
            Self::PriceTamper => 70,
            Self::StateSkip => 72,
            Self::Replay => 68,
            Self::QuantityLimitBypass => 66,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowStep {
    pub step_name: String,
    pub method: String,
    pub url_template: String,
    pub body_template: Option<String>,
    pub expected_status: u16,
    pub preconditions: Vec<String>,
    pub state_field: Option<String>,
    pub state_expected_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowInvariant {
    pub abuse_type: BusinessLogicAbuse,
    pub description: String,
    pub workflow_name: String,
    pub steps: Vec<WorkflowStep>,
    pub invariant_field: String,
    pub tampered_value: Option<String>,
    pub legitimate_value: Option<String>,
    pub prerequisite_step: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BusinessLogicValidationCase {
    pub abuse_type: BusinessLogicAbuse,
    pub workflow_name: String,
    pub invariant_description: String,
    pub before_state: WorkflowState,
    pub after_state: WorkflowState,
    pub before_exchange: Option<WorkflowExchange>,
    pub after_exchange: WorkflowExchange,
    pub tampered_field: String,
    pub legitimate_value: String,
    pub tampered_value: String,
    pub profile: String,
    pub object_id: String,
    pub security_property: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WorkflowState {
    pub status: u16,
    pub body_excerpt: String,
    pub state_fields: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WorkflowExchange {
    pub id: String,
    pub step_name: String,
    pub profile: String,
    pub method: String,
    pub url: String,
    pub request_body_excerpt: String,
    pub response_status: u16,
    pub response_body_excerpt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BusinessLogicDecision {
    Verified(VerifiedBusinessLogicFinding),
    Rejected(RejectedBusinessLogicHypothesis),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerifiedBusinessLogicFinding {
    pub title: String,
    pub abuse_type: String,
    pub vulnerability_class: String,
    pub workflow_name: String,
    pub object_id: String,
    pub profile: String,
    pub tampered_field: String,
    pub legitimate_value: String,
    pub tampered_value: String,
    pub evidence_exchange_ids: Vec<String>,
    pub evidence_markers: Vec<String>,
    pub before_state_summary: String,
    pub after_state_summary: String,
    pub security_property: String,
    pub score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RejectedBusinessLogicHypothesis {
    pub reason: String,
    pub observations: Vec<String>,
}

pub struct BusinessLogicValidator {
    pub min_body_similarity: f32,
}

impl Default for BusinessLogicValidator {
    fn default() -> Self {
        Self {
            min_body_similarity: 0.50,
        }
    }
}

impl BusinessLogicValidator {
    pub fn validate(&self, case: &BusinessLogicValidationCase) -> BusinessLogicDecision {
        let mut observations = Vec::new();

        match case.abuse_type {
            BusinessLogicAbuse::PriceTamper => self.validate_price_tamper(case, &mut observations),
            BusinessLogicAbuse::StateSkip => self.validate_state_skip(case, &mut observations),
            BusinessLogicAbuse::Replay => self.validate_replay(case, &mut observations),
            BusinessLogicAbuse::QuantityLimitBypass => {
                self.validate_quantity_limit_bypass(case, &mut observations)
            }
        }
    }

    fn validate_price_tamper(
        &self,
        case: &BusinessLogicValidationCase,
        observations: &mut Vec<String>,
    ) -> BusinessLogicDecision {
        if !is_success_like(case.after_state.status) {
            return BusinessLogicDecision::Rejected(RejectedBusinessLogicHypothesis {
                reason: "tampered request was rejected by the server".to_string(),
                observations: vec![format!("after_status={}", case.after_state.status)],
            });
        }

        let after_body = case.after_state.body_excerpt.to_ascii_lowercase();
        let tampered_lower = case.tampered_value.to_ascii_lowercase();
        let legitimate_lower = case.legitimate_value.to_ascii_lowercase();

        let tampered_value_reflected = after_body.contains(&tampered_lower);
        let legitimate_value_overridden =
            tampered_value_reflected && !after_body.contains(&legitimate_lower);

        observations.push(format!(
            "tampered_value_reflected={tampered_value_reflected}"
        ));
        observations.push(format!(
            "legitimate_value_overridden={legitimate_value_overridden}"
        ));

        let before_had_legitimate = case
            .before_state
            .body_excerpt
            .to_ascii_lowercase()
            .contains(&legitimate_lower);

        if !tampered_value_reflected && !legitimate_value_overridden {
            return BusinessLogicDecision::Rejected(RejectedBusinessLogicHypothesis {
                reason: "tampered price was not reflected in the response; server likely validates price server-side".to_string(),
                observations: std::mem::take(observations),
            });
        }

        if before_had_legitimate && legitimate_value_overridden {
            let mut markers = vec![format!(
                "{}: tampered {} -> {}",
                case.tampered_field, case.legitimate_value, case.tampered_value
            )];
            if let Some(before) = &case.before_exchange {
                markers.push(format!(
                    "before_step:{}:status_{}",
                    before.step_name, before.response_status
                ));
            }
            markers.push(format!(
                "after_step:{}:status_{}",
                case.after_exchange.step_name, case.after_exchange.response_status
            ));

            return BusinessLogicDecision::Verified(VerifiedBusinessLogicFinding {
                title: case.abuse_type.title().to_string(),
                abuse_type: case.abuse_type.as_str().to_string(),
                vulnerability_class: case.abuse_type.vulnerability_class().to_string(),
                workflow_name: case.workflow_name.clone(),
                object_id: case.object_id.clone(),
                profile: case.profile.clone(),
                tampered_field: case.tampered_field.clone(),
                legitimate_value: case.legitimate_value.clone(),
                tampered_value: case.tampered_value.clone(),
                evidence_exchange_ids: if let Some(before) = &case.before_exchange {
                    vec![before.id.clone(), case.after_exchange.id.clone()]
                } else {
                    vec![case.after_exchange.id.clone()]
                },
                evidence_markers: markers,
                before_state_summary: summarize_state(&case.before_state),
                after_state_summary: summarize_state(&case.after_state),
                security_property: case.abuse_type.security_property().to_string(),
                score: case.abuse_type.score(),
            });
        }

        BusinessLogicDecision::Rejected(RejectedBusinessLogicHypothesis {
            reason: "tampered value reflected but did not override the legitimate value; server likely compares both".to_string(),
            observations: std::mem::take(observations),
        })
    }

    fn validate_state_skip(
        &self,
        case: &BusinessLogicValidationCase,
        observations: &mut Vec<String>,
    ) -> BusinessLogicDecision {
        if !is_success_like(case.after_state.status) {
            return BusinessLogicDecision::Rejected(RejectedBusinessLogicHypothesis {
                reason: "state-skip attempt was rejected by the server".to_string(),
                observations: vec![format!("after_status={}", case.after_state.status)],
            });
        }

        let after_state_fields = &case.after_state.state_fields;
        let before_state_fields = &case.before_state.state_fields;

        let after_state_value = after_state_fields
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == case.tampered_field.to_ascii_lowercase());
        let before_state_value = before_state_fields
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == case.tampered_field.to_ascii_lowercase());

        if let (Some((_, after_val)), Some((_, before_val))) =
            (after_state_value, before_state_value)
        {
            let tf = &case.tampered_field;
            observations.push(format!("before_{tf}={before_val}"));
            observations.push(format!("after_{tf}={after_val}"));

            let legitimate_lower = case.legitimate_value.to_ascii_lowercase();
            let tampered_lower = case.tampered_value.to_ascii_lowercase();

            if after_val.to_ascii_lowercase().contains(&tampered_lower)
                && !before_val.to_ascii_lowercase().contains(&tampered_lower)
            {
                let mut markers = vec![format!(
                    "{}: state skipped from {} to {}",
                    case.tampered_field, before_val, after_val
                )];
                if let Some(before) = &case.before_exchange {
                    markers.push(format!(
                        "before_step:{}:status_{}",
                        before.step_name, before.response_status
                    ));
                }
                markers.push(format!(
                    "after_step:{}:status_{}",
                    case.after_exchange.step_name, case.after_exchange.response_status
                ));

                return BusinessLogicDecision::Verified(VerifiedBusinessLogicFinding {
                    title: case.abuse_type.title().to_string(),
                    abuse_type: case.abuse_type.as_str().to_string(),
                    vulnerability_class: case.abuse_type.vulnerability_class().to_string(),
                    workflow_name: case.workflow_name.clone(),
                    object_id: case.object_id.clone(),
                    profile: case.profile.clone(),
                    tampered_field: case.tampered_field.clone(),
                    legitimate_value: before_val.clone(),
                    tampered_value: after_val.clone(),
                    evidence_exchange_ids: if let Some(before) = &case.before_exchange {
                        vec![before.id.clone(), case.after_exchange.id.clone()]
                    } else {
                        vec![case.after_exchange.id.clone()]
                    },
                    evidence_markers: markers,
                    before_state_summary: summarize_state(&case.before_state),
                    after_state_summary: summarize_state(&case.after_state),
                    security_property: case.abuse_type.security_property().to_string(),
                    score: case.abuse_type.score(),
                });
            }

            if after_val == before_val {
                return BusinessLogicDecision::Rejected(RejectedBusinessLogicHypothesis {
                    reason: "state did not change after skip attempt; server enforces prerequisite steps".to_string(),
                    observations: std::mem::take(observations),
                });
            }

            if after_val.to_ascii_lowercase() == legitimate_lower {
                return BusinessLogicDecision::Rejected(RejectedBusinessLogicHypothesis {
                    reason: "state changed to legitimate value; server enforced correct transition"
                        .to_string(),
                    observations: std::mem::take(observations),
                });
            }
        }

        let after_body = case.after_state.body_excerpt.to_ascii_lowercase();
        let tampered_lower = case.tampered_value.to_ascii_lowercase();
        if after_body.contains(&tampered_lower) {
            return BusinessLogicDecision::Verified(VerifiedBusinessLogicFinding {
                title: case.abuse_type.title().to_string(),
                abuse_type: case.abuse_type.as_str().to_string(),
                vulnerability_class: case.abuse_type.vulnerability_class().to_string(),
                workflow_name: case.workflow_name.clone(),
                object_id: case.object_id.clone(),
                profile: case.profile.clone(),
                tampered_field: case.tampered_field.clone(),
                legitimate_value: case.legitimate_value.clone(),
                tampered_value: case.tampered_value.clone(),
                evidence_exchange_ids: if let Some(before) = &case.before_exchange {
                    vec![before.id.clone(), case.after_exchange.id.clone()]
                } else {
                    vec![case.after_exchange.id.clone()]
                },
                evidence_markers: vec![format!(
                    "{}: tampered value {} reflected in response",
                    case.tampered_field, case.tampered_value
                )],
                before_state_summary: summarize_state(&case.before_state),
                after_state_summary: summarize_state(&case.after_state),
                security_property: case.abuse_type.security_property().to_string(),
                score: case.abuse_type.score(),
            });
        }

        BusinessLogicDecision::Rejected(RejectedBusinessLogicHypothesis {
            reason: "state-skip attempt did not produce the expected state change; server likely validates state transitions".to_string(),
            observations: std::mem::take(observations),
        })
    }

    fn validate_replay(
        &self,
        case: &BusinessLogicValidationCase,
        observations: &mut Vec<String>,
    ) -> BusinessLogicDecision {
        if !is_success_like(case.after_state.status) {
            return BusinessLogicDecision::Rejected(RejectedBusinessLogicHypothesis {
                reason: "replayed request was rejected by the server".to_string(),
                observations: vec![format!("replay_status={}", case.after_state.status)],
            });
        }

        let after_body = case.after_state.body_excerpt.to_ascii_lowercase();
        let object_lower = case.object_id.to_ascii_lowercase();

        observations.push(format!(
            "replay_returned_success={}",
            is_success_like(case.after_state.status)
        ));
        observations.push(format!(
            "response_contains_object_ref={}",
            after_body.contains(&object_lower)
        ));

        let server_detects_duplicate = after_body.contains("duplicate")
            || after_body.contains("already_processed")
            || after_body.contains("idempotency")
            || after_body.contains("conflict");

        if server_detects_duplicate {
            return BusinessLogicDecision::Rejected(RejectedBusinessLogicHypothesis {
                reason: "replayed request appears to have been detected; server returned duplicate indicator".to_string(),
                observations: std::mem::take(observations),
            });
        }

        let state_changed = case.after_state.state_fields.iter().any(|(k, v)| {
            let k_lower = k.to_ascii_lowercase();
            let before_val = case
                .before_state
                .state_fields
                .iter()
                .find(|(bk, _)| bk.to_ascii_lowercase() == k_lower);
            (k_lower.contains("count")
                || k_lower.contains("total")
                || k_lower.contains("quantity")
                || k_lower.contains("status"))
                && before_val.map_or(true, |(_, bv)| bv != v)
        });

        if state_changed {
            return BusinessLogicDecision::Verified(VerifiedBusinessLogicFinding {
                title: case.abuse_type.title().to_string(),
                abuse_type: case.abuse_type.as_str().to_string(),
                vulnerability_class: case.abuse_type.vulnerability_class().to_string(),
                workflow_name: case.workflow_name.clone(),
                object_id: case.object_id.clone(),
                profile: case.profile.clone(),
                tampered_field: case.tampered_field.clone(),
                legitimate_value: case.legitimate_value.clone(),
                tampered_value: case.tampered_value.clone(),
                evidence_exchange_ids: if let Some(before) = &case.before_exchange {
                    vec![before.id.clone(), case.after_exchange.id.clone()]
                } else {
                    vec![case.after_exchange.id.clone()]
                },
                evidence_markers: vec![format!(
                    "replay: repeated action on {} produced duplicate effect (state changed)",
                    case.object_id
                )],
                before_state_summary: summarize_state(&case.before_state),
                after_state_summary: summarize_state(&case.after_state),
                security_property: case.abuse_type.security_property().to_string(),
                score: case.abuse_type.score(),
            });
        }

        BusinessLogicDecision::Rejected(RejectedBusinessLogicHypothesis {
            reason: "no evidence that replay produced a duplicate effect; server likely enforces idempotency".to_string(),
            observations: std::mem::take(observations),
        })
    }

    fn validate_quantity_limit_bypass(
        &self,
        case: &BusinessLogicValidationCase,
        observations: &mut Vec<String>,
    ) -> BusinessLogicDecision {
        if !is_success_like(case.after_state.status) {
            return BusinessLogicDecision::Rejected(RejectedBusinessLogicHypothesis {
                reason: "quantity bypass request was rejected by the server".to_string(),
                observations: vec![format!("after_status={}", case.after_state.status)],
            });
        }

        let after_body = case.after_state.body_excerpt.to_ascii_lowercase();
        let tampered_lower = case.tampered_value.to_ascii_lowercase();
        let legitimate_lower = case.legitimate_value.to_ascii_lowercase();

        let tampered_reflected = after_body.contains(&tampered_lower);
        let legitimate_overridden = tampered_reflected && !after_body.contains(&legitimate_lower);

        observations.push(format!("tampered_reflected={tampered_reflected}"));
        observations.push(format!("legitimate_overridden={legitimate_overridden}"));

        if !tampered_reflected {
            return BusinessLogicDecision::Rejected(RejectedBusinessLogicHypothesis {
                reason:
                    "tampered quantity was not reflected; server likely enforces limits server-side"
                        .to_string(),
                observations: std::mem::take(observations),
            });
        }

        if legitimate_overridden {
            return BusinessLogicDecision::Verified(VerifiedBusinessLogicFinding {
                title: case.abuse_type.title().to_string(),
                abuse_type: case.abuse_type.as_str().to_string(),
                vulnerability_class: case.abuse_type.vulnerability_class().to_string(),
                workflow_name: case.workflow_name.clone(),
                object_id: case.object_id.clone(),
                profile: case.profile.clone(),
                tampered_field: case.tampered_field.clone(),
                legitimate_value: case.legitimate_value.clone(),
                tampered_value: case.tampered_value.clone(),
                evidence_exchange_ids: if let Some(before) = &case.before_exchange {
                    vec![before.id.clone(), case.after_exchange.id.clone()]
                } else {
                    vec![case.after_exchange.id.clone()]
                },
                evidence_markers: vec![format!(
                    "{}: quantity/limit bypassed from {} to {}",
                    case.tampered_field, case.legitimate_value, case.tampered_value
                )],
                before_state_summary: summarize_state(&case.before_state),
                after_state_summary: summarize_state(&case.after_state),
                security_property: case.abuse_type.security_property().to_string(),
                score: case.abuse_type.score(),
            });
        } else {
            BusinessLogicDecision::Rejected(RejectedBusinessLogicHypothesis {
                reason: "tampered quantity reflected but did not override the limit; server likely validates server-side".to_string(),
                observations: std::mem::take(observations),
            })
        }
    }
}

fn is_success_like(status: u16) -> bool {
    (200..300).contains(&status)
}

fn summarize_state(state: &WorkflowState) -> String {
    let fields: Vec<String> = state
        .state_fields
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    format!("status_{} {{{}}}", state.status, fields.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_exchange(id: &str, step: &str, status: u16, body: &str) -> WorkflowExchange {
        WorkflowExchange {
            id: id.to_string(),
            step_name: step.to_string(),
            profile: "member_a".to_string(),
            method: "POST".to_string(),
            url: "http://localhost:3010/api/orders".to_string(),
            request_body_excerpt: "{}".to_string(),
            response_status: status,
            response_body_excerpt: body.to_string(),
        }
    }

    fn make_state(status: u16, body: &str, fields: Vec<(&str, &str)>) -> WorkflowState {
        WorkflowState {
            status,
            body_excerpt: body.to_string(),
            state_fields: fields
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn price_tamper_verified_when_tampered_price_overrides() {
        let case = BusinessLogicValidationCase {
            abuse_type: BusinessLogicAbuse::PriceTamper,
            workflow_name: "order_creation".to_string(),
            invariant_description: "Server must not accept client-supplied price".to_string(),
            before_state: make_state(
                200,
                r#"{"id":"ord-1","total_usd":"29.99"}"#,
                vec![("total_usd", "29.99")],
            ),
            after_state: make_state(
                200,
                r#"{"id":"ord-1","total_usd":"0.01"}"#,
                vec![("total_usd", "0.01")],
            ),
            before_exchange: Some(make_exchange(
                "step-create",
                "create_order",
                200,
                r#"{"id":"ord-1","total_usd":"29.99"}"#,
            )),
            after_exchange: make_exchange(
                "step-tamper",
                "tamper_price",
                200,
                r#"{"id":"ord-1","total_usd":"0.01"}"#,
            ),
            tampered_field: "total_usd".to_string(),
            legitimate_value: "29.99".to_string(),
            tampered_value: "0.01".to_string(),
            profile: "member_a".to_string(),
            object_id: "ord-1".to_string(),
            security_property: BusinessLogicAbuse::PriceTamper
                .security_property()
                .to_string(),
        };
        let validator = BusinessLogicValidator::default();
        let decision = validator.validate(&case);
        match decision {
            BusinessLogicDecision::Verified(finding) => {
                assert_eq!(finding.abuse_type, "price_tamper");
                assert_eq!(finding.vulnerability_class, "business_logic_price_tamper");
                assert_eq!(finding.legitimate_value, "29.99");
                assert_eq!(finding.tampered_value, "0.01");
                assert!(finding.score >= 70);
                assert!(!finding.evidence_markers.is_empty());
            }
            BusinessLogicDecision::Rejected(reason) => {
                panic!("expected verified price tampering, got rejected: {reason:?}");
            }
        }
    }

    #[test]
    fn price_tamper_rejected_when_server_validates() {
        let case = BusinessLogicValidationCase {
            abuse_type: BusinessLogicAbuse::PriceTamper,
            workflow_name: "order_creation".to_string(),
            invariant_description: "Server must not accept client-supplied price".to_string(),
            before_state: make_state(
                200,
                r#"{"id":"ord-2","total_usd":2999}"#,
                vec![("total_usd", "29.99")],
            ),
            after_state: make_state(
                200,
                r#"{"id":"ord-2","total_usd":2999}"#,
                vec![("total_usd", "29.99")],
            ),
            before_exchange: Some(make_exchange(
                "step-create",
                "create_order",
                200,
                r#"{"id":"ord-2","total_usd":2999}"#,
            )),
            after_exchange: make_exchange(
                "step-tamper",
                "tamper_price",
                200,
                r#"{"id":"ord-2","total_usd":2999}"#,
            ),
            tampered_field: "total_usd".to_string(),
            legitimate_value: "29.99".to_string(),
            tampered_value: "0.01".to_string(),
            profile: "member_a".to_string(),
            object_id: "ord-2".to_string(),
            security_property: BusinessLogicAbuse::PriceTamper
                .security_property()
                .to_string(),
        };
        let validator = BusinessLogicValidator::default();
        let decision = validator.validate(&case);
        match decision {
            BusinessLogicDecision::Rejected(reason) => {
                assert!(
                    reason.reason.contains("not reflected") || reason.reason.contains("validates")
                );
            }
            BusinessLogicDecision::Verified(finding) => {
                panic!("expected rejection for server-validated price, got verified: {finding:?}");
            }
        }
    }

    #[test]
    fn price_tamper_rejected_when_server_rejects_request() {
        let case = BusinessLogicValidationCase {
            abuse_type: BusinessLogicAbuse::PriceTamper,
            workflow_name: "order_creation".to_string(),
            invariant_description: "Server must not accept client-supplied price".to_string(),
            before_state: make_state(
                200,
                r#"{"id":"ord-3","total_usd":2999}"#,
                vec![("total_usd", "29.99")],
            ),
            after_state: make_state(400, r#"{"error":"invalid price"}"#, vec![]),
            before_exchange: Some(make_exchange(
                "step-create",
                "create_order",
                200,
                r#"{"id":"ord-3"}"#,
            )),
            after_exchange: make_exchange(
                "step-tamper",
                "tamper_price",
                400,
                r#"{"error":"invalid price"}"#,
            ),
            tampered_field: "total_usd".to_string(),
            legitimate_value: "29.99".to_string(),
            tampered_value: "0.01".to_string(),
            profile: "member_a".to_string(),
            object_id: "ord-3".to_string(),
            security_property: BusinessLogicAbuse::PriceTamper
                .security_property()
                .to_string(),
        };
        let validator = BusinessLogicValidator::default();
        let decision = validator.validate(&case);
        match decision {
            BusinessLogicDecision::Rejected(reason) => {
                assert!(reason.reason.contains("rejected"));
            }
            BusinessLogicDecision::Verified(_) => {
                panic!("expected rejection when server rejects tampered request");
            }
        }
    }

    #[test]
    fn state_skip_verified_when_forbidden_state_reached() {
        let case = BusinessLogicValidationCase {
            abuse_type: BusinessLogicAbuse::StateSkip,
            workflow_name: "order_fulfillment".to_string(),
            invariant_description: "Must complete payment before shipping".to_string(),
            before_state: make_state(
                200,
                r#"{"id":"ord-4","status":"draft"}"#,
                vec![("status", "draft")],
            ),
            after_state: make_state(
                200,
                r#"{"id":"ord-4","status":"shipped"}"#,
                vec![("status", "shipped")],
            ),
            before_exchange: Some(make_exchange(
                "step-submit",
                "submit_order",
                200,
                r#"{"id":"ord-4","status":"draft"}"#,
            )),
            after_exchange: make_exchange(
                "step-skip",
                "ship_without_payment",
                200,
                r#"{"id":"ord-4","status":"shipped"}"#,
            ),
            tampered_field: "status".to_string(),
            legitimate_value: "paid".to_string(),
            tampered_value: "shipped".to_string(),
            profile: "member_a".to_string(),
            object_id: "ord-4".to_string(),
            security_property: BusinessLogicAbuse::StateSkip
                .security_property()
                .to_string(),
        };
        let validator = BusinessLogicValidator::default();
        let decision = validator.validate(&case);
        match decision {
            BusinessLogicDecision::Verified(finding) => {
                assert_eq!(finding.abuse_type, "state_skip");
                assert_eq!(finding.vulnerability_class, "business_logic_state_skip");
                assert!(finding
                    .evidence_markers
                    .iter()
                    .any(|m| m.contains("state skipped")));
            }
            BusinessLogicDecision::Rejected(reason) => {
                panic!("expected verified state skip, got rejected: {reason:?}");
            }
        }
    }

    #[test]
    fn state_skip_rejected_when_state_does_not_change() {
        let case = BusinessLogicValidationCase {
            abuse_type: BusinessLogicAbuse::StateSkip,
            workflow_name: "order_fulfillment".to_string(),
            invariant_description: "Must complete payment before shipping".to_string(),
            before_state: make_state(
                200,
                r#"{"id":"ord-5","status":"draft"}"#,
                vec![("status", "draft")],
            ),
            after_state: make_state(
                200,
                r#"{"id":"ord-5","status":"draft","error":"cannot skip to shipped"}"#,
                vec![("status", "draft")],
            ),
            before_exchange: Some(make_exchange(
                "step-submit",
                "submit_order",
                200,
                r#"{"id":"ord-5"}"#,
            )),
            after_exchange: make_exchange(
                "step-skip",
                "ship_without_payment",
                200,
                r#"{"id":"ord-5","status":"draft","error":"cannot skip to shipped"}"#,
            ),
            tampered_field: "status".to_string(),
            legitimate_value: "paid".to_string(),
            tampered_value: "shipped".to_string(),
            profile: "member_a".to_string(),
            object_id: "ord-5".to_string(),
            security_property: BusinessLogicAbuse::StateSkip
                .security_property()
                .to_string(),
        };
        let validator = BusinessLogicValidator::default();
        let decision = validator.validate(&case);
        match decision {
            BusinessLogicDecision::Rejected(reason) => {
                assert!(
                    reason.reason.contains("did not change") || reason.reason.contains("enforces")
                );
            }
            BusinessLogicDecision::Verified(_) => {
                panic!("expected rejection when state does not change");
            }
        }
    }

    #[test]
    fn replay_verified_when_duplicate_effect_observed() {
        let case = BusinessLogicValidationCase {
            abuse_type: BusinessLogicAbuse::Replay,
            workflow_name: "payment_processing".to_string(),
            invariant_description: "One-time payment must not be charged twice".to_string(),
            before_state: make_state(
                200,
                r#"{"id":"pay-1","amount_usd":100,"status":"completed","charge_count":1}"#,
                vec![("charge_count", "1")],
            ),
            after_state: make_state(
                200,
                r#"{"id":"pay-1","amount_usd":100,"status":"completed","charge_count":2}"#,
                vec![("charge_count", "2")],
            ),
            before_exchange: Some(make_exchange(
                "step-first",
                "submit_payment",
                200,
                r#"{"id":"pay-1","charge_count":1}"#,
            )),
            after_exchange: make_exchange(
                "step-replay",
                "replay_payment",
                200,
                r#"{"id":"pay-1","charge_count":2}"#,
            ),
            tampered_field: "charge_count".to_string(),
            legitimate_value: "1".to_string(),
            tampered_value: "2".to_string(),
            profile: "member_a".to_string(),
            object_id: "pay-1".to_string(),
            security_property: BusinessLogicAbuse::Replay.security_property().to_string(),
        };
        let validator = BusinessLogicValidator::default();
        let decision = validator.validate(&case);
        match decision {
            BusinessLogicDecision::Verified(finding) => {
                assert_eq!(finding.abuse_type, "replay");
                assert!(finding
                    .evidence_markers
                    .iter()
                    .any(|m| m.contains("duplicate")));
            }
            BusinessLogicDecision::Rejected(reason) => {
                panic!("expected verified replay, got rejected: {reason:?}");
            }
        }
    }

    #[test]
    fn replay_rejected_when_server_detects_duplicate() {
        let case = BusinessLogicValidationCase {
            abuse_type: BusinessLogicAbuse::Replay,
            workflow_name: "payment_processing".to_string(),
            invariant_description: "One-time payment must not be charged twice".to_string(),
            before_state: make_state(
                200,
                r#"{"id":"pay-2","amount_usd":100,"status":"completed"}"#,
                vec![("charge_count", "1")],
            ),
            after_state: make_state(
                200,
                r#"{"id":"pay-2","amount_usd":100,"status":"already_processed","duplicate":true}"#,
                vec![("charge_count", "1")],
            ),
            before_exchange: Some(make_exchange(
                "step-first",
                "submit_payment",
                200,
                r#"{"id":"pay-2"}"#,
            )),
            after_exchange: make_exchange(
                "step-replay",
                "replay_payment",
                200,
                r#"{"id":"pay-2","duplicate":true}"#,
            ),
            tampered_field: "charge_count".to_string(),
            legitimate_value: "1".to_string(),
            tampered_value: "2".to_string(),
            profile: "member_a".to_string(),
            object_id: "pay-2".to_string(),
            security_property: BusinessLogicAbuse::Replay.security_property().to_string(),
        };
        let validator = BusinessLogicValidator::default();
        let decision = validator.validate(&case);
        match decision {
            BusinessLogicDecision::Rejected(reason) => {
                assert!(
                    reason.reason.contains("duplicate") || reason.reason.contains("idempotency")
                );
            }
            BusinessLogicDecision::Verified(_) => {
                panic!("expected rejection when server detects duplicate");
            }
        }
    }

    #[test]
    fn quantity_limit_bypass_verified_when_tampered_quantity_overrides() {
        let case = BusinessLogicValidationCase {
            abuse_type: BusinessLogicAbuse::QuantityLimitBypass,
            workflow_name: "order_creation".to_string(),
            invariant_description: "Server must not allow quantity above limit".to_string(),
            before_state: make_state(
                200,
                r#"{"id":"ord-6","quantity":1}"#,
                vec![("quantity", "1")],
            ),
            after_state: make_state(
                200,
                r#"{"id":"ord-6","quantity":9999}"#,
                vec![("quantity", "9999")],
            ),
            before_exchange: Some(make_exchange(
                "step-create",
                "create_order",
                200,
                r#"{"id":"ord-6"}"#,
            )),
            after_exchange: make_exchange(
                "step-bypass",
                "bypass_limit",
                200,
                r#"{"id":"ord-6","quantity":9999}"#,
            ),
            tampered_field: "quantity".to_string(),
            legitimate_value: "1".to_string(),
            tampered_value: "9999".to_string(),
            profile: "member_a".to_string(),
            object_id: "ord-6".to_string(),
            security_property: BusinessLogicAbuse::QuantityLimitBypass
                .security_property()
                .to_string(),
        };
        let validator = BusinessLogicValidator::default();
        let decision = validator.validate(&case);
        match decision {
            BusinessLogicDecision::Verified(finding) => {
                assert_eq!(finding.abuse_type, "quantity_limit_bypass");
                assert_eq!(finding.legitimate_value, "1");
                assert_eq!(finding.tampered_value, "9999");
            }
            BusinessLogicDecision::Rejected(reason) => {
                panic!("expected verified quantity bypass, got rejected: {reason:?}");
            }
        }
    }

    #[test]
    fn quantity_limit_bypass_rejected_when_server_enforces() {
        let case = BusinessLogicValidationCase {
            abuse_type: BusinessLogicAbuse::QuantityLimitBypass,
            workflow_name: "order_creation".to_string(),
            invariant_description: "Server must not allow quantity above limit".to_string(),
            before_state: make_state(
                200,
                r#"{"id":"ord-7","quantity":1}"#,
                vec![("quantity", "1")],
            ),
            after_state: make_state(
                200,
                r#"{"id":"ord-7","quantity":1,"error":"quantity exceeds limit"}"#,
                vec![("quantity", "1")],
            ),
            before_exchange: Some(make_exchange(
                "step-create",
                "create_order",
                200,
                r#"{"id":"ord-7"}"#,
            )),
            after_exchange: make_exchange(
                "step-bypass",
                "bypass_limit",
                200,
                r#"{"id":"ord-7","quantity":1,"error":"quantity exceeds limit"}"#,
            ),
            tampered_field: "quantity".to_string(),
            legitimate_value: "1".to_string(),
            tampered_value: "9999".to_string(),
            profile: "member_a".to_string(),
            object_id: "ord-7".to_string(),
            security_property: BusinessLogicAbuse::QuantityLimitBypass
                .security_property()
                .to_string(),
        };
        let validator = BusinessLogicValidator::default();
        let decision = validator.validate(&case);
        match decision {
            BusinessLogicDecision::Rejected(reason) => {
                assert!(
                    reason.reason.contains("not reflected") || reason.reason.contains("validates")
                );
            }
            BusinessLogicDecision::Verified(_) => {
                panic!("expected rejection when server enforces quantity limit");
            }
        }
    }

    #[test]
    fn abuse_type_properties() {
        assert_eq!(BusinessLogicAbuse::PriceTamper.as_str(), "price_tamper");
        assert_eq!(BusinessLogicAbuse::StateSkip.as_str(), "state_skip");
        assert_eq!(BusinessLogicAbuse::Replay.as_str(), "replay");
        assert_eq!(
            BusinessLogicAbuse::QuantityLimitBypass.as_str(),
            "quantity_limit_bypass"
        );
        assert!(BusinessLogicAbuse::PriceTamper.score() > 0);
        assert!(!BusinessLogicAbuse::StateSkip.security_property().is_empty());
        assert!(!BusinessLogicAbuse::Replay.vulnerability_class().is_empty());
    }

    #[test]
    fn decoy_workflow_not_flagged() {
        let case = BusinessLogicValidationCase {
            abuse_type: BusinessLogicAbuse::PriceTamper,
            workflow_name: "order_creation".to_string(),
            invariant_description: "Server must not accept client-supplied price".to_string(),
            before_state: make_state(
                200,
                r#"{"id":"ord-decoy","total_usd":5000}"#,
                vec![("total_usd", "50.00")],
            ),
            after_state: make_state(
                400,
                r#"{"error":"total_usd must match product price"}"#,
                vec![],
            ),
            before_exchange: Some(make_exchange(
                "step-create",
                "create_order",
                200,
                r#"{"id":"ord-decoy"}"#,
            )),
            after_exchange: make_exchange(
                "step-tamper",
                "tamper_price",
                400,
                r#"{"error":"total_usd must match product price"}"#,
            ),
            tampered_field: "total_usd".to_string(),
            legitimate_value: "50.00".to_string(),
            tampered_value: "0.01".to_string(),
            profile: "member_a".to_string(),
            object_id: "ord-decoy".to_string(),
            security_property: BusinessLogicAbuse::PriceTamper
                .security_property()
                .to_string(),
        };
        let validator = BusinessLogicValidator::default();
        let decision = validator.validate(&case);
        match decision {
            BusinessLogicDecision::Rejected(reason) => {
                assert!(reason.reason.contains("rejected"));
            }
            BusinessLogicDecision::Verified(_) => {
                panic!("decoy workflow must not be flagged as verified");
            }
        }
    }
}
