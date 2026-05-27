use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttackChainRule {
    pub from_finding_type: &'static str,
    pub to_finding_type: &'static str,
    pub reasoning: &'static str,
    pub confidence: f32,
}

pub fn builtin_attack_chain_rules() -> Vec<AttackChainRule> {
    vec![
        AttackChainRule {
            from_finding_type: "open_redirect",
            to_finding_type: "oauth_token_theft",
            reasoning: "Open redirect can expose OAuth authorization codes when redirect URI validation is weak.",
            confidence: 0.85,
        },
        AttackChainRule {
            from_finding_type: "xss",
            to_finding_type: "csrf_bypass",
            reasoning: "Script execution can read or submit CSRF-protected flows in the victim context.",
            confidence: 0.80,
        },
        AttackChainRule {
            from_finding_type: "ssrf",
            to_finding_type: "cloud_metadata_access",
            reasoning: "Server-side request forgery can reach metadata services or internal control planes.",
            confidence: 0.90,
        },
        AttackChainRule {
            from_finding_type: "idor",
            to_finding_type: "tenant_data_exposure",
            reasoning: "Object authorization failure can expose cross-tenant data at scale.",
            confidence: 0.90,
        },
        AttackChainRule {
            from_finding_type: "credential_exposure",
            to_finding_type: "account_takeover",
            reasoning: "Exposed reusable credentials can allow direct account access.",
            confidence: 0.95,
        },
        AttackChainRule {
            from_finding_type: "weak_ci_identity",
            to_finding_type: "cloud_privilege_escalation",
            reasoning: "CI identities can become cloud principals when trust policy and permissions chain together.",
            confidence: 0.85,
        },
        AttackChainRule {
            from_finding_type: "oracle_manipulation",
            to_finding_type: "defi_accounting_break",
            reasoning: "Manipulated price input can violate collateral, liquidation, or share accounting assumptions.",
            confidence: 0.80,
        },
    ]
}
