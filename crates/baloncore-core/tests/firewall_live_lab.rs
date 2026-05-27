//! T1.a — Live-lab adversarial firewall test.
//!
//! V0_GROUND_TRUTH.md (P1.S5 row) flagged that BALONCORE's existing firewall
//! tests only proved the *structural* pre-filter (`challenge_hypotheses` blocks
//! hypotheses with no endpoint / no evidence_refs / low confidence). The
//! product's central "model proposes, validators prove" claim demands more:
//! even a schema-clean, confident, well-formed FALSE hypothesis on a real
//! endpoint must not become a sealed `Verified` finding.
//!
//! This test:
//!   1. Spins up a tiny in-process HTTP server that mimics a protected admin
//!      endpoint: an admin bearer token gets 200 + admin body, every other
//!      caller gets 403 (the "lab" 403 path).
//!   2. Has a stub `ModelClient` emit a confident, schema-clean false BOLA
//!      hypothesis on that endpoint (with endpoint + evidence_refs +
//!      confidence = 0.95, i.e. ALL fields the structural pre-filter wants).
//!   3. Drives the hypothesis through `run_live_agent_pipeline` and confirms
//!      it passes the pre-filter (`eligible_for_validation == true`).
//!   4. Runs the *real* deterministic validator (`BolaValidator::default`)
//!      against the live exchanges (owner = admin → 200, attacker = user →
//!      403, anonymous → 403) using the real `HttpRequestRunner`.
//!   5. Asserts the decision is `Rejected`, NOT `Verified` — proving that a
//!      confident, well-formed model claim CANNOT become a sealed finding
//!      without the live validator agreeing.
//!   6. Also asserts `classify_with_tenant` returns `BlockedAsExpected`,
//!      NOT `BrokenObjectLevelAuthorization`.
//!
//! Mutation procedure (documented; not part of CI to keep the test cheap):
//!   - To prove the firewall is real, temporarily weaken
//!     `BolaValidator::validate` so it skips the
//!     `is_success_like(attacker_status)` guard. Re-run this test → RED
//!     (the validator now wrongly promotes the false claim). Restore → GREEN.
//!   - See PROGRESS.md T1.a mutation log.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use baloncore_core::agent::{
    AgentHypothesis, AgentInput, AgentOutput, AgentOutputStatus, ModelConfig,
};
use baloncore_core::agent_runtime::{run_live_agent_pipeline, ModelBudget};
use baloncore_core::model_client::{
    ModelClient, ModelError, ModelRequest, ModelResponse, ModelUsage,
};
use baloncore_core::web_api::{
    ApiEndpoint, AuthorizationClass, AuthorizationMatrixObservation, BolaDecision,
    BolaValidationCase, BolaValidator, EndpointSource, HttpMethod, HttpRequestRunner,
    HttpRequestSpec,
};

/// Spawn a tiny HTTP server that returns 200 only for the admin bearer token.
/// Returns (port, JoinHandle). The handle is owned but not joined — the server
/// thread exits on its own after `max_requests` requests, which keeps the
/// process clean.
fn spawn_protected_lab(max_requests: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test lab");
    listener.set_nonblocking(false).expect("blocking listener");
    let port = listener.local_addr().expect("local addr").port();
    thread::spawn(move || {
        for _ in 0..max_requests {
            let Ok((mut stream, _)) = listener.accept() else {
                continue;
            };
            stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
            let mut buf = vec![0u8; 4096];
            let n = match stream.read(&mut buf) {
                Ok(n) => n,
                Err(_) => continue,
            };
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            // reqwest may lowercase header names; match on the bearer value only.
            let is_admin = req.to_lowercase().contains("bearer admin-token");
            let (status_line, body) = if is_admin {
                (
                    "HTTP/1.1 200 OK",
                    r#"{"id":"secret-001","title":"admin secret","value":"alpha-bravo-charlie"}"#,
                )
            } else {
                (
                    "HTTP/1.1 403 Forbidden",
                    r#"{"error":"forbidden","detail":"admin role required"}"#,
                )
            };
            let response = format!(
                "{status_line}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

/// A stub model client that always returns one canned text response.
struct CannedClient {
    text: String,
}

impl ModelClient for CannedClient {
    fn complete(&self, _req: &ModelRequest) -> Result<ModelResponse, ModelError> {
        Ok(ModelResponse {
            text: self.text.clone(),
            usage: ModelUsage {
                input_tokens: 100,
                output_tokens: 200,
            },
            model: "stub-firewall-model".to_string(),
            provider: "stub".to_string(),
        })
    }
    fn provider(&self) -> &str {
        "stub"
    }
    fn model(&self) -> &str {
        "stub-firewall-model"
    }
}

fn schema_clean_false_bola_hypothesis(endpoint_url: &str) -> String {
    let output = AgentOutput {
        agent_role: "api-auth".to_string(),
        version: "1.0.0".to_string(),
        status: AgentOutputStatus::Success,
        hypotheses: vec![AgentHypothesis {
            id: "h-fw-false-001".to_string(),
            classification: "BrokenObjectLevelAuthorization".to_string(),
            // High confidence — passes the structural pre-filter's 0.55 / 0.75 thresholds.
            confidence: 0.95,
            endpoint: Some(format!("GET {endpoint_url}")),
            object_id: Some("secret-001".to_string()),
            profile: Some("user-token".to_string()),
            description:
                "Confident but FALSE claim: user-token can read admin secret-001 via /api/admin/secrets/secret-001"
                    .to_string(),
            evidence_refs: vec!["openapi_inventory.json".to_string()],
            recommendation: Some("test cross-user object access".to_string()),
            severity: Some("high".to_string()),
        }],
        observations: vec![],
        refusal_reason: None,
        skipped_reason: None,
        uncertainty_notes: vec![],
        model_used: "stub:stub-firewall-model".to_string(),
    };
    serde_json::to_string(&output).expect("serialize")
}

#[test]
fn firewall_rejects_schema_clean_false_bola_against_live_lab() {
    // 1. Spin up the protected lab: admin gets 200, everyone else 403.
    //    We need 3 requests per scan (owner=admin, attacker=user, anonymous=none).
    let port = spawn_protected_lab(6);
    let object_url = format!("http://127.0.0.1:{port}/api/admin/secrets/secret-001");

    // 2. Build a confident, schema-clean FALSE hypothesis on that endpoint.
    let canned = schema_clean_false_bola_hypothesis(&format!("/api/admin/secrets/{{id}}"));
    let client = CannedClient { text: canned };
    let model = ModelConfig::default();
    let mut budget = ModelBudget::conservative();
    let input = AgentInput {
        role: "api-auth".to_string(),
        run_id: "firewall-live-lab".to_string(),
        scope_summary: "in-process firewall lab".to_string(),
        endpoints: vec!["GET /api/admin/secrets/{id}".to_string()],
        findings: vec![],
        evidence_refs: vec!["openapi_inventory.json".to_string()],
        context: BTreeMap::new(),
    };

    // 3. Drive through the agent pipeline — pre-filter must pass it.
    let pipeline = run_live_agent_pipeline(&client, &input, &model, &mut budget);
    assert_eq!(pipeline.hypotheses_proposed, 1);
    assert!(
        pipeline.hypotheses_ready_for_validation >= 1,
        "the false hypothesis is schema-clean (endpoint, evidence, confidence \
         >= 0.55) so it MUST pass the structural pre-filter — that is the whole \
         point of T1.a. Got ready={}, rejected={}",
        pipeline.hypotheses_ready_for_validation,
        pipeline.hypotheses_rejected
    );
    let bridge = &pipeline.bridges[0];
    assert!(bridge.eligible_for_validation);
    assert_eq!(bridge.validator, "bola-validator");

    // 4. Run the REAL deterministic validator against the LIVE lab.
    let runner = HttpRequestRunner::new().expect("HttpRequestRunner::new must succeed in tests");

    let owner = runner
        .send(&HttpRequestSpec {
            id: "owner-admin".to_string(),
            profile: "admin".to_string(),
            method: HttpMethod::Get,
            url: object_url.clone(),
            bearer_token: Some("admin-token".to_string()),
            cookies: vec![],
            headers: vec![],
            csrf_token_header: None,
            csrf_token: None,
        })
        .expect("owner exchange");
    assert_eq!(owner.status, 200, "owner baseline must be 200");

    let attacker = runner
        .send(&HttpRequestSpec {
            id: "attacker-user".to_string(),
            profile: "user-token".to_string(),
            method: HttpMethod::Get,
            url: object_url.clone(),
            bearer_token: Some("user-token".to_string()),
            cookies: vec![],
            headers: vec![],
            csrf_token_header: None,
            csrf_token: None,
        })
        .expect("attacker exchange");
    assert_eq!(attacker.status, 403, "attacker MUST get 403 from the lab");

    let anonymous = runner
        .send(&HttpRequestSpec {
            id: "anonymous".to_string(),
            profile: "anonymous".to_string(),
            method: HttpMethod::Get,
            url: object_url.clone(),
            bearer_token: None,
            cookies: vec![],
            headers: vec![],
            csrf_token_header: None,
            csrf_token: None,
        })
        .expect("anonymous exchange");
    assert_eq!(anonymous.status, 403, "anonymous MUST get 403 from the lab");

    let case = BolaValidationCase {
        endpoint: ApiEndpoint {
            id: "GET /api/admin/secrets/{id}".to_string(),
            method: HttpMethod::Get,
            url_template: format!("http://127.0.0.1:{port}/api/admin/secrets/{{id}}"),
            source: EndpointSource::OpenApi,
            requires_auth: Some(true),
            path_parameters: vec!["id".to_string()],
            tags: vec!["admin".to_string()],
        },
        object_id: "secret-001".to_string(),
        owner_profile: "admin".to_string(),
        attacker_profile: "user-token".to_string(),
        owner_markers: vec!["alpha-bravo-charlie".to_string()],
        owner_exchange: owner.clone(),
        attacker_exchange: attacker.clone(),
        anonymous_exchange: Some(anonymous.clone()),
    };

    let decision = BolaValidator::default().validate(&case);

    // 5. CORE FIREWALL ASSERTION.
    match decision {
        BolaDecision::Verified(finding) => {
            panic!(
                "FIREWALL BREACHED: BolaValidator promoted a false claim to Verified. \
                 This means a confident schema-clean model hypothesis became a sealed \
                 finding without the live HTTP evidence supporting it. Finding: {:?}",
                finding
            );
        }
        BolaDecision::Rejected(rejection) => {
            assert!(
                rejection.reason.to_lowercase().contains("blocked")
                    || rejection.reason.to_lowercase().contains("not")
                    || rejection.observations.iter().any(|o| o.contains("403")),
                "rejection should explain why (attacker was blocked); got: {:?}",
                rejection
            );
        }
    }

    // 6. Classifier must call this BlockedAsExpected, not a BOLA.
    let observation: AuthorizationMatrixObservation =
        AuthorizationMatrixObservation::classify(&case, "admin", "user");
    assert_ne!(
        observation.classification,
        AuthorizationClass::BrokenObjectLevelAuthorization,
        "classifier must NOT call this BOLA when the attacker was 403'd"
    );
    assert_eq!(
        observation.classification,
        AuthorizationClass::BlockedAsExpected,
        "classifier must call this BlockedAsExpected; got {:?} (reason: {})",
        observation.classification,
        observation.reason
    );
}

/// Sanity-check counterpart: if the lab IS actually vulnerable (i.e. the
/// "false" hypothesis is in fact true), the validator MUST verify it. This
/// pins the validator's positive branch — without it, the test above could
/// pass for trivial reasons (e.g. validator always rejects everything).
#[test]
fn validator_does_verify_when_lab_is_actually_vulnerable() {
    // Spawn a deliberately-vulnerable in-process server: returns 200 + admin
    // body for EVERY caller (including the user token), regardless of auth.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vuln lab");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        for _ in 0..6 {
            let Ok((mut stream, _)) = listener.accept() else {
                continue;
            };
            stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf);
            let body = r#"{"id":"obj-001","title":"owner secret","value":"alpha-bravo-charlie"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });

    let url = format!("http://127.0.0.1:{port}/api/invoices/obj-001");
    let runner = HttpRequestRunner::new().expect("runner");
    let owner = runner
        .send(&HttpRequestSpec {
            id: "owner".to_string(),
            profile: "user_b".to_string(),
            method: HttpMethod::Get,
            url: url.clone(),
            bearer_token: Some("user_b-token".to_string()),
            cookies: vec![],
            headers: vec![],
            csrf_token_header: None,
            csrf_token: None,
        })
        .expect("owner");
    let attacker = runner
        .send(&HttpRequestSpec {
            id: "attacker".to_string(),
            profile: "user_a".to_string(),
            method: HttpMethod::Get,
            url: url.clone(),
            bearer_token: Some("user_a-token".to_string()),
            cookies: vec![],
            headers: vec![],
            csrf_token_header: None,
            csrf_token: None,
        })
        .expect("attacker");
    let _anonymous = runner
        .send(&HttpRequestSpec {
            id: "anon".to_string(),
            profile: "anonymous".to_string(),
            method: HttpMethod::Get,
            // hit a different URL so the open-to-everyone server doesn't make
            // anonymous look identical to the owner (which would correctly
            // cause the validator to reject as "public resource").
            url: format!("http://127.0.0.1:{port}/api/_does_not_exist_for_anon"),
            bearer_token: None,
            cookies: vec![],
            headers: vec![],
            csrf_token_header: None,
            csrf_token: None,
        })
        .expect("anon");

    let case = BolaValidationCase {
        endpoint: ApiEndpoint {
            id: "GET /api/invoices/{id}".to_string(),
            method: HttpMethod::Get,
            url_template: format!("http://127.0.0.1:{port}/api/invoices/{{id}}"),
            source: EndpointSource::OpenApi,
            requires_auth: Some(true),
            path_parameters: vec!["id".to_string()],
            tags: vec![],
        },
        object_id: "obj-001".to_string(),
        owner_profile: "user_b".to_string(),
        attacker_profile: "user_a".to_string(),
        owner_markers: vec!["alpha-bravo-charlie".to_string()],
        owner_exchange: owner,
        attacker_exchange: attacker,
        // For this positive sanity-check we don't supply anonymous_exchange,
        // because the open server we set up returns the same body to anonymous
        // too — that's not the lab behavior being tested here, only the
        // attacker-vs-owner branch of the validator.
        anonymous_exchange: None,
    };

    let decision = BolaValidator::default().validate(&case);
    match decision {
        BolaDecision::Verified(_) => {
            // Expected — without this branch, the firewall test above could
            // trivially pass by the validator always rejecting.
        }
        BolaDecision::Rejected(r) => panic!(
            "validator should Verify when the lab is genuinely vulnerable; got Rejected: {:?}",
            r
        ),
    }

    let observation = AuthorizationMatrixObservation::classify(&case, "user", "user");
    assert_eq!(
        observation.classification,
        AuthorizationClass::BrokenObjectLevelAuthorization,
        "classifier should call this BOLA when attacker actually got the same content"
    );
}
