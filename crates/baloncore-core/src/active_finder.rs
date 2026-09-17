//! A0 — active-finding foundation (Vertical A capability campaign).
//!
//! This is the shared substrate every active vuln-class finder will build on. It
//! adds NO vuln class itself. It provides:
//!   - [`ActiveFinder`]: the finder contract, mirroring `web_api::BolaValidator`'s
//!     `Verified | Rejected` decision shape so the validator-firewall and evidence
//!     sealing work unchanged. A finder may PROPOSE; only its deterministic proof
//!     turns a hypothesis into [`FinderDecision::Verified`].
//!   - [`FinderContext`]: bundles the target, auth profiles, the real
//!     `HttpRequestRunner`, a [`ScopeGuard`], a [`ProbeBudget`] and (optionally)
//!     the OOB collaborator. EVERY outbound probe goes through
//!     [`FinderContext::send`], which enforces scope and budget — a finder cannot
//!     leave authorized scope or exceed its probe budget.
//!   - [`OobCollaborator`]: a local out-of-band HTTP sink BALONCORE controls, so
//!     blind classes (SSRF, blind injection, XXE) have a deterministic proof
//!     signal — the SERVER reaching an attacker-controlled URL. Records every
//!     interaction as evidence.
//!   - [`differential`]: a control-vs-test comparator with stable thresholds for
//!     boolean- and time-based proofs.
//!
//! Invariants (same as the rest of the engine): authorized scope only; model
//! proposes, validator proves.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::evidence::{EvidenceKind, EvidenceRecord, RedactionStatus};
use crate::scope::ScopeGuard;
use crate::web_api::{HttpExchange, HttpRequestRunner, HttpRequestSpec, RejectedHypothesis};

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

// =============================================================================
// Decision shape — mirrors BolaValidator's Verified/Rejected contract.
// =============================================================================

/// How a finding was PROVEN. Every variant is a deterministic signal, never
/// "the payload reflected".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofKind {
    /// The server reached an attacker-controlled out-of-band destination.
    OutOfBandCallback,
    /// A true-condition vs false-condition response differed consistently.
    BooleanDifferential,
    /// An injected delay measurably and repeatably slowed the response.
    TimingDifferential,
    /// A forged/tampered token accessed a resource the original identity could not.
    ForgedTokenAccess,
    /// A before/after re-read confirmed a state change actually took effect.
    StateChange,
}

/// A sealed, deterministic proof produced by an [`ActiveFinder`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveProof {
    pub finder: String,
    pub vuln_class: String,
    pub title: String,
    pub target: String,
    pub proof_kind: ProofKind,
    /// Ids of the [`ProbeObservation`]s / exchanges that constitute the proof.
    pub evidence_ids: Vec<String>,
    /// Human-checkable markers found in the proving response(s).
    pub evidence_markers: Vec<String>,
    pub detail: String,
}

/// A finder's verdict. Same three-way shape the firewall expects: only
/// `Verified` may be sealed as a finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FinderDecision {
    Verified(ActiveProof),
    Rejected(RejectedHypothesis),
    /// The finder could not reach a verdict (budget exhausted, target
    /// unreachable, ambiguous signal). NEVER treated as a finding.
    Inconclusive(String),
}

impl FinderDecision {
    pub fn is_verified(&self) -> bool {
        matches!(self, FinderDecision::Verified(_))
    }
}

/// What can go wrong while probing. Scope/budget violations are refusals, not
/// panics — the finder gets an explicit error and must handle it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinderError {
    OutOfScope { url: String, reason: String },
    BudgetExhausted { detail: String },
    Transport(String),
}

impl std::fmt::Display for FinderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FinderError::OutOfScope { url, reason } => {
                write!(f, "out of scope: {url} ({reason})")
            }
            FinderError::BudgetExhausted { detail } => {
                write!(f, "probe budget exhausted: {detail}")
            }
            FinderError::Transport(e) => write!(f, "transport error: {e}"),
        }
    }
}

impl std::error::Error for FinderError {}

// =============================================================================
// Budget — mirrors the ModelBudget pattern, for probes instead of model calls.
// =============================================================================

/// Per-scan probe budget. A finder consumes one unit per outbound request via
/// [`FinderContext::send`]; the budget also has a wall-clock ceiling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeBudget {
    pub max_probes: u32,
    pub max_wall_ms: u64,
    pub used_probes: u32,
    pub started_at_ms: u128,
}

impl ProbeBudget {
    pub fn new(max_probes: u32, max_wall_ms: u64) -> Self {
        Self {
            max_probes,
            max_wall_ms,
            used_probes: 0,
            started_at_ms: now_millis(),
        }
    }

    /// A conservative default suitable for a single endpoint's worth of probing.
    pub fn conservative() -> Self {
        Self::new(50, 60_000)
    }

    pub fn remaining(&self) -> u32 {
        self.max_probes.saturating_sub(self.used_probes)
    }

    /// Try to consume one probe unit. Fails if the count or wall-clock ceiling
    /// is exceeded; on success the used count is incremented.
    pub fn try_consume(&mut self) -> Result<(), FinderError> {
        let elapsed = now_millis().saturating_sub(self.started_at_ms) as u64;
        if elapsed > self.max_wall_ms {
            return Err(FinderError::BudgetExhausted {
                detail: format!("wall clock {elapsed}ms exceeded {}ms", self.max_wall_ms),
            });
        }
        if self.used_probes >= self.max_probes {
            return Err(FinderError::BudgetExhausted {
                detail: format!("probe count reached cap {}", self.max_probes),
            });
        }
        self.used_probes += 1;
        Ok(())
    }
}

// =============================================================================
// Probe observation — what a single probe produced (incl. timing, since
// HttpExchange has no duration field).
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeObservation {
    pub id: String,
    pub url: String,
    pub status: u16,
    pub body: String,
    pub elapsed_ms: u128,
}

impl ProbeObservation {
    fn from_exchange(exchange: &HttpExchange, elapsed_ms: u128) -> Self {
        Self {
            id: exchange.id.clone(),
            url: exchange.url.clone(),
            status: exchange.status,
            body: exchange.response_body_excerpt.clone(),
            elapsed_ms,
        }
    }
}

// =============================================================================
// FinderContext — the only way a finder talks to the network. Enforces scope
// and budget on every send.
// =============================================================================

/// A named authorization profile a finder probes as (label + optional bearer
/// token). The runner already supports richer credentials; finders that need
/// more can extend this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProfileRef {
    pub name: String,
    pub bearer_token: Option<String>,
}

/// Bundles everything a finder is allowed to use. Construct once per target,
/// pass `&mut` to the finder. The borrow of the OOB collaborator is shared
/// (cheap clone of an `Arc`).
pub struct FinderContext {
    pub target: String,
    pub profiles: Vec<AuthProfileRef>,
    runner: HttpRequestRunner,
    scope: ScopeGuard,
    pub budget: ProbeBudget,
    pub oob: Option<OobCollaborator>,
    last_exchanges: Vec<HttpExchange>,
}

impl FinderContext {
    pub fn new(
        target: impl Into<String>,
        profiles: Vec<AuthProfileRef>,
        runner: HttpRequestRunner,
        scope: ScopeGuard,
        budget: ProbeBudget,
    ) -> Self {
        Self {
            target: target.into(),
            profiles,
            runner,
            scope,
            budget,
            oob: None,
            last_exchanges: Vec::new(),
        }
    }

    pub fn with_oob(mut self, oob: OobCollaborator) -> Self {
        self.oob = Some(oob);
        self
    }

    /// Send one probe. Refuses (without sending) if the URL is out of scope, and
    /// consumes one budget unit. Returns a [`ProbeObservation`] with timing.
    pub fn send(&mut self, spec: &HttpRequestSpec) -> Result<ProbeObservation, FinderError> {
        let decision = self.scope.evaluate(&spec.url);
        if !matches!(decision, crate::scope::ScopeDecision::Allowed { .. }) {
            let reason = match decision {
                crate::scope::ScopeDecision::Blocked { reason } => reason,
                _ => "blocked".to_string(),
            };
            return Err(FinderError::OutOfScope {
                url: spec.url.clone(),
                reason,
            });
        }
        // Only consume budget once scope is confirmed (a refused request never
        // reached the network and should not cost a probe).
        self.budget.try_consume()?;

        let started = Instant::now();
        let exchange = self
            .runner
            .send(spec)
            .map_err(|e| FinderError::Transport(e.to_string()))?;
        let elapsed_ms = started.elapsed().as_millis();
        let obs = ProbeObservation::from_exchange(&exchange, elapsed_ms);
        self.last_exchanges.push(exchange);
        Ok(obs)
    }

    /// Send one probe with a JSON body (login, create, etc.). Same scope/budget
    /// enforcement as [`send`](Self::send).
    pub fn send_json(
        &mut self,
        spec: &HttpRequestSpec,
        body: &serde_json::Value,
    ) -> Result<ProbeObservation, FinderError> {
        if !self.scope.is_allowed(&spec.url) {
            let reason = match self.scope.evaluate(&spec.url) {
                crate::scope::ScopeDecision::Blocked { reason } => reason,
                _ => "blocked".to_string(),
            };
            return Err(FinderError::OutOfScope {
                url: spec.url.clone(),
                reason,
            });
        }
        self.budget.try_consume()?;
        let started = Instant::now();
        let exchange = self
            .runner
            .send_with_json_body(spec, Some(body))
            .map_err(|e| FinderError::Transport(e.to_string()))?;
        let elapsed_ms = started.elapsed().as_millis();
        let obs = ProbeObservation::from_exchange(&exchange, elapsed_ms);
        self.last_exchanges.push(exchange);
        Ok(obs)
    }

    /// The raw exchanges sent so far (for evidence sealing by the caller).
    pub fn exchanges(&self) -> &[HttpExchange] {
        &self.last_exchanges
    }
}

/// The finder contract. Mirrors `BolaValidator::validate`'s shape: a finder is
/// given everything it may use (via the context) and returns a decision the
/// firewall/evidence layer already understands.
pub trait ActiveFinder {
    /// Stable short name, e.g. `"ssrf"`, `"jwt-auth"`.
    fn name(&self) -> &str;

    /// The vuln class this finder proves, e.g. `"SSRF"`.
    fn vuln_class(&self) -> &str;

    /// Do active work and return a deterministic verdict.
    fn probe(&self, ctx: &mut FinderContext) -> FinderDecision;
}

// =============================================================================
// Out-of-band collaborator sink.
// =============================================================================

/// One recorded inbound interaction at the OOB sink — proof that some server
/// reached our attacker-controlled destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OobInteraction {
    /// Correlation token embedded in the payload URL path (`/oob/<token>`).
    pub token: String,
    pub method: String,
    pub path: String,
    pub source: String,
    pub received_at_ms: u128,
    pub request_head: String,
}

/// A small local HTTP sink BALONCORE controls. Finders embed
/// [`payload_url`](OobCollaborator::payload_url) into target parameters; when the
/// SERVER fetches it, the sink records an [`OobInteraction`] — the deterministic
/// proof signal for blind classes. Localhost-only by default.
#[derive(Clone)]
pub struct OobCollaborator {
    base_url: String,
    interactions: Arc<Mutex<Vec<OobInteraction>>>,
    token_counter: Arc<AtomicU64>,
    shutdown: Arc<AtomicBool>,
    _handle: Arc<Option<JoinHandle<()>>>,
}

impl OobCollaborator {
    /// Start a sink bound to `127.0.0.1` on an ephemeral port.
    pub fn start_local() -> std::io::Result<Self> {
        Self::start_on("127.0.0.1")
    }

    /// Start a sink bound to `host` (use a routable host only for explicitly
    /// authorized remote testing). Binds an ephemeral port.
    pub fn start_on(host: &str) -> std::io::Result<Self> {
        let listener = TcpListener::bind(format!("{host}:0"))?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        let interactions: Arc<Mutex<Vec<OobInteraction>>> = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let interactions_thread = Arc::clone(&interactions);
        let shutdown_thread = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            while !shutdown_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, peer)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_millis(500)))
                            .ok();
                        let mut buf = vec![0u8; 8192];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let head = String::from_utf8_lossy(&buf[..n]).to_string();
                        let (method, path) = parse_request_line(&head);
                        let token = path
                            .rsplit('/')
                            .next()
                            .unwrap_or("")
                            .split(['?', '#'])
                            .next()
                            .unwrap_or("")
                            .to_string();
                        if let Ok(mut guard) = interactions_thread.lock() {
                            guard.push(OobInteraction {
                                token,
                                method,
                                path,
                                source: peer.to_string(),
                                received_at_ms: now_millis(),
                                request_head: head.lines().take(12).collect::<Vec<_>>().join("\n"),
                            });
                        }
                        let body = "baloncore-oob-sink";
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(15));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(15)),
                }
            }
        });

        Ok(Self {
            base_url: format!("http://{host}:{port}"),
            interactions,
            token_counter: Arc::new(AtomicU64::new(0)),
            shutdown,
            _handle: Arc::new(Some(handle)),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Mint a fresh correlation token, unique within this sink's lifetime.
    pub fn new_token(&self) -> String {
        let n = self.token_counter.fetch_add(1, Ordering::Relaxed);
        format!("t{:x}{:x}", now_millis() as u64 & 0xffffff, n)
    }

    /// The attacker-controlled URL to inject into a target parameter. A server
    /// that fetches this URL proves the interaction.
    pub fn payload_url(&self, token: &str) -> String {
        format!("{}/oob/{token}", self.base_url)
    }

    pub fn interactions(&self) -> Vec<OobInteraction> {
        self.interactions
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    pub fn interaction_for(&self, token: &str) -> Option<OobInteraction> {
        self.interactions
            .lock()
            .ok()?
            .iter()
            .find(|i| i.token == token)
            .cloned()
    }

    /// Block (up to `timeout`) until an interaction for `token` is recorded.
    /// Returns it if seen — the deterministic proof a blind finder waits on.
    pub fn wait_for(&self, token: &str, timeout: Duration) -> Option<OobInteraction> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(found) = self.interaction_for(token) {
                return Some(found);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Seal every recorded interaction as an evidence record.
    pub fn evidence(&self) -> Vec<EvidenceRecord> {
        self.interactions()
            .into_iter()
            .map(|i| EvidenceRecord {
                id: format!("oob-{}-{}", i.token, i.received_at_ms),
                target: self.base_url.clone(),
                kind: EvidenceKind::RuntimeObservation,
                summary: format!(
                    "OOB callback: {} {} from {} (token {})",
                    i.method, i.path, i.source, i.token
                ),
                artifact_path: None,
                sensitivity: Vec::new(),
                redaction_status: RedactionStatus::SafeToShare,
            })
            .collect()
    }
}

impl Drop for OobCollaborator {
    fn drop(&mut self) {
        // Only the last Arc owner actually stops the server thread.
        if Arc::strong_count(&self.shutdown) == 1 {
            self.shutdown.store(true, Ordering::Relaxed);
        }
    }
}

fn parse_request_line(head: &str) -> (String, String) {
    let first = head.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    (method, path)
}

// =============================================================================
// Differential prober — stable thresholds for boolean/time proofs.
// =============================================================================

/// Thresholds for [`differential`]. Defaults are deliberately conservative so
/// noise (jitter, near-identical bodies) does NOT register as a signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialConfig {
    /// Two bodies count as "different content" when their token-Jaccard
    /// similarity is strictly below this. Higher = stricter (more must differ).
    pub body_similarity_threshold: f32,
    /// A timing signal requires test >= control * this ratio …
    pub min_time_ratio: f64,
    /// … AND test - control >= this many ms (the absolute floor that survives
    /// network jitter). BOTH must hold.
    pub min_time_abs_ms: u128,
}

impl Default for DifferentialConfig {
    fn default() -> Self {
        Self {
            body_similarity_threshold: 0.85,
            min_time_ratio: 3.0,
            min_time_abs_ms: 500,
        }
    }
}

/// The outcome of comparing a control probe to a test probe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DifferentialOutcome {
    pub status_differs: bool,
    pub body_differs: bool,
    pub time_differs: bool,
    pub body_similarity: f32,
    pub control_ms: u128,
    pub test_ms: u128,
    pub detail: String,
}

impl DifferentialOutcome {
    /// A boolean-based signal: the test response differs from the control in a
    /// content-meaningful way (status code or body).
    pub fn is_boolean_signal(&self) -> bool {
        self.status_differs || self.body_differs
    }

    /// A timing-based signal.
    pub fn is_timing_signal(&self) -> bool {
        self.time_differs
    }
}

/// Compare a control observation to a test observation under stable thresholds.
/// This is a pure function — the deterministic core a finder reproduces.
pub fn differential(
    control: &ProbeObservation,
    test: &ProbeObservation,
    cfg: &DifferentialConfig,
) -> DifferentialOutcome {
    let status_differs = control.status != test.status;
    let body_similarity = token_jaccard(&control.body, &test.body);
    let body_differs = body_similarity < cfg.body_similarity_threshold;

    // Timing requires BOTH a ratio and an absolute gap — either alone is noise.
    let ratio_ok = (test.elapsed_ms as f64) >= (control.elapsed_ms as f64) * cfg.min_time_ratio;
    let abs_ok = test.elapsed_ms.saturating_sub(control.elapsed_ms) >= cfg.min_time_abs_ms;
    let time_differs = ratio_ok && abs_ok;

    let detail = format!(
        "status {}->{} (differs={status_differs}); body_similarity={body_similarity:.3} (differs={body_differs}); \
         time {}ms->{}ms (ratio_ok={ratio_ok}, abs_ok={abs_ok}, differs={time_differs})",
        control.status, test.status, control.elapsed_ms, test.elapsed_ms
    );

    DifferentialOutcome {
        status_differs,
        body_differs,
        time_differs,
        body_similarity,
        control_ms: control.elapsed_ms,
        test_ms: test.elapsed_ms,
        detail,
    }
}

/// Token-set Jaccard similarity over alphanumeric tokens (length >= 2). 1.0 =
/// identical token sets, 0.0 = disjoint. Local to keep this module self-contained.
fn token_jaccard(a: &str, b: &str) -> f32 {
    let tokens = |s: &str| -> std::collections::BTreeSet<String> {
        s.split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|t| t.len() >= 2)
            .map(|t| t.to_ascii_lowercase())
            .collect()
    };
    let sa = tokens(a);
    let sb = tokens(b);
    if sa.is_empty() && sb.is_empty() {
        return 1.0;
    }
    if sa.is_empty() || sb.is_empty() {
        return 0.0;
    }
    let inter = sa.intersection(&sb).count();
    let union = sa.union(&sb).count();
    inter as f32 / union as f32
}

/// Convenience: build a `BTreeMap` summary of a decision for logging/scorecards.
pub fn decision_summary(decision: &FinderDecision) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    match decision {
        FinderDecision::Verified(p) => {
            m.insert("decision".to_string(), "verified".to_string());
            m.insert("proof_kind".to_string(), format!("{:?}", p.proof_kind));
            m.insert("vuln_class".to_string(), p.vuln_class.clone());
        }
        FinderDecision::Rejected(r) => {
            m.insert("decision".to_string(), "rejected".to_string());
            m.insert("reason".to_string(), r.reason.clone());
        }
        FinderDecision::Inconclusive(reason) => {
            m.insert("decision".to_string(), "inconclusive".to_string());
            m.insert("reason".to_string(), reason.clone());
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScopeConfig;

    fn localhost_scope(port: u16) -> ScopeGuard {
        ScopeGuard::new(ScopeConfig {
            allow_urls: vec![format!("http://127.0.0.1:{port}/")],
            allow_hosts: vec!["127.0.0.1".to_string(), "localhost".to_string()],
            deny_hosts: vec![],
            max_depth: 2,
        })
        .expect("scope guard")
    }

    fn obs(id: &str, status: u16, body: &str, ms: u128) -> ProbeObservation {
        ProbeObservation {
            id: id.to_string(),
            url: "http://127.0.0.1/x".to_string(),
            status,
            body: body.to_string(),
            elapsed_ms: ms,
        }
    }

    // --- OOB collaborator ---

    #[test]
    fn oob_sink_records_a_server_side_callback() {
        let oob = OobCollaborator::start_local();
        let oob = match oob {
            Ok(o) => o,
            Err(e) => {
                eprintln!("[active_finder] SKIP oob test — cannot bind local socket: {e}");
                return;
            }
        };
        let token = oob.new_token();
        let url = oob.payload_url(&token);
        // Simulate the "server" fetching the attacker-controlled URL.
        let runner = HttpRequestRunner::new().expect("runner");
        let _ = runner.send(&crate::web_api::HttpRequestSpec {
            id: "sim-server-fetch".to_string(),
            profile: "server".to_string(),
            method: crate::web_api::HttpMethod::Get,
            url,
            bearer_token: None,
            cookies: vec![],
            headers: vec![],
            csrf_token_header: None,
            csrf_token: None,
        });
        let found = oob.wait_for(&token, Duration::from_secs(3));
        assert!(
            found.is_some(),
            "OOB sink must record the callback for {token}"
        );
        let it = found.unwrap();
        assert_eq!(it.token, token);
        assert!(it.path.contains("/oob/"));
        // Evidence sealing.
        let ev = oob.evidence();
        assert!(ev.iter().any(|e| e.summary.contains(&token)));
    }

    #[test]
    fn oob_sink_ignores_unrelated_tokens() {
        let Ok(oob) = OobCollaborator::start_local() else {
            eprintln!("[active_finder] SKIP — cannot bind");
            return;
        };
        let a = oob.new_token();
        let b = oob.new_token();
        assert_ne!(a, b, "tokens must be unique");
        // No callback yet → no interaction for either token.
        assert!(oob.interaction_for(&a).is_none());
        assert!(oob.wait_for(&b, Duration::from_millis(200)).is_none());
    }

    // --- differential prober (the mutation-checked core) ---

    #[test]
    fn differential_flags_planted_boolean_difference() {
        let cfg = DifferentialConfig::default();
        // Different status.
        let d = differential(
            &obs("c", 200, "welcome user alice", 50),
            &obs("t", 500, "welcome user alice", 50),
            &cfg,
        );
        assert!(d.status_differs && d.is_boolean_signal());
        // Same status, very different body (true vs false branch).
        let d2 = differential(
            &obs(
                "c",
                200,
                "query returned 1 row: user alice id 42 email a@x.com",
                50,
            ),
            &obs("t", 200, "no results found empty set zero rows", 50),
            &cfg,
        );
        assert!(
            d2.body_differs,
            "distinct bodies must register (sim={})",
            d2.body_similarity
        );
        assert!(d2.is_boolean_signal());
    }

    #[test]
    fn differential_ignores_body_noise() {
        let cfg = DifferentialConfig::default();
        // Near-identical bodies (one extra token) must NOT count as a difference.
        let d = differential(
            &obs(
                "c",
                200,
                "dashboard widgets alpha beta gamma delta epsilon zeta",
                50,
            ),
            &obs(
                "t",
                200,
                "dashboard widgets alpha beta gamma delta epsilon zeta now",
                50,
            ),
            &cfg,
        );
        assert!(
            !d.body_differs,
            "tiny body noise must be ignored (sim={})",
            d.body_similarity
        );
        assert!(!d.is_boolean_signal());
    }

    #[test]
    fn differential_flags_planted_time_difference() {
        let cfg = DifferentialConfig::default();
        // 50ms control vs 900ms test: ratio 18x and +850ms — a real injected sleep.
        let d = differential(&obs("c", 200, "ok", 50), &obs("t", 200, "ok", 900), &cfg);
        assert!(d.is_timing_signal(), "{}", d.detail);
    }

    #[test]
    fn differential_ignores_timing_jitter() {
        let cfg = DifferentialConfig::default();
        // 100ms vs 140ms: 1.4x and +40ms — ordinary jitter, NOT a signal.
        let d = differential(&obs("c", 200, "ok", 100), &obs("t", 200, "ok", 140), &cfg);
        assert!(!d.is_timing_signal(), "jitter must not flag: {}", d.detail);
        // A big ratio but tiny absolute gap (1ms -> 10ms) must also not flag.
        let d2 = differential(&obs("c", 200, "ok", 1), &obs("t", 200, "ok", 10), &cfg);
        assert!(
            !d2.is_timing_signal(),
            "sub-floor abs gap must not flag: {}",
            d2.detail
        );
    }

    // --- scope + budget enforcement in the context ---

    #[test]
    fn context_refuses_out_of_scope_send() {
        let runner = HttpRequestRunner::new().expect("runner");
        let scope = localhost_scope(9);
        let mut ctx = FinderContext::new(
            "http://127.0.0.1:9/",
            vec![],
            runner,
            scope,
            ProbeBudget::conservative(),
        );
        let spec = crate::web_api::HttpRequestSpec {
            id: "evil".to_string(),
            profile: "anon".to_string(),
            method: crate::web_api::HttpMethod::Get,
            url: "http://169.254.169.254/latest/meta-data/".to_string(),
            bearer_token: None,
            cookies: vec![],
            headers: vec![],
            csrf_token_header: None,
            csrf_token: None,
        };
        let err = ctx.send(&spec).unwrap_err();
        assert!(matches!(err, FinderError::OutOfScope { .. }), "got {err:?}");
        // A refused (never-sent) request must NOT consume budget.
        assert_eq!(ctx.budget.used_probes, 0);
    }

    #[test]
    fn budget_exhaustion_is_enforced() {
        let mut b = ProbeBudget::new(2, 60_000);
        assert!(b.try_consume().is_ok());
        assert!(b.try_consume().is_ok());
        let err = b.try_consume().unwrap_err();
        assert!(matches!(err, FinderError::BudgetExhausted { .. }));
        assert_eq!(b.remaining(), 0);
    }
}
