use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseRecommendation {
    pub classification: String,
    pub vulnerability_class: String,
    pub prevention_guidance: Vec<GuidanceItem>,
    pub detection_guidance: Vec<DetectionRule>,
    pub fix_template: Option<FixTemplate>,
    pub regression_tests: Vec<RegressionTest>,
    pub logging_suggestions: Vec<LoggingSuggestion>,
    pub waf_rules: Vec<WafRule>,
    pub least_privilege: Option<LeastPrivilegeGuidance>,
    pub threat_model_updates: Vec<ThreatModelSnippet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuidanceItem {
    pub title: String,
    pub description: String,
    pub priority: GuidancePriority,
    pub category: GuidanceCategory,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GuidancePriority {
    Critical,
    High,
    Medium,
    Low,
}

impl GuidancePriority {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GuidanceCategory {
    Prevention,
    Detection,
    Hardening,
    Monitoring,
    Infrastructure,
}

impl GuidanceCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Prevention => "prevention",
            Self::Detection => "detection",
            Self::Hardening => "hardening",
            Self::Monitoring => "monitoring",
            Self::Infrastructure => "infrastructure",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub rule_id: String,
    pub title: String,
    pub rule_type: DetectionRuleType,
    pub rule_content: String,
    pub severity: String,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DetectionRuleType {
    Sigma,
    Yara,
    Suricata,
    CustomLog,
    CloudAudit,
}

impl DetectionRuleType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sigma => "sigma",
            Self::Yara => "yara",
            Self::Suricata => "suricata",
            Self::CustomLog => "custom_log",
            Self::CloudAudit => "cloud_audit",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixTemplate {
    pub language: String,
    pub framework: String,
    pub before: String,
    pub after: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionTest {
    pub test_id: String,
    pub test_type: RegressionTestType,
    pub language: String,
    pub code: String,
    pub description: String,
    pub endpoint: Option<String>,
    pub assertion: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegressionTestType {
    IntegrationApi,
    Unit,
    Contract,
    E2e,
    LoadTest,
}

impl RegressionTestType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IntegrationApi => "integration_api",
            Self::Unit => "unit",
            Self::Contract => "contract",
            Self::E2e => "e2e",
            Self::LoadTest => "load_test",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingSuggestion {
    pub event_name: String,
    pub fields: Vec<LogField>,
    pub trigger: String,
    pub alert_threshold: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogField {
    pub name: String,
    pub field_type: String,
    pub required: bool,
    pub example: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafRule {
    pub rule_id: String,
    pub rule_type: WafRuleType,
    pub pattern: String,
    pub action: WafAction,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WafRuleType {
    PatternMatch,
    RateLimit,
    IpBlocklist,
    GeoBlock,
}

impl WafRuleType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PatternMatch => "pattern_match",
            Self::RateLimit => "rate_limit",
            Self::IpBlocklist => "ip_blocklist",
            Self::GeoBlock => "geo_block",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WafAction {
    Block,
    Challenge,
    Log,
    RateLimit,
}

impl WafAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Challenge => "challenge",
            Self::Log => "log",
            Self::RateLimit => "rate_limit",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeastPrivilegeGuidance {
    pub provider: String,
    pub current_policy: String,
    pub recommended_policy: String,
    pub removed_permissions: Vec<String>,
    pub added_constraints: Vec<String>,
    pub rollback_command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatModelSnippet {
    pub component: String,
    pub threat_type: String,
    pub description: String,
    pub impact: String,
    pub mitigation: String,
    pub stride_category: StrideCategory,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StrideCategory {
    Spoofing,
    Tampering,
    Repudiation,
    InformationDisclosure,
    DenialOfService,
    ElevationOfPrivilege,
}

impl StrideCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Spoofing => "spoofing",
            Self::Tampering => "tampering",
            Self::Repudiation => "repudiation",
            Self::InformationDisclosure => "information_disclosure",
            Self::DenialOfService => "denial_of_service",
            Self::ElevationOfPrivilege => "elevation_of_privilege",
        }
    }
}

pub fn recommend(classification: &str) -> DefenseRecommendation {
    match classification {
        "idor" | "broken_object_level_authorization" => DefenseRecommendation {
            classification: classification.to_string(),
            vulnerability_class: "idor".to_string(),
            prevention_guidance: vec![
                GuidanceItem {
                    title: "Implement object-level authorization".to_string(),
                    description: "Every API endpoint that accesses an object by ID must verify the requesting user has access to that object. Use a centralized authorization middleware.".to_string(),
                    priority: GuidancePriority::Critical,
                    category: GuidanceCategory::Prevention,
                },
                GuidanceItem {
                    title: "Use indirect object references".to_string(),
                    description: "Replace direct object references (database IDs) with indirect references mapped per-user. Prevents enumeration of resources.".to_string(),
                    priority: GuidancePriority::High,
                    category: GuidanceCategory::Prevention,
                },
                GuidanceItem {
                    title: "Add rate limiting on object access".to_string(),
                    description: "Limit the number of objects a user can access per time window to slow down enumeration attacks.".to_string(),
                    priority: GuidancePriority::Medium,
                    category: GuidanceCategory::Hardening,
                },
            ],
            detection_guidance: vec![
                DetectionRule {
                    rule_id: "SIG-001-IDOR".to_string(),
                    title: "Potential IDOR - Cross-Tenant Object Access".to_string(),
                    rule_type: DetectionRuleType::Sigma,
                    rule_content: r#"title: Potential IDOR - Cross-Tenant Object Access
status: experimental
logsource:
    product: web_application
    service: api
detection:
    selection:
        http.response_code: 200
        http.method: GET
        user.id|expand: '%user_accessible_ids%'
    condition: not selection
fields:
    - user.id
    - http.url
    - object.id
level: high
"#.to_string(),
                    severity: "high".to_string(),
                    references: vec!["OWASP API5:2023".to_string(), "CWE-639".to_string()],
                },
            ],
            fix_template: Some(FixTemplate {
                language: "typescript".to_string(),
                framework: "express".to_string(),
                before: r#"app.get('/api/invoices/:id', async (req, res) => {
  const invoice = await db.getInvoices(req.params.id);
  res.json(invoice);
});"#.to_string(),
                after: r#"app.get('/api/invoices/:id', async (req, res) => {
  const invoice = await db.getInvoices(req.params.id);
  if (invoice.userId !== req.user.id) {
    return res.status(403).json({ error: 'Access denied' });
  }
  res.json(invoice);
});"#.to_string(),
                description: "Add object-level authorization check comparing the object owner to the authenticated user".to_string(),
            }),
            regression_tests: vec![
                RegressionTest {
                    test_id: "REG-001-IDOR".to_string(),
                    test_type: RegressionTestType::IntegrationApi,
                    language: "typescript".to_string(),
                    code: r#"describe('IDOR Prevention', () => {
  it('denies access to other users invoices', async () => {
    const userAToken = await login('user_a');
    const userBInvoiceId = await createInvoice('user_b', { amount: 500 });
    const res = await request(app)
      .get(`/api/invoices/${userBInvoiceId}`)
      .set('Authorization', `Bearer ${userAToken}`);
    expect(res.status).toBe(403);
  });
  it('allows access to own invoices', async () => {
    const userAToken = await login('user_a');
    const userAInvoiceId = await createInvoice('user_a', { amount: 100 });
    const res = await request(app)
      .get(`/api/invoices/${userAInvoiceId}`)
      .set('Authorization', `Bearer ${userAToken}`);
    expect(res.status).toBe(200);
  });
});"#.to_string(),
                    description: "Verifies users can only access their own resources".to_string(),
                    endpoint: Some("/api/invoices/{id}".to_string()),
                    assertion: "response.status === 403 for cross-tenant access".to_string(),
                },
            ],
            logging_suggestions: vec![
                LoggingSuggestion {
                    event_name: "object_access_denied".to_string(),
                    fields: vec![
                        LogField { name: "user_id".to_string(), field_type: "string".to_string(), required: true, example: "usr_abc123".to_string() },
                        LogField { name: "object_type".to_string(), field_type: "string".to_string(), required: true, example: "invoice".to_string() },
                        LogField { name: "object_id".to_string(), field_type: "string".to_string(), required: true, example: "inv_456".to_string() },
                        LogField { name: "object_owner".to_string(), field_type: "string".to_string(), required: true, example: "usr_xyz789".to_string() },
                    ],
                    trigger: "Object access where object_owner !== requesting user".to_string(),
                    alert_threshold: Some("5 denials per minute per user".to_string()),
                },
            ],
            waf_rules: vec![
                WafRule {
                    rule_id: "WAF-001-IDOR".to_string(),
                    rule_type: WafRuleType::RateLimit,
                    pattern: "/api/invoices/*/".to_string(),
                    action: WafAction::RateLimit,
                    description: "Rate limit invoice access patterns to prevent IDOR enumeration".to_string(),
                },
            ],
            least_privilege: None,
            threat_model_updates: vec![
                ThreatModelSnippet {
                    component: "API - Object Access".to_string(),
                    threat_type: "Information Disclosure".to_string(),
                    description: "Authenticated users may access objects belonging to other users if object-level authorization is not enforced.".to_string(),
                    impact: "Data breach of sensitive user data, regulatory violations".to_string(),
                    mitigation: "Implement object-level authorization on all endpoints accessing user-owned resources".to_string(),
                    stride_category: StrideCategory::InformationDisclosure,
                },
            ],
        },
        "reentrancy" => DefenseRecommendation {
            classification: "reentrancy".to_string(),
            vulnerability_class: "reentrancy".to_string(),
            prevention_guidance: vec![
                GuidanceItem {
                    title: "Use checks-effects-interactions pattern".to_string(),
                    description: "Ensure all state changes happen before any external calls. Move state modifications before external contract interactions.".to_string(),
                    priority: GuidancePriority::Critical,
                    category: GuidanceCategory::Prevention,
                },
                GuidanceItem {
                    title: "Implement reentrancy guard".to_string(),
                    description: "Add a nonReentrant modifier to all functions that make external calls. Use OpenZeppelin's ReentrancyGuard.".to_string(),
                    priority: GuidancePriority::Critical,
                    category: GuidanceCategory::Prevention,
                },
                GuidanceItem {
                    title: "Use pull-over-push payment pattern".to_string(),
                    description: "Instead of pushing payments to recipients, let them pull their own funds. This eliminates the reentrancy vector entirely.".to_string(),
                    priority: GuidancePriority::High,
                    category: GuidanceCategory::Prevention,
                },
            ],
            detection_guidance: vec![
                DetectionRule {
                    rule_id: "SIG-002-REENTRANCY".to_string(),
                    title: "Smart Contract Reentrancy Detection".to_string(),
                    rule_type: DetectionRuleType::Sigma,
                    rule_content: r#"title: Smart Contract Reentrancy Event
status: experimental
logsource:
    product: blockchain
    service: smart_contract
detection:
    selection:
        event: ExternalCallBeforeStateUpdate
    condition: selection
level: critical
"#.to_string(),
                    severity: "critical".to_string(),
                    references: vec!["SWC-107".to_string()],
                },
            ],
            fix_template: Some(FixTemplate {
                language: "solidity".to_string(),
                framework: "openzeppelin".to_string(),
                before: r#"function withdraw(uint256 amount) public {
    uint256 balance = balances[msg.sender];
    require(balance >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount;
}"#.to_string(),
                after: r#"import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Vault is ReentrancyGuard {
    function withdraw(uint256 amount) public nonReentrant {
        uint256 balance = balances[msg.sender];
        require(balance >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}"#.to_string(),
                description: "Move state changes before external calls and add nonReentrant modifier".to_string(),
            }),
            regression_tests: vec![
                RegressionTest {
                    test_id: "REG-002-REENTRANCY".to_string(),
                    test_type: RegressionTestType::Contract,
                    language: "solidity".to_string(),
                    code: r#"function test_reentrancy_protection() public {
    VulnerableVault vault = new VulnerableVault();
    vault.deposit{value: 1 ether}();
    vm.prank(attacker);
    vm.expectRevert("ReentrancyGuard: reentrant call");
    attackerContract.attack(address(vault));
}"#.to_string(),
                    description: "Verify reentrancy guard prevents reentrancy attacks".to_string(),
                    endpoint: None,
                    assertion: "vm.expectRevert on reentrant call".to_string(),
                },
            ],
            logging_suggestions: vec![
                LoggingSuggestion {
                    event_name: "contract_external_call".to_string(),
                    fields: vec![
                        LogField { name: "contract".to_string(), field_type: "address".to_string(), required: true, example: "0x1234...".to_string() },
                        LogField { name: "function".to_string(), field_type: "string".to_string(), required: true, example: "withdraw".to_string() },
                        LogField { name: "caller".to_string(), field_type: "address".to_string(), required: true, example: "0x5678...".to_string() },
                    ],
                    trigger: "External call from contract function before state updates".to_string(),
                    alert_threshold: Some("Multiple calls to same function from same caller within same block".to_string()),
                },
            ],
            waf_rules: vec![],
            least_privilege: None,
            threat_model_updates: vec![
                ThreatModelSnippet {
                    component: "Smart Contract".to_string(),
                    threat_type: "Reentrancy".to_string(),
                    description: "External contracts may re-enter functions before state updates complete, allowing double-spending or fund draining.".to_string(),
                    impact: "Complete loss of contract funds".to_string(),
                    mitigation: "Checks-effects-interactions pattern + ReentrancyGuard".to_string(),
                    stride_category: StrideCategory::Tampering,
                },
            ],
        },
        "access_control" | "broken_authentication" | "broken_access_control" => DefenseRecommendation {
            classification: classification.to_string(),
            vulnerability_class: "access_control".to_string(),
            prevention_guidance: vec![
                GuidanceItem {
                    title: "Enforce role-based access control".to_string(),
                    description: "Implement RBAC with least-privilege principles. Define clear roles and map each endpoint to required permissions.".to_string(),
                    priority: GuidancePriority::Critical,
                    category: GuidanceCategory::Prevention,
                },
                GuidanceItem {
                    title: "Add onlyOwner/onlyRole modifiers".to_string(),
                    description: "For smart contracts, add access control modifiers to privileged functions. Use OpenZeppelin's Ownable or AccessControl.".to_string(),
                    priority: GuidancePriority::Critical,
                    category: GuidanceCategory::Prevention,
                },
                GuidanceItem {
                    title: "Separate admin and user endpoints".to_string(),
                    description: "Admin operations should be on separate endpoints with additional authentication checks. Audit all admin-capable routes.".to_string(),
                    priority: GuidancePriority::High,
                    category: GuidanceCategory::Hardening,
                },
            ],
            detection_guidance: vec![DetectionRule {
                rule_id: "SIG-003-ACCESS".to_string(),
                title: "Unauthorized Access Attempt".to_string(),
                rule_type: DetectionRuleType::Sigma,
                rule_content: r#"title: Unauthorized Access Attempt to Privileged Endpoint
status: experimental
logsource:
    product: web_application
    service: auth
detection:
    selection:
        http.response_code: 403
        http.method: POST|PUT|DELETE
    condition: selection
fields:
    - source.ip
    - user.name
    - http.url
level: medium
"#.to_string(),
                severity: "medium".to_string(),
                references: vec!["OWASP API1:2023".to_string()],
            }],
            fix_template: Some(FixTemplate {
                language: "solidity".to_string(),
                framework: "openzeppelin".to_string(),
                before: r#"function adminAction() public {
    // no access control
    performAdminTask();
}"#.to_string(),
                after: r#"import "@openzeppelin/contracts/access/Ownable.sol";

contract MyContract is Ownable {
    function adminAction() public onlyOwner {
        performAdminTask();
    }
}"#.to_string(),
                description: "Add onlyOwner modifier to privileged functions".to_string(),
            }),
            regression_tests: vec![RegressionTest {
                test_id: "REG-003-ACCESS".to_string(),
                test_type: RegressionTestType::IntegrationApi,
                language: "typescript".to_string(),
                code: r#"describe('Access Control', () => {
  it('denies non-admin access to admin endpoint', async () => {
    const userToken = await login('regular_user');
    const res = await request(app)
      .post('/api/admin/users')
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(403);
  });
  it('allows admin access to admin endpoint', async () => {
    const adminToken = await login('admin');
    const res = await request(app)
      .post('/api/admin/users')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
  });
});"#.to_string(),
                description: "Verifies role-based access control enforcement".to_string(),
                endpoint: Some("/api/admin/users".to_string()),
                assertion: "response.status === 403 for non-admin".to_string(),
            }],
            logging_suggestions: vec![LoggingSuggestion {
                event_name: "access_denied".to_string(),
                fields: vec![
                    LogField { name: "user_id".to_string(), field_type: "string".to_string(), required: true, example: "usr_123".to_string() },
                    LogField { name: "required_role".to_string(), field_type: "string".to_string(), required: true, example: "admin".to_string() },
                    LogField { name: "user_role".to_string(), field_type: "string".to_string(), required: true, example: "viewer".to_string() },
                    LogField { name: "endpoint".to_string(), field_type: "string".to_string(), required: true, example: "/api/admin/users".to_string() },
                ],
                trigger: "Access denied due to insufficient role".to_string(),
                alert_threshold: Some("10 denials per minute per user".to_string()),
            }],
            waf_rules: vec![],
            least_privilege: None,
            threat_model_updates: vec![ThreatModelSnippet {
                component: "Authorization".to_string(),
                threat_type: "Privilege Escalation".to_string(),
                description: "Users may access administrative functions if role-based access control is missing or misconfigured.".to_string(),
                impact: "Complete system compromise, data manipulation, data exfiltration".to_string(),
                mitigation: "Implement RBAC with least-privilege, add access control modifiers to all privileged functions".to_string(),
                stride_category: StrideCategory::ElevationOfPrivilege,
            }],
        },
        "xss" | "cross_site_scripting" => DefenseRecommendation {
            classification: classification.to_string(),
            vulnerability_class: "xss".to_string(),
            prevention_guidance: vec![
                GuidanceItem { title: "Output encode all user-supplied data".to_string(), description: "Always contextually encode user input before rendering in HTML. Use framework-provided encoding (React JSX, Django autoescape, etc.).".to_string(), priority: GuidancePriority::Critical, category: GuidanceCategory::Prevention },
                GuidanceItem { title: "Implement Content Security Policy".to_string(), description: "Deploy a strict CSP header that limits script sources to same-origin or explicitly trusted domains. Use nonce-based CSP for inline scripts.".to_string(), priority: GuidancePriority::High, category: GuidanceCategory::Prevention },
            ],
            detection_guidance: vec![DetectionRule {
                rule_id: "SIG-004-XSS".to_string(),
                title: "Potential XSS - Script Reflection in Response".to_string(),
                rule_type: DetectionRuleType::Sigma,
                rule_content: r#"title: Potential XSS - Script Reflection in Response
status: experimental
logsource:
    product: web_application
    service: http
detection:
    selection:
        http.response.body|contains: '<script>'
        http.request.query|contains: '<script>'
    condition: selection
level: high
"#.to_string(),
                severity: "high".to_string(),
                references: vec!["OWASP A03:2021".to_string(), "CWE-79".to_string()],
            }],
            fix_template: Some(FixTemplate {
                language: "typescript".to_string(),
                framework: "react".to_string(),
                before: r#"<div dangerouslySetInnerHTML={{ __html: userInput }} />"#.to_string(),
                after: r#"<div>{userInput}</div>
// React automatically escapes HTML in JSX expressions"#.to_string(),
                description: "Use React's built-in JSX escaping instead of dangerouslySetInnerHTML".to_string(),
            }),
            regression_tests: vec![RegressionTest {
                test_id: "REG-004-XSS".to_string(),
                test_type: RegressionTestType::IntegrationApi,
                language: "typescript".to_string(),
                code: r#"describe('XSS Prevention', () => {
  it('escapes script tags in user input', async () => {
    const res = await request(app)
      .get('/api/search?q=<script>alert(1)</script>');
    expect(res.text).not.toContain('<script>');
    expect(res.text).not.toContain('alert(1)');
  });
});"#.to_string(),
                description: "Verifies script tags are escaped in API responses".to_string(),
                endpoint: Some("/api/search".to_string()),
                assertion: "response does not contain unescaped <script> tags".to_string(),
            }],
            logging_suggestions: vec![],
            waf_rules: vec![
                WafRule { rule_id: "WAF-002-XSS".to_string(), rule_type: WafRuleType::PatternMatch, pattern: "(?i)<script|javascript:|onerror=|onload=".to_string(), action: WafAction::Block, description: "Block common XSS patterns in request parameters".to_string() },
                WafRule { rule_id: "WAF-003-XSS-RATE".to_string(), rule_type: WafRuleType::RateLimit, pattern: "/api/".to_string(), action: WafAction::RateLimit, description: "Rate limit API requests to prevent XSS probing".to_string() },
            ],
            least_privilege: None,
            threat_model_updates: vec![ThreatModelSnippet {
                component: "Web Frontend".to_string(),
                threat_type: "Cross-Site Scripting".to_string(),
                description: "User input reflected without proper encoding allows script execution in victim browsers.".to_string(),
                impact: "Session hijacking, credential theft, malware distribution".to_string(),
                mitigation: "Contextual output encoding + Content Security Policy".to_string(),
                stride_category: StrideCategory::Tampering,
            }],
        },
        "ssrf" | "server_side_request_forgery" => DefenseRecommendation {
            classification: classification.to_string(),
            vulnerability_class: "ssrf".to_string(),
            prevention_guidance: vec![
                GuidanceItem { title: "Implement URL allowlisting".to_string(), description: "Only allow outbound requests to explicitly approved domains and IP ranges. Deny all internal/private IP ranges by default.".to_string(), priority: GuidancePriority::Critical, category: GuidanceCategory::Prevention },
                GuidanceItem { title: "Disable URL scheme redirects".to_string(), description: "Prevent redirects from HTTP to internal services. Follow redirects only to same-origin or allowlisted domains.".to_string(), priority: GuidancePriority::High, category: GuidanceCategory::Prevention },
            ],
            detection_guidance: vec![DetectionRule {
                rule_id: "SIG-005-SSRF".to_string(),
                title: "SSRF - Outbound Request to Internal IP".to_string(),
                rule_type: DetectionRuleType::Sigma,
                rule_content: r#"title: SSRF - Outbound Request to Internal IP
status: experimental
logsource:
    product: web_application
    service: http_client
detection:
    selection:
        dest.ip|cidr: '10.0.0.0/8'
        dest.ip|cidr: '172.16.0.0/12'
        dest.ip|cidr: '192.168.0.0/16'
        dest.ip|cidr: '169.254.169.254/32'
    condition: selection
level: critical
"#.to_string(),
                severity: "critical".to_string(),
                references: vec!["OWASP API8:2023".to_string(), "CWE-918".to_string()],
            }],
            fix_template: Some(FixTemplate {
                language: "python".to_string(),
                framework: "requests".to_string(),
                before: r#"response = requests.get(user_provided_url)"#.to_string(),
                after: r#"from urllib.parse import urlparse
import ipaddress

ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com']
INTERNAL_RANGES = [ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'), ipaddress.ip_network('192.168.0.0/16')]

def is_safe_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False
    if parsed.hostname not in ALLOWED_DOMAINS:
        return False
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if any(ip in rng for rng in INTERNAL_RANGES):
            return False
    except ValueError:
        pass  # hostname, not IP
    return parsed.hostname in ALLOWED_DOMAINS

if not is_safe_url(user_provided_url):
    raise ValueError('URL not allowed')
response = requests.get(user_provided_url)"#.to_string(),
                description: "Validate URL scheme, domain allowlist, and block internal IP ranges before making outbound requests".to_string(),
            }),
            regression_tests: vec![RegressionTest {
                test_id: "REG-005-SSRF".to_string(),
                test_type: RegressionTestType::IntegrationApi,
                language: "typescript".to_string(),
                code: r#"describe('SSRF Prevention', () => {
  it('blocks requests to internal IPs', async () => {
    const res = await request(app)
      .post('/api/fetch')
      .send({ url: 'http://169.254.169.254/latest/meta-data/' });
    expect(res.status).toBe(400);
  });
  it('blocks requests to private networks', async () => {
    const res = await request(app)
      .post('/api/fetch')
      .send({ url: 'http://192.168.1.1/admin' });
    expect(res.status).toBe(400);
  });
  it('allows requests to allowlisted domains', async () => {
    const res = await request(app)
      .post('/api/fetch')
      .send({ url: 'https://api.example.com/data' });
    expect(res.status).toBe(200);
  });
});"#.to_string(),
                description: "Verifies SSRF protection blocks internal IPs and allows safe domains".to_string(),
                endpoint: Some("/api/fetch".to_string()),
                assertion: "response.status === 400 for internal IPs".to_string(),
            }],
            logging_suggestions: vec![LoggingSuggestion {
                event_name: "outbound_url_request_blocked".to_string(),
                fields: vec![
                    LogField { name: "requested_url".to_string(), field_type: "string".to_string(), required: true, example: "http://169.254.169.254/".to_string() },
                    LogField { name: "reason".to_string(), field_type: "string".to_string(), required: true, example: "internal_ip_blocked".to_string() },
                    LogField { name: "requesting_user".to_string(), field_type: "string".to_string(), required: true, example: "usr_abc".to_string() },
                ],
                trigger: "Outbound URL request blocked by SSRF protection".to_string(),
                alert_threshold: Some("3 blocked requests per minute per user".to_string()),
            }],
            waf_rules: vec![WafRule {
                rule_id: "WAF-004-SSRF".to_string(),
                rule_type: WafRuleType::PatternMatch,
                pattern: "169.254.169.254|metadata|internal".to_string(),
                action: WafAction::Block,
                description: "Block requests containing cloud metadata endpoints or internal network references".to_string(),
            }],
            least_privilege: None,
            threat_model_updates: vec![ThreatModelSnippet {
                component: "URL Fetch Service".to_string(),
                threat_type: "Server-Side Request Forgery".to_string(),
                description: "Server makes outbound HTTP requests based on user-supplied URLs, allowing access to internal services and cloud metadata.".to_string(),
                impact: "Cloud credential theft, internal service discovery, data exfiltration".to_string(),
                mitigation: "URL allowlisting + internal IP range blocking + cloud metadata endpoint blocking".to_string(),
                stride_category: StrideCategory::InformationDisclosure,
            }],
        },
        "sql_injection" | "injection" => DefenseRecommendation {
            classification: classification.to_string(),
            vulnerability_class: "injection".to_string(),
            prevention_guidance: vec![
                GuidanceItem { title: "Use parameterized queries".to_string(), description: "Never concatenate user input into SQL queries. Use parameterized queries or ORM abstractions exclusively.".to_string(), priority: GuidancePriority::Critical, category: GuidanceCategory::Prevention },
                GuidanceItem { title: "Apply least-privilege database permissions".to_string(), description: "Application database users should have SELECT/INSERT/UPDATE/DELETE only on required tables. No DROP, ALTER, or GRANT permissions.".to_string(), priority: GuidancePriority::High, category: GuidanceCategory::Hardening },
            ],
            detection_guidance: vec![DetectionRule {
                rule_id: "SIG-006-SQLI".to_string(),
                title: "Potential SQL Injection Attempt".to_string(),
                rule_type: DetectionRuleType::Sigma,
                rule_content: r#"title: Potential SQL Injection Attempt
status: experimental
logsource:
    product: web_application
    service: api
detection:
    selection:
        http.request.query|contains:
            - "' OR "
            - "1=1"
            - "UNION SELECT"
            - "-- "
            - "; DROP "
    condition: selection
level: high
"#.to_string(),
                severity: "high".to_string(),
                references: vec!["OWASP A03:2021".to_string(), "CWE-89".to_string()],
            }],
            fix_template: Some(FixTemplate {
                language: "typescript".to_string(),
                framework: "node-postgres".to_string(),
                before: r#"const result = await pool.query(`SELECT * FROM users WHERE id = ${req.params.id}`);"#.to_string(),
                after: r#"const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id]);"#.to_string(),
                description: "Replace string interpolation with parameterized query".to_string(),
            }),
            regression_tests: vec![RegressionTest {
                test_id: "REG-006-SQLI".to_string(),
                test_type: RegressionTestType::IntegrationApi,
                language: "typescript".to_string(),
                code: r#"describe('SQL Injection Prevention', () => {
  it('handles SQL injection attempts safely', async () => {
    const res = await request(app)
      .get("/api/users?id=1' OR '1'='1");
    expect(res.status).toBe(400);
    expect(res.body.error).toBeDefined();
  });
});"#.to_string(),
                description: "Verifies SQL injection attempts are rejected".to_string(),
                endpoint: Some("/api/users".to_string()),
                assertion: "response.status === 400 for SQL injection input".to_string(),
            }],
            logging_suggestions: vec![],
            waf_rules: vec![WafRule {
                rule_id: "WAF-005-SQLI".to_string(),
                rule_type: WafRuleType::PatternMatch,
                pattern: "(?i)(union.*select|or.*1=1|'.*--|;.*drop|exec.*\\(|insert.*into)".to_string(),
                action: WafAction::Block,
                description: "Block common SQL injection patterns".to_string(),
            }],
            least_privilege: None,
            threat_model_updates: vec![ThreatModelSnippet {
                component: "Database Layer".to_string(),
                threat_type: "SQL Injection".to_string(),
                description: "User input directly incorporated into SQL queries allows database manipulation and data theft.".to_string(),
                impact: "Complete database compromise, data exfiltration, authentication bypass".to_string(),
                mitigation: "Parameterized queries + least-privilege database permissions + input validation".to_string(),
                stride_category: StrideCategory::Tampering,
            }],
        },
        "cloud_privilege_escalation" | "iam" | "cloud_metadata_access" => defense_for_cloud(classification),
        "tenant_isolation" | "broken_tenant_isolation" => defense_for_tenant_isolation(classification),
        "business_logic_price_tamper" => defense_for_business_logic("price_tamper", classification),
        "business_logic_state_skip" => defense_for_business_logic("state_skip", classification),
        "business_logic_replay" => defense_for_business_logic("replay", classification),
        "business_logic_quantity_limit_bypass" => defense_for_business_logic("quantity_limit_bypass", classification),
        _ => generic_defense(classification),
    }
}

fn defense_for_cloud(classification: &str) -> DefenseRecommendation {
    DefenseRecommendation {
        classification: classification.to_string(),
        vulnerability_class: "cloud_iam".to_string(),
        prevention_guidance: vec![
            GuidanceItem { title: "Apply least-privilege IAM policies".to_string(), description: "Review all IAM policies and remove wildcards (*). Grant only the specific actions needed on specific resources. Use AWS IAM Access Analyzer to identify unused permissions.".to_string(), priority: GuidancePriority::Critical, category: GuidanceCategory::Prevention },
            GuidanceItem { title: "Enable MFA for all privileged roles".to_string(), description: "Require MFA for console and CLI access to all roles with privileged permissions. Use IAM conditions to enforce MFA.".to_string(), priority: GuidancePriority::Critical, category: GuidanceCategory::Prevention },
            GuidanceItem { title: "Remove unused credentials and roles".to_string(), description: "Audit for unused access keys, roles, and policies. Delete or disable credentials not used in 90 days.".to_string(), priority: GuidancePriority::High, category: GuidanceCategory::Hardening },
        ],
        detection_guidance: vec![
            DetectionRule {
                rule_id: "SIG-007-CLOUD-IAM".to_string(),
                title: "Suspicious IAM Activity".to_string(),
                rule_type: DetectionRuleType::CloudAudit,
                rule_content: r#"title: Suspicious IAM Activity - Privilege Escalation Attempt
status: experimental
logsource:
    product: cloud
    service: iam
detection:
    selection:
        eventSource: iam.amazonaws.com
        eventName|contains:
            - AttachRolePolicy
            - PutRolePolicy
            - CreateAccessKey
            - UpdateLoginProfile
        userIdentity|contains: 'AssumedRole'
    condition: selection
level: high
"#.to_string(),
                severity: "high".to_string(),
                references: vec!["CIS AWS Benchmark 1.16".to_string()],
            },
            DetectionRule {
                rule_id: "SIG-008-CLOUD-META".to_string(),
                title: "SSRF to Cloud Metadata Endpoint".to_string(),
                rule_type: DetectionRuleType::CloudAudit,
                rule_content: r#"title: SSRF to Cloud Metadata Endpoint
status: experimental
logsource:
    product: cloud
    service: vpc
detection:
    selection:
        dest.ip: '169.254.169.254'
    condition: selection
level: critical
"#.to_string(),
                severity: "critical".to_string(),
                references: vec!["MITRE ATT&CK T1552.005".to_string()],
            },
        ],
        fix_template: None,
        regression_tests: vec![RegressionTest {
            test_id: "REG-007-CLOUD-IAM".to_string(),
            test_type: RegressionTestType::IntegrationApi,
            language: "python".to_string(),
            code: r#"def test_no_wildcard_in_iam_policies():
    """Verify no IAM policy contains wildcard actions on wildcard resources."""
    policies = iam.list_policies()
    for policy in policies:
        doc = iam.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy['DefaultVersionId'])
        for statement in doc['Document']['Statement']:
            if statement['Effect'] == 'Allow':
                actions = statement.get('Action', [])
                resources = statement.get('Resource', [])
                assert '*' not in (actions if isinstance(actions, list) else [actions]), f"Wildcard action in {policy['PolicyName']}"
                assert '*' not in (resources if isinstance(resources, list) else [resources]), f"Wildcard resource in {policy['PolicyName']}" "#.to_string(),
            description: "Verify no IAM policies grant wildcard permissions".to_string(),
            endpoint: None,
            assertion: "No wildcard actions or resources in IAM policies".to_string(),
        }],
        logging_suggestions: vec![LoggingSuggestion {
            event_name: "iam_privilege_change".to_string(),
            fields: vec![
                LogField { name: "actor".to_string(), field_type: "string".to_string(), required: true, example: "user@example.com".to_string() },
                LogField { name: "action".to_string(), field_type: "string".to_string(), required: true, example: "AttachRolePolicy".to_string() },
                LogField { name: "target_role".to_string(), field_type: "string".to_string(), required: true, example: "admin-role".to_string() },
            ],
            trigger: "Any IAM privilege change operation".to_string(),
            alert_threshold: Some("Any privilege change outside business hours".to_string()),
        }],
        waf_rules: vec![],
        least_privilege: Some(LeastPrivilegeGuidance {
            provider: "aws".to_string(),
            current_policy: r#"{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}"#.to_string(),
            recommended_policy: r#"{
  "Effect": "Allow",
  "Action": [
    "s3:GetObject",
    "s3:ListBucket"
  ],
  "Resource": [
    "arn:aws:s3:::my-bucket",
    "arn:aws:s3:::my-bucket/*"
  ]
}"#.to_string(),
            removed_permissions: vec!["* on *".to_string()],
            added_constraints: vec!["Limited to S3 read actions on specific bucket".to_string(), "No IAM, EC2, or admin actions".to_string()],
            rollback_command: "aws iam put-role-policy --role-name ROLE --policy-name POLICY --policy-document policy.json".to_string(),
        }),
        threat_model_updates: vec![ThreatModelSnippet {
            component: "Cloud IAM".to_string(),
            threat_type: "Privilege Escalation".to_string(),
            description: "Overly permissive IAM roles can be exploited to escalate privileges across cloud resources.".to_string(),
            impact: "Full cloud account compromise, data exfiltration, resource destruction".to_string(),
            mitigation: "Least-privilege IAM policies, MFA enforcement, credential rotation".to_string(),
            stride_category: StrideCategory::ElevationOfPrivilege,
        }],
    }
}

fn defense_for_tenant_isolation(classification: &str) -> DefenseRecommendation {
    DefenseRecommendation {
        classification: classification.to_string(),
        vulnerability_class: "tenant_isolation".to_string(),
        prevention_guidance: vec![
            GuidanceItem {
                title: "Enforce tenant-scoped data access".to_string(),
                description: "Every data access query must include a tenant_id filter. Use row-level security (RLS) in databases and tenant-scoped middleware in APIs.".to_string(),
                priority: GuidancePriority::Critical,
                category: GuidanceCategory::Prevention,
            },
            GuidanceItem {
                title: "Implement tenant context in authentication middleware".to_string(),
                description: "Set the current tenant_id in the request context from the authenticated user's claims. Never accept tenant_id from request body or query parameters for authorization decisions.".to_string(),
                priority: GuidancePriority::Critical,
                category: GuidanceCategory::Prevention,
            },
            GuidanceItem {
                title: "Add tenant boundary integration tests".to_string(),
                description: "Write automated tests where user A attempts to access user B's resources across all tenant-scoped endpoints. These should run in CI on every deployment.".to_string(),
                priority: GuidancePriority::High,
                category: GuidanceCategory::Prevention,
            },
        ],
        detection_guidance: vec![DetectionRule {
            rule_id: "SIG-009-TENANT-ISOLATION".to_string(),
            title: "Potential Tenant Isolation Violation".to_string(),
            rule_type: DetectionRuleType::Sigma,
            rule_content: r#"title: Potential Tenant Isolation Violation - Cross-Tenant Resource Access
status: experimental
logsource:
    product: web_application
    service: api
detection:
    selection:
        http.response_code:
            - 200
            - 201
        user.tenant_id|expand: '%user_tenant_id%'
        object.tenant_id|ne: user.tenant_id
    condition: selection
fields:
    - user.id
    - user.tenant_id
    - object.id
    - object.tenant_id
    - http.url
level: critical
"#.to_string(),
            severity: "critical".to_string(),
            references: vec!["OWASP API6:2023".to_string(), "CWE-639".to_string()],
        }],
        fix_template: Some(FixTemplate {
            language: "typescript".to_string(),
            framework: "express".to_string(),
            before: r#"app.get('/api/tenants/:tenantId/resources/:id', async (req, res) => {
  const resource = await db.getResource(req.params.id);
  res.json(resource);
});"#.to_string(),
            after: r#"app.get('/api/tenants/:tenantId/resources/:id', tenantGuard(), async (req, res) => {
  if (req.params.tenantId !== req.user.tenantId) {
    return res.status(403).json({ error: 'Cross-tenant access denied' });
  }
  const resource = await db.getResource(req.params.id);
  if (resource.tenantId !== req.user.tenantId) {
    return res.status(403).json({ error: 'Cross-tenant access denied' });
  }
  res.json(resource);
});"#.to_string(),
            description: "Add tenant-scoped authorization middleware and verify object tenant ownership before returning data".to_string(),
        }),
        regression_tests: vec![
            RegressionTest {
                test_id: "REG-009-TENANT-ISOLATION".to_string(),
                test_type: RegressionTestType::IntegrationApi,
                language: "typescript".to_string(),
                code: r#"describe('Tenant Isolation', () => {
  it('denies cross-tenant resource access', async () => {
    const tenantAToken = await login('user_a', 'tenant_a');
    const tenantBResourceId = await createResource('user_b', 'tenant_b', { name: 'private' });
    const res = await request(app)
      .get(`/api/tenants/tenant_b/resources/${tenantBResourceId}`)
      .set('Authorization', `Bearer ${tenantAToken}`);
    expect(res.status).toBe(403);
  });
  it('allows same-tenant resource access', async () => {
    const tenantAToken = await login('user_a', 'tenant_a');
    const tenantAResourceId = await createResource('user_a', 'tenant_a', { name: 'my-resource' });
    const res = await request(app)
      .get(`/api/tenants/tenant_a/resources/${tenantAResourceId}`)
      .set('Authorization', `Bearer ${tenantAToken}`);
    expect(res.status).toBe(200);
  });
});"#.to_string(),
                description: "Verifies users cannot access resources belonging to other tenants".to_string(),
                endpoint: Some("/api/tenants/{tenantId}/resources/{id}".to_string()),
                assertion: "response.status === 403 for cross-tenant access, 200 for same-tenant".to_string(),
            },
        ],
        logging_suggestions: vec![LoggingSuggestion {
            event_name: "tenant_isolation_violation".to_string(),
            fields: vec![
                LogField { name: "user_id".to_string(), field_type: "string".to_string(), required: true, example: "usr_abc123".to_string() },
                LogField { name: "user_tenant_id".to_string(), field_type: "string".to_string(), required: true, example: "tenant_xyz".to_string() },
                LogField { name: "target_tenant_id".to_string(), field_type: "string".to_string(), required: true, example: "tenant_abc".to_string() },
                LogField { name: "resource_id".to_string(), field_type: "string".to_string(), required: true, example: "res_789".to_string() },
            ],
            trigger: "User attempts to access resource in a different tenant".to_string(),
            alert_threshold: Some("3 violations per minute per user".to_string()),
        }],
        waf_rules: vec![WafRule {
            rule_id: "WAF-009-TENANT".to_string(),
            rule_type: WafRuleType::PatternMatch,
            pattern: "/api/tenants/[^/]+/".to_string(),
            action: WafAction::Challenge,
            description: "Challenge requests with mismatched tenant context in URL vs. auth token".to_string(),
        }],
        least_privilege: None,
        threat_model_updates: vec![ThreatModelSnippet {
            component: "API - Multi-Tenant Data Access".to_string(),
            threat_type: "Information Disclosure".to_string(),
            description: "Insufficient tenant isolation allows one tenant to access another tenant's data through API endpoints.".to_string(),
            impact: "Cross-tenant data breach, regulatory violations, loss of customer trust".to_string(),
            mitigation: "Enforce tenant context at middleware level, verify object ownership on every access, add tenant boundary integration tests".to_string(),
            stride_category: StrideCategory::InformationDisclosure,
        }],
    }
}

fn defense_for_business_logic(abuse_type: &str, classification: &str) -> DefenseRecommendation {
    match abuse_type {
        "price_tamper" => DefenseRecommendation {
            classification: classification.to_string(),
            vulnerability_class: "business_logic_price_tamper".to_string(),
            prevention_guidance: vec![
                GuidanceItem { title: "Validate all client-supplied prices server-side".to_string(), description: "Server accepts client-supplied price that overrides the authoritative price, allowing an attacker to purchase at a reduced amount.".to_string(), priority: GuidancePriority::Critical, category: GuidanceCategory::Prevention },
                GuidanceItem { title: "Enforce workflow state machines".to_string(), description: "Implement server-side state machines for multi-step workflows.".to_string(), priority: GuidancePriority::High, category: GuidanceCategory::Prevention },
                GuidanceItem { title: "Add idempotency for state-changing operations".to_string(), description: "Require idempotency keys for POST operations that change state.".to_string(), priority: GuidancePriority::High, category: GuidanceCategory::Hardening },
            ],
            detection_guidance: vec![DetectionRule {
                rule_id: "SIG-010-PRICE-TAMPER".to_string(),
                title: "Potential Price Tampering - Client-Supplied Price Override".to_string(),
                rule_type: DetectionRuleType::Sigma,
                rule_content: r#"title: Potential Price Tampering
status: experimental
logsource:
    product: web_application
    service: api
detection:
    selection:
        http.method: POST
        http.url|contains: '/orders'
        json.total_usd|ne: json.unit_price * json.quantity
    condition: selection
level: high
"#.to_string(),
                severity: "high".to_string(),
                references: vec!["OWASP API4:2023".to_string(), "CWE-841".to_string()],
            }],
            fix_template: Some(FixTemplate {
                language: "typescript".to_string(),
                framework: "express".to_string(),
                before: r#"app.post('/api/orders', async (req, res) => {
  const { product_id, quantity, total_usd } = req.body;
  const order = await db.createOrder({ product_id, quantity, total_usd });
  res.status(201).json(order);
});"#.to_string(),
                after: r#"app.post('/api/orders', async (req, res) => {
  const { product_id, quantity } = req.body;
  const product = await db.getProduct(product_id);
  const total_usd = product.price_usd * quantity;
  if (req.body.total_usd !== undefined && req.body.total_usd !== total_usd) {
    return res.status(400).json({ error: 'total_usd must match', expected: total_usd });
  }
  const order = await db.createOrder({ product_id, quantity, total_usd });
  res.status(201).json(order);
});"#.to_string(),
                description: "Business Logic: Price Tampering".to_string(),
            }),
            regression_tests: vec![RegressionTest {
                test_id: "REG-010-PRICE-TAMPER".to_string(),
                test_type: RegressionTestType::IntegrationApi,
                language: "typescript".to_string(),
                code: r#"describe('Price Tamper', () => {
  it('rejects order with tampered price', async () => {
    const res = await request(app).post('/api/orders').send({ product_id: 'prod-alpha', quantity: 1, total_usd: 0.01 });
    expect(res.status).toBe(400);
  });
});"#.to_string(),
                description: "Verifies the server rejects orders where total_usd does not match product price".to_string(),
                endpoint: Some("/api/orders".to_string()),
                assertion: "response.status === 400 for tampered price".to_string(),
            }],
            logging_suggestions: vec![LoggingSuggestion {
                event_name: "business_logic_price_tamper_violation".to_string(),
                fields: vec![
                    LogField { name: "user_id".to_string(), field_type: "string".to_string(), required: true, example: "usr_abc123".to_string() },
                    LogField { name: "submitted_total_usd".to_string(), field_type: "number".to_string(), required: true, example: "0.01".to_string() },
                    LogField { name: "expected_total_usd".to_string(), field_type: "number".to_string(), required: true, example: "29.99".to_string() },
                ],
                trigger: "Client-supplied price does not match expected price".to_string(),
                alert_threshold: Some("3 violations per minute per user".to_string()),
            }],
            waf_rules: vec![WafRule { rule_id: "WAF-010-PRICE-TAMPER".to_string(), rule_type: WafRuleType::PatternMatch, pattern: "/api/orders".to_string(), action: WafAction::Challenge, description: "Challenge price-related order submissions".to_string() }],
            least_privilege: None,
            threat_model_updates: vec![ThreatModelSnippet { component: "API - Order Workflow".to_string(), threat_type: "Business Logic Abuse".to_string(), description: "Server accepts client-supplied price that overrides the authoritative price.".to_string(), impact: "Financial loss through price manipulation".to_string(), mitigation: "Server-side price validation, state machine enforcement".to_string(), stride_category: StrideCategory::Tampering }],
        },
        "state_skip" => DefenseRecommendation {
            classification: classification.to_string(),
            vulnerability_class: "business_logic_state_skip".to_string(),
            prevention_guidance: vec![
                GuidanceItem { title: "Enforce workflow state transitions server-side".to_string(), description: "Server allows skipping a required prerequisite step, e.g., shipping without payment.".to_string(), priority: GuidancePriority::Critical, category: GuidanceCategory::Prevention },
                GuidanceItem { title: "Validate state before each transition".to_string(), description: "Check current state before allowing any state transition. Require prerequisite states explicitly.".to_string(), priority: GuidancePriority::High, category: GuidanceCategory::Prevention },
            ],
            detection_guidance: vec![DetectionRule {
                rule_id: "SIG-011-STATE-SKIP".to_string(),
                title: "Potential State-Skip - Workflow Prerequisite Bypass".to_string(),
                rule_type: DetectionRuleType::Sigma,
                rule_content: r#"title: Potential State-Skip
status: experimental
logsource:
    product: web_application
    service: api
detection:
    selection:
        json.status|change_to: 'shipped'
        json.previous_status:
            - 'draft'
            - 'pending'
    condition: selection
level: high
"#.to_string(),
                severity: "high".to_string(),
                references: vec!["OWASP API4:2023".to_string(), "CWE-841".to_string()],
            }],
            fix_template: Some(FixTemplate {
                language: "typescript".to_string(),
                framework: "express".to_string(),
                before: "app.post('/api/orders/:id/ship', async (req, res) => { order.status = 'shipped'; res.json(order); });".to_string(),
                after: "app.post('/api/orders/:id/ship', async (req, res) => { if (order.status !== 'paid') return res.status(400); order.status = 'shipped'; res.json(order); });".to_string(),
                description: "Business Logic: State-Skip Bypass".to_string(),
            }),
            regression_tests: vec![RegressionTest {
                test_id: "REG-011-STATE-SKIP".to_string(),
                test_type: RegressionTestType::IntegrationApi,
                language: "typescript".to_string(),
                code: "it('rejects ship for unpaid order', async () => { const res = await ship(order_id); expect(res.status).toBe(400); });".to_string(),
                description: "Verifies the server rejects shipping when order is not in paid status".to_string(),
                endpoint: Some("/api/orders/:id/ship".to_string()),
                assertion: "response.status === 400 for unpaid order".to_string(),
            }],
            logging_suggestions: vec![LoggingSuggestion {
                event_name: "business_logic_state_skip_violation".to_string(),
                fields: vec![
                    LogField { name: "order_id".to_string(), field_type: "string".to_string(), required: true, example: "ord_001".to_string() },
                    LogField { name: "previous_status".to_string(), field_type: "string".to_string(), required: true, example: "draft".to_string() },
                    LogField { name: "new_status".to_string(), field_type: "string".to_string(), required: true, example: "shipped".to_string() },
                ],
                trigger: "Workflow state transition bypasses required prerequisite".to_string(),
                alert_threshold: Some("3 violations per minute per user".to_string()),
            }],
            waf_rules: vec![],
            least_privilege: None,
            threat_model_updates: vec![ThreatModelSnippet { component: "API - Order Workflow".to_string(), threat_type: "Business Logic Abuse".to_string(), description: "Server allows skipping prerequisite steps in workflow.".to_string(), impact: "Unauthorized state transitions, fraud".to_string(), mitigation: "State machine enforcement on every transition".to_string(), stride_category: StrideCategory::Tampering }],
        },
        "replay" => DefenseRecommendation {
            classification: classification.to_string(),
            vulnerability_class: "business_logic_replay".to_string(),
            prevention_guidance: vec![
                GuidanceItem { title: "Require idempotency keys for state-changing operations".to_string(), description: "Server allows a one-time action to be replayed, producing a duplicate effect.".to_string(), priority: GuidancePriority::Critical, category: GuidanceCategory::Prevention },
                GuidanceItem { title: "Track and deduplicate requests".to_string(), description: "Use idempotency keys or request fingerprints to detect and reject duplicate submissions.".to_string(), priority: GuidancePriority::High, category: GuidanceCategory::Prevention },
            ],
            detection_guidance: vec![DetectionRule {
                rule_id: "SIG-012-REPLAY".to_string(),
                title: "Potential Replay Attack - Duplicate One-Time Action".to_string(),
                rule_type: DetectionRuleType::Sigma,
                rule_content: r#"title: Potential Replay Attack
status: experimental
logsource:
    product: web_application
    service: api
detection:
    selection:
        http.method: POST
        event.idempotency_key|exists: false
    condition: selection
level: high
"#.to_string(),
                severity: "high".to_string(),
                references: vec!["OWASP API4:2023".to_string(), "CWE-841".to_string()],
            }],
            fix_template: Some(FixTemplate {
                language: "typescript".to_string(),
                framework: "express".to_string(),
                before: "app.post('/api/orders/:id/pay', async (req, res) => { order.status = 'paid'; res.json(order); });".to_string(),
                after: "app.post('/api/orders/:id/pay', async (req, res) => { const key = req.headers['idempotency-key']; const existing = await db.findByIdempotencyKey(key); if (existing) return res.json(existing); order.status = 'paid'; res.json(order); });".to_string(),
                description: "Business Logic: Replay Attack".to_string(),
            }),
            regression_tests: vec![RegressionTest {
                test_id: "REG-012-REPLAY".to_string(),
                test_type: RegressionTestType::IntegrationApi,
                language: "typescript".to_string(),
                code: "it('rejects duplicate payment with same idempotency key', async () => { await pay(key1); const res = await pay(key1); expect(res.body.duplicate).toBe(true); });".to_string(),
                description: "Verifies the server detects and rejects replayed one-time actions".to_string(),
                endpoint: Some("/api/orders/:id/pay".to_string()),
                assertion: "duplicate idempotency key returns existing result".to_string(),
            }],
            logging_suggestions: vec![LoggingSuggestion {
                event_name: "business_logic_replay_violation".to_string(),
                fields: vec![
                    LogField { name: "idempotency_key".to_string(), field_type: "string".to_string(), required: true, example: "pay-abc123".to_string() },
                    LogField { name: "order_id".to_string(), field_type: "string".to_string(), required: true, example: "ord_001".to_string() },
                ],
                trigger: "Replayed one-time action detected without idempotency key".to_string(),
                alert_threshold: Some("3 violations per minute per user".to_string()),
            }],
            waf_rules: vec![],
            least_privilege: None,
            threat_model_updates: vec![ThreatModelSnippet { component: "API - Payment Workflow".to_string(), threat_type: "Business Logic Abuse".to_string(), description: "Server allows replaying one-time actions.".to_string(), impact: "Duplicate charges, double resource creation".to_string(), mitigation: "Idempotency keys for all state-changing operations".to_string(), stride_category: StrideCategory::Tampering }],
        },
        "quantity_limit_bypass" => DefenseRecommendation {
            classification: classification.to_string(),
            vulnerability_class: "business_logic_quantity_limit_bypass".to_string(),
            prevention_guidance: vec![
                GuidanceItem { title: "Enforce quantity limits server-side".to_string(), description: "Server allows exceeding configured quantity or rate limits.".to_string(), priority: GuidancePriority::Critical, category: GuidanceCategory::Prevention },
                GuidanceItem { title: "Validate all client-supplied quantities against configured limits".to_string(), description: "Check quantity against max limits before processing; reject with clear error message.".to_string(), priority: GuidancePriority::High, category: GuidanceCategory::Prevention },
            ],
            detection_guidance: vec![DetectionRule {
                rule_id: "SIG-013-QUANTITY-BYPASS".to_string(),
                title: "Potential Quantity Limit Bypass".to_string(),
                rule_type: DetectionRuleType::Sigma,
                rule_content: r#"title: Potential Quantity Limit Bypass
status: experimental
logsource:
    product: web_application
    service: api
detection:
    selection:
        http.method: POST
        json.quantity|gt: 10
    condition: selection
level: medium
"#.to_string(),
                severity: "medium".to_string(),
                references: vec!["OWASP API4:2023".to_string(), "CWE-841".to_string()],
            }],
            fix_template: Some(FixTemplate {
                language: "typescript".to_string(),
                framework: "express".to_string(),
                before: "app.post('/api/orders', async (req, res) => { const order = await db.createOrder(req.body); res.json(order); });".to_string(),
                after: "app.post('/api/orders', async (req, res) => { if (req.body.quantity > MAX_QTY) return res.status(400).json({ error: 'quantity exceeds limit' }); const order = await db.createOrder(req.body); res.json(order); });".to_string(),
                description: "Business Logic: Quantity/limit bypass".to_string(),
            }),
            regression_tests: vec![RegressionTest {
                test_id: "REG-013-QUANTITY-BYPASS".to_string(),
                test_type: RegressionTestType::IntegrationApi,
                language: "typescript".to_string(),
                code: "it('rejects order exceeding quantity limit', async () => { const res = await request(app).post('/api/orders').send({ quantity: 9999 }); expect(res.status).toBe(400); });".to_string(),
                description: "Verifies the server rejects orders that exceed configured quantity limits".to_string(),
                endpoint: Some("/api/orders".to_string()),
                assertion: "response.status === 400 for quantity exceeding limit".to_string(),
            }],
            logging_suggestions: vec![LoggingSuggestion {
                event_name: "business_logic_quantity_limit_violation".to_string(),
                fields: vec![
                    LogField { name: "quantity_requested".to_string(), field_type: "number".to_string(), required: true, example: "9999".to_string() },
                    LogField { name: "quantity_limit".to_string(), field_type: "number".to_string(), required: true, example: "10".to_string() },
                ],
                trigger: "Client-submitted quantity exceeds configured limit".to_string(),
                alert_threshold: Some("3 violations per minute per user".to_string()),
            }],
            waf_rules: vec![],
            least_privilege: None,
            threat_model_updates: vec![ThreatModelSnippet { component: "API - Order Workflow".to_string(), threat_type: "Business Logic Abuse".to_string(), description: "Server allows exceeding quantity limits.".to_string(), impact: "Resource exhaustion, fraud".to_string(), mitigation: "Server-side quantity limit enforcement".to_string(), stride_category: StrideCategory::Tampering }],
        },
        _ => generic_defense(classification),
    }
}

fn generic_defense(classification: &str) -> DefenseRecommendation {
    DefenseRecommendation {
        classification: classification.to_string(),
        vulnerability_class: classification.to_string(),
        prevention_guidance: vec![
            GuidanceItem { title: "Implement defense-in-depth".to_string(), description: "Apply multiple layers of security controls. No single control should be the only barrier.".to_string(), priority: GuidancePriority::High, category: GuidanceCategory::Prevention },
            GuidanceItem { title: "Conduct security review".to_string(), description: "Perform a thorough security review of the affected component. Consider threat modeling and penetration testing.".to_string(), priority: GuidancePriority::Medium, category: GuidanceCategory::Prevention },
        ],
        detection_guidance: vec![DetectionRule {
            rule_id: format!("SIG-GEN-{}", classification.to_ascii_uppercase().chars().take(12).collect::<String>()),
            title: format!("{} - Anomalous Activity Detected", classification),
            rule_type: DetectionRuleType::Sigma,
            rule_content: format!(r#"title: {classification} - Anomalous Activity Detected
status: experimental
logsource:
    product: web_application
    service: api
detection:
    selection:
        http.response_code:
            - 200
            - 201
        event_type: '{classification}'
    condition: selection
fields:
    - user.id
    - source.ip
    - http.url
    - http.method
level: medium
"#, classification = classification),
            severity: "medium".to_string(),
            references: vec!["OWASP Top 10".to_string()],
        }],
        fix_template: None,
        regression_tests: vec![],
        logging_suggestions: vec![],
        waf_rules: vec![],
        least_privilege: None,
        threat_model_updates: vec![ThreatModelSnippet {
            component: "General".to_string(),
            threat_type: classification.to_string(),
            description: format!("A {} vulnerability was identified that requires further analysis.", classification),
            impact: "Varies based on vulnerability class and context".to_string(),
            mitigation: "Implement defense-in-depth and conduct security review".to_string(),
            stride_category: StrideCategory::Tampering,
        }],
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseReport {
    pub target: String,
    pub classification: String,
    pub vulnerability_class: String,
    pub recommendations: DefenseRecommendation,
    pub maturity_score: DefenseMaturityScore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseMaturityScore {
    pub prevention: f64,
    pub detection: f64,
    pub fix_available: bool,
    pub regression_available: bool,
    pub overall: f64,
}

impl DefenseMaturityScore {
    pub fn from_recommendation(rec: &DefenseRecommendation) -> Self {
        let prevention = if rec.prevention_guidance.is_empty() {
            0.0
        } else if rec.prevention_guidance.len() >= 3 {
            0.9
        } else {
            0.5
        };
        let detection = if rec.detection_guidance.is_empty() {
            0.1
        } else {
            0.8
        };
        let fix_available = rec.fix_template.is_some();
        let regression_available = !rec.regression_tests.is_empty();
        let overall = (prevention * 0.35
            + detection * 0.25
            + if fix_available { 0.20_f64 } else { 0.05 }
            + if regression_available { 0.20 } else { 0.05 })
        .min(1.0);
        Self {
            prevention,
            detection,
            fix_available,
            regression_available,
            overall,
        }
    }
}

pub fn generate_defense_report(target: &str, classification: &str) -> DefenseReport {
    let recommendations = recommend(classification);
    let maturity_score = DefenseMaturityScore::from_recommendation(&recommendations);
    DefenseReport {
        target: target.to_string(),
        classification: classification.to_string(),
        vulnerability_class: recommendations.vulnerability_class.clone(),
        recommendations,
        maturity_score,
    }
}

pub fn generate_regression_tests(classification: &str) -> Vec<RegressionTest> {
    recommend(classification).regression_tests
}

pub fn generate_sigma_rule(classification: &str) -> Option<DetectionRule> {
    let rec = recommend(classification);
    rec.detection_guidance
        .into_iter()
        .find(|r| r.rule_type == DetectionRuleType::Sigma)
}

pub fn generate_least_privilege_guidance(classification: &str) -> Option<LeastPrivilegeGuidance> {
    recommend(classification).least_privilege
}

pub fn render_defense_report(report: &DefenseReport) -> String {
    let mut md = String::new();
    md.push_str(&format!(
        "# BALONCORE Defense Report: {}\n\n",
        report.classification
    ));
    md.push_str(&format!("**Target:** {}\n", report.target));
    md.push_str(&format!(
        "**Vulnerability Class:** {}\n",
        report.vulnerability_class
    ));
    md.push_str(&format!(
        "**Defense Maturity Score:** {:.0}%\n\n",
        report.maturity_score.overall * 100.0
    ));
    md.push_str(&format!(
        "- Prevention: {:.0}%\n",
        report.maturity_score.prevention * 100.0
    ));
    md.push_str(&format!(
        "- Detection: {:.0}%\n",
        report.maturity_score.detection * 100.0
    ));
    md.push_str(&format!(
        "- Fix Available: {}\n",
        if report.maturity_score.fix_available {
            "Yes"
        } else {
            "No"
        }
    ));
    md.push_str(&format!(
        "- Regression Tests: {}\n\n",
        if report.maturity_score.regression_available {
            "Yes"
        } else {
            "No"
        }
    ));

    md.push_str("## Prevention Guidance\n\n");
    for item in &report.recommendations.prevention_guidance {
        md.push_str(&format!(
            "### [{}] {}\n\n",
            item.priority.as_str().to_uppercase(),
            item.title
        ));
        md.push_str(&format!("{}\n\n", item.description));
    }

    if !report.recommendations.detection_guidance.is_empty() {
        md.push_str("## Detection Guidance\n\n");
        for rule in &report.recommendations.detection_guidance {
            md.push_str(&format!("### {} (`{}`)\n\n", rule.title, rule.rule_id));
            md.push_str(&format!(
                "**Type:** {} | **Severity:** {}\n\n",
                rule.rule_type.as_str(),
                rule.severity
            ));
            md.push_str("```\n");
            md.push_str(&rule.rule_content);
            md.push_str("```\n\n");
        }
    }

    if let Some(ref fix) = report.recommendations.fix_template {
        md.push_str(&format!(
            "## Fix Template ({}/{})\n\n",
            fix.language, fix.framework
        ));
        md.push_str(&format!("{}\n\n", fix.description));
        md.push_str("**Before:**\n```");
        md.push_str(&fix.language);
        md.push_str("\n");
        md.push_str(&fix.before);
        md.push_str("\n```\n\n");
        md.push_str("**After:**\n```");
        md.push_str(&fix.language);
        md.push_str("\n");
        md.push_str(&fix.after);
        md.push_str("\n```\n\n");
    }

    if !report.recommendations.regression_tests.is_empty() {
        md.push_str("## Regression Tests\n\n");
        for test in &report.recommendations.regression_tests {
            md.push_str(&format!(
                "### {} ({})\n\n",
                test.test_id,
                test.test_type.as_str()
            ));
            md.push_str(&format!("{}\n\n", test.description));
            if let Some(ref endpoint) = test.endpoint {
                md.push_str(&format!("**Endpoint:** `{}`\n\n", endpoint));
            }
            md.push_str(&format!("**Assertion:** {}\n\n", test.assertion));
            md.push_str("```");
            md.push_str(&test.language);
            md.push_str("\n");
            md.push_str(&test.code);
            md.push_str("\n```\n\n");
        }
    }

    if !report.recommendations.logging_suggestions.is_empty() {
        md.push_str("## Logging Suggestions\n\n");
        for log in &report.recommendations.logging_suggestions {
            md.push_str(&format!("### `{}`\n\n", log.event_name));
            md.push_str(&format!("**Trigger:** {}\n\n", log.trigger));
            if let Some(ref threshold) = log.alert_threshold {
                md.push_str(&format!("**Alert Threshold:** {}\n\n", threshold));
            }
            md.push_str("| Field | Type | Required | Example |\n");
            md.push_str("|-------|------|----------|---------|\n");
            for field in &log.fields {
                md.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    field.name,
                    field.field_type,
                    if field.required { "Yes" } else { "No" },
                    field.example
                ));
            }
            md.push_str("\n");
        }
    }

    if !report.recommendations.waf_rules.is_empty() {
        md.push_str("## WAF Rules\n\n");
        for rule in &report.recommendations.waf_rules {
            md.push_str(&format!(
                "### {} ({})\n\n",
                rule.rule_id,
                rule.rule_type.as_str()
            ));
            md.push_str(&format!(
                "**Action:** {} | **Pattern:** `{}`\n\n",
                rule.action.as_str(),
                rule.pattern
            ));
            md.push_str(&format!("{}\n\n", rule.description));
        }
    }

    if let Some(ref lp) = report.recommendations.least_privilege {
        md.push_str("## Least-Privilege Guidance\n\n");
        md.push_str(&format!("**Provider:** {}\n\n", lp.provider));
        md.push_str("**Current Policy:**\n```json\n");
        md.push_str(&lp.current_policy);
        md.push_str("\n```\n\n**Recommended Policy:**\n```json\n");
        md.push_str(&lp.recommended_policy);
        md.push_str("\n```\n\n**Removed Permissions:**\n");
        for perm in &lp.removed_permissions {
            md.push_str(&format!("- {}\n", perm));
        }
        md.push_str("\n**Added Constraints:**\n");
        for c in &lp.added_constraints {
            md.push_str(&format!("- {}\n", c));
        }
        md.push_str(&format!(
            "\n**Rollback Command:** `{}`\n\n",
            lp.rollback_command
        ));
    }

    if !report.recommendations.threat_model_updates.is_empty() {
        md.push_str("## Threat Model Updates\n\n");
        for tm in &report.recommendations.threat_model_updates {
            md.push_str(&format!(
                "### {} - {} ({})\n\n",
                tm.component,
                tm.threat_type,
                tm.stride_category.as_str()
            ));
            md.push_str(&format!("**Description:** {}\n\n", tm.description));
            md.push_str(&format!("**Impact:** {}\n\n", tm.impact));
            md.push_str(&format!("**Mitigation:** {}\n\n", tm.mitigation));
        }
    }

    md
}

pub fn recommend_for_findings(classifications: &[String]) -> Vec<DefenseRecommendation> {
    let mut seen = std::collections::BTreeSet::new();
    let mut results = Vec::new();
    for class in classifications {
        let key = class.to_ascii_lowercase().replace(' ', "_");
        if seen.insert(key.clone()) {
            results.push(recommend(&key));
        }
    }
    if results.is_empty() {
        results.push(recommend("unknown"));
    }
    results
}

pub fn defense_maturity_for_finding(classification: &str) -> DefenseMaturityScore {
    let rec = recommend(classification);
    DefenseMaturityScore::from_recommendation(&rec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recommend_idor() {
        let rec = recommend("idor");
        assert_eq!(rec.vulnerability_class, "idor");
        assert!(!rec.prevention_guidance.is_empty());
        assert!(rec.fix_template.is_some());
        assert!(!rec.regression_tests.is_empty());
        assert!(!rec.detection_guidance.is_empty());
        assert!(!rec.threat_model_updates.is_empty());
    }

    #[test]
    fn test_recommend_bola() {
        let rec = recommend("broken_object_level_authorization");
        assert_eq!(rec.vulnerability_class, "idor");
        assert!(!rec.prevention_guidance.is_empty());
    }

    #[test]
    fn test_recommend_reentrancy() {
        let rec = recommend("reentrancy");
        assert_eq!(rec.vulnerability_class, "reentrancy");
        assert!(rec.prevention_guidance.len() >= 3);
        assert!(rec.fix_template.is_some());
        assert!(!rec.regression_tests.is_empty());
    }

    #[test]
    fn test_recommend_access_control() {
        let rec = recommend("access_control");
        assert_eq!(rec.vulnerability_class, "access_control");
        assert!(!rec.prevention_guidance.is_empty());
        assert!(rec.fix_template.is_some());
    }

    #[test]
    fn test_recommend_xss() {
        let rec = recommend("xss");
        assert_eq!(rec.vulnerability_class, "xss");
        assert!(!rec.waf_rules.is_empty());
        assert!(rec.fix_template.is_some());
    }

    #[test]
    fn test_recommend_ssrf() {
        let rec = recommend("ssrf");
        assert_eq!(rec.vulnerability_class, "ssrf");
        assert!(!rec.waf_rules.is_empty());
        assert!(rec.fix_template.is_some());
    }

    #[test]
    fn test_recommend_sql_injection() {
        let rec = recommend("sql_injection");
        assert_eq!(rec.vulnerability_class, "injection");
        assert!(rec.fix_template.is_some());
    }

    #[test]
    fn test_recommend_cloud() {
        let rec = recommend("cloud_privilege_escalation");
        assert!(!rec.prevention_guidance.is_empty());
        assert!(rec.least_privilege.is_some());
        assert!(!rec.detection_guidance.is_empty());
    }

    #[test]
    fn test_recommend_generic() {
        let rec = recommend("unknown_vuln");
        assert!(!rec.prevention_guidance.is_empty());
        assert!(!rec.threat_model_updates.is_empty());
    }

    #[test]
    fn test_defense_maturity_score() {
        let rec = recommend("idor");
        let score = DefenseMaturityScore::from_recommendation(&rec);
        assert!(score.overall > 0.5);
        assert!(score.prevention > 0.0);
        assert!(score.detection > 0.0);
        assert!(score.fix_available);
        assert!(score.regression_available);
    }

    #[test]
    fn test_generate_defense_report() {
        let report = generate_defense_report("http://target", "reentrancy");
        assert_eq!(report.target, "http://target");
        assert_eq!(report.classification, "reentrancy");
        assert!(report.maturity_score.overall > 0.0);
    }

    #[test]
    fn test_generate_regression_tests() {
        let tests = generate_regression_tests("idor");
        assert!(!tests.is_empty());
        assert_eq!(tests[0].test_id, "REG-001-IDOR");
    }

    #[test]
    fn test_generate_sigma_rule() {
        let rule = generate_sigma_rule("idor");
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().rule_type, DetectionRuleType::Sigma);
    }

    #[test]
    fn test_generate_least_privilege() {
        let lp = generate_least_privilege_guidance("cloud_privilege_escalation");
        assert!(lp.is_some());
        let lp = lp.unwrap();
        assert_eq!(lp.provider, "aws");
        assert!(!lp.removed_permissions.is_empty());
    }

    #[test]
    fn test_render_defense_report() {
        let report = generate_defense_report("http://target", "idor");
        let md = render_defense_report(&report);
        assert!(md.contains("# BALONCORE Defense Report"));
        assert!(md.contains("Prevention Guidance"));
        assert!(md.contains("Detection Guidance"));
        assert!(md.contains("Regression Tests"));
        assert!(md.contains("Fix Template"));
    }

    #[test]
    fn test_render_defense_report_cloud() {
        let report = generate_defense_report(
            "arn:aws:iam::123456:role/admin",
            "cloud_privilege_escalation",
        );
        let md = render_defense_report(&report);
        assert!(md.contains("Least-Privilege"));
        assert!(md.contains("Threat Model"));
    }

    #[test]
    fn test_guidance_priority_as_str() {
        assert_eq!(GuidancePriority::Critical.as_str(), "critical");
        assert_eq!(GuidancePriority::High.as_str(), "high");
        assert_eq!(GuidancePriority::Medium.as_str(), "medium");
        assert_eq!(GuidancePriority::Low.as_str(), "low");
    }

    #[test]
    fn test_guidance_category_as_str() {
        assert_eq!(GuidanceCategory::Prevention.as_str(), "prevention");
        assert_eq!(GuidanceCategory::Detection.as_str(), "detection");
    }

    #[test]
    fn test_detection_rule_type_as_str() {
        assert_eq!(DetectionRuleType::Sigma.as_str(), "sigma");
        assert_eq!(DetectionRuleType::CloudAudit.as_str(), "cloud_audit");
    }

    #[test]
    fn test_regression_test_type_as_str() {
        assert_eq!(
            RegressionTestType::IntegrationApi.as_str(),
            "integration_api"
        );
        assert_eq!(RegressionTestType::Contract.as_str(), "contract");
    }

    #[test]
    fn test_stride_category_as_str() {
        assert_eq!(StrideCategory::Spoofing.as_str(), "spoofing");
        assert_eq!(
            StrideCategory::ElevationOfPrivilege.as_str(),
            "elevation_of_privilege"
        );
    }

    #[test]
    fn test_waf_rule_type_as_str() {
        assert_eq!(WafRuleType::RateLimit.as_str(), "rate_limit");
        assert_eq!(WafAction::Block.as_str(), "block");
    }

    #[test]
    fn test_regression_tests_for_reentrancy() {
        let tests = generate_regression_tests("reentrancy");
        assert!(!tests.is_empty());
        assert_eq!(tests[0].test_type, RegressionTestType::Contract);
    }

    #[test]
    fn test_recommend_tenant_isolation() {
        let rec = recommend("tenant_isolation");
        assert_eq!(rec.vulnerability_class, "tenant_isolation");
        assert!(!rec.prevention_guidance.is_empty());
        assert!(rec.prevention_guidance.len() >= 3);
        assert!(rec.fix_template.is_some());
        assert!(!rec.regression_tests.is_empty());
        assert!(!rec.detection_guidance.is_empty());
        assert!(!rec.waf_rules.is_empty());
        assert!(!rec.threat_model_updates.is_empty());
    }

    #[test]
    fn test_recommend_broken_tenant_isolation() {
        let rec = recommend("broken_tenant_isolation");
        assert_eq!(rec.vulnerability_class, "tenant_isolation");
        assert!(!rec.prevention_guidance.is_empty());
    }

    #[test]
    fn test_generic_defense_has_detection() {
        let rec = recommend("custom_vulnerability");
        assert!(!rec.detection_guidance.is_empty());
        assert!(rec.detection_guidance[0].rule_type == DetectionRuleType::Sigma);
    }

    #[test]
    fn test_recommend_for_findings() {
        let classes = vec![
            "idor".to_string(),
            "reentrancy".to_string(),
            "idor".to_string(),
        ];
        let results = recommend_for_findings(&classes);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].vulnerability_class, "idor");
        assert_eq!(results[1].vulnerability_class, "reentrancy");
    }

    #[test]
    fn test_defense_maturity_for_finding() {
        let score = defense_maturity_for_finding("idor");
        assert!(score.overall > 0.5);
        assert!(score.fix_available);
        assert!(score.regression_available);
    }
}
