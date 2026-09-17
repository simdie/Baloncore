//! Offline Terraform **HCL** (`.tf`) ingestor → `IAMGraph`.
//!
//! The other Terraform path (`terraform.rs`) consumes Terraform *state/plan
//! JSON*. Static IaC corpora such as TerraGoat ship raw HCL `.tf` source, so
//! this module parses the HCL directly (via the `hcl` crate) and builds the
//! same `IAMGraph` the cloud analyzer runs on — no `terraform` binary, no cloud
//! account, no daemon. Detection (public-exposure, over-privileged IAM) stays
//! in `IAMGraph::analyze()`; this module only translates IaC facts into graph
//! nodes/edges:
//!   - `aws_iam_user` / `aws_iam_role`  → `IAMPrincipal`
//!   - `aws_iam_user_policy` / `aws_iam_role_policy` (inline) → `IAMPolicy`
//!     parsed from the embedded JSON, LINKED to the referenced principal (so the
//!     over-privileged check, which requires a principal, fires)
//!   - `aws_iam_policy` (+ attachments) → `IAMPolicy` linked via attachment
//!   - `aws_security_group` → `CloudResource`, marked public iff an `ingress`
//!     rule allows `0.0.0.0/0`
//!   - `aws_s3_bucket` → `CloudResource`, marked public iff `acl` is a
//!     public-read ACL
//!
//! Everything else is ignored (TerraGoat has many resource types this analyzer
//! does not model; they are simply not added to the graph).

use std::path::Path;

use hcl::expr::TemplateExpr;
use hcl::{Block, Body, Expression};
use serde_json::Value;

use crate::cloud_iam::{
    CloudProvider, CloudResource, Effect, IAMGraph, IAMPolicy, IAMPrincipal, IAMStatement,
    PolicySourceType, PrincipalKind,
};

/// Parse the given `.tf` files into a single `IAMGraph`. Returns an error only
/// if a file cannot be read or is not valid HCL.
pub fn ingest_hcl_files<P: AsRef<Path>>(paths: &[P]) -> Result<IAMGraph, String> {
    let mut bodies: Vec<Body> = Vec::new();
    for p in paths {
        let raw = std::fs::read_to_string(p.as_ref())
            .map_err(|e| format!("read {}: {e}", p.as_ref().display()))?;
        let body: Body =
            hcl::from_str(&raw).map_err(|e| format!("parse HCL {}: {e}", p.as_ref().display()))?;
        bodies.push(body);
    }
    Ok(ingest_bodies(&bodies))
}

/// Parse HCL from in-memory strings (used by tests).
pub fn ingest_hcl_str(sources: &[&str]) -> Result<IAMGraph, String> {
    let mut bodies = Vec::new();
    for s in sources {
        bodies.push(hcl::from_str::<Body>(s).map_err(|e| format!("parse HCL: {e}"))?);
    }
    Ok(ingest_bodies(&bodies))
}

/// One parsed `resource "<type>" "<name>" { .. }` block.
struct ResourceBlock<'a> {
    rtype: String,
    rname: String,
    body: &'a Body,
}

impl<'a> ResourceBlock<'a> {
    fn address(&self) -> String {
        format!("{}.{}", self.rtype, self.rname)
    }
}

fn ingest_bodies(bodies: &[Body]) -> IAMGraph {
    let mut graph = IAMGraph::new("terragoat-hcl", CloudProvider::AWS);

    // Collect every resource block across all files.
    let mut resources: Vec<ResourceBlock> = Vec::new();
    for body in bodies {
        for block in body.blocks() {
            if block.identifier() == "resource" {
                let labels = block.labels();
                if labels.len() >= 2 {
                    resources.push(ResourceBlock {
                        rtype: labels[0].as_str().to_string(),
                        rname: labels[1].as_str().to_string(),
                        body: block.body(),
                    });
                }
            }
        }
    }

    // Pass 1: principals (so inline policies can be linked to them).
    for r in &resources {
        match r.rtype.as_str() {
            "aws_iam_user" => {
                graph.add_principal(IAMPrincipal::new(
                    r.address(),
                    CloudProvider::AWS,
                    PrincipalKind::User,
                    r.address(),
                ));
            }
            "aws_iam_role" => {
                graph.add_principal(IAMPrincipal::new(
                    r.address(),
                    CloudProvider::AWS,
                    PrincipalKind::Role,
                    r.address(),
                ));
            }
            _ => {}
        }
    }

    // Pass 2: policies + linkage + public resources.
    for r in &resources {
        match r.rtype.as_str() {
            "aws_iam_user_policy" | "aws_iam_role_policy" => {
                if let Some(policy) = inline_policy(r) {
                    // Link the inline policy to its referenced principal so the
                    // over-privileged check (which needs a principal) fires.
                    let ref_key = r
                        .body
                        .attributes()
                        .find(|a| a.key() == "user" || a.key() == "role")
                        .and_then(|a| referenced_address(a.expr()));
                    if let Some(principal_addr) = ref_key {
                        if let Some(principal) = graph.principals.get_mut(&principal_addr) {
                            principal.policies.push(policy.name.clone());
                        }
                    }
                    graph.add_policy(policy);
                }
            }
            "aws_iam_policy" => {
                if let Some(policy) = inline_policy(r) {
                    graph.add_policy(policy);
                }
            }
            "aws_iam_user_policy_attachment" | "aws_iam_role_policy_attachment" => {
                // Link an attached managed/custom policy to its principal.
                let principal_addr = r
                    .body
                    .attributes()
                    .find(|a| a.key() == "user" || a.key() == "role")
                    .and_then(|a| referenced_address(a.expr()));
                let policy_addr = r
                    .body
                    .attributes()
                    .find(|a| a.key() == "policy_arn")
                    .and_then(|a| referenced_address(a.expr()));
                if let (Some(pa), Some(pol)) = (principal_addr, policy_addr) {
                    if let Some(principal) = graph.principals.get_mut(&pa) {
                        // store both the address and the short name
                        principal.policies.push(pol.clone());
                        if let Some(short) = pol.rsplit('.').next() {
                            principal.policies.push(short.to_string());
                        }
                    }
                }
            }
            "aws_security_group" => {
                let mut res = CloudResource::new(
                    r.address(),
                    CloudProvider::AWS,
                    "security-group",
                    r.address(),
                );
                let open = open_ingress_details(r);
                if !open.is_empty() {
                    res.is_public = true;
                    res.public_access_details = open;
                }
                graph.add_resource(res);
            }
            "aws_s3_bucket" => {
                let mut res =
                    CloudResource::new(r.address(), CloudProvider::AWS, "s3-bucket", r.address());
                if let Some(acl) = attr_string(r, "acl") {
                    if acl == "public-read" || acl == "public-read-write" {
                        res.is_public = true;
                        res.public_access_details = vec![format!("bucket ACL is `{acl}`")];
                    }
                }
                graph.add_resource(res);
            }
            _ => {}
        }
    }

    graph
}

/// Build an `IAMPolicy` from an inline-policy resource block's `policy`
/// attribute (an embedded JSON document). The policy id/name is the resource
/// address so findings/ground-truth key on it.
fn inline_policy(r: &ResourceBlock) -> Option<IAMPolicy> {
    let json = r
        .body
        .attributes()
        .find(|a| a.key() == "policy")
        .and_then(|a| expr_to_string(a.expr()))?;
    let value: Value = serde_json::from_str(&json).ok()?;
    let mut policy = IAMPolicy::new(r.address(), r.address(), CloudProvider::AWS);
    policy.source_type = PolicySourceType::Terraform;
    policy.source_doc = json;

    let statements = match value.get("Statement") {
        Some(Value::Array(a)) => a.clone(),
        Some(obj @ Value::Object(_)) => vec![obj.clone()],
        _ => Vec::new(),
    };
    for (i, stmt) in statements.iter().enumerate() {
        let actions = json_string_or_array(stmt.get("Action"));
        let resources = json_string_or_array(stmt.get("Resource"));
        let deny = stmt.get("Effect").and_then(|e| e.as_str()) == Some("Deny");
        let id = format!("{}-stmt-{i}", r.address());
        let statement = if deny {
            IAMStatement::new_deny(id, actions, resources)
        } else {
            IAMStatement::new_allow(id, actions, resources)
        };
        let _ = Effect::Allow; // keep Effect import meaningful regardless of branch
        policy = policy.with_statement(statement);
    }
    Some(policy)
}

/// Collect `ingress` rules that allow `0.0.0.0/0`, returning human-readable
/// details (empty if the security group has no world-open ingress).
fn open_ingress_details(r: &ResourceBlock) -> Vec<String> {
    let mut details = Vec::new();
    for block in r.body.blocks().filter(|b| b.identifier() == "ingress") {
        let cidrs = block
            .body()
            .attributes()
            .find(|a| a.key() == "cidr_blocks")
            .map(|a| expr_to_strings(a.expr()))
            .unwrap_or_default();
        if cidrs.iter().any(|c| c == "0.0.0.0/0") {
            let from = block
                .body()
                .attributes()
                .find(|a| a.key() == "from_port")
                .and_then(|a| expr_to_string(a.expr()))
                .unwrap_or_else(|| "?".to_string());
            let to = block
                .body()
                .attributes()
                .find(|a| a.key() == "to_port")
                .and_then(|a| expr_to_string(a.expr()))
                .unwrap_or_else(|| "?".to_string());
            details.push(format!("ingress {from}-{to} open to 0.0.0.0/0"));
        }
    }
    details
}

fn attr_string(r: &ResourceBlock, key: &str) -> Option<String> {
    r.body
        .attributes()
        .find(|a| a.key() == key)
        .and_then(|a| expr_to_string(a.expr()))
}

/// Render a scalar expression to a String. Traversals / variables / function
/// calls (e.g. `aws_iam_user.user.name`) are rendered via their Display form.
fn expr_to_string(e: &Expression) -> Option<String> {
    match e {
        Expression::String(s) => Some(s.clone()),
        Expression::TemplateExpr(t) => Some(template_text(t)),
        Expression::Bool(b) => Some(b.to_string()),
        Expression::Number(n) => Some(n.to_string()),
        Expression::Null => None,
        Expression::Array(_) | Expression::Object(_) => None,
        other => Some(other.to_string()),
    }
}

/// The literal text behind a quoted-string / heredoc template expression.
fn template_text(t: &TemplateExpr) -> String {
    match t {
        TemplateExpr::QuotedString(s) => s.clone(),
        TemplateExpr::Heredoc(h) => h.template.clone(),
    }
}

fn expr_to_strings(e: &Expression) -> Vec<String> {
    match e {
        Expression::Array(items) => items.iter().filter_map(expr_to_string).collect(),
        _ => expr_to_string(e).into_iter().collect(),
    }
}

/// For an attribute whose value references another resource
/// (e.g. `user = aws_iam_user.user.name`), recover the `type.name` address by
/// taking the first two dot-separated segments of the Display form.
fn referenced_address(e: &Expression) -> Option<String> {
    let s = match e {
        Expression::String(s) => s.clone(),
        Expression::TemplateExpr(t) => template_text(t),
        other => other.to_string(),
    };
    // Strip `${ ... }` template wrapping if present.
    let s = s
        .trim()
        .trim_start_matches("${")
        .trim_end_matches('}')
        .trim();
    let segs: Vec<&str> = s.split('.').collect();
    if segs.len() >= 2 && segs[0].starts_with("aws_") {
        Some(format!("{}.{}", segs[0], segs[1]))
    } else {
        None
    }
}

fn json_string_or_array(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

/// Convenience: also accept a `&Block` (top-level) — not used yet but keeps the
/// API symmetric for callers that already hold blocks.
#[allow(dead_code)]
fn block_address(block: &Block) -> Option<String> {
    let labels = block.labels();
    if labels.len() >= 2 {
        Some(format!("{}.{}", labels[0].as_str(), labels[1].as_str()))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPEN_SG: &str = r#"
resource "aws_security_group" "web-node" {
  name = "web_node_sg"
  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"#;

    const WILDCARD_POLICY: &str = r#"
resource "aws_iam_user" "user" {
  name = "the-user"
}
resource "aws_iam_user_policy" "userpolicy" {
  name = "excess_policy"
  user = aws_iam_user.user.name
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    { "Action": ["ec2:*","s3:*"], "Effect": "Allow", "Resource": "*" }
  ]
}
EOF
}
"#;

    const SCOPED_POLICY: &str = r#"
resource "aws_iam_user" "app" {
  name = "app-user"
}
resource "aws_iam_user_policy" "scoped" {
  name = "scoped_policy"
  user = aws_iam_user.app.name
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    { "Action": ["s3:GetObject"], "Effect": "Allow", "Resource": "arn:aws:s3:::my-bucket/*" }
  ]
}
EOF
}
"#;

    const PRIVATE_SG: &str = r#"
resource "aws_security_group" "internal" {
  name = "internal_sg"
  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
"#;

    #[test]
    fn open_security_group_is_public() {
        let g = ingest_hcl_str(&[OPEN_SG]).unwrap();
        let r = g
            .resources
            .get("aws_security_group.web-node")
            .expect("sg resource present");
        assert!(r.is_public, "0.0.0.0/0 ingress must mark the SG public");
        assert!(!r.public_access_details.is_empty());
    }

    #[test]
    fn private_security_group_is_not_public() {
        let g = ingest_hcl_str(&[PRIVATE_SG]).unwrap();
        let r = g.resources.get("aws_security_group.internal").unwrap();
        assert!(!r.is_public, "10.0.0.0/8 ingress must NOT be public");
    }

    #[test]
    fn wildcard_inline_policy_is_linked_and_over_privileged() {
        let g = ingest_hcl_str(&[WILDCARD_POLICY]).unwrap();
        let policy = g
            .policies
            .get("aws_iam_user_policy.userpolicy")
            .expect("policy present");
        assert!(
            policy.is_over_privileged(),
            "wildcard ec2:*/s3:*/Resource:* must be over-privileged"
        );
        // The policy must be linked to the user principal, else analyze() emits
        // no finding.
        let user = g.principals.get("aws_iam_user.user").expect("user present");
        assert!(
            user.policies
                .contains(&"aws_iam_user_policy.userpolicy".to_string()),
            "inline policy must be linked to its user; got {:?}",
            user.policies
        );
    }

    #[test]
    fn scoped_inline_policy_is_not_over_privileged() {
        let g = ingest_hcl_str(&[SCOPED_POLICY]).unwrap();
        let policy = g.policies.get("aws_iam_user_policy.scoped").unwrap();
        assert!(
            !policy.is_over_privileged(),
            "scoped s3:GetObject on a specific ARN must NOT be over-privileged"
        );
    }

    #[test]
    fn analyze_flags_vuln_and_spares_decoys() {
        // End-to-end through the real analyzer: the open SG + wildcard policy
        // are flagged; the scoped policy + private SG are not.
        let g = ingest_hcl_str(&[OPEN_SG, WILDCARD_POLICY, SCOPED_POLICY, PRIVATE_SG]).unwrap();
        let mut g = g;
        let result = g.analyze();
        let flagged: Vec<&str> = result
            .findings
            .iter()
            .map(|f| f.affected_resource.as_str())
            .collect();
        assert!(
            flagged
                .iter()
                .any(|a| a.contains("aws_security_group.web-node")),
            "open SG must be flagged; flagged={flagged:?}"
        );
        assert!(
            flagged
                .iter()
                .any(|a| a.contains("aws_iam_user_policy.userpolicy")),
            "wildcard policy must be flagged; flagged={flagged:?}"
        );
        assert!(
            !flagged.iter().any(|a| a.contains("scoped")),
            "scoped policy must NOT be flagged; flagged={flagged:?}"
        );
        assert!(
            !flagged.iter().any(|a| a.contains("internal")),
            "private SG must NOT be flagged; flagged={flagged:?}"
        );
    }
}
