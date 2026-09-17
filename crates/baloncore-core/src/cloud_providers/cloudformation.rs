use crate::cloud_iam::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloudFormationTemplate {
    #[serde(default, rename = "AWSTemplateFormatVersion")]
    pub format_version: Option<String>,
    #[serde(default, rename = "Description")]
    pub description: Option<String>,
    #[serde(default, rename = "Resources")]
    pub resources: serde_json::Value,
    #[serde(default, rename = "Parameters")]
    pub parameters: Option<serde_json::Value>,
    #[serde(default, rename = "Outputs")]
    pub outputs: Option<serde_json::Value>,
}

pub struct CloudFormationIngestor;

impl CloudFormationIngestor {
    pub fn ingest(template: &CloudFormationTemplate, account_id: Option<&str>) -> IAMGraph {
        let aid = account_id.unwrap_or("cloudformation-managed");
        let mut graph = IAMGraph::new(format!("cloudformation-{}", aid), CloudProvider::AWS);
        graph.account_id = Some(aid.to_string());

        if let Some(resources) = template.resources.as_object() {
            for (logical_id, resource_def) in resources {
                let resource_type = resource_def
                    .get("Type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown");

                match resource_type {
                    "AWS::IAM::Role" => {
                        Self::ingest_role(&mut graph, logical_id, resource_def, aid)
                    }
                    "AWS::IAM::User" => {
                        Self::ingest_user(&mut graph, logical_id, resource_def, aid)
                    }
                    "AWS::IAM::Group" => {
                        Self::ingest_group(&mut graph, logical_id, resource_def, aid)
                    }
                    "AWS::IAM::Policy" | "AWS::IAM::ManagedPolicy" => {
                        Self::ingest_policy(&mut graph, logical_id, resource_def)
                    }
                    "AWS::S3::Bucket" | "AWS::S3::BucketPolicy" => {
                        Self::ingest_s3_bucket(&mut graph, logical_id, resource_def)
                    }
                    "AWS::EC2::SecurityGroup" => {
                        Self::ingest_security_group(&mut graph, logical_id, resource_def)
                    }
                    "AWS::IAM::RolePolicy" | "AWS::IAM::UserPolicy" | "AWS::IAM::GroupPolicy" => {
                        Self::ingest_inline_policy(&mut graph, logical_id, resource_def)
                    }
                    _ => Self::ingest_generic_resource(
                        &mut graph,
                        logical_id,
                        resource_type,
                        resource_def,
                    ),
                }
            }
        }

        graph
    }

    pub fn ingest_json(json: &str) -> Result<IAMGraph, String> {
        let template: CloudFormationTemplate = serde_json::from_str(json)
            .map_err(|e| format!("failed to parse CloudFormation template: {e}"))?;
        Ok(Self::ingest(&template, None))
    }

    pub fn ingest_yaml(yaml_str: &str) -> Result<IAMGraph, String> {
        // Real CloudFormation templates use short-form intrinsic tags
        // (`!Ref`, `!Sub`, `!GetAtt`, `!Select`, ...). serde_yaml cannot
        // deserialize those tagged scalars straight into a tag-less
        // serde_json::Value (it errors "invalid type: enum"). So we parse into
        // serde_yaml::Value first and convert tagged nodes to their canonical
        // CloudFormation JSON form (`!Ref X` -> {"Ref": "X"}, `!Sub s` ->
        // {"Fn::Sub": s}, etc.). The literal values the analyzer cares about
        // (CidrIp, Action, Resource) pass through unchanged.
        let yaml_value: serde_yaml::Value = serde_yaml::from_str(yaml_str)
            .map_err(|e| format!("failed to parse YAML CloudFormation template: {e}"))?;
        let json_value = cfn_yaml_to_json(yaml_value);
        let template: CloudFormationTemplate = serde_json::from_value(json_value)
            .map_err(|e| format!("failed to parse CloudFormation template: {e}"))?;
        Ok(Self::ingest(&template, None))
    }

    /// Parse one template file (YAML or JSON) into its `Resources` map,
    /// handling CloudFormation intrinsic tags.
    fn read_resources(
        path: &std::path::Path,
    ) -> Result<serde_json::Map<String, serde_json::Value>, String> {
        let raw =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let is_yaml = matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yaml") | Some("yml")
        );
        let json_value = if is_yaml {
            cfn_yaml_to_json(
                serde_yaml::from_str(&raw)
                    .map_err(|e| format!("parse YAML {}: {e}", path.display()))?,
            )
        } else {
            serde_json::from_str(&raw).map_err(|e| format!("parse JSON {}: {e}", path.display()))?
        };
        let template: CloudFormationTemplate = serde_json::from_value(json_value)
            .map_err(|e| format!("parse CloudFormation {}: {e}", path.display()))?;
        Ok(template.resources.as_object().cloned().unwrap_or_default())
    }

    /// Ingest several CloudFormation template files into ONE graph by merging
    /// their `Resources` maps. Used to analyze a target template alongside
    /// separate negative-control templates. Later files win on logical-id
    /// collisions (callers should keep ids distinct).
    pub fn ingest_files(paths: &[std::path::PathBuf]) -> Result<IAMGraph, String> {
        let mut merged = serde_json::Map::new();
        for p in paths {
            for (k, v) in Self::read_resources(p)? {
                merged.insert(k, v);
            }
        }
        let template = CloudFormationTemplate {
            format_version: None,
            description: None,
            resources: serde_json::Value::Object(merged),
            parameters: None,
            outputs: None,
        };
        Ok(Self::ingest(&template, None))
    }

    pub fn ingest_file(path: &std::path::Path) -> Result<IAMGraph, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read CloudFormation template: {e}"))?;
        if path.extension().and_then(|e| e.to_str()) == Some("yaml")
            || path.extension().and_then(|e| e.to_str()) == Some("yml")
        {
            Self::ingest_yaml(&raw)
        } else {
            Self::ingest_json(&raw)
        }
    }

    fn ingest_role(
        graph: &mut IAMGraph,
        logical_id: &str,
        resource_def: &serde_json::Value,
        account_id: &str,
    ) {
        let properties = resource_def.get("Properties").unwrap_or(resource_def);
        let role_name = properties
            .get("RoleName")
            .and_then(|v| v.as_str())
            .unwrap_or(logical_id)
            .to_string();

        let arn = properties
            .get("Arn")
            .and_then(|v| v.as_str())
            .unwrap_or(&format!("arn:aws:iam::{}:role/{}", account_id, role_name))
            .to_string();

        let mut principal = IAMPrincipal::new(
            format!("cf-role-{}", logical_id),
            CloudProvider::AWS,
            PrincipalKind::Role,
            role_name.clone(),
        )
        .with_arn(&arn)
        .with_account(account_id);

        if let Some(policies) = properties
            .get("ManagedPolicyArns")
            .and_then(|v| v.as_array())
        {
            for p in policies {
                if let Some(s) = p.as_str() {
                    let policy_name = s.rsplit('/').next().unwrap_or(s).to_string();
                    principal = principal.with_policy(policy_name);
                }
            }
        }

        graph.add_principal(principal);

        if let Some(trust_policy) = properties.get("AssumeRolePolicyDocument") {
            if let Some(trust) = crate::cloud_providers::aws_iam::AWSIAMIngestor::parse_trust_policy(
                &format!("cf-trust-{}", logical_id),
                &arn,
                trust_policy,
            ) {
                graph.add_trust(trust);
            }
        }

        if let Some(policies) = properties.get("Policies").and_then(|v| v.as_array()) {
            for (idx, policy) in policies.iter().enumerate() {
                let policy_name = policy
                    .get("PolicyName")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&format!("cf-inline-{}", idx))
                    .to_string();
                let mut iam_policy = IAMPolicy::new(
                    format!("cf-policy-{}-{}", logical_id, idx),
                    policy_name,
                    CloudProvider::AWS,
                );
                iam_policy.source_type = PolicySourceType::CloudFormation;
                if let Some(doc) = policy.get("PolicyDocument") {
                    crate::cloud_providers::aws_iam::AWSIAMIngestor::parse_policy_document_into(
                        doc,
                        &mut iam_policy,
                    );
                    iam_policy.source_doc = serde_json::to_string(doc).unwrap_or_default();
                }
                graph.add_policy(iam_policy);
                // Attach to role
                if let Some(role) = graph.principals.get_mut(&format!("cf-role-{}", logical_id)) {
                    role.policies
                        .push(format!("cf-policy-{}-{}", logical_id, idx));
                }
            }
        }
    }

    fn ingest_user(
        graph: &mut IAMGraph,
        logical_id: &str,
        resource_def: &serde_json::Value,
        account_id: &str,
    ) {
        let properties = resource_def.get("Properties").unwrap_or(resource_def);
        let user_name = properties
            .get("UserName")
            .and_then(|v| v.as_str())
            .unwrap_or(logical_id)
            .to_string();

        let principal = IAMPrincipal::new(
            format!("cf-user-{}", logical_id),
            CloudProvider::AWS,
            PrincipalKind::User,
            user_name,
        )
        .with_account(account_id);

        graph.add_principal(principal);
    }

    fn ingest_group(
        graph: &mut IAMGraph,
        logical_id: &str,
        resource_def: &serde_json::Value,
        account_id: &str,
    ) {
        let properties = resource_def.get("Properties").unwrap_or(resource_def);
        let group_name = properties
            .get("GroupName")
            .and_then(|v| v.as_str())
            .unwrap_or(logical_id)
            .to_string();

        let principal = IAMPrincipal::new(
            format!("cf-group-{}", logical_id),
            CloudProvider::AWS,
            PrincipalKind::Group,
            group_name,
        )
        .with_account(account_id);

        graph.add_principal(principal);
    }

    fn ingest_policy(graph: &mut IAMGraph, logical_id: &str, resource_def: &serde_json::Value) {
        let properties = resource_def.get("Properties").unwrap_or(resource_def);
        let policy_name = properties
            .get("PolicyName")
            .and_then(|v| v.as_str())
            .unwrap_or(logical_id)
            .to_string();

        let mut policy = IAMPolicy::new(
            format!("cf-policy-{}", logical_id),
            policy_name,
            CloudProvider::AWS,
        );
        policy.source_type = PolicySourceType::CloudFormation;

        if let Some(doc) = properties.get("PolicyDocument") {
            crate::cloud_providers::aws_iam::AWSIAMIngestor::parse_policy_document_into(
                doc,
                &mut policy,
            );
            policy.source_doc = serde_json::to_string(doc).unwrap_or_default();
        }

        // Link the policy to every principal it is attached to. CloudFormation
        // attaches an AWS::IAM::Policy via `Roles`, `Users`, and/or `Groups`,
        // each a list of names or `{ "Ref": "LogicalId" }` references. The
        // over-privileged check only fires for a policy reachable from a
        // principal, so ALL three must be linked (previously only Roles were).
        let policy_id = format!("cf-policy-{}", logical_id);
        for (prop, prefix) in [
            ("Roles", "cf-role-"),
            ("Users", "cf-user-"),
            ("Groups", "cf-group-"),
        ] {
            if let Some(refs) = properties.get(prop).and_then(|v| v.as_array()) {
                for r in refs {
                    let target = r
                        .as_str()
                        .map(String::from)
                        .or_else(|| r.get("Ref").and_then(|v| v.as_str()).map(String::from));
                    if let Some(name) = target {
                        if let Some(principal) =
                            graph.principals.get_mut(&format!("{prefix}{name}"))
                        {
                            principal.policies.push(policy_id.clone());
                        }
                    }
                }
            }
        }

        graph.add_policy(policy);
    }

    /// Ingest an `AWS::EC2::SecurityGroup`, marking it publicly exposed when any
    /// ingress rule allows `0.0.0.0/0` (or `::/0`).
    fn ingest_security_group(
        graph: &mut IAMGraph,
        logical_id: &str,
        resource_def: &serde_json::Value,
    ) {
        let properties = resource_def.get("Properties").unwrap_or(resource_def);
        let address = format!("AWS::EC2::SecurityGroup.{logical_id}");
        let mut resource = CloudResource::new(
            format!("cf-sg-{logical_id}"),
            CloudProvider::AWS,
            "security-group",
            address,
        );

        let mut details = Vec::new();
        if let Some(ingress) = properties
            .get("SecurityGroupIngress")
            .and_then(|v| v.as_array())
        {
            for rule in ingress {
                let cidr = rule
                    .get("CidrIp")
                    .and_then(|v| v.as_str())
                    .or_else(|| rule.get("CidrIpv6").and_then(|v| v.as_str()));
                if matches!(cidr, Some("0.0.0.0/0") | Some("::/0")) {
                    let from = rule
                        .get("FromPort")
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "?".to_string());
                    let to = rule
                        .get("ToPort")
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "?".to_string());
                    details.push(format!("ingress {from}-{to} open to {}", cidr.unwrap()));
                }
            }
        }
        if !details.is_empty() {
            resource.is_public = true;
            resource.public_access_details = details;
        }
        graph.add_resource(resource);
    }

    fn ingest_inline_policy(
        graph: &mut IAMGraph,
        logical_id: &str,
        resource_def: &serde_json::Value,
    ) {
        let properties = resource_def.get("Properties").unwrap_or(resource_def);
        let policy_name = properties
            .get("PolicyName")
            .and_then(|v| v.as_str())
            .unwrap_or(logical_id)
            .to_string();

        let mut policy = IAMPolicy::new(
            format!("cf-inline-{}", logical_id),
            policy_name,
            CloudProvider::AWS,
        );
        policy.source_type = PolicySourceType::CloudFormation;

        if let Some(doc) = properties.get("PolicyDocument") {
            crate::cloud_providers::aws_iam::AWSIAMIngestor::parse_policy_document_into(
                doc,
                &mut policy,
            );
            policy.source_doc = serde_json::to_string(doc).unwrap_or_default();
        }

        graph.add_policy(policy);

        // Attach to role/user/group
        if let Some(role_name) = properties.get("RoleName").and_then(|v| v.as_str()) {
            if let Some(role) = graph.principals.get_mut(&format!("cf-role-{}", role_name)) {
                role.policies.push(format!("cf-inline-{}", logical_id));
            }
        }
    }

    fn ingest_s3_bucket(graph: &mut IAMGraph, logical_id: &str, resource_def: &serde_json::Value) {
        let properties = resource_def.get("Properties").unwrap_or(resource_def);
        let bucket_name = properties
            .get("BucketName")
            .and_then(|v| v.as_str())
            .unwrap_or(logical_id)
            .to_string();

        let mut bucket = CloudResource::new(
            format!("cf-s3-{}", logical_id),
            CloudProvider::AWS,
            "s3-bucket",
            bucket_name.clone(),
        );

        if let Some(access_config) = properties.get("PublicAccessBlockConfiguration") {
            let block_public_acls = access_config
                .get("BlockPublicAcls")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let block_public_policy = access_config
                .get("BlockPublicPolicy")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let restrict_public_buckets = access_config
                .get("RestrictPublicBuckets")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if !block_public_acls || !block_public_policy || !restrict_public_buckets {
                let mut details = Vec::new();
                if !block_public_acls {
                    details.push("BlockPublicAcls is false".to_string());
                }
                if !block_public_policy {
                    details.push("BlockPublicPolicy is false".to_string());
                }
                if !restrict_public_buckets {
                    details.push("RestrictPublicBuckets is false".to_string());
                }
                bucket = bucket.with_public_access(details);
            }
        }

        bucket.raw_config = Some(properties.clone());
        graph.add_resource(bucket);
    }

    fn ingest_generic_resource(
        graph: &mut IAMGraph,
        logical_id: &str,
        resource_type: &str,
        resource_def: &serde_json::Value,
    ) {
        let properties = resource_def.get("Properties").unwrap_or(resource_def);
        let name = properties
            .get("Name")
            .or_else(|| properties.get("BucketName"))
            .or_else(|| properties.get("DBInstanceIdentifier"))
            .and_then(|v| v.as_str())
            .unwrap_or(logical_id)
            .to_string();

        let resource = CloudResource::new(
            format!(
                "cf-{}-{}",
                resource_type.replace("::", "-").to_lowercase(),
                logical_id
            ),
            CloudProvider::AWS,
            resource_type.to_string(),
            name,
        );

        graph.add_resource(resource);
    }
}

/// Convert a parsed `serde_yaml::Value` to `serde_json::Value`, collapsing
/// CloudFormation short-form intrinsic tags into their canonical JSON form so
/// the template deserializes:
///   `!Ref X`     -> {"Ref": "X"}
///   `!Sub s`     -> {"Fn::Sub": s}
///   `!GetAtt a`  -> {"Fn::GetAtt": "a"}   (and likewise for other tags)
/// Literal scalars/sequences/maps pass through unchanged, so the values the
/// analyzer reads (CidrIp, Action, Resource, …) are preserved exactly.
fn cfn_yaml_to_json(value: serde_yaml::Value) -> serde_json::Value {
    use serde_json::Value as J;
    use serde_yaml::Value as Y;
    match value {
        Y::Null => J::Null,
        Y::Bool(b) => J::Bool(b),
        Y::Number(n) => {
            if let Some(i) = n.as_i64() {
                J::from(i)
            } else if let Some(u) = n.as_u64() {
                J::from(u)
            } else if let Some(f) = n.as_f64() {
                serde_json::Number::from_f64(f)
                    .map(J::Number)
                    .unwrap_or(J::Null)
            } else {
                J::Null
            }
        }
        Y::String(s) => J::String(s),
        Y::Sequence(seq) => J::Array(seq.into_iter().map(cfn_yaml_to_json).collect()),
        Y::Mapping(map) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in map {
                let key = match k {
                    Y::String(s) => s,
                    Y::Bool(b) => b.to_string(),
                    Y::Number(n) => n.to_string(),
                    Y::Null => "null".to_string(),
                    other => format!("{:?}", other),
                };
                obj.insert(key, cfn_yaml_to_json(v));
            }
            J::Object(obj)
        }
        Y::Tagged(tagged) => {
            // `tagged.tag` displays as e.g. "!Ref"; strip the bang and map to
            // the CloudFormation function key. `Ref`/`Condition` are not `Fn::`.
            let raw = tagged.tag.to_string();
            let name = raw.trim_start_matches('!');
            let key = if name == "Ref" || name == "Condition" {
                name.to_string()
            } else {
                format!("Fn::{name}")
            };
            let mut obj = serde_json::Map::new();
            obj.insert(key, cfn_yaml_to_json(tagged.value));
            J::Object(obj)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloudformation_ingest_role_with_trust() {
        let json = r#"{
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "DeployRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": "DeployRole",
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Principal": {"Service": "ec2.amazonaws.com"},
                                "Action": "sts:AssumeRole"
                            }]
                        },
                        "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AdminAccess"]
                    }
                }
            }
        }"#;
        let graph = CloudFormationIngestor::ingest_json(json).unwrap();
        assert!(graph.principals.contains_key("cf-role-DeployRole"));
        assert!(!graph.trust_relationships.is_empty());
    }

    #[test]
    fn test_cloudformation_ingest_s3_bucket() {
        let json = r#"{
            "Resources": {
                "PublicBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": "my-public-bucket",
                        "PublicAccessBlockConfiguration": {
                            "BlockPublicAcls": false,
                            "BlockPublicPolicy": false,
                            "RestrictPublicBuckets": false
                        }
                    }
                }
            }
        }"#;
        let graph = CloudFormationIngestor::ingest_json(json).unwrap();
        assert!(graph.resources.contains_key("cf-s3-PublicBucket"));
        let bucket = graph.resources.get("cf-s3-PublicBucket").unwrap();
        assert!(bucket.is_public);
    }

    #[test]
    fn test_cloudformation_ingest_empty() {
        let json = r#"{ "Resources": {} }"#;
        let graph = CloudFormationIngestor::ingest_json(json).unwrap();
        assert_eq!(graph.principals.len(), 0);
        assert_eq!(graph.resources.len(), 0);
    }

    #[test]
    fn test_cloudformation_yaml() {
        let yaml = r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  AdminRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: AdminRole
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: "*"
            Action: sts:AssumeRole
"#;
        let graph = CloudFormationIngestor::ingest_yaml(yaml).unwrap();
        assert!(graph.principals.contains_key("cf-role-AdminRole"));
        assert!(graph.trust_relationships.iter().any(|t| t.allows_external));
    }

    // --- regression tests for the real-CloudFormation capability fixes ---

    #[test]
    fn yaml_short_form_intrinsics_parse() {
        // serde_yaml cannot deserialize `!Ref`/`!Sub` straight into JSON; the
        // converter must collapse them so the template ingests.
        let yaml = r#"
Resources:
  WebSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupName: !Sub "${AWS::AccountId}-sg"
      VpcId: !Ref WebVPC
      SecurityGroupIngress:
        - CidrIp: 0.0.0.0/0
          FromPort: 22
          ToPort: 22
          IpProtocol: tcp
"#;
        let mut graph = CloudFormationIngestor::ingest_yaml(yaml).expect("intrinsics must parse");
        let result = graph.analyze();
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.affected_resource.contains("WebSG")
                    && f.classification == "PublicResourceExposure"),
            "open SG must be flagged public; findings={:?}",
            result
                .findings
                .iter()
                .map(|f| &f.affected_resource)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn user_attached_policy_is_linked_and_over_privileged() {
        // An AWS::IAM::Policy attached via `Users` (not `Roles`) must be linked
        // to the user so the over-privileged check fires.
        let yaml = r#"
Resources:
  AppUser:
    Type: AWS::IAM::User
    Properties:
      UserName: AppUser
  ExcessPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: excess_policy
      PolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Action: ["ec2:*", "s3:*"]
            Resource: "*"
      Users:
        - !Ref AppUser
"#;
        let mut graph = CloudFormationIngestor::ingest_yaml(yaml).unwrap();
        let user = graph
            .principals
            .get("cf-user-AppUser")
            .expect("user present");
        assert!(
            user.policies
                .contains(&"cf-policy-ExcessPolicy".to_string()),
            "policy must be linked to the user via Users; got {:?}",
            user.policies
        );
        let result = graph.analyze();
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.classification == "OverPrivilegedPolicy"
                    && f.affected_resource.contains("excess_policy")),
            "user-attached wildcard policy must be flagged; findings={:?}",
            result
                .findings
                .iter()
                .map(|f| &f.affected_resource)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn least_privilege_and_internal_sg_are_not_flagged() {
        // The negative-control shape: scoped policy + internal SG must NOT fire.
        let yaml = r#"
Resources:
  AppUser2:
    Type: AWS::IAM::User
    Properties:
      UserName: AppUser2
  ScopedPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: scoped_policy
      PolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Action: ["s3:GetObject"]
            Resource: "arn:aws:s3:::my-bucket/reports/*"
      Users:
        - !Ref AppUser2
  InternalSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupName: internal
      SecurityGroupIngress:
        - CidrIp: 10.0.0.0/8
          FromPort: 443
          ToPort: 443
          IpProtocol: tcp
"#;
        let mut graph = CloudFormationIngestor::ingest_yaml(yaml).unwrap();
        let result = graph.analyze();
        assert!(
            result.findings.is_empty(),
            "scoped policy + internal SG must produce no findings; got {:?}",
            result
                .findings
                .iter()
                .map(|f| &f.affected_resource)
                .collect::<Vec<_>>()
        );
    }
}
