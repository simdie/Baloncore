//! T3.a — end-to-end integration test for `validate-saas-extras`.
//!
//! Drives the BALONCORE CLI against the in-tree vulnerable SaaS lab and
//! asserts:
//!   - The GraphQL BOLA validator returns Verified on the planted cross-tenant
//!     `project(id: "proj-b-001")` lookup.
//!   - The business-logic StateSkip validator returns Verified on the planted
//!     ship-without-paying flow.
//!
//! Skips with a logged reason when `node` is missing.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .expect("repo root")
}

fn baloncore_bin() -> Option<PathBuf> {
    let root = repo_root();
    for candidate in ["target/debug/baloncore", "target/release/baloncore"] {
        let p = root.join(candidate);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn node_available() -> bool {
    Command::new("node")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn validate_saas_extras_verifies_both_planted_bugs() {
    if !node_available() {
        eprintln!("[validate_saas_extras] SKIP — `node` not on PATH");
        return;
    }
    let Some(bin) = baloncore_bin() else {
        eprintln!("[validate_saas_extras] SKIP — baloncore binary not built");
        return;
    };
    let root = repo_root();
    let workspace = std::env::temp_dir().join(format!(
        "baloncore-validate-saas-extras-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::create_dir_all(&workspace).expect("workspace");
    let out_dir = workspace.join("artifacts");

    let status = Command::new(&bin)
        .current_dir(&root)
        .arg("validate-saas-extras")
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--lab-port")
        .arg("3059")
        .arg("--json")
        .status()
        .expect("spawn validate-saas-extras");
    assert!(status.success(), "exit code: {status:?}");

    let summary_path = out_dir.join("validate_saas_extras_summary.json");
    assert!(summary_path.exists(), "summary file missing");
    let summary: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&summary_path).unwrap()).expect("parse summary");

    assert_eq!(
        summary["graphql_bola"]["verified"], serde_json::Value::Bool(true),
        "GraphQL BOLA must be Verified on the planted cross-tenant probe; \
         got: {}",
        summary["graphql_bola"]
    );
    assert_eq!(
        summary["business_logic"]["verified"], serde_json::Value::Bool(true),
        "Business-logic StateSkip must be Verified on the planted ship-without-pay probe; \
         got: {}",
        summary["business_logic"]
    );

    let _ = std::fs::remove_dir_all(&workspace);
}
