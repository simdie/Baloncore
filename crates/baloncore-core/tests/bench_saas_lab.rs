//! T1.b — end-to-end integration test for `bench-saas`.
//!
//! Spawns the in-tree `labs/vulnerable-saas` lab via `node`, runs the bench
//! through the BALONCORE CLI binary, and asserts the resulting BenchmarkRun
//! correctly scores the planted cross-tenant BOLA as `TruePositive` and the
//! decoy `proj-b-secret` as `TrueNegative`. Always tears the lab down via the
//! `bench-saas` Drop guard.
//!
//! Skipped (with a logged reason) when `node` is missing on the host.

use std::path::PathBuf;
use std::process::Command;

use baloncore_core::{
    evaluation::GroundTruthLabel, load_benchmark_run, BenchmarkRun,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .expect("repo root resolvable from CARGO_MANIFEST_DIR")
}

fn baloncore_bin() -> Option<PathBuf> {
    // Try debug + release; CI typically builds the bin already.
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
fn bench_saas_real_lab_produces_real_benchmark_run() {
    if !node_available() {
        eprintln!("[bench_saas_lab] SKIP — `node` not found on PATH");
        return;
    }
    let Some(bin) = baloncore_bin() else {
        eprintln!(
            "[bench_saas_lab] SKIP — baloncore binary not found; build first with `cargo build`"
        );
        return;
    };
    let root = repo_root();
    let workspace = std::env::temp_dir().join(format!(
        "baloncore-bench-saas-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::create_dir_all(&workspace).expect("create workspace");
    let run_out = workspace.join("benchmark_run.json");
    let sc_out = workspace.join("scorecard.json");

    let status = Command::new(&bin)
        .current_dir(&root)
        .arg("bench-saas")
        .arg("--run-results-output")
        .arg(&run_out)
        .arg("--scorecard-output")
        .arg(&sc_out)
        // Use a non-default port to avoid collisions if another lab is running.
        .arg("--lab-port")
        .arg("3057")
        .status()
        .expect("spawn bench-saas");
    assert!(status.success(), "bench-saas should exit 0; got {status:?}");
    assert!(run_out.exists(), "benchmark_run.json must exist");
    assert!(sc_out.exists(), "scorecard.json must exist");

    let run: BenchmarkRun =
        load_benchmark_run(&run_out).expect("load BenchmarkRun");
    assert_eq!(run.suite_id, "baloncore-saas-cross-tenant-v1");
    assert_eq!(run.results.len(), 2, "expected 2 probes (planted + decoy)");

    let planted = run
        .results
        .iter()
        .find(|r| r.case_id == "vuln-cross-tenant-bola-proj-b-001")
        .expect("planted result present");
    assert_eq!(
        planted.prediction,
        GroundTruthLabel::TruePositive,
        "planted cross-tenant BOLA must be detected; got {:?} (actual_classification={:?})",
        planted.prediction,
        planted.actual_classification
    );

    let decoy = run
        .results
        .iter()
        .find(|r| r.case_id == "decoy-proj-b-secret")
        .expect("decoy result present");
    assert_eq!(
        decoy.prediction,
        GroundTruthLabel::TrueNegative,
        "decoy proj-b-secret must NOT be flagged; got {:?} (actual_classification={:?})",
        decoy.prediction,
        decoy.actual_classification
    );

    let _ = std::fs::remove_dir_all(&workspace);
}
