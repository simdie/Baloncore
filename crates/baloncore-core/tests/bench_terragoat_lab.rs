//! P2.S3 external corpus — end-to-end integration test for `bench-terragoat`.
//!
//! Runs the OFFLINE TerraGoat IaC analysis via the BALONCORE CLI binary and
//! asserts the resulting BenchmarkRun:
//!   - scores the open security group + the over-privileged IAM policy (planted
//!     vulns) as `TruePositive`, and
//!   - scores the encrypted-private bucket + the two negative-control decoys as
//!     `TrueNegative`.
//!
//! No Docker, no network — pure `.tf` parsing. Skipped (with a logged reason)
//! unless the corpus has been vendored by `scripts/fetch_terragoat.sh` (the
//! NEEDS-HUMAN git clone); the test must not fail merely because nobody ran it.

use std::path::PathBuf;

use baloncore_core::{evaluation::GroundTruthLabel, load_benchmark_run, BenchmarkRun};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .expect("repo root resolvable from CARGO_MANIFEST_DIR")
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

fn terragoat_vendored(root: &std::path::Path) -> bool {
    root.join(".baloncore/corpus/terragoat/terragoat/terraform/aws/iam.tf")
        .exists()
}

#[test]
fn bench_terragoat_offline_scores_iac_correctly() {
    let root = repo_root();
    if !terragoat_vendored(&root) {
        eprintln!(
            "[bench_terragoat_lab] SKIP — TerraGoat not vendored. Run \
             `scripts/fetch_terragoat.sh` to enable this test."
        );
        return;
    }
    let Some(bin) = baloncore_bin() else {
        eprintln!(
            "[bench_terragoat_lab] SKIP — baloncore binary not found; build with `cargo build`"
        );
        return;
    };

    let workspace = std::env::temp_dir().join(format!(
        "baloncore-bench-terragoat-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::create_dir_all(&workspace).expect("create workspace");
    let run_out = workspace.join("benchmark_run.json");
    let sc_out = workspace.join("scorecard.json");

    let status = std::process::Command::new(&bin)
        .current_dir(&root)
        .arg("bench-terragoat")
        .arg("--run-results-output")
        .arg(&run_out)
        .arg("--scorecard-output")
        .arg(&sc_out)
        .status()
        .expect("spawn bench-terragoat");
    assert!(
        status.success(),
        "bench-terragoat should exit 0; got {status:?}"
    );
    assert!(run_out.exists(), "benchmark_run.json must exist");

    let run: BenchmarkRun = load_benchmark_run(&run_out).expect("load BenchmarkRun");
    assert_eq!(run.suite_id, "baloncore-terragoat-iam-v1");
    assert_eq!(
        run.results.len(),
        5,
        "expected 5 probes (2 vulns + 3 decoys)"
    );

    let by_id = |id: &str| {
        run.results
            .iter()
            .find(|r| r.case_id == id)
            .unwrap_or_else(|| panic!("missing result {id}"))
    };

    for vuln in [
        "vuln-open-security-group-web-node",
        "vuln-overprivileged-user-policy",
    ] {
        let r = by_id(vuln);
        assert_eq!(
            r.prediction,
            GroundTruthLabel::TruePositive,
            "{vuln} must be detected; got {:?} (class={:?})",
            r.prediction,
            r.actual_classification
        );
    }

    for decoy in [
        "decoy-encrypted-private-logs-bucket",
        "decoy-least-privilege-policy",
        "decoy-internal-security-group",
    ] {
        let r = by_id(decoy);
        assert_eq!(
            r.prediction,
            GroundTruthLabel::TrueNegative,
            "decoy {decoy} must NOT be flagged; got {:?} (class={:?})",
            r.prediction,
            r.actual_classification
        );
    }

    let _ = std::fs::remove_dir_all(&workspace);
}
