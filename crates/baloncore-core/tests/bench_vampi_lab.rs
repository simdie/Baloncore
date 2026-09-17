//! P2.S3 external corpus — end-to-end integration test for `bench-vampi`.
//!
//! Boots the locally-vendored erev0s/VAmPI target in BOTH vulnerable and secure
//! modes via the BALONCORE CLI binary, then asserts the resulting BenchmarkRun:
//!   - scores the planted BOLA on the VULNERABLE build as `TruePositive`,
//!   - scores the SAME probe on the SECURE build as `TrueNegative` (decoy: the
//!     bug toggled off must produce zero findings), and
//!   - scores the owner-self-access decoy as `TrueNegative`.
//! Both builds are torn down via the runner's Drop guard.
//!
//! Skipped (with a logged reason) unless the target has been vendored by
//! `scripts/fetch_vampi.sh` — this requires a network fetch + pip install and is
//! therefore NEEDS-HUMAN; the test must not fail merely because nobody ran it.

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

/// The target is "ready" only if both the checkout and its venv interpreter
/// exist — i.e. `scripts/fetch_vampi.sh` has been run on this host.
fn vampi_vendored(root: &std::path::Path) -> bool {
    let dir = root.join(".baloncore/corpus/vampi/VAmPI");
    dir.join("config.py").exists() && dir.join(".venv/bin/python").exists()
}

#[test]
fn bench_vampi_real_target_scores_toggle_correctly() {
    let root = repo_root();
    if !vampi_vendored(&root) {
        eprintln!(
            "[bench_vampi_lab] SKIP — VAmPI not vendored. Run `scripts/fetch_vampi.sh` \
             (network + pip) to enable this test."
        );
        return;
    }
    let Some(bin) = baloncore_bin() else {
        eprintln!("[bench_vampi_lab] SKIP — baloncore binary not found; build with `cargo build`");
        return;
    };

    let workspace =
        std::env::temp_dir().join(format!("baloncore-bench-vampi-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::create_dir_all(&workspace).expect("create workspace");
    let run_out = workspace.join("benchmark_run.json");
    let sc_out = workspace.join("scorecard.json");

    let status = std::process::Command::new(&bin)
        .current_dir(&root)
        .arg("bench-vampi")
        .arg("--run-results-output")
        .arg(&run_out)
        .arg("--scorecard-output")
        .arg(&sc_out)
        // Non-default ports to avoid collisions with a dev instance.
        .arg("--vulnerable-port")
        .arg("5071")
        .arg("--secure-port")
        .arg("5072")
        .status()
        .expect("spawn bench-vampi");
    assert!(
        status.success(),
        "bench-vampi should exit 0; got {status:?}"
    );
    assert!(run_out.exists(), "benchmark_run.json must exist");

    let run: BenchmarkRun = load_benchmark_run(&run_out).expect("load BenchmarkRun");
    assert_eq!(run.suite_id, "baloncore-vampi-bola-v1");
    assert_eq!(
        run.results.len(),
        3,
        "expected 3 probes (1 vuln + 2 decoys)"
    );

    let by_id = |id: &str| {
        run.results
            .iter()
            .find(|r| r.case_id == id)
            .unwrap_or_else(|| panic!("missing result {id}"))
    };

    let planted = by_id("vuln-bola-books-vulnerable");
    assert_eq!(
        planted.prediction,
        GroundTruthLabel::TruePositive,
        "planted BOLA on vulnerable build must be detected; got {:?} (class={:?})",
        planted.prediction,
        planted.actual_classification
    );

    let secure = by_id("decoy-bola-books-secure");
    assert_eq!(
        secure.prediction,
        GroundTruthLabel::TrueNegative,
        "secure-build decoy must NOT be flagged (bug toggled off); got {:?} (class={:?})",
        secure.prediction,
        secure.actual_classification
    );

    let owner = by_id("decoy-owner-self-access");
    assert_eq!(
        owner.prediction,
        GroundTruthLabel::TrueNegative,
        "owner-self-access decoy must NOT be flagged; got {:?} (class={:?})",
        owner.prediction,
        owner.actual_classification
    );

    let _ = std::fs::remove_dir_all(&workspace);
}
