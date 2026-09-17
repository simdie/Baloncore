//! P2.S3 external corpus — end-to-end integration test for `bench-dvga`.
//!
//! Runs the locally-vendored DVGA Docker image via the BALONCORE CLI binary and
//! asserts the resulting BenchmarkRun:
//!   - scores the forged-admin-identity GraphQL bypass as `TruePositive`,
//!   - scores the masked-non-admin decoy as `TrueNegative`, and
//!   - scores the public-paste decoy as `TrueNegative`.
//! The container is torn down via the runner's Drop guard.
//!
//! Skipped (with a logged reason) unless Docker is running AND the pinned image
//! is present — i.e. `scripts/fetch_dvga.sh` has been run. This requires a
//! Docker pull and is therefore NEEDS-HUMAN; the test must not fail merely
//! because nobody ran it.

use std::path::PathBuf;
use std::process::Command;

use baloncore_core::{evaluation::GroundTruthLabel, load_benchmark_run, BenchmarkRun};

const DVGA_IMAGE: &str =
    "dolevf/dvga@sha256:040aa33c199d99f3380c9ff9a1ee5d725e9abca7b189c63a35a2a73bda79c957";

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

fn docker_image_available() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
        && Command::new("docker")
            .args(["image", "inspect", DVGA_IMAGE])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

#[test]
fn bench_dvga_real_target_scores_graphql_bola_correctly() {
    if !docker_image_available() {
        eprintln!(
            "[bench_dvga_lab] SKIP — Docker not running or DVGA image not present. \
             Run `scripts/fetch_dvga.sh` to enable this test."
        );
        return;
    }
    let Some(bin) = baloncore_bin() else {
        eprintln!("[bench_dvga_lab] SKIP — baloncore binary not found; build with `cargo build`");
        return;
    };
    let root = repo_root();
    let workspace =
        std::env::temp_dir().join(format!("baloncore-bench-dvga-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::create_dir_all(&workspace).expect("create workspace");
    let run_out = workspace.join("benchmark_run.json");
    let sc_out = workspace.join("scorecard.json");

    let status = Command::new(&bin)
        .current_dir(&root)
        .arg("bench-dvga")
        .arg("--run-results-output")
        .arg(&run_out)
        .arg("--scorecard-output")
        .arg(&sc_out)
        // Distinct non-default host port to avoid collisions with a dev
        // instance AND with the VAmPI lab test (which uses 5071/5072) when the
        // whole workspace test suite runs the live-lab tests concurrently.
        .arg("--host-port")
        .arg("5081")
        .status()
        .expect("spawn bench-dvga");
    assert!(status.success(), "bench-dvga should exit 0; got {status:?}");
    assert!(run_out.exists(), "benchmark_run.json must exist");

    let run: BenchmarkRun = load_benchmark_run(&run_out).expect("load BenchmarkRun");
    assert_eq!(run.suite_id, "baloncore-dvga-graphql-bola-v1");
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

    let planted = by_id("vuln-jwt-forge-admin-password");
    assert_eq!(
        planted.prediction,
        GroundTruthLabel::TruePositive,
        "forged-admin GraphQL bypass must be detected; got {:?} (class={:?})",
        planted.prediction,
        planted.actual_classification
    );

    for decoy in ["decoy-nonadmin-identity-masked", "decoy-public-paste"] {
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
