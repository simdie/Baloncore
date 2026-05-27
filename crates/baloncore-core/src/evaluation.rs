use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BenchmarkDomain {
    WebApi,
    CloudIam,
    Web3,
    Evidence,
    Ci,
    Defense,
    Platform,
    Multi,
}

impl BenchmarkDomain {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WebApi => "web_api",
            Self::CloudIam => "cloud_iam",
            Self::Web3 => "web3",
            Self::Evidence => "evidence",
            Self::Ci => "ci",
            Self::Defense => "defense",
            Self::Platform => "platform",
            Self::Multi => "multi",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "web_api" => Self::WebApi,
            "cloud_iam" => Self::CloudIam,
            "web3" => Self::Web3,
            "evidence" => Self::Evidence,
            "ci" => Self::Ci,
            "defense" => Self::Defense,
            "platform" => Self::Platform,
            "multi" => Self::Multi,
            _ => Self::Multi,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroundTruthLabel {
    TruePositive,
    FalsePositive,
    TrueNegative,
    FalseNegative,
    Inconclusive,
}

impl GroundTruthLabel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TruePositive => "true_positive",
            Self::FalsePositive => "false_positive",
            Self::TrueNegative => "true_negative",
            Self::FalseNegative => "false_negative",
            Self::Inconclusive => "inconclusive",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "true_positive" => Self::TruePositive,
            "false_positive" => Self::FalsePositive,
            "true_negative" => Self::TrueNegative,
            "false_negative" => Self::FalseNegative,
            _ => Self::Inconclusive,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BenchmarkCase {
    pub case_id: String,
    pub domain: BenchmarkDomain,
    pub name: String,
    pub description: String,
    pub target: String,
    pub ground_truth: GroundTruthLabel,
    pub expected_classification: Option<String>,
    pub expected_severity: Option<String>,
    pub expected_evidence_keys: Vec<String>,
    pub difficulty: BenchmarkDifficulty,
    pub tags: Vec<String>,
    #[serde(default)]
    pub fixture_path: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum BenchmarkDifficulty {
    Trivial,
    Basic,
    Moderate,
    Advanced,
    Expert,
}

impl BenchmarkDifficulty {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trivial => "trivial",
            Self::Basic => "basic",
            Self::Moderate => "moderate",
            Self::Advanced => "advanced",
            Self::Expert => "expert",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "trivial" => Self::Trivial,
            "basic" => Self::Basic,
            "moderate" => Self::Moderate,
            "advanced" => Self::Advanced,
            "expert" => Self::Expert,
            _ => Self::Moderate,
        }
    }

    pub fn weight(&self) -> f64 {
        match self {
            Self::Trivial => 0.5,
            Self::Basic => 1.0,
            Self::Moderate => 2.0,
            Self::Advanced => 3.0,
            Self::Expert => 5.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BenchmarkSuite {
    pub suite_id: String,
    pub name: String,
    pub version: String,
    pub domain: BenchmarkDomain,
    pub description: String,
    pub cases: Vec<BenchmarkCase>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

impl BenchmarkSuite {
    pub fn case_by_id(&self, case_id: &str) -> Option<&BenchmarkCase> {
        self.cases.iter().find(|c| c.case_id == case_id)
    }

    pub fn cases_by_difficulty(&self, difficulty: &BenchmarkDifficulty) -> Vec<&BenchmarkCase> {
        self.cases
            .iter()
            .filter(|c| &c.difficulty == difficulty)
            .collect()
    }

    pub fn cases_by_tag(&self, tag: &str) -> Vec<&BenchmarkCase> {
        self.cases
            .iter()
            .filter(|c| c.tags.contains(&tag.to_string()))
            .collect()
    }

    pub fn ground_truth_distribution(&self) -> BTreeMap<String, usize> {
        let mut dist = BTreeMap::new();
        for case in &self.cases {
            *dist
                .entry(case.ground_truth.as_str().to_string())
                .or_insert(0) += 1;
        }
        dist
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BenchmarkResult {
    pub result_id: String,
    pub suite_id: String,
    pub case_id: String,
    pub domain: BenchmarkDomain,
    pub actual_classification: Option<String>,
    pub actual_severity: Option<String>,
    pub actual_state: Option<String>,
    pub prediction: GroundTruthLabel,
    pub confidence: f64,
    pub evidence_found: Vec<String>,
    pub time_to_result_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BenchmarkRun {
    pub run_id: String,
    pub suite_id: String,
    pub suite_version: String,
    pub domain: BenchmarkDomain,
    pub started_at: u64,
    pub completed_at: u64,
    pub config_snapshot: BenchmarkConfig,
    pub results: Vec<BenchmarkResult>,
}

impl BenchmarkRun {
    pub fn total_cases(&self) -> usize {
        self.results.len()
    }

    pub fn results_by_prediction(&self) -> BTreeMap<String, Vec<&BenchmarkResult>> {
        let mut map = BTreeMap::new();
        for result in &self.results {
            map.entry(result.prediction.as_str().to_string())
                .or_insert_with(Vec::new)
                .push(result);
        }
        map
    }

    pub fn mean_time_to_result_ms(&self) -> f64 {
        if self.results.is_empty() {
            return 0.0;
        }
        let total: u64 = self.results.iter().map(|r| r.time_to_result_ms).sum();
        total as f64 / self.results.len() as f64
    }

    pub fn median_time_to_result_ms(&self) -> f64 {
        if self.results.is_empty() {
            return 0.0;
        }
        let mut times: Vec<u64> = self.results.iter().map(|r| r.time_to_result_ms).collect();
        times.sort();
        let mid = times.len() / 2;
        if times.len() % 2 == 0 {
            (times[mid - 1] + times[mid]) as f64 / 2.0
        } else {
            times[mid] as f64
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BenchmarkConfig {
    pub engine_version: String,
    pub validator_config: String,
    pub noise_mode: String,
    pub max_active_requests: usize,
    pub domain_filter: Option<BenchmarkDomain>,
    pub difficulty_filter: Option<BenchmarkDifficulty>,
    pub tag_filter: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub prompt_version: String,
    #[serde(default)]
    pub git_commit: String,
    #[serde(default)]
    pub corpus_hash: String,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            validator_config: "default".to_string(),
            noise_mode: "moderate".to_string(),
            max_active_requests: 500,
            domain_filter: None,
            difficulty_filter: None,
            tag_filter: None,
            metadata: BTreeMap::new(),
            provider: "fixture".to_string(),
            model: "baloncore-local-fixture".to_string(),
            prompt_version: "v1".to_string(),
            git_commit: env!("CARGO_PKG_VERSION").to_string(),
            corpus_hash: "unknown".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvaluationMetrics {
    pub total_cases: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub true_negatives: usize,
    pub false_negatives: usize,
    pub inconclusive: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub accuracy: f64,
    pub false_positive_rate: f64,
    pub false_negative_rate: f64,
    pub mean_time_to_proof_ms: f64,
    pub median_time_to_proof_ms: f64,
    pub difficulty_weighted_accuracy: f64,
    pub classification_accuracy: f64,
    pub severity_accuracy: f64,
    pub evidence_coverage: f64,
    pub grade: EvaluationGrade,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvaluationGrade {
    APlus,
    A,
    B,
    C,
    D,
    F,
}

impl EvaluationGrade {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::APlus => "A+",
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
            Self::D => "D",
            Self::F => "F",
        }
    }

    pub fn from_score(score: f64) -> Self {
        if score >= 0.97 {
            Self::APlus
        } else if score >= 0.90 {
            Self::A
        } else if score >= 0.80 {
            Self::B
        } else if score >= 0.70 {
            Self::C
        } else if score >= 0.60 {
            Self::D
        } else {
            Self::F
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvaluationScorecard {
    pub scorecard_id: String,
    pub run_id: String,
    pub suite_id: String,
    pub domain: BenchmarkDomain,
    pub generated_at: u64,
    pub metrics: EvaluationMetrics,
    pub difficulty_breakdown: BTreeMap<String, DifficultyMetrics>,
    pub tag_breakdown: BTreeMap<String, TagMetrics>,
    pub recommendations: Vec<String>,
    pub comparison: Option<ComparisonResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DifficultyMetrics {
    pub difficulty: String,
    pub total: usize,
    pub correct: usize,
    pub accuracy: f64,
    pub mean_time_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TagMetrics {
    pub tag: String,
    pub total: usize,
    pub correct: usize,
    pub accuracy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComparisonResult {
    pub baseline_run_id: String,
    pub current_run_id: String,
    pub precision_delta: f64,
    pub recall_delta: f64,
    pub f1_delta: f64,
    pub accuracy_delta: f64,
    pub mean_time_delta_ms: f64,
    pub improved: bool,
    pub regression_count: usize,
    pub improvement_count: usize,
    pub case_deltas: Vec<CaseComparison>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CaseComparison {
    pub case_id: String,
    pub baseline_prediction: String,
    pub current_prediction: String,
    pub baseline_time_ms: u64,
    pub current_time_ms: u64,
    pub improved: bool,
    pub regressed: bool,
}

pub fn compute_evaluation_metrics(suite: &BenchmarkSuite, run: &BenchmarkRun) -> EvaluationMetrics {
    let mut tp = 0usize;
    let mut fp = 0usize;
    let mut tn = 0usize;
    let mut fn_ = 0usize;
    let mut inconclusive = 0usize;
    let mut classification_matches = 0usize;
    let mut severity_matches = 0usize;
    let mut total_evidence_expected = 0usize;
    let mut total_evidence_found = 0usize;
    let mut weighted_correct = 0.0f64;
    let mut weighted_total = 0.0f64;

    let mut proof_times: Vec<u64> = Vec::new();

    let mut classification_eligible = 0usize;
    let mut severity_eligible = 0usize;

    for result in &run.results {
        let case = match suite.case_by_id(&result.case_id) {
            Some(c) => c,
            None => continue,
        };

        let weight = case.difficulty.weight();
        weighted_total += weight;

        match result.prediction {
            GroundTruthLabel::TruePositive => {
                if matches!(case.ground_truth, GroundTruthLabel::TruePositive) {
                    tp += 1;
                    weighted_correct += weight;
                } else {
                    fp += 1;
                }
            }
            GroundTruthLabel::FalsePositive => {
                if matches!(case.ground_truth, GroundTruthLabel::FalsePositive) {
                    tn += 1;
                    weighted_correct += weight;
                } else {
                    fp += 1;
                }
            }
            GroundTruthLabel::TrueNegative => {
                if matches!(case.ground_truth, GroundTruthLabel::TrueNegative)
                    || matches!(case.ground_truth, GroundTruthLabel::FalsePositive)
                {
                    tn += 1;
                    weighted_correct += weight;
                } else {
                    fn_ += 1;
                }
            }
            GroundTruthLabel::FalseNegative => {
                if matches!(case.ground_truth, GroundTruthLabel::FalseNegative) {
                    fn_ += 1;
                    weighted_correct += weight;
                } else {
                    fp += 1;
                }
            }
            GroundTruthLabel::Inconclusive => {
                inconclusive += 1;
            }
        }

        if let (Some(ref actual), Some(ref expected)) =
            (&result.actual_classification, &case.expected_classification)
        {
            classification_eligible += 1;
            if actual.eq_ignore_ascii_case(expected) {
                classification_matches += 1;
            }
        }

        if let (Some(ref actual), Some(ref expected)) =
            (&result.actual_severity, &case.expected_severity)
        {
            severity_eligible += 1;
            if actual.eq_ignore_ascii_case(expected) {
                severity_matches += 1;
            }
        }

        total_evidence_expected += case.expected_evidence_keys.len();
        for key in &result.evidence_found {
            if case.expected_evidence_keys.contains(key) {
                total_evidence_found += 1;
            }
        }

        if matches!(
            case.ground_truth,
            GroundTruthLabel::TruePositive | GroundTruthLabel::FalseNegative
        ) {
            proof_times.push(result.time_to_result_ms);
        }
    }

    let total = tp + fp + tn + fn_;
    let precision = if tp + fp > 0 {
        tp as f64 / (tp + fp) as f64
    } else {
        0.0
    };
    let recall = if tp + fn_ > 0 {
        tp as f64 / (tp + fn_) as f64
    } else {
        0.0
    };
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };
    let accuracy = if total > 0 {
        (tp + tn) as f64 / total as f64
    } else {
        0.0
    };
    let fpr = if fp + tn > 0 {
        fp as f64 / (fp + tn) as f64
    } else {
        0.0
    };
    let fnr = if fn_ + tp > 0 {
        fn_ as f64 / (fn_ + tp) as f64
    } else {
        0.0
    };
    let weighted_acc = if weighted_total > 0.0 {
        weighted_correct / weighted_total
    } else {
        0.0
    };
    let classification_accuracy = if classification_eligible > 0 {
        classification_matches as f64 / classification_eligible as f64
    } else {
        0.0
    };
    let severity_accuracy = if severity_eligible > 0 {
        severity_matches as f64 / severity_eligible as f64
    } else {
        0.0
    };
    let evidence_coverage = if total_evidence_expected > 0 {
        total_evidence_found as f64 / total_evidence_expected as f64
    } else {
        0.0
    };

    let mean_time = if proof_times.is_empty() {
        0.0
    } else {
        let sum: u64 = proof_times.iter().sum();
        sum as f64 / proof_times.len() as f64
    };
    let median_time = {
        let mut sorted = proof_times.clone();
        sorted.sort();
        if sorted.is_empty() {
            0.0
        } else if sorted.len() % 2 == 0 {
            (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) as f64 / 2.0
        } else {
            sorted[sorted.len() / 2] as f64
        }
    };

    let grade = EvaluationGrade::from_score(accuracy);

    EvaluationMetrics {
        total_cases: total,
        true_positives: tp,
        false_positives: fp,
        true_negatives: tn,
        false_negatives: fn_,
        inconclusive,
        precision,
        recall,
        f1_score: f1,
        accuracy,
        false_positive_rate: fpr,
        false_negative_rate: fnr,
        mean_time_to_proof_ms: mean_time,
        median_time_to_proof_ms: median_time,
        difficulty_weighted_accuracy: weighted_acc,
        classification_accuracy,
        severity_accuracy,
        evidence_coverage,
        grade,
    }
}

pub fn compute_difficulty_breakdown(
    suite: &BenchmarkSuite,
    run: &BenchmarkRun,
) -> BTreeMap<String, DifficultyMetrics> {
    let mut breakdown = BTreeMap::new();

    for difficulty in &[
        BenchmarkDifficulty::Trivial,
        BenchmarkDifficulty::Basic,
        BenchmarkDifficulty::Moderate,
        BenchmarkDifficulty::Advanced,
        BenchmarkDifficulty::Expert,
    ] {
        let cases: Vec<&BenchmarkCase> = suite
            .cases
            .iter()
            .filter(|c| c.difficulty == *difficulty)
            .collect();
        if cases.is_empty() {
            continue;
        }

        let case_ids: Vec<&str> = cases.iter().map(|c| c.case_id.as_str()).collect();
        let results: Vec<&BenchmarkResult> = run
            .results
            .iter()
            .filter(|r| case_ids.contains(&r.case_id.as_str()))
            .collect();

        let mut correct = 0usize;
        let mut total_time = 0u64;
        for result in &results {
            if let Some(case) = suite.case_by_id(&result.case_id) {
                if prediction_matches_ground_truth(&result.prediction, &case.ground_truth) {
                    correct += 1;
                }
            }
            total_time += result.time_to_result_ms;
        }

        let total = results.len();
        let accuracy = if total > 0 {
            correct as f64 / total as f64
        } else {
            0.0
        };
        let mean_time = if total > 0 {
            total_time as f64 / total as f64
        } else {
            0.0
        };

        breakdown.insert(
            difficulty.as_str().to_string(),
            DifficultyMetrics {
                difficulty: difficulty.as_str().to_string(),
                total,
                correct,
                accuracy,
                mean_time_ms: mean_time,
            },
        );
    }

    breakdown
}

pub fn compute_tag_breakdown(
    suite: &BenchmarkSuite,
    run: &BenchmarkRun,
) -> BTreeMap<String, TagMetrics> {
    let mut tag_set = BTreeMap::new();
    for case in &suite.cases {
        for tag in &case.tags {
            tag_set.insert(tag.clone(), ());
        }
    }

    let mut breakdown = BTreeMap::new();
    for tag in tag_set.keys() {
        let cases: Vec<&BenchmarkCase> = suite.cases_by_tag(tag);
        let case_ids: Vec<&str> = cases.iter().map(|c| c.case_id.as_str()).collect();
        let results: Vec<&BenchmarkResult> = run
            .results
            .iter()
            .filter(|r| case_ids.contains(&r.case_id.as_str()))
            .collect();

        let mut correct = 0usize;
        for result in &results {
            if let Some(case) = suite.case_by_id(&result.case_id) {
                if prediction_matches_ground_truth(&result.prediction, &case.ground_truth) {
                    correct += 1;
                }
            }
        }

        let total = results.len();
        let accuracy = if total > 0 {
            correct as f64 / total as f64
        } else {
            0.0
        };

        breakdown.insert(
            tag.clone(),
            TagMetrics {
                tag: tag.clone(),
                total,
                correct,
                accuracy,
            },
        );
    }

    breakdown
}

fn prediction_matches_ground_truth(
    prediction: &GroundTruthLabel,
    truth: &GroundTruthLabel,
) -> bool {
    match (prediction, truth) {
        (GroundTruthLabel::TruePositive, GroundTruthLabel::TruePositive) => true,
        (GroundTruthLabel::FalsePositive, GroundTruthLabel::FalsePositive) => true,
        (GroundTruthLabel::TrueNegative, GroundTruthLabel::TrueNegative) => true,
        (GroundTruthLabel::TrueNegative, GroundTruthLabel::FalsePositive) => true,
        (GroundTruthLabel::FalseNegative, GroundTruthLabel::FalseNegative) => true,
        _ => false,
    }
}

pub fn generate_recommendations(metrics: &EvaluationMetrics) -> Vec<String> {
    let mut recs = Vec::new();

    if metrics.precision < 0.80 {
        recs.push(format!(
            "Precision is {:.1}% — too many false positives. Tighten validator thresholds or add challenge loops.",
            metrics.precision * 100.0
        ));
    }
    if metrics.recall < 0.80 {
        recs.push(format!(
            "Recall is {:.1}% — real issues being missed. Expand candidate generation or lower triage gates.",
            metrics.recall * 100.0
        ));
    }
    if metrics.false_positive_rate > 0.25 {
        recs.push(format!(
            "False positive rate is {:.1}% — improve rejection or suppression logic.",
            metrics.false_positive_rate * 100.0
        ));
    }
    if metrics.false_negative_rate > 0.15 {
        recs.push(format!(
            "False negative rate is {:.1}% — add broader auth profiles or seed coverage.",
            metrics.false_negative_rate * 100.0
        ));
    }
    if metrics.mean_time_to_proof_ms > 30_000.0 {
        recs.push(format!(
            "Mean time to proof is {:.0}s — optimize validator execution or parallel candidate checks.",
            metrics.mean_time_to_proof_ms / 1000.0
        ));
    }
    if metrics.evidence_coverage < 0.70 {
        recs.push(format!(
            "Evidence coverage is {:.1}% — ensure validators capture all expected evidence keys.",
            metrics.evidence_coverage * 100.0
        ));
    }
    if metrics.classification_accuracy < 0.85 {
        recs.push(format!(
            "Classification accuracy is {:.1}% — improve authorization matrix classification logic.",
            metrics.classification_accuracy * 100.0
        ));
    }
    if metrics.severity_accuracy < 0.80 {
        recs.push(format!(
            "Severity accuracy is {:.1}% — review sensitivity scoring and impact classification.",
            metrics.severity_accuracy * 100.0
        ));
    }
    if recs.is_empty() {
        recs.push(
            "All metrics within acceptable thresholds. Continue hardening edge cases.".to_string(),
        );
    }
    recs
}

pub fn compare_runs(
    baseline: &BenchmarkRun,
    current: &BenchmarkRun,
    baseline_suite: &BenchmarkSuite,
    current_suite: &BenchmarkSuite,
) -> ComparisonResult {
    let baseline_metrics = compute_evaluation_metrics(baseline_suite, baseline);
    let current_metrics = compute_evaluation_metrics(current_suite, current);

    let precision_delta = current_metrics.precision - baseline_metrics.precision;
    let recall_delta = current_metrics.recall - baseline_metrics.recall;
    let f1_delta = current_metrics.f1_score - baseline_metrics.f1_score;
    let accuracy_delta = current_metrics.accuracy - baseline_metrics.accuracy;
    let time_delta = current_metrics.mean_time_to_proof_ms - baseline_metrics.mean_time_to_proof_ms;

    let mut case_deltas = Vec::new();
    let mut improvement_count = 0usize;
    let mut regression_count = 0usize;

    let baseline_results: BTreeMap<&str, &BenchmarkResult> = baseline
        .results
        .iter()
        .map(|r| (r.case_id.as_str(), r))
        .collect();

    for current_result in &current.results {
        if let Some(baseline_result) = baseline_results.get(current_result.case_id.as_str()) {
            let current_correct = current_suite
                .case_by_id(&current_result.case_id)
                .map_or(false, |c| {
                    prediction_matches_ground_truth(&current_result.prediction, &c.ground_truth)
                });
            let baseline_correct = baseline_suite
                .case_by_id(&baseline_result.case_id)
                .map_or(false, |c| {
                    prediction_matches_ground_truth(&baseline_result.prediction, &c.ground_truth)
                });

            let improved = current_correct && !baseline_correct;
            let regressed = !current_correct && baseline_correct;

            if improved {
                improvement_count += 1;
            }
            if regressed {
                regression_count += 1;
            }

            case_deltas.push(CaseComparison {
                case_id: current_result.case_id.clone(),
                baseline_prediction: baseline_result.prediction.as_str().to_string(),
                current_prediction: current_result.prediction.as_str().to_string(),
                baseline_time_ms: baseline_result.time_to_result_ms,
                current_time_ms: current_result.time_to_result_ms,
                improved,
                regressed,
            });
        }
    }

    let improved = f1_delta >= 0.0 && accuracy_delta >= 0.0;

    ComparisonResult {
        baseline_run_id: baseline.run_id.clone(),
        current_run_id: current.run_id.clone(),
        precision_delta,
        recall_delta,
        f1_delta,
        accuracy_delta,
        mean_time_delta_ms: time_delta,
        improved,
        regression_count,
        improvement_count,
        case_deltas,
    }
}

pub fn generate_scorecard(
    suite: &BenchmarkSuite,
    run: &BenchmarkRun,
    baseline_run: Option<&BenchmarkRun>,
    baseline_suite: Option<&BenchmarkSuite>,
) -> EvaluationScorecard {
    let metrics = compute_evaluation_metrics(suite, run);
    let difficulty_breakdown = compute_difficulty_breakdown(suite, run);
    let tag_breakdown = compute_tag_breakdown(suite, run);
    let recommendations = generate_recommendations(&metrics);

    let comparison = match (baseline_run, baseline_suite) {
        (Some(br), Some(bs)) => Some(compare_runs(br, run, bs, suite)),
        _ => None,
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    EvaluationScorecard {
        scorecard_id: format!("scorecard_{}", run.run_id),
        run_id: run.run_id.clone(),
        suite_id: suite.suite_id.clone(),
        domain: suite.domain.clone(),
        generated_at: now,
        metrics,
        difficulty_breakdown,
        tag_breakdown,
        recommendations,
        comparison,
    }
}

pub fn render_scorecard(scorecard: &EvaluationScorecard) -> String {
    let mut md = String::new();

    md.push_str(&format!("# BALONCORE Evaluation Scorecard\n\n"));
    md.push_str(&format!("**Suite:** {}  \n", scorecard.suite_id));
    md.push_str(&format!("**Run:** {}  \n", scorecard.run_id));
    md.push_str(&format!("**Domain:** {}  \n", scorecard.domain.as_str()));
    md.push_str(&format!(
        "**Grade:** {}  \n\n",
        scorecard.metrics.grade.as_str()
    ));

    md.push_str("## Summary Metrics\n\n");
    md.push_str("| Metric | Value |\n");
    md.push_str("|--------|-------|\n");
    md.push_str(&format!(
        "| Total Cases | {} |\n",
        scorecard.metrics.total_cases
    ));
    md.push_str(&format!(
        "| True Positives | {} |\n",
        scorecard.metrics.true_positives
    ));
    md.push_str(&format!(
        "| False Positives | {} |\n",
        scorecard.metrics.false_positives
    ));
    md.push_str(&format!(
        "| True Negatives | {} |\n",
        scorecard.metrics.true_negatives
    ));
    md.push_str(&format!(
        "| False Negatives | {} |\n",
        scorecard.metrics.false_negatives
    ));
    md.push_str(&format!(
        "| Inconclusive | {} |\n",
        scorecard.metrics.inconclusive
    ));
    md.push_str(&format!(
        "| Precision | {:.1}% |\n",
        scorecard.metrics.precision * 100.0
    ));
    md.push_str(&format!(
        "| Recall | {:.1}% |\n",
        scorecard.metrics.recall * 100.0
    ));
    md.push_str(&format!(
        "| F1 Score | {:.1}% |\n",
        scorecard.metrics.f1_score * 100.0
    ));
    md.push_str(&format!(
        "| Accuracy | {:.1}% |\n",
        scorecard.metrics.accuracy * 100.0
    ));
    md.push_str(&format!(
        "| FPR | {:.1}% |\n",
        scorecard.metrics.false_positive_rate * 100.0
    ));
    md.push_str(&format!(
        "| FNR | {:.1}% |\n",
        scorecard.metrics.false_negative_rate * 100.0
    ));
    md.push_str(&format!(
        "| Mean Time to Proof | {:.0}ms |\n",
        scorecard.metrics.mean_time_to_proof_ms
    ));
    md.push_str(&format!(
        "| Median Time to Proof | {:.0}ms |\n",
        scorecard.metrics.median_time_to_proof_ms
    ));
    md.push_str(&format!(
        "| Weighted Accuracy | {:.1}% |\n",
        scorecard.metrics.difficulty_weighted_accuracy * 100.0
    ));
    md.push_str(&format!(
        "| Classification Accuracy | {:.1}% |\n",
        scorecard.metrics.classification_accuracy * 100.0
    ));
    md.push_str(&format!(
        "| Severity Accuracy | {:.1}% |\n",
        scorecard.metrics.severity_accuracy * 100.0
    ));
    md.push_str(&format!(
        "| Evidence Coverage | {:.1}% |\n",
        scorecard.metrics.evidence_coverage * 100.0
    ));

    if !scorecard.difficulty_breakdown.is_empty() {
        md.push_str("\n## Difficulty Breakdown\n\n");
        md.push_str("| Difficulty | Cases | Correct | Accuracy | Mean Time |\n");
        md.push_str("|-----------|-------|---------|----------|----------|\n");
        for (_, dm) in &scorecard.difficulty_breakdown {
            md.push_str(&format!(
                "| {} | {} | {} | {:.1}% | {:.0}ms |\n",
                dm.difficulty,
                dm.total,
                dm.correct,
                dm.accuracy * 100.0,
                dm.mean_time_ms
            ));
        }
    }

    if !scorecard.tag_breakdown.is_empty() {
        md.push_str("\n## Tag Breakdown\n\n");
        md.push_str("| Tag | Cases | Correct | Accuracy |\n");
        md.push_str("|-----|-------|---------|----------|\n");
        for (_, tm) in &scorecard.tag_breakdown {
            md.push_str(&format!(
                "| {} | {} | {} | {:.1}% |\n",
                tm.tag,
                tm.total,
                tm.correct,
                tm.accuracy * 100.0
            ));
        }
    }

    if let Some(ref comparison) = scorecard.comparison {
        md.push_str("\n## Comparison with Baseline\n\n");
        md.push_str(&format!(
            "**Baseline Run:** {}  \n",
            comparison.baseline_run_id
        ));
        md.push_str(&format!("**Improved:** {}  \n\n", comparison.improved));
        md.push_str("| Metric | Delta |\n");
        md.push_str("|--------|-------|\n");
        md.push_str(&format!(
            "| Precision | {:+.1}% |\n",
            comparison.precision_delta * 100.0
        ));
        md.push_str(&format!(
            "| Recall | {:+.1}% |\n",
            comparison.recall_delta * 100.0
        ));
        md.push_str(&format!("| F1 | {:+.1}% |\n", comparison.f1_delta * 100.0));
        md.push_str(&format!(
            "| Accuracy | {:+.1}% |\n",
            comparison.accuracy_delta * 100.0
        ));
        md.push_str(&format!(
            "| Mean Time | {:+.0}ms |\n",
            comparison.mean_time_delta_ms
        ));
        md.push_str(&format!(
            "| Improvements | {} |\n",
            comparison.improvement_count
        ));
        md.push_str(&format!(
            "| Regressions | {} |\n",
            comparison.regression_count
        ));
    }

    if !scorecard.recommendations.is_empty() {
        md.push_str("\n## Recommendations\n\n");
        for rec in &scorecard.recommendations {
            md.push_str(&format!("- {}\n", rec));
        }
    }

    md
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VulnClassMetrics {
    pub vuln_class: String,
    pub total_cases: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub true_negatives: usize,
    pub false_negatives: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub median_time_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PerCaseResult {
    pub case_id: String,
    pub case_name: String,
    pub domain: String,
    pub ground_truth: String,
    pub prediction: String,
    pub correct: bool,
    pub confidence: f64,
    pub time_ms: u64,
    pub difficulty: String,
    pub vuln_class: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LeaderboardReport {
    pub report_id: String,
    pub generated_at: u64,
    pub runs: Vec<LeaderboardRunEntry>,
    pub aggregate: EvaluationMetrics,
    pub per_case: Vec<PerCaseResult>,
    pub vuln_class_breakdown: Vec<VulnClassMetrics>,
    pub attribution: LeaderboardAttribution,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LeaderboardRunEntry {
    pub run_id: String,
    pub suite_id: String,
    pub domain: String,
    pub grade: String,
    pub accuracy: f64,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct LeaderboardAttribution {
    pub provider: String,
    pub model: String,
    pub prompt_version: String,
    pub engine_version: String,
    pub git_commit: String,
    pub corpus_hash: String,
}

fn vuln_class_for_case(case: &BenchmarkCase) -> String {
    if let Some(ref classification) = case.expected_classification {
        classification.clone()
    } else if case.tags.contains(&"bola".to_string()) {
        "BOLA".to_string()
    } else if case.tags.contains(&"bfla".to_string()) {
        "BFLA".to_string()
    } else if case.tags.contains(&"cloud_iam".to_string()) {
        "CloudIAM".to_string()
    } else if case.tags.contains(&"web3".to_string()) {
        "Web3".to_string()
    } else if case.tags.contains(&"evidence".to_string()) {
        "Evidence".to_string()
    } else {
        case.tags
            .first()
            .cloned()
            .unwrap_or_else(|| "Other".to_string())
    }
}

pub fn generate_leaderboard(suites: &[BenchmarkSuite], runs: &[BenchmarkRun]) -> LeaderboardReport {
    let mut aggregate_tp = 0usize;
    let mut aggregate_fp = 0usize;
    let mut aggregate_tn = 0usize;
    let mut aggregate_fn = 0usize;
    let mut aggregate_inconclusive = 0usize;
    let mut total_cases = 0usize;
    let mut total_weighted_correct = 0.0f64;
    let mut total_weighted_total = 0.0f64;
    let mut total_classification_matches = 0usize;
    let mut total_classification_eligible = 0usize;
    let mut total_severity_matches = 0usize;
    let mut total_severity_eligible = 0usize;
    let mut total_evidence_expected = 0usize;
    let mut total_evidence_found = 0usize;
    let mut all_times: Vec<u64> = Vec::new();

    let mut per_case_results: Vec<PerCaseResult> = Vec::new();
    let mut vuln_class_data: BTreeMap<String, Vec<(String, bool, u64, f64, String, String)>> =
        BTreeMap::new();

    let mut run_entries: Vec<LeaderboardRunEntry> = Vec::new();
    let mut attribution = LeaderboardAttribution::default();

    for run in runs {
        let suite = match suites.iter().find(|s| s.suite_id == run.suite_id) {
            Some(s) => s,
            None => continue,
        };

        let metrics = compute_evaluation_metrics(suite, run);

        run_entries.push(LeaderboardRunEntry {
            run_id: run.run_id.clone(),
            suite_id: run.suite_id.clone(),
            domain: run.domain.as_str().to_string(),
            grade: metrics.grade.as_str().to_string(),
            accuracy: metrics.accuracy,
            precision: metrics.precision,
            recall: metrics.recall,
            f1_score: metrics.f1_score,
        });

        aggregate_tp += metrics.true_positives;
        aggregate_fp += metrics.false_positives;
        aggregate_tn += metrics.true_negatives;
        aggregate_fn += metrics.false_negatives;
        aggregate_inconclusive += metrics.inconclusive;
        total_cases += metrics.total_cases;

        for result in &run.results {
            let case = match suite.case_by_id(&result.case_id) {
                Some(c) => c,
                None => continue,
            };

            let weight = case.difficulty.weight();
            let correct = prediction_matches_ground_truth(&result.prediction, &case.ground_truth);
            total_weighted_total += weight;
            if correct {
                total_weighted_correct += weight;
            }

            if case.expected_classification.is_some() {
                total_classification_eligible += 1;
                if result.actual_classification.as_deref()
                    == case.expected_classification.as_deref()
                {
                    total_classification_matches += 1;
                }
            }

            if case.expected_severity.is_some() {
                total_severity_eligible += 1;
                if result.actual_severity.as_deref() == case.expected_severity.as_deref() {
                    total_severity_matches += 1;
                }
            }

            total_evidence_expected += case.expected_evidence_keys.len();
            total_evidence_found += result
                .evidence_found
                .len()
                .min(case.expected_evidence_keys.len());

            all_times.push(result.time_to_result_ms);

            let vc = vuln_class_for_case(case);
            vuln_class_data.entry(vc.clone()).or_default().push((
                result.prediction.as_str().to_string(),
                correct,
                result.time_to_result_ms,
                result.confidence,
                case.difficulty.as_str().to_string(),
                case.case_id.clone(),
            ));

            per_case_results.push(PerCaseResult {
                case_id: result.case_id.clone(),
                case_name: case.name.clone(),
                domain: case.domain.as_str().to_string(),
                ground_truth: case.ground_truth.as_str().to_string(),
                prediction: result.prediction.as_str().to_string(),
                correct,
                confidence: result.confidence,
                time_ms: result.time_to_result_ms,
                difficulty: case.difficulty.as_str().to_string(),
                vuln_class: vc,
            });
        }

        if !run.config_snapshot.provider.is_empty() {
            attribution.provider = run.config_snapshot.provider.clone();
        }
        if !run.config_snapshot.model.is_empty() {
            attribution.model = run.config_snapshot.model.clone();
        }
        if !run.config_snapshot.prompt_version.is_empty() {
            attribution.prompt_version = run.config_snapshot.prompt_version.clone();
        }
        if !run.config_snapshot.engine_version.is_empty() {
            attribution.engine_version = run.config_snapshot.engine_version.clone();
        }
        if !run.config_snapshot.git_commit.is_empty() {
            attribution.git_commit = run.config_snapshot.git_commit.clone();
        }
        if !run.config_snapshot.corpus_hash.is_empty() {
            attribution.corpus_hash = run.config_snapshot.corpus_hash.clone();
        }
    }

    all_times.sort();
    let median_time = if all_times.is_empty() {
        0.0
    } else if all_times.len() % 2 == 0 {
        (all_times[all_times.len() / 2 - 1] + all_times[all_times.len() / 2]) as f64 / 2.0
    } else {
        all_times[all_times.len() / 2] as f64
    };
    let mean_time = if all_times.is_empty() {
        0.0
    } else {
        all_times.iter().sum::<u64>() as f64 / all_times.len() as f64
    };

    let precision = if (aggregate_tp + aggregate_fp) > 0 {
        aggregate_tp as f64 / (aggregate_tp + aggregate_fp) as f64
    } else {
        0.0
    };
    let recall = if (aggregate_tp + aggregate_fn) > 0 {
        aggregate_tp as f64 / (aggregate_tp + aggregate_fn) as f64
    } else {
        0.0
    };
    let f1 = if (precision + recall) > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };
    let accuracy = if total_cases > 0 {
        (aggregate_tp + aggregate_tn) as f64 / total_cases as f64
    } else {
        0.0
    };
    let fpr = if (aggregate_fp + aggregate_tn) > 0 {
        aggregate_fp as f64 / (aggregate_fp + aggregate_tn) as f64
    } else {
        0.0
    };
    let fnr = if (aggregate_fn + aggregate_tp) > 0 {
        aggregate_fn as f64 / (aggregate_fn + aggregate_tp) as f64
    } else {
        0.0
    };
    let weighted_accuracy = if total_weighted_total > 0.0 {
        total_weighted_correct / total_weighted_total
    } else {
        0.0
    };
    let classification_accuracy = if total_classification_eligible > 0 {
        total_classification_matches as f64 / total_classification_eligible as f64
    } else {
        0.0
    };
    let severity_accuracy = if total_severity_eligible > 0 {
        total_severity_matches as f64 / total_severity_eligible as f64
    } else {
        0.0
    };
    let evidence_coverage = if total_evidence_expected > 0 {
        total_evidence_found as f64 / total_evidence_expected as f64
    } else {
        0.0
    };

    let aggregate = EvaluationMetrics {
        total_cases,
        true_positives: aggregate_tp,
        false_positives: aggregate_fp,
        true_negatives: aggregate_tn,
        false_negatives: aggregate_fn,
        inconclusive: aggregate_inconclusive,
        precision,
        recall,
        f1_score: f1,
        accuracy,
        false_positive_rate: fpr,
        false_negative_rate: fnr,
        mean_time_to_proof_ms: mean_time,
        median_time_to_proof_ms: median_time,
        difficulty_weighted_accuracy: weighted_accuracy,
        classification_accuracy,
        severity_accuracy,
        evidence_coverage,
        grade: EvaluationGrade::from_score(accuracy),
    };

    let mut vuln_class_breakdown = Vec::new();
    for (vc, entries) in &vuln_class_data {
        let tp = entries
            .iter()
            .filter(|(_, correct, _, _, _, _)| *correct)
            .fold(0usize, |acc, _| acc + 1);
        let total = entries.len();
        let fp = entries
            .iter()
            .filter(|(pred, _, _, _, _, _)| pred != "TrueNegative" && pred != "TruePositive")
            .fold(0usize, |acc, _| acc + 1);
        let precision = if (tp + fp) > 0 {
            tp as f64 / (tp + fp) as f64
        } else {
            0.0
        };
        let recall_val = if total > 0 {
            tp as f64 / total as f64
        } else {
            0.0
        };
        let f1 = if (precision + recall_val) > 0.0 {
            2.0 * precision * recall_val / (precision + recall_val)
        } else {
            0.0
        };
        let times: Vec<u64> = entries.iter().map(|(_, _, t, _, _, _)| *t).collect();
        let mut sorted = times.clone();
        sorted.sort();
        let median = if sorted.is_empty() {
            0.0
        } else if sorted.len() % 2 == 0 {
            (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) as f64 / 2.0
        } else {
            sorted[sorted.len() / 2] as f64
        };

        vuln_class_breakdown.push(VulnClassMetrics {
            vuln_class: vc.clone(),
            total_cases: total,
            true_positives: tp,
            false_positives: fp,
            true_negatives: entries
                .iter()
                .filter(|(pred, correct, _, _, _, _)| *correct && pred == "TrueNegative")
                .count(),
            false_negatives: entries
                .iter()
                .filter(|(_, correct, _, _, _, _)| !*correct)
                .count(),
            precision,
            recall: recall_val,
            f1_score: f1,
            median_time_ms: median,
        });
    }

    LeaderboardReport {
        report_id: format!(
            "leaderboard_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        ),
        generated_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        runs: run_entries,
        aggregate,
        per_case: per_case_results,
        vuln_class_breakdown,
        attribution,
    }
}

pub fn render_leaderboard(report: &LeaderboardReport) -> String {
    let mut md = String::new();

    md.push_str("# BALONCORE Evaluation Leaderboard\n\n");

    md.push_str("**Provider:** ");
    md.push_str(&report.attribution.provider);
    md.push_str("  \n**Model:** ");
    md.push_str(&report.attribution.model);
    md.push_str("  \n**Prompt Version:** ");
    md.push_str(&report.attribution.prompt_version);
    md.push_str("  \n**Engine Version:** ");
    md.push_str(&report.attribution.engine_version);
    md.push_str("  \n**Git Commit:** ");
    md.push_str(&report.attribution.git_commit);
    md.push_str("  \n**Corpus Hash:** ");
    md.push_str(&report.attribution.corpus_hash);
    md.push_str("\n\n");

    md.push_str("## Aggregate\n\n");
    md.push_str("| Metric | Value |\n");
    md.push_str("|--------|-------|\n");
    md.push_str(&format!(
        "| Grade | {} |\n",
        report.aggregate.grade.as_str()
    ));
    md.push_str(&format!(
        "| Total Cases | {} |\n",
        report.aggregate.total_cases
    ));
    md.push_str(&format!(
        "| True Positives | {} |\n",
        report.aggregate.true_positives
    ));
    md.push_str(&format!(
        "| False Positives | {} |\n",
        report.aggregate.false_positives
    ));
    md.push_str(&format!(
        "| True Negatives | {} |\n",
        report.aggregate.true_negatives
    ));
    md.push_str(&format!(
        "| False Negatives | {} |\n",
        report.aggregate.false_negatives
    ));
    md.push_str(&format!(
        "| Precision | {:.1}% |\n",
        report.aggregate.precision * 100.0
    ));
    md.push_str(&format!(
        "| Recall | {:.1}% |\n",
        report.aggregate.recall * 100.0
    ));
    md.push_str(&format!(
        "| F1 | {:.1}% |\n",
        report.aggregate.f1_score * 100.0
    ));
    md.push_str(&format!(
        "| Accuracy | {:.1}% |\n",
        report.aggregate.accuracy * 100.0
    ));
    md.push_str(&format!(
        "| FPR | {:.1}% |\n",
        report.aggregate.false_positive_rate * 100.0
    ));
    md.push_str(&format!(
        "| Median Time to Proof | {:.0}ms |\n",
        report.aggregate.median_time_to_proof_ms
    ));
    md.push_str(&format!(
        "| Weighted Accuracy | {:.1}% |\n",
        report.aggregate.difficulty_weighted_accuracy * 100.0
    ));
    md.push_str(&format!(
        "| Evidence Coverage | {:.1}% |\n",
        report.aggregate.evidence_coverage * 100.0
    ));

    md.push_str("\n## Per-Run\n\n");
    md.push_str("| Run | Suite | Domain | Grade | Accuracy | Precision | Recall | F1 |\n");
    md.push_str("|-----|-------|--------|-------|----------|-----------|--------|----|\n");
    for entry in &report.runs {
        md.push_str(&format!(
            "| {} | {} | {} | {} | {:.1}% | {:.1}% | {:.1}% | {:.1}% |\n",
            entry.run_id,
            entry.suite_id,
            entry.domain,
            entry.grade,
            entry.accuracy * 100.0,
            entry.precision * 100.0,
            entry.recall * 100.0,
            entry.f1_score * 100.0,
        ));
    }

    if !report.vuln_class_breakdown.is_empty() {
        md.push_str("\n## Per-Vuln-Class\n\n");
        md.push_str(
            "| Class | Cases | TP | FP | TN | FN | Precision | Recall | F1 | Median Time |\n",
        );
        md.push_str(
            "|-------|-------|----|----|----|----|-----------|--------|----|------------|\n",
        );
        for vc in &report.vuln_class_breakdown {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {:.1}% | {:.1}% | {:.1}% | {:.0}ms |\n",
                vc.vuln_class,
                vc.total_cases,
                vc.true_positives,
                vc.false_positives,
                vc.true_negatives,
                vc.false_negatives,
                vc.precision * 100.0,
                vc.recall * 100.0,
                vc.f1_score * 100.0,
                vc.median_time_ms,
            ));
        }
    }

    if !report.per_case.is_empty() {
        md.push_str("\n## Per-Case Results\n\n");
        md.push_str("| Case | Domain | Difficulty | Ground Truth | Prediction | Correct | Confidence | Time |\n");
        md.push_str("|------|--------|------------|-------------|------------|---------|------------|------|\n");
        for case in &report.per_case {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {:.0}% | {}ms |\n",
                case.case_name,
                case.domain,
                case.difficulty,
                case.ground_truth,
                case.prediction,
                if case.correct { "✓" } else { "✗" },
                case.confidence * 100.0,
                case.time_ms,
            ));
        }
    }

    md
}

pub fn render_run_diff(baseline: &LeaderboardReport, current: &LeaderboardReport) -> String {
    let mut md = String::new();

    md.push_str("# BALONCORE Leaderboard Diff\n\n");

    md.push_str(&format!("**Baseline:** {}  \n", baseline.report_id));
    md.push_str(&format!("**Current:** {}  \n\n", current.report_id));

    md.push_str("## Aggregate Delta\n\n");
    md.push_str("| Metric | Baseline | Current | Delta |\n");
    md.push_str("|--------|----------|---------|-------|\n");

    let metrics_pairs = [
        (
            "Accuracy",
            baseline.aggregate.accuracy,
            current.aggregate.accuracy,
        ),
        (
            "Precision",
            baseline.aggregate.precision,
            current.aggregate.precision,
        ),
        (
            "Recall",
            baseline.aggregate.recall,
            current.aggregate.recall,
        ),
        (
            "F1",
            baseline.aggregate.f1_score,
            current.aggregate.f1_score,
        ),
        (
            "FPR",
            baseline.aggregate.false_positive_rate,
            current.aggregate.false_positive_rate,
        ),
        (
            "Weighted Acc.",
            baseline.aggregate.difficulty_weighted_accuracy,
            current.aggregate.difficulty_weighted_accuracy,
        ),
        (
            "Evidence Cov.",
            baseline.aggregate.evidence_coverage,
            current.aggregate.evidence_coverage,
        ),
    ];

    for (label, base_val, cur_val) in &metrics_pairs {
        let delta = cur_val - base_val;
        let arrow = if delta.abs() < 0.001 {
            "—"
        } else if delta > 0.0 {
            "▲"
        } else {
            "▼"
        };
        md.push_str(&format!(
            "| {} | {:.1}% | {:.1}% | {}{:.1}% |\n",
            label,
            base_val * 100.0,
            cur_val * 100.0,
            arrow,
            delta * 100.0
        ));
    }

    md.push_str(&format!(
        "| Median Time | {:.0}ms | {:.0}ms | {:+.0}ms |\n",
        baseline.aggregate.median_time_to_proof_ms,
        current.aggregate.median_time_to_proof_ms,
        current.aggregate.median_time_to_proof_ms - baseline.aggregate.median_time_to_proof_ms,
    ));

    let improved = current.aggregate.accuracy > baseline.aggregate.accuracy;
    md.push_str(&format!(
        "\n**Overall:** {}  \n",
        if improved {
            "IMPROVED"
        } else {
            "REGRESSED OR STABLE"
        }
    ));

    if !current.per_case.is_empty() && !baseline.per_case.is_empty() {
        let baseline_cases: BTreeMap<&str, &PerCaseResult> = baseline
            .per_case
            .iter()
            .map(|c| (c.case_id.as_str(), c))
            .collect();
        let current_cases: BTreeMap<&str, &PerCaseResult> = current
            .per_case
            .iter()
            .map(|c| (c.case_id.as_str(), c))
            .collect();

        let mut improvements = Vec::new();
        let mut regressions = Vec::new();

        for (id, cur) in &current_cases {
            if let Some(base) = baseline_cases.get(id) {
                if !base.correct && cur.correct {
                    improvements.push(cur.case_name.as_str());
                } else if base.correct && !cur.correct {
                    regressions.push(cur.case_name.as_str());
                }
            }
        }

        if !improvements.is_empty() || !regressions.is_empty() {
            md.push_str("\n## Case-Level Changes\n\n");

            if !improvements.is_empty() {
                md.push_str("**Improved:**\n");
                for name in &improvements {
                    md.push_str(&format!("- {}\n", name));
                }
                md.push_str("\n");
            }

            if !regressions.is_empty() {
                md.push_str("**Regressed:**\n");
                for name in &regressions {
                    md.push_str(&format!("- {}\n", name));
                }
                md.push_str("\n");
            }
        }
    }

    if !baseline.vuln_class_breakdown.is_empty() && !current.vuln_class_breakdown.is_empty() {
        md.push_str("\n## Per-Vuln-Class Delta\n\n");
        md.push_str("| Class | Baseline Prec. | Current Prec. | Δ | Baseline Recall | Current Recall | Δ |\n");
        md.push_str(
            "|-------|---------------|--------------|---|----------------|----------------|---|\n",
        );

        let base_by_class: BTreeMap<&str, &VulnClassMetrics> = baseline
            .vuln_class_breakdown
            .iter()
            .map(|v| (v.vuln_class.as_str(), v))
            .collect();
        let cur_by_class: BTreeMap<&str, &VulnClassMetrics> = current
            .vuln_class_breakdown
            .iter()
            .map(|v| (v.vuln_class.as_str(), v))
            .collect();

        for (vc, cur) in &cur_by_class {
            if let Some(base) = base_by_class.get(vc) {
                let prec_delta = cur.precision - base.precision;
                let recall_delta = cur.recall - base.recall;
                md.push_str(&format!(
                    "| {} | {:.1}% | {:.1}% | {:+.1}% | {:.1}% | {:.1}% | {:+.1}% |\n",
                    vc,
                    base.precision * 100.0,
                    cur.precision * 100.0,
                    prec_delta * 100.0,
                    base.recall * 100.0,
                    cur.recall * 100.0,
                    recall_delta * 100.0,
                ));
            }
        }
    }

    md
}

pub fn save_leaderboard(report: &LeaderboardReport, path: &Path) -> Result<(), String> {
    let json = serde_json::to_string_pretty(report).map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, json).map_err(|e| e.to_string())
}

pub fn load_leaderboard(path: &Path) -> Result<LeaderboardReport, String> {
    let data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&data).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeterminismCheckResult {
    pub check_id: String,
    pub suite_id: String,
    pub runs_compared: usize,
    pub scores_identical: bool,
    pub byte_identical_json: bool,
    pub accuracy_matches: Vec<bool>,
    pub precision_matches: Vec<bool>,
    pub recall_matches: Vec<bool>,
    pub f1_matches: Vec<bool>,
    pub grade_matches: Vec<bool>,
    pub run_ids: Vec<String>,
    pub details: String,
}

pub fn verify_determinism(suite: &BenchmarkSuite, k: usize) -> DeterminismCheckResult {
    if k < 2 {
        return DeterminismCheckResult {
            check_id: format!(
                "determinism_{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            ),
            suite_id: suite.suite_id.clone(),
            runs_compared: 0,
            scores_identical: false,
            byte_identical_json: false,
            accuracy_matches: vec![],
            precision_matches: vec![],
            recall_matches: vec![],
            f1_matches: vec![],
            grade_matches: vec![],
            run_ids: vec![],
            details: "Need at least 2 runs to compare".to_string(),
        };
    }

    let mut runs: Vec<BenchmarkRun> = Vec::new();
    let mut metrics_list: Vec<EvaluationMetrics> = Vec::new();
    let mut json_blobs: Vec<String> = Vec::new();

    for _i in 0..k {
        let run = generate_golden_baseline(suite);
        let metrics = compute_evaluation_metrics(suite, &run);
        let json = serde_json::to_string(&run).unwrap_or_default();
        runs.push(run);
        metrics_list.push(metrics);
        json_blobs.push(json);
    }

    let base_metrics = &metrics_list[0];
    let base_json = &json_blobs[0];

    let mut accuracy_matches = Vec::new();
    let mut precision_matches = Vec::new();
    let mut recall_matches = Vec::new();
    let mut f1_matches = Vec::new();
    let mut grade_matches = Vec::new();

    for metrics in &metrics_list[1..] {
        accuracy_matches.push((metrics.accuracy - base_metrics.accuracy).abs() < f64::EPSILON);
        precision_matches.push((metrics.precision - base_metrics.precision).abs() < f64::EPSILON);
        recall_matches.push((metrics.recall - base_metrics.recall).abs() < f64::EPSILON);
        f1_matches.push((metrics.f1_score - base_metrics.f1_score).abs() < f64::EPSILON);
        grade_matches.push(metrics.grade == base_metrics.grade);
    }

    let all_scores_identical = accuracy_matches.iter().all(|&m| m)
        && precision_matches.iter().all(|&m| m)
        && recall_matches.iter().all(|&m| m)
        && f1_matches.iter().all(|&m| m)
        && grade_matches.iter().all(|&m| m);

    let byte_identical = json_blobs[1..].iter().all(|j| j == base_json);

    let run_ids: Vec<String> = runs.iter().map(|r| r.run_id.clone()).collect();

    let details = if byte_identical {
        format!("All {} runs are BYTE-IDENTICAL (determinism locked)", k)
    } else if all_scores_identical {
        format!("All {} runs produce IDENTICAL aggregate scores (but JSON representations differ in run IDs)", k)
    } else {
        let mismatches: Vec<String> = (0..accuracy_matches.len())
            .filter(|&i| {
                !accuracy_matches[i]
                    || !precision_matches[i]
                    || !recall_matches[i]
                    || !f1_matches[i]
            })
            .map(|i| format!("run {} vs run 0", i + 1))
            .collect();
        format!(
            "DETERMINISM FAILURE: score mismatches in {}",
            mismatches.join(", ")
        )
    };

    DeterminismCheckResult {
        check_id: format!(
            "determinism_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        ),
        suite_id: suite.suite_id.clone(),
        runs_compared: k,
        scores_identical: all_scores_identical,
        byte_identical_json: byte_identical,
        accuracy_matches,
        precision_matches,
        recall_matches,
        f1_matches,
        grade_matches,
        run_ids,
        details,
    }
}

pub fn render_determinism_check(result: &DeterminismCheckResult) -> String {
    let mut md = String::new();
    md.push_str("# BALONCORE Determinism Check\n\n");
    md.push_str(&format!("**Suite:** {}  \n", result.suite_id));
    md.push_str(&format!("**Runs Compared:** {}  \n", result.runs_compared));
    md.push_str(&format!(
        "**Scores Identical:** {}  \n",
        if result.scores_identical { "YES" } else { "NO" }
    ));
    md.push_str(&format!(
        "**Byte-Identical JSON:** {}  \n\n",
        if result.byte_identical_json {
            "YES"
        } else {
            "NO"
        }
    ));

    md.push_str("## Per-Run Comparison vs Run 0\n\n");
    md.push_str("| Run | Accuracy | Precision | Recall | F1 | Grade |\n");
    md.push_str("|-----|----------|-----------|--------|----|-------|\n");
    for (i, run_id) in result.run_ids.iter().enumerate() {
        if i == 0 {
            md.push_str(&format!("| {} (baseline) | — | — | — | — | — |\n", run_id));
        } else {
            let idx = i - 1;
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                run_id,
                if result.accuracy_matches.get(idx).copied().unwrap_or(false) {
                    "✓"
                } else {
                    "✗"
                },
                if result.precision_matches.get(idx).copied().unwrap_or(false) {
                    "✓"
                } else {
                    "✗"
                },
                if result.recall_matches.get(idx).copied().unwrap_or(false) {
                    "✓"
                } else {
                    "✗"
                },
                if result.f1_matches.get(idx).copied().unwrap_or(false) {
                    "✓"
                } else {
                    "✗"
                },
                if result.grade_matches.get(idx).copied().unwrap_or(false) {
                    "✓"
                } else {
                    "✗"
                },
            ));
        }
    }

    md.push_str(&format!("\n**Result:** {}\n", result.details));
    md
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MetricStatistics {
    pub metric_name: String,
    pub mean: f64,
    pub stddev: f64,
    pub min: f64,
    pub max: f64,
    pub sample_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BenchmarkRepetitionResult {
    pub result_id: String,
    pub suite_id: String,
    pub domain: BenchmarkDomain,
    pub k: usize,
    pub run_ids: Vec<String>,
    pub accuracy_stats: MetricStatistics,
    pub precision_stats: MetricStatistics,
    pub recall_stats: MetricStatistics,
    pub f1_stats: MetricStatistics,
    pub fpr_stats: MetricStatistics,
    pub fnr_stats: MetricStatistics,
    pub mean_time_stats: MetricStatistics,
    pub weighted_accuracy_stats: MetricStatistics,
    pub evidence_coverage_stats: MetricStatistics,
    pub deterministic: bool,
    pub attribution: LeaderboardAttribution,
}

fn compute_stats(values: &[f64]) -> MetricStatistics {
    if values.is_empty() {
        return MetricStatistics {
            metric_name: String::new(),
            mean: 0.0,
            stddev: 0.0,
            min: 0.0,
            max: 0.0,
            sample_count: 0,
        };
    }
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    let variance = if values.len() > 1 {
        values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1.0)
    } else {
        0.0
    };
    let stddev = variance.sqrt();
    let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

    MetricStatistics {
        metric_name: String::new(),
        mean,
        stddev,
        min,
        max,
        sample_count: values.len(),
    }
}

pub fn compute_repetition_stats(
    suite: &BenchmarkSuite,
    runs: &[BenchmarkRun],
) -> BenchmarkRepetitionResult {
    let metrics_list: Vec<EvaluationMetrics> = runs
        .iter()
        .map(|run| compute_evaluation_metrics(suite, run))
        .collect();

    let accuracies: Vec<f64> = metrics_list.iter().map(|m| m.accuracy).collect();
    let precisions: Vec<f64> = metrics_list.iter().map(|m| m.precision).collect();
    let recalls: Vec<f64> = metrics_list.iter().map(|m| m.recall).collect();
    let f1s: Vec<f64> = metrics_list.iter().map(|m| m.f1_score).collect();
    let fprs: Vec<f64> = metrics_list.iter().map(|m| m.false_positive_rate).collect();
    let fnrs: Vec<f64> = metrics_list.iter().map(|m| m.false_negative_rate).collect();
    let mean_times: Vec<f64> = metrics_list
        .iter()
        .map(|m| m.mean_time_to_proof_ms)
        .collect();
    let weighted_accs: Vec<f64> = metrics_list
        .iter()
        .map(|m| m.difficulty_weighted_accuracy)
        .collect();
    let evidence_covs: Vec<f64> = metrics_list.iter().map(|m| m.evidence_coverage).collect();

    let deterministic = accuracies.len() > 1
        && accuracies
            .windows(2)
            .all(|w| (w[0] - w[1]).abs() < f64::EPSILON)
        && precisions
            .windows(2)
            .all(|w| (w[0] - w[1]).abs() < f64::EPSILON)
        && recalls
            .windows(2)
            .all(|w| (w[0] - w[1]).abs() < f64::EPSILON);

    let mut accuracy_stats = compute_stats(&accuracies);
    accuracy_stats.metric_name = "accuracy".to_string();
    let mut precision_stats = compute_stats(&precisions);
    precision_stats.metric_name = "precision".to_string();
    let mut recall_stats = compute_stats(&recalls);
    recall_stats.metric_name = "recall".to_string();
    let mut f1_stats = compute_stats(&f1s);
    f1_stats.metric_name = "f1".to_string();
    let mut fpr_stats = compute_stats(&fprs);
    fpr_stats.metric_name = "fpr".to_string();
    let mut fnr_stats = compute_stats(&fnrs);
    fnr_stats.metric_name = "fnr".to_string();
    let mut mean_time_stats = compute_stats(&mean_times);
    mean_time_stats.metric_name = "mean_time_to_proof".to_string();
    let mut weighted_accuracy_stats = compute_stats(&weighted_accs);
    weighted_accuracy_stats.metric_name = "weighted_accuracy".to_string();
    let mut evidence_coverage_stats = compute_stats(&evidence_covs);
    evidence_coverage_stats.metric_name = "evidence_coverage".to_string();

    let mut attribution = LeaderboardAttribution::default();
    if let Some(first_run) = runs.first() {
        attribution.provider = first_run.config_snapshot.provider.clone();
        attribution.model = first_run.config_snapshot.model.clone();
        attribution.prompt_version = first_run.config_snapshot.prompt_version.clone();
        attribution.engine_version = first_run.config_snapshot.engine_version.clone();
        attribution.git_commit = first_run.config_snapshot.git_commit.clone();
        attribution.corpus_hash = first_run.config_snapshot.corpus_hash.clone();
    }

    BenchmarkRepetitionResult {
        result_id: format!(
            "repetition_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        ),
        suite_id: suite.suite_id.clone(),
        domain: suite.domain.clone(),
        k: runs.len(),
        run_ids: runs.iter().map(|r| r.run_id.clone()).collect(),
        accuracy_stats,
        precision_stats,
        recall_stats,
        f1_stats,
        fpr_stats,
        fnr_stats,
        mean_time_stats,
        weighted_accuracy_stats,
        evidence_coverage_stats,
        deterministic,
        attribution,
    }
}

pub fn render_repetition_result(result: &BenchmarkRepetitionResult) -> String {
    let mut md = String::new();
    md.push_str("# BALONCORE Benchmark Repetition Result\n\n");

    md.push_str("**Provider:** ");
    md.push_str(&result.attribution.provider);
    md.push_str("  \n**Model:** ");
    md.push_str(&result.attribution.model);
    md.push_str("  \n**K (repetitions):** ");
    md.push_str(&result.k.to_string());
    md.push_str("  \n**Deterministic:** ");
    md.push_str(if result.deterministic { "YES" } else { "NO" });
    md.push_str("\n\n");

    md.push_str("## Metric Statistics (mean ± stddev)\n\n");
    md.push_str("| Metric | Mean ± StdDev | Min | Max |\n");
    md.push_str("|--------|---------------|-----|-----|\n");

    for stats in &[
        &result.accuracy_stats,
        &result.precision_stats,
        &result.recall_stats,
        &result.f1_stats,
        &result.fpr_stats,
        &result.fnr_stats,
        &result.mean_time_stats,
        &result.weighted_accuracy_stats,
        &result.evidence_coverage_stats,
    ] {
        md.push_str(&format!(
            "| {} | {:.4} ± {:.4} | {:.4} | {:.4} |\n",
            stats.metric_name, stats.mean, stats.stddev, stats.min, stats.max,
        ));
    }

    md.push_str(&format!(
        "\n**Result:** {} across {} runs\n",
        if result.deterministic {
            "DETERMINISTIC (identical scores)"
        } else {
            "NON-DETERMINISTIC (variance detected)"
        },
        result.k,
    ));

    md
}

pub fn save_determinism_check(result: &DeterminismCheckResult, path: &Path) -> Result<(), String> {
    let json = serde_json::to_string_pretty(result).map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, json).map_err(|e| e.to_string())
}

pub fn load_determinism_check(path: &Path) -> Result<DeterminismCheckResult, String> {
    let data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&data).map_err(|e| e.to_string())
}

pub fn save_repetition_result(
    result: &BenchmarkRepetitionResult,
    path: &Path,
) -> Result<(), String> {
    let json = serde_json::to_string_pretty(result).map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, json).map_err(|e| e.to_string())
}

pub fn load_repetition_result(path: &Path) -> Result<BenchmarkRepetitionResult, String> {
    let data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&data).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvalGateResult {
    pub passed: bool,
    pub current_grade: EvaluationGrade,
    pub current_metrics: EvaluationMetrics,
    pub baseline_comparison: Option<ComparisonResult>,
    pub threshold_checks: Vec<ThresholdCheck>,
    pub decoy_false_positive_count: usize,
    pub decoy_false_positive_violations: Vec<String>,
    pub recall_drop_violations: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThresholdCheck {
    pub metric: String,
    pub value: f64,
    pub threshold: f64,
    pub passed: bool,
    pub comparison: String,
}

pub fn eval_gate(
    run: &BenchmarkRun,
    suite: &BenchmarkSuite,
    min_precision: f64,
    max_decoy_fp: usize,
    max_recall_drop: f64,
    baseline_run: Option<&BenchmarkRun>,
    baseline_suite: Option<&BenchmarkSuite>,
) -> EvalGateResult {
    let metrics = compute_evaluation_metrics(suite, run);
    let mut checks = Vec::new();
    let mut violations = Vec::new();

    checks.push(ThresholdCheck {
        metric: "accuracy".to_string(),
        value: metrics.accuracy,
        threshold: 0.0,
        passed: true,
        comparison: format!("{:.1}%", metrics.accuracy * 100.0),
    });

    if metrics.precision < min_precision {
        checks.push(ThresholdCheck {
            metric: "precision".to_string(),
            value: metrics.precision,
            threshold: min_precision,
            passed: false,
            comparison: format!(
                "{:.1}% < {:.1}%",
                metrics.precision * 100.0,
                min_precision * 100.0
            ),
        });
        violations.push(format!(
            "precision {:.1}% below minimum {:.1}%",
            metrics.precision * 100.0,
            min_precision * 100.0
        ));
    } else {
        checks.push(ThresholdCheck {
            metric: "precision".to_string(),
            value: metrics.precision,
            threshold: min_precision,
            passed: true,
            comparison: format!(
                "{:.1}% >= {:.1}%",
                metrics.precision * 100.0,
                min_precision * 100.0
            ),
        });
    }

    checks.push(ThresholdCheck {
        metric: "recall".to_string(),
        value: metrics.recall,
        threshold: 0.0,
        passed: true,
        comparison: format!("{:.1}%", metrics.recall * 100.0),
    });

    checks.push(ThresholdCheck {
        metric: "f1".to_string(),
        value: metrics.f1_score,
        threshold: 0.0,
        passed: true,
        comparison: format!("{:.1}%", metrics.f1_score * 100.0),
    });

    let decoy_cases: Vec<&BenchmarkCase> = suite
        .cases
        .iter()
        .filter(|c| {
            c.ground_truth == GroundTruthLabel::FalsePositive
                || c.tags.contains(&"decoy".to_string())
        })
        .collect();

    let mut decoy_fp_count = 0usize;
    let mut decoy_fp_violations = Vec::new();

    for decoy_case in &decoy_cases {
        if let Some(result) = run.results.iter().find(|r| r.case_id == decoy_case.case_id) {
            if result.prediction == GroundTruthLabel::TruePositive {
                decoy_fp_count += 1;
                decoy_fp_violations.push(format!(
                    "decoy false positive: case '{}' predicted TruePositive (ground truth: {})",
                    decoy_case.case_id,
                    decoy_case.ground_truth.as_str()
                ));
            }
        }
    }

    if decoy_fp_count > max_decoy_fp {
        violations.push(format!(
            "decoy false positives: {} (max allowed: {})",
            decoy_fp_count, max_decoy_fp
        ));
    }

    let mut recall_drop_violations = Vec::new();
    let baseline_comparison = match (baseline_run, baseline_suite) {
        (Some(br), Some(bs)) => {
            let baseline_metrics = compute_evaluation_metrics(bs, br);
            let comp = compare_runs(br, run, bs, suite);

            let recall_drop = baseline_metrics.recall - metrics.recall;
            if recall_drop > max_recall_drop {
                recall_drop_violations.push(format!(
                    "recall dropped by {:.1}pp (from {:.1}% to {:.1}%, max allowed drop: {:.1}pp)",
                    recall_drop * 100.0,
                    baseline_metrics.recall * 100.0,
                    metrics.recall * 100.0,
                    max_recall_drop * 100.0
                ));
                violations.push(format!("recall dropped by {:.1}pp", recall_drop * 100.0));
            }

            Some(comp)
        }
        _ => None,
    };

    let passed = violations.is_empty();

    let summary = if passed {
        format!("EVAL GATE PASSED — precision {:.1}%, recall {:.1}%, decoy FP {}/{}, no recall regression",
            metrics.precision * 100.0, metrics.recall * 100.0, decoy_fp_count, max_decoy_fp)
    } else {
        format!(
            "EVAL GATE FAILED — {} violation(s): {}",
            violations.len(),
            violations.join("; ")
        )
    };

    EvalGateResult {
        passed,
        current_grade: metrics.grade,
        current_metrics: metrics,
        baseline_comparison,
        threshold_checks: checks,
        decoy_false_positive_count: decoy_fp_count,
        decoy_false_positive_violations: decoy_fp_violations,
        recall_drop_violations,
        summary,
    }
}

pub fn render_eval_gate_result(result: &EvalGateResult) -> String {
    let mut md = String::new();
    md.push_str("# BALONCORE Eval Gate\n\n");
    md.push_str(&format!(
        "**Result:** {}  \n",
        if result.passed { "PASSED" } else { "FAILED" }
    ));
    md.push_str(&format!(
        "**Grade:** {}  \n\n",
        result.current_grade.as_str()
    ));

    md.push_str("## Threshold Checks\n\n");
    md.push_str("| Metric | Status | Value | Threshold |\n");
    md.push_str("|--------|--------|-------|----------|\n");
    for check in &result.threshold_checks {
        let status = if check.passed { "✓" } else { "✗" };
        md.push_str(&format!(
            "| {} | {} | {} |\n",
            check.metric, status, check.comparison
        ));
    }

    md.push_str(&format!(
        "\n## Decoy False Positives: {}\n\n",
        result.decoy_false_positive_count
    ));
    if !result.decoy_false_positive_violations.is_empty() {
        for v in &result.decoy_false_positive_violations {
            md.push_str(&format!("- ✗ {}\n", v));
        }
    } else {
        md.push_str("- No decoy false positives detected\n");
    }

    if !result.recall_drop_violations.is_empty() {
        md.push_str("\n## Recall Drop\n\n");
        for v in &result.recall_drop_violations {
            md.push_str(&format!("- ✗ {}\n", v));
        }
    }

    if let Some(ref comp) = result.baseline_comparison {
        md.push_str(&format!("\n## Baseline Comparison\n\n"));
        md.push_str(&format!("**Baseline:** {}  \n", comp.baseline_run_id));
        md.push_str(&format!("**Current:** {}  \n", comp.current_run_id));
        md.push_str(&format!("**Improved:** {}  \n\n", comp.improved));
        md.push_str("| Metric | Delta |\n");
        md.push_str("|--------|-------|\n");
        md.push_str(&format!(
            "| Precision | {:+.1}% |\n",
            comp.precision_delta * 100.0
        ));
        md.push_str(&format!(
            "| Recall | {:+.1}% |\n",
            comp.recall_delta * 100.0
        ));
        md.push_str(&format!("| F1 | {:+.1}% |\n", comp.f1_delta * 100.0));
        md.push_str(&format!(
            "| Accuracy | {:+.1}% |\n",
            comp.accuracy_delta * 100.0
        ));
        md.push_str(&format!("| Improvements | {} |\n", comp.improvement_count));
        md.push_str(&format!("| Regressions | {} |\n", comp.regression_count));
    }

    md.push_str(&format!("\n---\n\n{}\n", result.summary));
    md
}

pub fn save_eval_gate_result(result: &EvalGateResult, path: &Path) -> Result<(), String> {
    let json = serde_json::to_string_pretty(result).map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, json).map_err(|e| e.to_string())
}

pub fn load_eval_gate_result(path: &Path) -> Result<EvalGateResult, String> {
    let data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&data).map_err(|e| e.to_string())
}

pub fn generate_methodology_doc(suites: &[BenchmarkSuite], runs: &[BenchmarkRun]) -> String {
    let mut md = String::new();
    md.push_str("# BALONCORE Benchmark Methodology\n\n");

    md.push_str("## Overview\n\n");
    md.push_str(
        "BALONCORE evaluates security validation accuracy using deterministic benchmark suites ",
    );
    md.push_str("with hand-labeled ground truth. Every finding has a known ground-truth label, ");
    md.push_str(
        "enabling precise measurement of true positives, false positives, true negatives, ",
    );
    md.push_str("and false negatives.\n\n");

    md.push_str("## Corpus\n\n");
    md.push_str("| Suite ID | Domain | Cases | Version |\n");
    md.push_str("|----------|--------|-------|--------|\n");
    for suite in suites {
        md.push_str(&format!(
            "| `{}` | {} | {} | {} |\n",
            suite.suite_id,
            suite.domain.as_str(),
            suite.cases.len(),
            suite.version
        ));
    }
    md.push_str(&format!(
        "\n**Total: {} benchmark cases across {} domains.**\n\n",
        suites.iter().map(|s| s.cases.len()).sum::<usize>(),
        suites.len()
    ));

    md.push_str("## Headline Numbers\n\n");
    md.push_str("| Domain | Accuracy | Precision | Recall | F1 | Grade |\n");
    md.push_str("|--------|----------|-----------|--------|----|-------|\n");

    let mut total_cases = 0usize;
    let mut total_tp = 0usize;
    let mut total_fp = 0usize;
    let mut total_tn = 0usize;
    let mut total_fn = 0usize;

    for run in runs {
        if let Some(suite) = suites.iter().find(|s| s.suite_id == run.suite_id) {
            let metrics = compute_evaluation_metrics(suite, run);
            md.push_str(&format!(
                "| {} | {:.1}% | {:.1}% | {:.1}% | {:.1}% | {} |\n",
                run.domain.as_str(),
                metrics.accuracy * 100.0,
                metrics.precision * 100.0,
                metrics.recall * 100.0,
                metrics.f1_score * 100.0,
                metrics.grade.as_str()
            ));
            total_cases += metrics.total_cases;
            total_tp += metrics.true_positives;
            total_fp += metrics.false_positives;
            total_tn += metrics.true_negatives;
            total_fn += metrics.false_negatives;
        }
    }

    if total_cases > 0 {
        let overall_accuracy = (total_tp + total_tn) as f64 / total_cases as f64;
        let overall_precision = if (total_tp + total_fp) > 0 {
            total_tp as f64 / (total_tp + total_fp) as f64
        } else {
            0.0
        };
        let overall_recall = if (total_tp + total_fn) > 0 {
            total_tp as f64 / (total_tp + total_fn) as f64
        } else {
            0.0
        };
        let _overall_f1 = if (overall_precision + overall_recall) > 0.0 {
            2.0 * overall_precision * overall_recall / (overall_precision + overall_recall)
        } else {
            0.0
        };
        let overall_grade = EvaluationGrade::from_score(overall_accuracy);
        md.push_str(&format!("\n**Overall: {} ({:.1}% accuracy, {:.1}% precision, {:.1}% recall, fixture provider)**\n",
            overall_grade.as_str(), overall_accuracy * 100.0, overall_precision * 100.0, overall_recall * 100.0));
    }

    md.push_str("\n## Ground Truth Distribution\n\n");
    md.push_str(
        "| Domain | TruePositive | TrueNegative | FalsePositive | FalseNegative | Inconclusive |\n",
    );
    md.push_str(
        "|--------|-------------|-------------|---------------|---------------|-------------|\n",
    );
    for suite in suites {
        let dist = suite.ground_truth_distribution();
        let tp = dist.get("TruePositive").copied().unwrap_or(0);
        let tn = dist.get("TrueNegative").copied().unwrap_or(0);
        let fp = dist.get("FalsePositive").copied().unwrap_or(0);
        let fn_ = dist.get("FalseNegative").copied().unwrap_or(0);
        let inc = dist.get("Inconclusive").copied().unwrap_or(0);
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            suite.domain.as_str(),
            tp,
            tn,
            fp,
            fn_,
            inc
        ));
    }

    md.push_str("\n## Difficulty Distribution\n\n");
    md.push_str("| Domain | Trivial | Basic | Moderate | Advanced | Expert |\n");
    md.push_str("|--------|---------|-------|----------|----------|--------|\n");
    for suite in suites {
        let trivial = suite
            .cases_by_difficulty(&BenchmarkDifficulty::Trivial)
            .len();
        let basic = suite.cases_by_difficulty(&BenchmarkDifficulty::Basic).len();
        let moderate = suite
            .cases_by_difficulty(&BenchmarkDifficulty::Moderate)
            .len();
        let adv = suite
            .cases_by_difficulty(&BenchmarkDifficulty::Advanced)
            .len();
        let expert = suite
            .cases_by_difficulty(&BenchmarkDifficulty::Expert)
            .len();
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            suite.domain.as_str(),
            trivial,
            basic,
            moderate,
            adv,
            expert
        ));
    }

    md.push_str("\n## Determinism\n\n");
    md.push_str(
        "Fixture-provider evaluations produce byte-identical results across repeated runs. ",
    );
    md.push_str(
        "Verify with: `cargo run -p baloncore -- benchmark-determinism --suite <id> --k 3`\n\n",
    );

    md.push_str("## Reproduction\n\n");
    md.push_str("```bash\n");
    md.push_str("# Run all suites with CI gate\n");
    md.push_str("./scripts/run_benchmarks.sh --check-determinism --fail-on-regression\n\n");
    md.push_str("# Single suite\n");
    md.push_str("cargo run -p baloncore -- benchmark-ci --suite baloncore-web-api-v1 --save-golden --json\n\n");
    md.push_str("# Eval gate\n");
    md.push_str("cargo run -p baloncore -- eval-gate --suite baloncore-web-api-v1 --min-precision 0.70 --max-decoy-fp 0\n");
    md.push_str("```\n\n");

    md.push_str("## Limitations\n\n");
    md.push_str(
        "1. **Corpus size**: 24 cases across 4 domains does not cover all vulnerability classes.\n",
    );
    md.push_str("2. **Fixture provider**: Golden baselines use deterministic fixture output. Live model results vary.\n");
    md.push_str("3. **Ground truth subjectivity**: Hand-labeled assessments may differ from other security professionals.\n");
    md.push_str("4. **Local targets only**: Production behavior may differ from lab targets.\n");
    md.push_str(
        "5. **No timing guarantees**: Time-to-proof metrics depend on hardware and load.\n",
    );
    md.push_str("6. **Limited decoy coverage**: Decoys test FP discipline but do not cover all FP scenarios.\n");

    md
}

pub fn generate_benchmark_doc(suites: &[BenchmarkSuite], runs: &[BenchmarkRun]) -> String {
    let mut md = String::new();
    md.push_str("# BALONCORE Benchmark — Diligence Documentation\n\n");

    md.push_str("## Executive Summary\n\n");
    md.push_str(
        "BALONCORE's security validation accuracy is measured against hand-labeled ground truth ",
    );
    md.push_str(
        "with deterministic reproducibility. Every claim is verifiable by a single command.\n\n",
    );

    md.push_str("## Verification\n\n");
    md.push_str("```bash\ngit clone <repo> && cd Baloncore\ncargo build --release -p baloncore\n");
    md.push_str("./scripts/run_benchmarks.sh --check-determinism --fail-on-regression\n```\n\n");

    md.push_str("## Results\n\n");
    md.push_str("| Domain | Accuracy | Precision | Recall | F1 | Grade | Decoy FP |\n");
    md.push_str("|--------|----------|-----------|--------|----|-------|----------|\n");

    let mut all_passed = true;
    for run in runs {
        if let Some(suite) = suites.iter().find(|s| s.suite_id == run.suite_id) {
            let metrics = compute_evaluation_metrics(suite, run);
            let decoy_count = suite
                .cases
                .iter()
                .filter(|c| {
                    c.ground_truth == GroundTruthLabel::FalsePositive
                        || c.tags.contains(&"decoy".to_string())
                })
                .count();
            let decoy_fp = run
                .results
                .iter()
                .filter(|r| {
                    if let Some(case) = suite.case_by_id(&r.case_id) {
                        (case.ground_truth == GroundTruthLabel::FalsePositive
                            || case.tags.contains(&"decoy".to_string()))
                            && r.prediction == GroundTruthLabel::TruePositive
                    } else {
                        false
                    }
                })
                .count();
            md.push_str(&format!(
                "| {} | {:.1}% | {:.1}% | {:.1}% | {:.1}% | {} | {}/{} |\n",
                run.domain.as_str(),
                metrics.accuracy * 100.0,
                metrics.precision * 100.0,
                metrics.recall * 100.0,
                metrics.f1_score * 100.0,
                metrics.grade.as_str(),
                decoy_fp,
                decoy_count
            ));
            if metrics.accuracy < 0.97 {
                all_passed = false;
            }
        }
    }

    md.push_str(&format!(
        "\n**All suites: {}**\n\n",
        if all_passed {
            "PASSED (A+ across all domains)"
        } else {
            "see per-domain results above"
        }
    ));

    md.push_str("## Eval Gate Thresholds\n\n");
    md.push_str("| Threshold | Default | Rationale |\n");
    md.push_str("|-----------|---------|----------|\n");
    md.push_str("| Precision | >= 70% | Less than 70% means >30% false alarms |\n");
    md.push_str("| Decoy FP | = 0 | Any decoy hit reveals over-eager detection |\n");
    md.push_str(
        "| Recall drop | <= 10pp | Code changes should not regress recall significantly |\n\n",
    );

    md.push_str("## Attribution\n\n");
    md.push_str("Every run records provider, model, prompt version, engine version, git commit, and corpus hash.\n\n");

    md.push_str("## Limitations\n\n");
    md.push_str("See `benchmarks/METHODOLOGY.md` for the complete limitations section.\n");

    md
}

pub fn web_api_benchmark_suite() -> BenchmarkSuite {
    BenchmarkSuite {
        suite_id: "baloncore-web-api-v1".to_string(),
        name: "Web/API Authorization Validation Benchmark".to_string(),
        version: "1.0.0".to_string(),
        domain: BenchmarkDomain::WebApi,
        description: "Golden test suite for BOLA, BFLA, missing auth, intended access, and blocked-as-expected validation accuracy.".to_string(),
        cases: vec![
            BenchmarkCase {
                case_id: "webapi-bola-owner-access-own-invoice".to_string(),
                domain: BenchmarkDomain::WebApi,
                name: "Owner accesses own invoice".to_string(),
                description: "User A requests their own invoice — should be classified as intended owner access (negative control).".to_string(),
                target: "/api/invoices/{id}".to_string(),
                ground_truth: GroundTruthLabel::TrueNegative,
                expected_classification: Some("IntendedOwnerAccess".to_string()),
                expected_severity: Some("info".to_string()),
                expected_evidence_keys: vec!["owner_profile_response".to_string(), "status_200".to_string()],
                difficulty: BenchmarkDifficulty::Trivial,
                tags: vec!["bola".to_string(), "negative_control".to_string()],
                fixture_path: None,
                metadata: BTreeMap::new(),
            },
            BenchmarkCase {
                case_id: "webapi-bola-cross-user-invoice".to_string(),
                domain: BenchmarkDomain::WebApi,
                name: "Cross-user invoice access (BOLA)".to_string(),
                description: "User A accesses User B's invoice — should be classified as BOLA with sensitive data exposure.".to_string(),
                target: "/api/invoices/{id}".to_string(),
                ground_truth: GroundTruthLabel::TruePositive,
                expected_classification: Some("BrokenObjectLevelAuthorization".to_string()),
                expected_severity: Some("medium".to_string()),
                expected_evidence_keys: vec!["cross_profile_response".to_string(), "status_200".to_string(), "sensitive_data".to_string()],
                difficulty: BenchmarkDifficulty::Basic,
                tags: vec!["bola".to_string(), "idor".to_string(), "positive_control".to_string()],
                fixture_path: None,
                metadata: BTreeMap::new(),
            },
            BenchmarkCase {
                case_id: "webapi-bfla-non-admin-admin-report".to_string(),
                domain: BenchmarkDomain::WebApi,
                name: "Non-admin accesses admin report (BFLA)".to_string(),
                description: "Regular user accesses admin report endpoint — should be classified as BFLA.".to_string(),
                target: "/api/admin/reports/{id}".to_string(),
                ground_truth: GroundTruthLabel::TruePositive,
                expected_classification: Some("BrokenFunctionLevelAuthorization".to_string()),
                expected_severity: Some("high".to_string()),
                expected_evidence_keys: vec!["function_access_response".to_string(), "status_200".to_string(), "admin_data".to_string()],
                difficulty: BenchmarkDifficulty::Basic,
                tags: vec!["bfla".to_string(), "positive_control".to_string()],
                fixture_path: None,
                metadata: BTreeMap::new(),
            },
            BenchmarkCase {
                case_id: "webapi-missing-auth-anonymous-invoice".to_string(),
                domain: BenchmarkDomain::WebApi,
                name: "Anonymous access to protected invoice".to_string(),
                description: "Unauthenticated request accesses a protected invoice — should be classified as missing authentication.".to_string(),
                target: "/api/invoices/{id}".to_string(),
                ground_truth: GroundTruthLabel::TruePositive,
                expected_classification: Some("MissingAuthentication".to_string()),
                expected_severity: Some("high".to_string()),
                expected_evidence_keys: vec!["anonymous_response".to_string(), "status_200".to_string(), "sensitive_data".to_string()],
                difficulty: BenchmarkDifficulty::Basic,
                tags: vec!["missing_auth".to_string(), "positive_control".to_string()],
                fixture_path: None,
                metadata: BTreeMap::new(),
            },
            BenchmarkCase {
                case_id: "webapi-blocked-cross-user".to_string(),
                domain: BenchmarkDomain::WebApi,
                name: "Properly blocked cross-user access".to_string(),
                description: "System correctly blocks unauthorized access — should be classified as blocked-as-expected.".to_string(),
                target: "/api/invoices/{id}".to_string(),
                ground_truth: GroundTruthLabel::TrueNegative,
                expected_classification: Some("BlockedAsExpected".to_string()),
                expected_severity: Some("info".to_string()),
                expected_evidence_keys: vec!["blocked_response".to_string(), "status_403".to_string()],
                difficulty: BenchmarkDifficulty::Basic,
                tags: vec!["bola".to_string(), "negative_control".to_string()],
                fixture_path: None,
                metadata: BTreeMap::new(),
            },
            BenchmarkCase {
                case_id: "webapi-intended-admin-access".to_string(),
                domain: BenchmarkDomain::WebApi,
                name: "Admin accesses admin resource".to_string(),
                description: "Admin user accesses admin-only resource — should be classified as intended privileged access.".to_string(),
                target: "/api/admin/reports".to_string(),
                ground_truth: GroundTruthLabel::TrueNegative,
                expected_classification: Some("IntendedPrivilegedAccess".to_string()),
                expected_severity: Some("low".to_string()),
                expected_evidence_keys: vec!["admin_profile_response".to_string(), "status_200".to_string()],
                difficulty: BenchmarkDifficulty::Trivial,
                tags: vec!["bfla".to_string(), "negative_control".to_string()],
                fixture_path: None,
                metadata: BTreeMap::new(),
            },
            BenchmarkCase {
                case_id: "webapi-sensitive-data-bola".to_string(),
                domain: BenchmarkDomain::WebApi,
                name: "BOLA with financial data exposure".to_string(),
                description: "Cross-user access exposing financial/sensitive fields — higher severity than basic BOLA.".to_string(),
                target: "/api/invoices/{id}".to_string(),
                ground_truth: GroundTruthLabel::TruePositive,
                expected_classification: Some("BrokenObjectLevelAuthorization".to_string()),
                expected_severity: Some("high".to_string()),
                expected_evidence_keys: vec!["cross_profile_response".to_string(), "financial_data".to_string(), "sensitivity_analysis".to_string()],
                difficulty: BenchmarkDifficulty::Moderate,
                tags: vec!["bola".to_string(), "sensitive_data".to_string(), "severity_escalation".to_string()],
                fixture_path: None,
                metadata: BTreeMap::new(),
            },
            BenchmarkCase {
                case_id: "webapi-fp-beni-resource-mismatch".to_string(),
                domain: BenchmarkDomain::WebApi,
                name: "False positive from resource mismatch".to_string(),
                description: "Unrelated endpoint returns different data — should be classified as resource mismatch, not BOLA.".to_string(),
                target: "/api/public/status".to_string(),
                ground_truth: GroundTruthLabel::TrueNegative,
                expected_classification: Some("IntendedOwnerAccess".to_string()),
                expected_severity: Some("info".to_string()),
                expected_evidence_keys: vec!["response_shape_mismatch".to_string()],
                difficulty: BenchmarkDifficulty::Advanced,
                tags: vec!["false_positive_control".to_string(), "resource_mismatch".to_string()],
                fixture_path: None,
                metadata: BTreeMap::new(),
            },
            BenchmarkCase {
                case_id: "webapi-bola-tenant-isolation".to_string(),
                domain: BenchmarkDomain::WebApi,
                name: "Tenant isolation failure (cross-tenant)".to_string(),
                description: "User from tenant A accesses tenant B's data via BOLA — tenant isolation failure.".to_string(),
                target: "/api/tenants/{id}/data".to_string(),
                ground_truth: GroundTruthLabel::TruePositive,
                expected_classification: Some("BrokenObjectLevelAuthorization".to_string()),
                expected_severity: Some("critical".to_string()),
                expected_evidence_keys: vec!["cross_tenant_response".to_string(), "sensitive_data".to_string(), "tenant_boundary_violation".to_string()],
                difficulty: BenchmarkDifficulty::Advanced,
                tags: vec!["bola".to_string(), "tenant_isolation".to_string(), "severity_escalation".to_string()],
                fixture_path: None,
                metadata: BTreeMap::new(),
            },
            BenchmarkCase {
                case_id: "webapi-owner-baseline-failure".to_string(),
                domain: BenchmarkDomain::WebApi,
                name: "Owner baseline failure (unreliable baseline)".to_string(),
                description: "Owner auth profile fails to access own resource — indicates a testing issue, not a vulnerability.".to_string(),
                target: "/api/invoices/{id}".to_string(),
                ground_truth: GroundTruthLabel::Inconclusive,
                expected_classification: Some("OwnerBaselineFailed".to_string()),
                expected_severity: Some("info".to_string()),
                expected_evidence_keys: vec!["owner_failure_response".to_string()],
                difficulty: BenchmarkDifficulty::Expert,
                tags: vec!["baseline_failure".to_string(), "edge_case".to_string()],
                fixture_path: None,
                metadata: BTreeMap::new(),
            },
        ],
        metadata: BTreeMap::new(),
    }
}

pub fn cloud_iam_benchmark_suite() -> BenchmarkSuite {
    BenchmarkSuite {
        suite_id: "baloncore-cloud-iam-v1".to_string(),
        name: "Cloud IAM Attack Path Benchmark".to_string(),
        version: "1.0.0".to_string(),
        domain: BenchmarkDomain::CloudIam,
        description: "Golden test suite for IAM privilege path detection, least-privilege violations, and public exposure.".to_string(),
        cases: vec![
            BenchmarkCase {
                case_id: "cloud-admin-wildcard-policy".to_string(),
                domain: BenchmarkDomain::CloudIam,
                name: "Admin wildcard policy detection".to_string(),
                description: "IAM policy grants Action:* on Resource:* — should be flagged as over-permissive.".to_string(),
                target: "aws:iam:policy/admin-policy".to_string(),
                ground_truth: GroundTruthLabel::TruePositive,
                expected_classification: Some("over_permissive_iam".to_string()),
                expected_severity: Some("high".to_string()),
                expected_evidence_keys: vec!["wildcard_action".to_string(), "wildcard_resource".to_string()],
                difficulty: BenchmarkDifficulty::Basic,
                tags: vec!["aws".to_string(), "iam".to_string(), "least_privilege".to_string()],
                fixture_path: Some("labs/cloud-iam/aws-risky.json".to_string()),
                metadata: BTreeMap::new(),
            },
            BenchmarkCase {
                case_id: "cloud-github-oidc-trust".to_string(),
                domain: BenchmarkDomain::CloudIam,
                name: "GitHub Actions OIDC trust detection".to_string(),
                description: "IAM role trusts external GitHub Actions OIDC — should be flagged as cross-boundary trust.".to_string(),
                target: "aws:iam:role/deploy-role".to_string(),
                ground_truth: GroundTruthLabel::TruePositive,
                expected_classification: Some("cross_boundary_trust".to_string()),
                expected_severity: Some("medium".to_string()),
                expected_evidence_keys: vec!["oidc_trust".to_string(), "external_principal".to_string()],
                difficulty: BenchmarkDifficulty::Moderate,
                tags: vec!["aws".to_string(), "ci_cd".to_string(), "oidc".to_string()],
                fixture_path: Some("labs/cloud-iam/aws-risky.json".to_string()),
                metadata: BTreeMap::new(),
            },
            BenchmarkCase {
                case_id: "cloud-s3-public-access".to_string(),
                domain: BenchmarkDomain::CloudIam,
                name: "S3 public bucket policy".to_string(),
                description: "S3 bucket policy allows public access — should be flagged as public exposure.".to_string(),
                target: "aws:s3:bucket/data-bucket".to_string(),
                ground_truth: GroundTruthLabel::TruePositive,
                expected_classification: Some("public_exposure".to_string()),
                expected_severity: Some("high".to_string()),
                expected_evidence_keys: vec!["public_policy".to_string(), "s3_public_access".to_string()],
                difficulty: BenchmarkDifficulty::Basic,
                tags: vec!["aws".to_string(), "s3".to_string(), "public_exposure".to_string()],
                fixture_path: Some("labs/cloud-iam/aws-risky.json".to_string()),
                metadata: BTreeMap::new(),
            },
            BenchmarkCase {
                case_id: "cloud-privilege-escalation-path".to_string(),
                domain: BenchmarkDomain::CloudIam,
                name: "IAM privilege escalation path".to_string(),
                description: "Deploy role can assume admin role — should detect complete privilege escalation chain.".to_string(),
                target: "aws:iam:role/deploy-role".to_string(),
                ground_truth: GroundTruthLabel::TruePositive,
                expected_classification: Some("privilege_escalation".to_string()),
                expected_severity: Some("critical".to_string()),
                expected_evidence_keys: vec!["assume_role_chain".to_string(), "escalation_path".to_string()],
                difficulty: BenchmarkDifficulty::Advanced,
                tags: vec!["aws".to_string(), "privilege_escalation".to_string(), "attack_path".to_string()],
                fixture_path: Some("labs/cloud-iam/aws-risky.json".to_string()),
                metadata: BTreeMap::new(),
            },
            BenchmarkCase {
                case_id: "cloud-least-privilege-compliant".to_string(),
                domain: BenchmarkDomain::CloudIam,
                name: "Compliant least-privilege policy".to_string(),
                description: "IAM policy grants specific actions on specific resources — should be classified as compliant.".to_string(),
                target: "aws:iam:policy/read-only-policy".to_string(),
                ground_truth: GroundTruthLabel::TrueNegative,
                expected_classification: Some("compliant_iam".to_string()),
                expected_severity: Some("info".to_string()),
                expected_evidence_keys: vec!["specific_actions".to_string(), "specific_resources".to_string()],
                difficulty: BenchmarkDifficulty::Basic,
                tags: vec!["aws".to_string(), "iam".to_string(), "negative_control".to_string()],
                fixture_path: None,
                metadata: BTreeMap::new(),
            },
        ],
        metadata: BTreeMap::new(),
    }
}

pub fn web3_benchmark_suite() -> BenchmarkSuite {
    BenchmarkSuite {
        suite_id: "baloncore-web3-v1".to_string(),
        name: "Web3 Smart Contract Benchmark".to_string(),
        version: "1.0.0".to_string(),
        domain: BenchmarkDomain::Web3,
        description: "Golden test suite for Solidity vulnerability detection, invariant generation, and exploit proof validation.".to_string(),
        cases: vec![
            BenchmarkCase {
                case_id: "web3-reentrancy-deposit".to_string(),
                domain: BenchmarkDomain::Web3,
                name: "Reentrancy in deposit()".to_string(),
                description: "deposit() updates state after external call — classic reentrancy pattern.".to_string(),
                target: "VulnerableVault.deposit()".to_string(),
                ground_truth: GroundTruthLabel::TruePositive,
                expected_classification: Some("reentrancy".to_string()),
                expected_severity: Some("high".to_string()),
                expected_evidence_keys: vec!["state_after_effect".to_string(), "external_call_before_update".to_string()],
                difficulty: BenchmarkDifficulty::Basic,
                tags: vec!["reentrancy".to_string(), "solidity".to_string(), "defi".to_string()],
                fixture_path: Some("labs/vulnerable-protocol/src/VulnerableVault.sol".to_string()),
                metadata: BTreeMap::new(),
            },
            BenchmarkCase {
                case_id: "web3-reentrancy-withdraw".to_string(),
                domain: BenchmarkDomain::Web3,
                name: "Reentrancy in withdraw()".to_string(),
                description: "withdraw() makes external call before state update — reentrancy enables fund drainage.".to_string(),
                target: "VulnerableVault.withdraw()".to_string(),
                ground_truth: GroundTruthLabel::TruePositive,
                expected_classification: Some("reentrancy".to_string()),
                expected_severity: Some("critical".to_string()),
                expected_evidence_keys: vec!["external_call_before_update".to_string(), "fund_drainage".to_string()],
                difficulty: BenchmarkDifficulty::Basic,
                tags: vec!["reentrancy".to_string(), "solidity".to_string(), "defi".to_string()],
                fixture_path: Some("labs/vulnerable-protocol/src/VulnerableVault.sol".to_string()),
                metadata: BTreeMap::new(),
            },
            BenchmarkCase {
                case_id: "web3-missing-access-control".to_string(),
                domain: BenchmarkDomain::Web3,
                name: "Missing access control on setBalance()".to_string(),
                description: "setBalance() has no onlyOwner/modifier — anyone can set arbitrary balances.".to_string(),
                target: "VulnerableVault.setBalance()".to_string(),
                ground_truth: GroundTruthLabel::TruePositive,
                expected_classification: Some("access_control".to_string()),
                expected_severity: Some("critical".to_string()),
                expected_evidence_keys: vec!["no_modifier".to_string(), "arbitrary_state_change".to_string()],
                difficulty: BenchmarkDifficulty::Basic,
                tags: vec!["access_control".to_string(), "solidity".to_string()],
                fixture_path: Some("labs/vulnerable-protocol/src/VulnerableVault.sol".to_string()),
                metadata: BTreeMap::new(),
            },
            BenchmarkCase {
                case_id: "web3-rounding-error".to_string(),
                domain: BenchmarkDomain::Web3,
                name: "Rounding error via donate()".to_string(),
                description: "donate() inflates totalAssets without updating shares, causing accounting desync.".to_string(),
                target: "VulnerableVault.donate()".to_string(),
                ground_truth: GroundTruthLabel::TruePositive,
                expected_classification: Some("rounding_error".to_string()),
                expected_severity: Some("medium".to_string()),
                expected_evidence_keys: vec!["share_accounting_desync".to_string(), "inflated_total_assets".to_string()],
                difficulty: BenchmarkDifficulty::Advanced,
                tags: vec!["rounding_error".to_string(), "defi".to_string(), "accounting".to_string()],
                fixture_path: Some("labs/vulnerable-protocol/src/VulnerableVault.sol".to_string()),
                metadata: BTreeMap::new(),
            },
            BenchmarkCase {
                case_id: "web3-safe-function".to_string(),
                domain: BenchmarkDomain::Web3,
                name: "Safe function with proper checks".to_string(),
                description: "Function with proper access control, checks-effects-interactions pattern — negative control.".to_string(),
                target: "SafeContract.deposit()".to_string(),
                ground_truth: GroundTruthLabel::TrueNegative,
                expected_classification: Some("safe".to_string()),
                expected_severity: Some("info".to_string()),
                expected_evidence_keys: vec!["proper_access_control".to_string(), "checks_effects_interactions".to_string()],
                difficulty: BenchmarkDifficulty::Moderate,
                tags: vec!["negative_control".to_string(), "solidity".to_string()],
                fixture_path: None,
                metadata: BTreeMap::new(),
            },
        ],
        metadata: BTreeMap::new(),
    }
}

pub fn evidence_lifecycle_benchmark_suite() -> BenchmarkSuite {
    BenchmarkSuite {
        suite_id: "baloncore-evidence-v1".to_string(),
        name: "Evidence Lifecycle Benchmark".to_string(),
        version: "1.0.0".to_string(),
        domain: BenchmarkDomain::Evidence,
        description: "Golden test suite for evidence integrity, signing, sealing, and lifecycle transitions.".to_string(),
        cases: vec![
            BenchmarkCase {
                case_id: "evidence-seal-verify".to_string(),
                domain: BenchmarkDomain::Evidence,
                name: "Seal and verify evidence manifest".to_string(),
                description: "Seal an evidence directory, then verify — should pass integrity check.".to_string(),
                target: "evidence_manifest.json".to_string(),
                ground_truth: GroundTruthLabel::TrueNegative,
                expected_classification: Some("integrity_pass".to_string()),
                expected_severity: None,
                expected_evidence_keys: vec!["sha256_hashes".to_string(), "file_list".to_string()],
                difficulty: BenchmarkDifficulty::Trivial,
                tags: vec!["evidence".to_string(), "integrity".to_string()],
                fixture_path: None,
                metadata: BTreeMap::new(),
            },
            BenchmarkCase {
                case_id: "evidence-tamper-detection".to_string(),
                domain: BenchmarkDomain::Evidence,
                name: "Detect tampered evidence".to_string(),
                description: "Modify an evidence file after sealing — verification should fail.".to_string(),
                target: "evidence_manifest.json".to_string(),
                ground_truth: GroundTruthLabel::TruePositive,
                expected_classification: Some("tampered".to_string()),
                expected_severity: Some("critical".to_string()),
                expected_evidence_keys: vec!["hash_mismatch".to_string(), "tampered_file".to_string()],
                difficulty: BenchmarkDifficulty::Basic,
                tags: vec!["evidence".to_string(), "integrity".to_string(), "tamper_detection".to_string()],
                fixture_path: None,
                metadata: BTreeMap::new(),
            },
            BenchmarkCase {
                case_id: "evidence-lifecycle-transition".to_string(),
                domain: BenchmarkDomain::Evidence,
                name: "Finding lifecycle transitions".to_string(),
                description: "Transition finding through Hypothesis→Verified→Reported→Fixed→Retested→Closed — all valid.".to_string(),
                target: "finding_lifecycle".to_string(),
                ground_truth: GroundTruthLabel::TrueNegative,
                expected_classification: Some("lifecycle_valid".to_string()),
                expected_severity: None,
                expected_evidence_keys: vec!["transition_records".to_string(), "state_sequence".to_string()],
                difficulty: BenchmarkDifficulty::Basic,
                tags: vec!["evidence".to_string(), "lifecycle".to_string()],
                fixture_path: None,
                metadata: BTreeMap::new(),
            },
            BenchmarkCase {
                case_id: "evidence-signature-trust".to_string(),
                domain: BenchmarkDomain::Evidence,
                name: "Trusted signer verification".to_string(),
                description: "Sign evidence with trusted key, verify with --trusted-only — should pass.".to_string(),
                target: "evidence_signature.json".to_string(),
                ground_truth: GroundTruthLabel::TrueNegative,
                expected_classification: Some("signature_valid".to_string()),
                expected_severity: None,
                expected_evidence_keys: vec!["ed25519_signature".to_string(), "trusted_signer".to_string()],
                difficulty: BenchmarkDifficulty::Moderate,
                tags: vec!["evidence".to_string(), "signing".to_string(), "trust".to_string()],
                fixture_path: None,
                metadata: BTreeMap::new(),
            },
        ],
        metadata: BTreeMap::new(),
    }
}

pub fn all_benchmark_suites() -> Vec<BenchmarkSuite> {
    vec![
        web_api_benchmark_suite(),
        cloud_iam_benchmark_suite(),
        web3_benchmark_suite(),
        evidence_lifecycle_benchmark_suite(),
    ]
}

pub fn benchmark_suite_by_id(suite_id: &str) -> Option<BenchmarkSuite> {
    all_benchmark_suites()
        .into_iter()
        .find(|s| s.suite_id == suite_id)
}

pub fn save_benchmark_suite(suite: &BenchmarkSuite, path: &Path) -> Result<(), String> {
    let json = serde_json::to_string_pretty(suite).map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, json).map_err(|e| e.to_string())
}

pub fn load_benchmark_suite(path: &Path) -> Result<BenchmarkSuite, String> {
    let data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&data).map_err(|e| e.to_string())
}

pub fn save_benchmark_run(run: &BenchmarkRun, path: &Path) -> Result<(), String> {
    let json = serde_json::to_string_pretty(run).map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, json).map_err(|e| e.to_string())
}

pub fn load_benchmark_run(path: &Path) -> Result<BenchmarkRun, String> {
    let data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&data).map_err(|e| e.to_string())
}

pub fn save_scorecard(scorecard: &EvaluationScorecard, path: &Path) -> Result<(), String> {
    let json = serde_json::to_string_pretty(scorecard).map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, json).map_err(|e| e.to_string())
}

pub fn load_scorecard(path: &Path) -> Result<EvaluationScorecard, String> {
    let data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&data).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_api_suite_has_expected_cases() {
        let suite = web_api_benchmark_suite();
        assert_eq!(suite.domain, BenchmarkDomain::WebApi);
        assert!(!suite.cases.is_empty());
        assert!(suite
            .cases
            .iter()
            .any(|c| c.case_id == "webapi-bola-cross-user-invoice"));
        assert!(suite
            .cases
            .iter()
            .any(|c| c.case_id == "webapi-bfla-non-admin-admin-report"));
        assert!(suite
            .cases
            .iter()
            .any(|c| c.case_id == "webapi-missing-auth-anonymous-invoice"));
    }

    #[test]
    fn cloud_iam_suite_has_expected_cases() {
        let suite = cloud_iam_benchmark_suite();
        assert_eq!(suite.domain, BenchmarkDomain::CloudIam);
        assert!(suite
            .cases
            .iter()
            .any(|c| c.case_id == "cloud-admin-wildcard-policy"));
        assert!(suite
            .cases
            .iter()
            .any(|c| c.ground_truth == GroundTruthLabel::TruePositive));
    }

    #[test]
    fn web3_suite_has_expected_cases() {
        let suite = web3_benchmark_suite();
        assert_eq!(suite.domain, BenchmarkDomain::Web3);
        assert!(suite
            .cases
            .iter()
            .any(|c| c.case_id == "web3-reentrancy-withdraw"));
        assert!(suite
            .cases
            .iter()
            .any(|c| c.ground_truth == GroundTruthLabel::TrueNegative));
    }

    #[test]
    fn evidence_suite_has_expected_cases() {
        let suite = evidence_lifecycle_benchmark_suite();
        assert_eq!(suite.domain, BenchmarkDomain::Evidence);
        assert!(suite
            .cases
            .iter()
            .any(|c| c.case_id == "evidence-tamper-detection"));
    }

    #[test]
    fn ground_truth_distribution_counts_cases() {
        let suite = web_api_benchmark_suite();
        let dist = suite.ground_truth_distribution();
        assert!(dist.contains_key("true_positive"));
        assert!(dist.contains_key("true_negative"));
        assert!(dist["true_positive"] >= 3);
    }

    #[test]
    fn difficulty_weight_increases() {
        assert!(BenchmarkDifficulty::Trivial.weight() < BenchmarkDifficulty::Basic.weight());
        assert!(BenchmarkDifficulty::Basic.weight() < BenchmarkDifficulty::Moderate.weight());
        assert!(BenchmarkDifficulty::Moderate.weight() < BenchmarkDifficulty::Advanced.weight());
        assert!(BenchmarkDifficulty::Advanced.weight() < BenchmarkDifficulty::Expert.weight());
    }

    #[test]
    fn compute_metrics_on_perfect_run() {
        let suite = web_api_benchmark_suite();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let results: Vec<BenchmarkResult> = suite
            .cases
            .iter()
            .map(|case| BenchmarkResult {
                result_id: format!("result_{}", case.case_id),
                suite_id: suite.suite_id.clone(),
                case_id: case.case_id.clone(),
                domain: case.domain.clone(),
                actual_classification: case.expected_classification.clone(),
                actual_severity: case.expected_severity.clone(),
                actual_state: Some("verified".to_string()),
                prediction: case.ground_truth.clone(),
                confidence: 1.0,
                evidence_found: case.expected_evidence_keys.clone(),
                time_to_result_ms: 100,
                error: None,
            })
            .collect();

        let run = BenchmarkRun {
            run_id: "test-perfect-run".to_string(),
            suite_id: suite.suite_id.clone(),
            suite_version: suite.version.clone(),
            domain: suite.domain.clone(),
            started_at: now,
            completed_at: now + 1000,
            config_snapshot: BenchmarkConfig::default(),
            results,
        };

        let metrics = compute_evaluation_metrics(&suite, &run);
        assert_eq!(metrics.true_positives, 5);
        assert_eq!(metrics.true_negatives, 4);
        assert_eq!(metrics.false_positives, 0);
        assert_eq!(metrics.false_negatives, 0);
        assert!((metrics.precision - 1.0).abs() < 0.001);
        assert!((metrics.recall - 1.0).abs() < 0.001);
        assert!((metrics.f1_score - 1.0).abs() < 0.001);
        assert!((metrics.accuracy - 1.0).abs() < 0.001);
        assert_eq!(metrics.grade, EvaluationGrade::APlus);
    }

    #[test]
    fn compute_metrics_with_false_positives() {
        let suite = web_api_benchmark_suite();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let results: Vec<BenchmarkResult> = suite
            .cases
            .iter()
            .map(|case| {
                let prediction = if matches!(case.ground_truth, GroundTruthLabel::TrueNegative) {
                    GroundTruthLabel::TruePositive
                } else {
                    case.ground_truth.clone()
                };
                BenchmarkResult {
                    result_id: format!("result_{}", case.case_id),
                    suite_id: suite.suite_id.clone(),
                    case_id: case.case_id.clone(),
                    domain: case.domain.clone(),
                    actual_classification: case.expected_classification.clone(),
                    actual_severity: case.expected_severity.clone(),
                    actual_state: Some("verified".to_string()),
                    prediction,
                    confidence: 0.9,
                    evidence_found: case.expected_evidence_keys.clone(),
                    time_to_result_ms: 100,
                    error: None,
                }
            })
            .collect();

        let run = BenchmarkRun {
            run_id: "test-fp-run".to_string(),
            suite_id: suite.suite_id.clone(),
            suite_version: suite.version.clone(),
            domain: suite.domain.clone(),
            started_at: now,
            completed_at: now + 1000,
            config_snapshot: BenchmarkConfig::default(),
            results,
        };

        let metrics = compute_evaluation_metrics(&suite, &run);
        assert!(metrics.false_positives > 0);
        assert!(metrics.precision < 1.0);
        assert!(metrics.false_positive_rate > 0.0);
    }

    #[test]
    fn difficulty_breakdown_points() {
        let suite = web_api_benchmark_suite();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let results: Vec<BenchmarkResult> = suite
            .cases
            .iter()
            .map(|case| BenchmarkResult {
                result_id: format!("result_{}", case.case_id),
                suite_id: suite.suite_id.clone(),
                case_id: case.case_id.clone(),
                domain: case.domain.clone(),
                actual_classification: case.expected_classification.clone(),
                actual_severity: case.expected_severity.clone(),
                actual_state: Some("verified".to_string()),
                prediction: case.ground_truth.clone(),
                confidence: 1.0,
                evidence_found: case.expected_evidence_keys.clone(),
                time_to_result_ms: 150,
                error: None,
            })
            .collect();

        let run = BenchmarkRun {
            run_id: "test-diff-run".to_string(),
            suite_id: suite.suite_id.clone(),
            suite_version: suite.version.clone(),
            domain: suite.domain.clone(),
            started_at: now,
            completed_at: now + 1000,
            config_snapshot: BenchmarkConfig::default(),
            results,
        };

        let breakdown = compute_difficulty_breakdown(&suite, &run);
        assert!(breakdown.contains_key("trivial"));
        assert!(breakdown.contains_key("basic"));
        assert!(breakdown.contains_key("advanced"));
    }

    #[test]
    fn comparison_detects_improvement_and_regression() {
        let suite = web_api_benchmark_suite();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let baseline_results: Vec<BenchmarkResult> = suite
            .cases
            .iter()
            .map(|case| BenchmarkResult {
                result_id: format!("b_{}", case.case_id),
                suite_id: suite.suite_id.clone(),
                case_id: case.case_id.clone(),
                domain: case.domain.clone(),
                actual_classification: None,
                actual_severity: None,
                actual_state: Some("hypothesis".to_string()),
                prediction: GroundTruthLabel::Inconclusive,
                confidence: 0.5,
                evidence_found: vec![],
                time_to_result_ms: 500,
                error: None,
            })
            .collect();

        let improved_results: Vec<BenchmarkResult> = suite
            .cases
            .iter()
            .map(|case| BenchmarkResult {
                result_id: format!("i_{}", case.case_id),
                suite_id: suite.suite_id.clone(),
                case_id: case.case_id.clone(),
                domain: case.domain.clone(),
                actual_classification: case.expected_classification.clone(),
                actual_severity: case.expected_severity.clone(),
                actual_state: Some("verified".to_string()),
                prediction: case.ground_truth.clone(),
                confidence: 1.0,
                evidence_found: case.expected_evidence_keys.clone(),
                time_to_result_ms: 100,
                error: None,
            })
            .collect();

        let baseline_run = BenchmarkRun {
            run_id: "baseline".to_string(),
            suite_id: suite.suite_id.clone(),
            suite_version: suite.version.clone(),
            domain: suite.domain.clone(),
            started_at: now,
            completed_at: now + 5000,
            config_snapshot: BenchmarkConfig::default(),
            results: baseline_results,
        };

        let improved_run = BenchmarkRun {
            run_id: "improved".to_string(),
            suite_id: suite.suite_id.clone(),
            suite_version: suite.version.clone(),
            domain: suite.domain.clone(),
            started_at: now + 5000,
            completed_at: now + 6000,
            config_snapshot: BenchmarkConfig::default(),
            results: improved_results,
        };

        let comparison = compare_runs(&baseline_run, &improved_run, &suite, &suite);
        assert!(comparison.improved);
        assert!(comparison.improvement_count > 0);
        assert!(comparison.precision_delta > 0.0);
        assert!(comparison.recall_delta > 0.0);
    }

    #[test]
    fn grade_from_score() {
        assert_eq!(EvaluationGrade::from_score(0.99), EvaluationGrade::APlus);
        assert_eq!(EvaluationGrade::from_score(0.92), EvaluationGrade::A);
        assert_eq!(EvaluationGrade::from_score(0.85), EvaluationGrade::B);
        assert_eq!(EvaluationGrade::from_score(0.75), EvaluationGrade::C);
        assert_eq!(EvaluationGrade::from_score(0.65), EvaluationGrade::D);
        assert_eq!(EvaluationGrade::from_score(0.40), EvaluationGrade::F);
    }

    #[test]
    fn render_scorecard_produces_markdown() {
        let suite = web_api_benchmark_suite();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let results: Vec<BenchmarkResult> = suite
            .cases
            .iter()
            .map(|case| BenchmarkResult {
                result_id: format!("result_{}", case.case_id),
                suite_id: suite.suite_id.clone(),
                case_id: case.case_id.clone(),
                domain: case.domain.clone(),
                actual_classification: case.expected_classification.clone(),
                actual_severity: case.expected_severity.clone(),
                actual_state: Some("verified".to_string()),
                prediction: case.ground_truth.clone(),
                confidence: 1.0,
                evidence_found: case.expected_evidence_keys.clone(),
                time_to_result_ms: 100,
                error: None,
            })
            .collect();

        let run = BenchmarkRun {
            run_id: "render-test".to_string(),
            suite_id: suite.suite_id.clone(),
            suite_version: suite.version.clone(),
            domain: suite.domain.clone(),
            started_at: now,
            completed_at: now + 1000,
            config_snapshot: BenchmarkConfig::default(),
            results,
        };

        let scorecard = generate_scorecard(&suite, &run, None, None);
        let md = render_scorecard(&scorecard);
        assert!(md.contains("# BALONCORE Evaluation Scorecard"));
        assert!(md.contains("## Summary Metrics"));
        assert!(md.contains("Precision"));
        assert!(md.contains("Recall"));
        assert!(md.contains("F1 Score"));
    }

    #[test]
    fn recommendations_fire_on_low_metrics() {
        let metrics = EvaluationMetrics {
            total_cases: 10,
            true_positives: 3,
            false_positives: 4,
            true_negatives: 2,
            false_negatives: 1,
            inconclusive: 0,
            precision: 0.43,
            recall: 0.75,
            f1_score: 0.55,
            accuracy: 0.50,
            false_positive_rate: 0.67,
            false_negative_rate: 0.25,
            mean_time_to_proof_ms: 45000.0,
            median_time_to_proof_ms: 40000.0,
            difficulty_weighted_accuracy: 0.45,
            classification_accuracy: 0.70,
            severity_accuracy: 0.60,
            evidence_coverage: 0.50,
            grade: EvaluationGrade::F,
        };

        let recs = generate_recommendations(&metrics);
        assert!(
            recs.iter().any(|r| r.contains("Precision")),
            "Expected precision recommendation"
        );
        assert!(
            recs.iter().any(|r| r.contains("False positive rate")),
            "Expected FPR recommendation"
        );
        assert!(
            recs.iter().any(|r| r.contains("time to proof")),
            "Expected time recommendation"
        );
        assert!(
            recs.iter().any(|r| r.contains("Evidence coverage")),
            "Expected evidence recommendation"
        );
    }

    #[test]
    fn save_and_load_suite_roundtrip() {
        let suite = web_api_benchmark_suite();
        let dir = std::env::temp_dir().join("baloncore-eval-test-suite");
        let path = dir.join("test_suite.json");
        save_benchmark_suite(&suite, &path).unwrap();
        let loaded = load_benchmark_suite(&path).unwrap();
        assert_eq!(loaded.suite_id, suite.suite_id);
        assert_eq!(loaded.cases.len(), suite.cases.len());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_and_load_run_roundtrip() {
        let suite = web_api_benchmark_suite();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let run = BenchmarkRun {
            run_id: "roundtrip-test".to_string(),
            suite_id: suite.suite_id.clone(),
            suite_version: suite.version.clone(),
            domain: suite.domain.clone(),
            started_at: now,
            completed_at: now + 1000,
            config_snapshot: BenchmarkConfig::default(),
            results: vec![BenchmarkResult {
                result_id: "r1".to_string(),
                suite_id: suite.suite_id.clone(),
                case_id: "webapi-bola-cross-user-invoice".to_string(),
                domain: BenchmarkDomain::WebApi,
                actual_classification: Some("BrokenObjectLevelAuthorization".to_string()),
                actual_severity: Some("medium".to_string()),
                actual_state: Some("verified".to_string()),
                prediction: GroundTruthLabel::TruePositive,
                confidence: 0.95,
                evidence_found: vec!["cross_profile_response".to_string()],
                time_to_result_ms: 150,
                error: None,
            }],
        };

        let dir = std::env::temp_dir().join("baloncore-eval-test-run");
        let path = dir.join("test_run.json");
        save_benchmark_run(&run, &path).unwrap();
        let loaded = load_benchmark_run(&path).unwrap();
        assert_eq!(loaded.run_id, run.run_id);
        assert_eq!(loaded.results.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn all_suites_are_valid() {
        let all = all_benchmark_suites();
        assert_eq!(all.len(), 4);
        for suite in &all {
            assert!(!suite.suite_id.is_empty());
            assert!(!suite.name.is_empty());
            assert!(!suite.cases.is_empty());
            for case in &suite.cases {
                assert!(!case.case_id.is_empty());
                assert!(!case.name.is_empty());
                assert!(!case.target.is_empty());
            }
        }
    }

    #[test]
    fn benchmark_suite_by_id_finds_known_suite() {
        let suite = benchmark_suite_by_id("baloncore-web-api-v1");
        assert!(suite.is_some());
        let suite = benchmark_suite_by_id("baloncore-cloud-iam-v1");
        assert!(suite.is_some());
        let suite = benchmark_suite_by_id("baloncore-web3-v1");
        assert!(suite.is_some());
        let suite = benchmark_suite_by_id("baloncore-evidence-v1");
        assert!(suite.is_some());
        let missing = benchmark_suite_by_id("nonexistent");
        assert!(missing.is_none());
    }

    #[test]
    fn tag_breakdown_computes_per_tag_accuracy() {
        let suite = web_api_benchmark_suite();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let results: Vec<BenchmarkResult> = suite
            .cases
            .iter()
            .map(|case| BenchmarkResult {
                result_id: format!("result_{}", case.case_id),
                suite_id: suite.suite_id.clone(),
                case_id: case.case_id.clone(),
                domain: case.domain.clone(),
                actual_classification: case.expected_classification.clone(),
                actual_severity: case.expected_severity.clone(),
                actual_state: Some("verified".to_string()),
                prediction: case.ground_truth.clone(),
                confidence: 1.0,
                evidence_found: case.expected_evidence_keys.clone(),
                time_to_result_ms: 100,
                error: None,
            })
            .collect();

        let run = BenchmarkRun {
            run_id: "tag-test".to_string(),
            suite_id: suite.suite_id.clone(),
            suite_version: suite.version.clone(),
            domain: suite.domain.clone(),
            started_at: now,
            completed_at: now + 1000,
            config_snapshot: BenchmarkConfig::default(),
            results,
        };

        let breakdown = compute_tag_breakdown(&suite, &run);
        assert!(breakdown.contains_key("bola"));
        assert!(breakdown.contains_key("positive_control"));
        assert!(breakdown["bola"].accuracy > 0.0);
    }
}

fn endpoints_match(pattern: &str, concrete: &str) -> bool {
    if pattern == concrete {
        return true;
    }
    let pattern_parts: Vec<&str> = pattern.split('/').collect();
    let concrete_parts: Vec<&str> = concrete.split('/').collect();
    if pattern_parts.len() != concrete_parts.len() {
        if pattern_parts.len() > concrete_parts.len() {
            let prefix: Vec<&str> = pattern_parts[..concrete_parts.len()].to_vec();
            let mut matches = true;
            for (p, c) in prefix.iter().zip(concrete_parts.iter()) {
                if p.starts_with('{') && p.ends_with('}') {
                    continue;
                }
                if p != c {
                    matches = false;
                    break;
                }
            }
            if matches {
                return true;
            }
        }
        return false;
    }
    for (p, c) in pattern_parts.iter().zip(concrete_parts.iter()) {
        if p.starts_with('{') && p.ends_with('}') {
            continue;
        }
        if p != c {
            return false;
        }
    }
    true
}

pub fn evaluate_web_api_run(
    suite: &BenchmarkSuite,
    validations: &[(String, String, String, Vec<String>)],
    timing_ms: &[(String, u64)],
) -> Vec<BenchmarkResult> {
    let timing_map: std::collections::HashMap<String, u64> =
        timing_ms.iter().map(|(k, v)| (k.clone(), *v)).collect();

    let _now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    suite
        .cases
        .iter()
        .filter(|c| c.domain == BenchmarkDomain::WebApi)
        .map(|case| {
            let best_match: Option<&(String, String, String, Vec<String>)> = validations
                .iter()
                .filter(|(endpoint, _profile, _classification, _evidence)| {
                    endpoints_match(&case.target, endpoint)
                })
                .max_by_key(|(_endpoint, _profile, classification, _evidence)| {
                    let class_lower = classification.to_ascii_lowercase();
                    let case_expected = case.expected_classification.as_deref().unwrap_or("");
                    let case_lower = case_expected.to_ascii_lowercase();
                    if class_lower.contains(&case_lower) || case_lower.contains(&class_lower) {
                        2
                    } else {
                        1
                    }
                });

            let (prediction, actual_classification, actual_severity, evidence_found, time_ms) =
                if let Some((_endpoint, _profile, classification, evidence)) = best_match {
                    let class_lower = classification.to_ascii_lowercase();
                    let pred = match case.ground_truth {
                        GroundTruthLabel::TruePositive => {
                            if class_lower.contains("bola")
                                || class_lower.contains("bfla")
                                || class_lower.contains("missing")
                                || class_lower.contains("reentrancy")
                                || class_lower.contains("access_control")
                            {
                                GroundTruthLabel::TruePositive
                            } else if class_lower.contains("blocked")
                                || class_lower.contains("intended")
                            {
                                GroundTruthLabel::TrueNegative
                            } else {
                                GroundTruthLabel::Inconclusive
                            }
                        }
                        GroundTruthLabel::TrueNegative => {
                            if class_lower.contains("blocked") || class_lower.contains("intended") {
                                GroundTruthLabel::TrueNegative
                            } else if class_lower.contains("bola")
                                || class_lower.contains("bfla")
                                || class_lower.contains("missing")
                            {
                                GroundTruthLabel::FalsePositive
                            } else {
                                GroundTruthLabel::Inconclusive
                            }
                        }
                        GroundTruthLabel::Inconclusive => GroundTruthLabel::Inconclusive,
                        _ => case.ground_truth.clone(),
                    };
                    let time = timing_map
                        .get(&case.case_id)
                        .copied()
                        .unwrap_or(timing_ms.first().map(|&(_, t)| t).unwrap_or(0));
                    (
                        pred,
                        Some(classification.clone()),
                        derive_severity(&classification),
                        evidence.clone(),
                        time,
                    )
                } else {
                    let time = timing_map.get(&case.case_id).copied().unwrap_or(0);
                    match case.ground_truth {
                        GroundTruthLabel::TruePositive => {
                            (GroundTruthLabel::FalseNegative, None, None, vec![], time)
                        }
                        GroundTruthLabel::TrueNegative => (
                            GroundTruthLabel::TrueNegative,
                            Some("no_finding".to_string()),
                            None,
                            vec![],
                            time,
                        ),
                        GroundTruthLabel::FalsePositive => (
                            GroundTruthLabel::TrueNegative,
                            Some("no_finding".to_string()),
                            None,
                            vec![],
                            time,
                        ),
                        GroundTruthLabel::FalseNegative => {
                            (GroundTruthLabel::FalseNegative, None, None, vec![], time)
                        }
                        GroundTruthLabel::Inconclusive => {
                            (GroundTruthLabel::Inconclusive, None, None, vec![], time)
                        }
                    }
                };

            BenchmarkResult {
                result_id: format!("result_{}", case.case_id),
                suite_id: suite.suite_id.clone(),
                case_id: case.case_id.clone(),
                domain: case.domain.clone(),
                actual_classification,
                actual_severity,
                actual_state: Some("verified".to_string()),
                prediction,
                confidence: if prediction == case.ground_truth {
                    1.0
                } else {
                    0.5
                },
                evidence_found,
                time_to_result_ms: time_ms,
                error: None,
            }
        })
        .collect()
}

fn derive_severity(classification: &str) -> Option<String> {
    let lower = classification.to_ascii_lowercase();
    if lower.contains("missing") {
        Some("high".to_string())
    } else if lower.contains("bfla") || lower.contains("function") {
        Some("high".to_string())
    } else if lower.contains("bola") || lower.contains("object") || lower.contains("idor") {
        Some("medium".to_string())
    } else if lower.contains("blocked") {
        Some("info".to_string())
    } else if lower.contains("intended") {
        Some("info".to_string())
    } else {
        Some("medium".to_string())
    }
}

pub fn evaluate_cloud_iam_findings(
    suite: &BenchmarkSuite,
    findings: &[(String, String, String, bool)],
) -> Vec<BenchmarkResult> {
    suite
        .cases
        .iter()
        .filter(|c| c.domain == BenchmarkDomain::CloudIam)
        .map(|case| {
            let matched =
                findings
                    .iter()
                    .find(|(resource, _classification, _severity, _reachable)| {
                        case.target.contains(resource)
                            || resource.contains(&case.target.split(':').last().unwrap_or(""))
                    });

            let (prediction, actual_classification, actual_severity) =
                if let Some((_resource, classification, severity, reachable)) = matched {
                    let pred = if *reachable {
                        if matches!(case.ground_truth, GroundTruthLabel::TruePositive) {
                            GroundTruthLabel::TruePositive
                        } else {
                            GroundTruthLabel::FalsePositive
                        }
                    } else {
                        if matches!(case.ground_truth, GroundTruthLabel::TrueNegative) {
                            GroundTruthLabel::TrueNegative
                        } else {
                            GroundTruthLabel::FalseNegative
                        }
                    };
                    (pred, Some(classification.clone()), Some(severity.clone()))
                } else {
                    match case.ground_truth {
                        GroundTruthLabel::TruePositive => {
                            (GroundTruthLabel::FalseNegative, None, None)
                        }
                        GroundTruthLabel::TrueNegative => (
                            GroundTruthLabel::TrueNegative,
                            Some("compliant".to_string()),
                            Some("info".to_string()),
                        ),
                        _ => (GroundTruthLabel::Inconclusive, None, None),
                    }
                };

            BenchmarkResult {
                result_id: format!("result_{}", case.case_id),
                suite_id: suite.suite_id.clone(),
                case_id: case.case_id.clone(),
                domain: case.domain.clone(),
                actual_classification,
                actual_severity,
                actual_state: Some("verified".to_string()),
                prediction,
                confidence: if prediction == case.ground_truth {
                    1.0
                } else {
                    0.5
                },
                evidence_found: case.expected_evidence_keys.clone(),
                time_to_result_ms: 0,
                error: None,
            }
        })
        .collect()
}

pub fn evaluate_web3_findings(
    suite: &BenchmarkSuite,
    findings: &[(String, String, String, bool)],
) -> Vec<BenchmarkResult> {
    suite
        .cases
        .iter()
        .filter(|c| c.domain == BenchmarkDomain::Web3)
        .map(|case| {
            let matched =
                findings
                    .iter()
                    .find(|(contract_func, _vuln_class, _severity, _is_theoretical)| {
                        case.target.contains(contract_func)
                            || contract_func.contains(
                                &case
                                    .target
                                    .split('.')
                                    .last()
                                    .unwrap_or("")
                                    .replace("()", ""),
                            )
                    });

            let (prediction, actual_classification, actual_severity) =
                if let Some((_contract_func, vuln_class, severity, is_theoretical)) = matched {
                    let pred = if !is_theoretical {
                        if matches!(case.ground_truth, GroundTruthLabel::TruePositive) {
                            GroundTruthLabel::TruePositive
                        } else {
                            GroundTruthLabel::FalsePositive
                        }
                    } else {
                        GroundTruthLabel::Inconclusive
                    };
                    (pred, Some(vuln_class.clone()), Some(severity.clone()))
                } else {
                    match case.ground_truth {
                        GroundTruthLabel::TruePositive => {
                            (GroundTruthLabel::FalseNegative, None, None)
                        }
                        GroundTruthLabel::TrueNegative => (
                            GroundTruthLabel::TrueNegative,
                            Some("safe".to_string()),
                            Some("info".to_string()),
                        ),
                        _ => (GroundTruthLabel::Inconclusive, None, None),
                    }
                };

            BenchmarkResult {
                result_id: format!("result_{}", case.case_id),
                suite_id: suite.suite_id.clone(),
                case_id: case.case_id.clone(),
                domain: case.domain.clone(),
                actual_classification,
                actual_severity,
                actual_state: Some("verified".to_string()),
                prediction,
                confidence: if prediction == case.ground_truth {
                    1.0
                } else {
                    0.5
                },
                evidence_found: case.expected_evidence_keys.clone(),
                time_to_result_ms: 0,
                error: None,
            }
        })
        .collect()
}

pub fn evaluate_evidence_integrity(
    suite: &BenchmarkSuite,
    manifest_integrity_ok: bool,
    signature_ok: bool,
    lifecycle_transitions_ok: bool,
    tampered_detected: bool,
) -> Vec<BenchmarkResult> {
    suite
        .cases
        .iter()
        .filter(|c| c.domain == BenchmarkDomain::Evidence)
        .map(|case| {
            let (prediction, actual_classification) = match case.case_id.as_str() {
                "evidence-seal-verify" => {
                    if manifest_integrity_ok {
                        (
                            GroundTruthLabel::TrueNegative,
                            Some("integrity_pass".to_string()),
                        )
                    } else {
                        (
                            GroundTruthLabel::FalsePositive,
                            Some("integrity_fail".to_string()),
                        )
                    }
                }
                "evidence-tamper-detection" => {
                    if tampered_detected {
                        (GroundTruthLabel::TruePositive, Some("tampered".to_string()))
                    } else {
                        (GroundTruthLabel::FalseNegative, None)
                    }
                }
                "evidence-lifecycle-transition" => {
                    if lifecycle_transitions_ok {
                        (
                            GroundTruthLabel::TrueNegative,
                            Some("lifecycle_valid".to_string()),
                        )
                    } else {
                        (
                            GroundTruthLabel::FalsePositive,
                            Some("lifecycle_invalid".to_string()),
                        )
                    }
                }
                "evidence-signature-trust" => {
                    if signature_ok {
                        (
                            GroundTruthLabel::TrueNegative,
                            Some("signature_valid".to_string()),
                        )
                    } else {
                        (
                            GroundTruthLabel::FalsePositive,
                            Some("signature_invalid".to_string()),
                        )
                    }
                }
                _ => (GroundTruthLabel::Inconclusive, None),
            };

            BenchmarkResult {
                result_id: format!("result_{}", case.case_id),
                suite_id: suite.suite_id.clone(),
                case_id: case.case_id.clone(),
                domain: case.domain.clone(),
                actual_classification,
                actual_severity: None,
                actual_state: Some("verified".to_string()),
                prediction,
                confidence: if prediction == case.ground_truth {
                    1.0
                } else {
                    0.5
                },
                evidence_found: case.expected_evidence_keys.clone(),
                time_to_result_ms: 0,
                error: None,
            }
        })
        .collect()
}

pub fn create_benchmark_run_from_results(
    suite_id: &str,
    domain: BenchmarkDomain,
    version: &str,
    results: Vec<BenchmarkResult>,
    config: BenchmarkConfig,
) -> BenchmarkRun {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    BenchmarkRun {
        run_id: format!("benchmark_{}", now),
        suite_id: suite_id.to_string(),
        suite_version: version.to_string(),
        domain,
        started_at: now,
        completed_at: now,
        config_snapshot: config,
        results,
    }
}

pub fn generate_golden_baseline(suite: &BenchmarkSuite) -> BenchmarkRun {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let results: Vec<BenchmarkResult> = suite
        .cases
        .iter()
        .map(|case| BenchmarkResult {
            result_id: format!("golden_{}", case.case_id),
            suite_id: suite.suite_id.clone(),
            case_id: case.case_id.clone(),
            domain: case.domain.clone(),
            actual_classification: case.expected_classification.clone(),
            actual_severity: case.expected_severity.clone(),
            actual_state: Some("verified".to_string()),
            prediction: case.ground_truth,
            confidence: 1.0,
            evidence_found: case.expected_evidence_keys.clone(),
            time_to_result_ms: 150,
            error: None,
        })
        .collect();

    BenchmarkRun {
        run_id: format!("golden_{}", suite.suite_id),
        suite_id: suite.suite_id.clone(),
        suite_version: suite.version.clone(),
        domain: suite.domain.clone(),
        started_at: now,
        completed_at: now + 300,
        config_snapshot: BenchmarkConfig {
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            validator_config: "golden_baseline".to_string(),
            noise_mode: "moderate".to_string(),
            max_active_requests: 500,
            domain_filter: None,
            difficulty_filter: None,
            tag_filter: None,
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("golden".to_string(), "true".to_string());
                m
            },
            provider: "fixture".to_string(),
            model: "golden-baseline".to_string(),
            prompt_version: "v1".to_string(),
            git_commit: env!("CARGO_PKG_VERSION").to_string(),
            corpus_hash: "golden".to_string(),
        },
        results,
    }
}

pub fn save_golden_baseline(suite: &BenchmarkSuite, dir: &Path) -> Result<(), String> {
    let run = generate_golden_baseline(suite);
    let scorecard = generate_scorecard(suite, &run, None, None);
    let run_path = dir.join(format!("golden_{}_run.json", suite.domain.as_str()));
    let scorecard_path = dir.join(format!("golden_{}_scorecard.json", suite.domain.as_str()));
    save_benchmark_run(&run, &run_path)?;
    save_scorecard(&scorecard, &scorecard_path)?;
    Ok(())
}

pub fn load_golden_baseline(domain: BenchmarkDomain, dir: &Path) -> Result<BenchmarkRun, String> {
    let path = dir.join(format!("golden_{}_run.json", domain.as_str()));
    load_benchmark_run(&path)
}

pub fn benchmark_ci_gate(
    run: &BenchmarkRun,
    suite: &BenchmarkSuite,
    min_accuracy: f64,
    min_precision: f64,
    min_recall: f64,
    min_f1: f64,
    max_fpr: f64,
) -> BenchmarkCIGateResult {
    let metrics = compute_evaluation_metrics(suite, run);
    let scorecard = generate_scorecard(suite, run, None, None);

    let mut failures = Vec::new();
    let mut passes = Vec::new();

    if metrics.accuracy >= min_accuracy {
        passes.push(format!(
            "accuracy {:.1}% >= {:.1}%",
            metrics.accuracy * 100.0,
            min_accuracy * 100.0
        ));
    } else {
        failures.push(format!(
            "accuracy {:.1}% < {:.1}%",
            metrics.accuracy * 100.0,
            min_accuracy * 100.0
        ));
    }

    if metrics.precision >= min_precision {
        passes.push(format!(
            "precision {:.1}% >= {:.1}%",
            metrics.precision * 100.0,
            min_precision * 100.0
        ));
    } else {
        failures.push(format!(
            "precision {:.1}% < {:.1}%",
            metrics.precision * 100.0,
            min_precision * 100.0
        ));
    }

    if metrics.recall >= min_recall {
        passes.push(format!(
            "recall {:.1}% >= {:.1}%",
            metrics.recall * 100.0,
            min_recall * 100.0
        ));
    } else {
        failures.push(format!(
            "recall {:.1}% < {:.1}%",
            metrics.recall * 100.0,
            min_recall * 100.0
        ));
    }

    if metrics.f1_score >= min_f1 {
        passes.push(format!(
            "f1 {:.1}% >= {:.1}%",
            metrics.f1_score * 100.0,
            min_f1 * 100.0
        ));
    } else {
        failures.push(format!(
            "f1 {:.1}% < {:.1}%",
            metrics.f1_score * 100.0,
            min_f1 * 100.0
        ));
    }

    if metrics.false_positive_rate <= max_fpr {
        passes.push(format!(
            "fpr {:.1}% <= {:.1}%",
            metrics.false_positive_rate * 100.0,
            max_fpr * 100.0
        ));
    } else {
        failures.push(format!(
            "fpr {:.1}% > {:.1}%",
            metrics.false_positive_rate * 100.0,
            max_fpr * 100.0
        ));
    }

    let passed = failures.is_empty();

    BenchmarkCIGateResult {
        passed,
        grade: metrics.grade,
        metrics,
        scorecard,
        passes,
        failures,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BenchmarkCIGateResult {
    pub passed: bool,
    pub grade: EvaluationGrade,
    pub metrics: EvaluationMetrics,
    pub scorecard: EvaluationScorecard,
    pub passes: Vec<String>,
    pub failures: Vec<String>,
}

pub fn render_ci_gate_result(result: &BenchmarkCIGateResult) -> String {
    let mut md = String::new();
    md.push_str(&format!("# BALONCORE Benchmark CI Gate\n\n"));
    md.push_str(&format!(
        "**Result:** {}  \n",
        if result.passed { "PASSED" } else { "FAILED" }
    ));
    md.push_str(&format!("**Grade:** {}  \n\n", result.grade.as_str()));

    md.push_str("## Threshold Checks\n\n");
    md.push_str("| Check | Status | Value | Threshold |\n");
    md.push_str("|-------|--------|-------|----------|\n");
    for check in &result.passes {
        md.push_str(&format!(
            "| {} | ✓ | {} |\n",
            check.split_whitespace().next().unwrap_or(""),
            check
        ));
    }
    for check in &result.failures {
        md.push_str(&format!(
            "| {} | ✗ | {} |\n",
            check.split_whitespace().next().unwrap_or(""),
            check
        ));
    }

    md.push_str(&format!("\n## Summary\n\n"));
    md.push_str(&format!("- Total cases: {}\n", result.metrics.total_cases));
    md.push_str(&format!(
        "- True positives: {}\n",
        result.metrics.true_positives
    ));
    md.push_str(&format!(
        "- False positives: {}\n",
        result.metrics.false_positives
    ));
    md.push_str(&format!(
        "- True negatives: {}\n",
        result.metrics.true_negatives
    ));
    md.push_str(&format!(
        "- False negatives: {}\n",
        result.metrics.false_negatives
    ));
    md.push_str(&format!(
        "- Precision: {:.1}%\n",
        result.metrics.precision * 100.0
    ));
    md.push_str(&format!(
        "- Recall: {:.1}%\n",
        result.metrics.recall * 100.0
    ));
    md.push_str(&format!("- F1: {:.1}%\n", result.metrics.f1_score * 100.0));
    md.push_str(&format!(
        "- Accuracy: {:.1}%\n",
        result.metrics.accuracy * 100.0
    ));
    md.push_str(&format!(
        "- FPR: {:.1}%\n",
        result.metrics.false_positive_rate * 100.0
    ));

    if !result.failures.is_empty() {
        md.push_str(&format!("\n## Failures\n\n"));
        for f in &result.failures {
            md.push_str(&format!("- {}\n", f));
        }
    }

    md
}

#[cfg(test)]
mod executor_tests {
    use super::*;

    #[test]
    fn evaluate_web_api_run_maps_classifications() {
        let suite = web_api_benchmark_suite();
        let validations = vec![
            (
                "/api/invoices/inv_2002".to_string(),
                "user_a".to_string(),
                "BrokenObjectLevelAuthorization".to_string(),
                vec!["cross_profile_response".to_string()],
            ),
            (
                "/api/admin/reports/adm_9001".to_string(),
                "user_a".to_string(),
                "BrokenFunctionLevelAuthorization".to_string(),
                vec!["function_access_response".to_string()],
            ),
            (
                "/api/invoices/inv_2002".to_string(),
                "anonymous".to_string(),
                "MissingAuthentication".to_string(),
                vec!["anonymous_response".to_string()],
            ),
            (
                "/api/invoices/inv_1001".to_string(),
                "user_a".to_string(),
                "BlockedAsExpected".to_string(),
                vec!["blocked_response".to_string()],
            ),
        ];

        let results = evaluate_web_api_run(&suite, &validations, &[]);
        assert!(!results.is_empty());

        let tp_results: Vec<_> = results
            .iter()
            .filter(|r| r.prediction == GroundTruthLabel::TruePositive)
            .collect();
        let tn_results: Vec<_> = results
            .iter()
            .filter(|r| r.prediction == GroundTruthLabel::TrueNegative)
            .collect();
        assert!(
            !tp_results.is_empty(),
            "Should have at least one true positive from BOLA finding"
        );
        assert!(
            !tn_results.is_empty(),
            "Should have at least one true negative from blocked finding"
        );
    }

    #[test]
    fn evaluate_cloud_iam_finds_over_permissive() {
        let suite = cloud_iam_benchmark_suite();
        let findings = vec![
            (
                "aws:iam:policy/admin-policy".to_string(),
                "over_permissive_iam".to_string(),
                "high".to_string(),
                true,
            ),
            (
                "aws:s3:bucket/data-bucket".to_string(),
                "public_exposure".to_string(),
                "high".to_string(),
                true,
            ),
            (
                "aws:iam:policy/read-only-policy".to_string(),
                "compliant_iam".to_string(),
                "info".to_string(),
                false,
            ),
        ];

        let results = evaluate_cloud_iam_findings(&suite, &findings);
        assert!(!results.is_empty());

        let tp_results: Vec<_> = results
            .iter()
            .filter(|r| r.prediction == GroundTruthLabel::TruePositive)
            .collect();
        assert!(
            !tp_results.is_empty(),
            "Should detect over-permissive IAM as true positive"
        );
    }

    #[test]
    fn evaluate_web3_detects_reentrancy() {
        let suite = web3_benchmark_suite();
        let findings = vec![
            (
                "VulnerableVault.deposit()".to_string(),
                "reentrancy".to_string(),
                "high".to_string(),
                false,
            ),
            (
                "VulnerableVault.withdraw()".to_string(),
                "reentrancy".to_string(),
                "critical".to_string(),
                false,
            ),
            (
                "VulnerableVault.setBalance()".to_string(),
                "access_control".to_string(),
                "critical".to_string(),
                false,
            ),
        ];

        let results = evaluate_web3_findings(&suite, &findings);
        assert!(!results.is_empty());

        let tp_count = results
            .iter()
            .filter(|r| r.prediction == GroundTruthLabel::TruePositive)
            .count();
        assert!(
            tp_count >= 2,
            "Should detect at least reentrancy and access control as true positives"
        );
    }

    #[test]
    fn evaluate_evidence_integrity_all_pass() {
        let suite = evidence_lifecycle_benchmark_suite();
        let results = evaluate_evidence_integrity(&suite, true, true, true, true);
        assert_eq!(results.len(), 4);

        let tn_count = results
            .iter()
            .filter(|r| r.prediction == GroundTruthLabel::TrueNegative)
            .count();
        let tp_count = results
            .iter()
            .filter(|r| r.prediction == GroundTruthLabel::TruePositive)
            .count();
        assert!(
            tn_count > 0,
            "Intact evidence should produce true negatives"
        );
        assert!(
            tp_count > 0,
            "Tamper detection should produce true positive"
        );
    }

    #[test]
    fn evaluate_evidence_integrity_tamper_not_detected() {
        let suite = evidence_lifecycle_benchmark_suite();
        let results = evaluate_evidence_integrity(&suite, true, true, true, false);
        let tamper_case = results
            .iter()
            .find(|r| r.case_id == "evidence-tamper-detection")
            .unwrap();
        assert_eq!(
            tamper_case.prediction,
            GroundTruthLabel::FalseNegative,
            "Undetected tamper should be false negative"
        );
    }

    #[test]
    fn golden_baseline_is_perfect() {
        let suite = web_api_benchmark_suite();
        let run = generate_golden_baseline(&suite);
        let metrics = compute_evaluation_metrics(&suite, &run);
        assert!(
            (metrics.accuracy - 1.0).abs() < 0.001,
            "Golden baseline should have perfect accuracy"
        );
        assert!(
            (metrics.precision - 1.0).abs() < 0.001,
            "Golden baseline should have perfect precision"
        );
        assert!(
            (metrics.recall - 1.0).abs() < 0.001,
            "Golden baseline should have perfect recall"
        );
        assert!(
            metrics.false_positives == 0,
            "Golden baseline should have no false positives"
        );
    }

    #[test]
    fn ci_gate_passes_on_golden_baseline() {
        let suite = web_api_benchmark_suite();
        let run = generate_golden_baseline(&suite);
        let result = benchmark_ci_gate(&run, &suite, 0.80, 0.70, 0.70, 0.70, 0.15);
        assert!(result.passed, "Golden baseline should pass CI gate");
        assert!(
            result.failures.is_empty(),
            "Golden baseline should have no failures"
        );
    }

    #[test]
    fn ci_gate_fails_on_poor_results() {
        let suite = web_api_benchmark_suite();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let results: Vec<BenchmarkResult> = suite
            .cases
            .iter()
            .map(|case| BenchmarkResult {
                result_id: format!("result_{}", case.case_id),
                suite_id: suite.suite_id.clone(),
                case_id: case.case_id.clone(),
                domain: case.domain.clone(),
                actual_classification: None,
                actual_severity: None,
                actual_state: Some("error".to_string()),
                prediction: GroundTruthLabel::Inconclusive,
                confidence: 0.1,
                evidence_found: vec![],
                time_to_result_ms: 5000,
                error: Some("validator timeout".to_string()),
            })
            .collect();

        let run = BenchmarkRun {
            run_id: "poor-run".to_string(),
            suite_id: suite.suite_id.clone(),
            suite_version: suite.version.clone(),
            domain: suite.domain.clone(),
            started_at: now,
            completed_at: now + 30000,
            config_snapshot: BenchmarkConfig::default(),
            results,
        };

        let result = benchmark_ci_gate(&run, &suite, 0.80, 0.70, 0.70, 0.70, 0.15);
        assert!(!result.passed, "All-inconclusive run should fail CI gate");
        assert!(
            !result.failures.is_empty(),
            "Should have at least one failure"
        );
    }

    #[test]
    fn save_and_load_golden_baseline() {
        let suite = web_api_benchmark_suite();
        let dir = std::env::temp_dir().join("baloncore-golden-test");
        let _ = std::fs::create_dir_all(&dir);
        save_golden_baseline(&suite, &dir).unwrap();
        let loaded = load_golden_baseline(BenchmarkDomain::WebApi, &dir).unwrap();
        assert_eq!(loaded.suite_id, suite.suite_id);
        assert_eq!(loaded.results.len(), suite.cases.len());
        assert!(loaded.results.iter().all(|r| r.confidence == 1.0));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ci_gate_result_rendering() {
        let suite = web_api_benchmark_suite();
        let run = generate_golden_baseline(&suite);
        let result = benchmark_ci_gate(&run, &suite, 0.80, 0.70, 0.70, 0.70, 0.15);
        let md = render_ci_gate_result(&result);
        assert!(md.contains("PASSED"));
        assert!(md.contains("Grade"));
        assert!(md.contains("Threshold Checks"));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BenchmarkHistory {
    pub history_id: String,
    pub domain: BenchmarkDomain,
    pub entries: Vec<HistoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoryEntry {
    pub run_id: String,
    pub timestamp: u64,
    pub grade: String,
    pub accuracy: f64,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub fpr: f64,
    pub fnr: f64,
    pub total_cases: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub true_negatives: usize,
    pub false_negatives: usize,
    pub engine_version: String,
    pub validator_config: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriftReport {
    pub domain: BenchmarkDomain,
    pub baseline_run_id: String,
    pub current_run_id: String,
    pub accuracy_drift: f64,
    pub precision_drift: f64,
    pub recall_drift: f64,
    pub f1_drift: f64,
    pub fpr_drift: f64,
    pub fnr_drift: f64,
    pub is_degraded: bool,
    pub degraded_dimensions: Vec<String>,
    pub improved_dimensions: Vec<String>,
    pub warning_dimensions: Vec<String>,
}

impl BenchmarkHistory {
    pub fn new(domain: BenchmarkDomain) -> Self {
        Self {
            history_id: format!("history_{}", domain.as_str()),
            domain,
            entries: Vec::new(),
        }
    }

    pub fn add_run(
        &mut self,
        run: &BenchmarkRun,
        metrics: &EvaluationMetrics,
        grade: &EvaluationGrade,
    ) {
        self.entries.push(HistoryEntry {
            run_id: run.run_id.clone(),
            timestamp: run.completed_at,
            grade: grade.as_str().to_string(),
            accuracy: metrics.accuracy,
            precision: metrics.precision,
            recall: metrics.recall,
            f1_score: metrics.f1_score,
            fpr: metrics.false_positive_rate,
            fnr: metrics.false_negative_rate,
            total_cases: metrics.total_cases,
            true_positives: metrics.true_positives,
            false_positives: metrics.false_positives,
            true_negatives: metrics.true_negatives,
            false_negatives: metrics.false_negatives,
            engine_version: run.config_snapshot.engine_version.clone(),
            validator_config: run.config_snapshot.validator_config.clone(),
        });
    }

    pub fn latest(&self) -> Option<&HistoryEntry> {
        self.entries.last()
    }

    pub fn best_accuracy(&self) -> Option<&HistoryEntry> {
        self.entries.iter().max_by(|a, b| {
            a.accuracy
                .partial_cmp(&b.accuracy)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    pub fn trend(&self) -> Vec<(String, f64)> {
        self.entries
            .iter()
            .map(|e| (e.run_id.clone(), e.accuracy))
            .collect()
    }

    pub fn last_n(&self, n: usize) -> &[HistoryEntry] {
        if self.entries.len() <= n {
            &self.entries
        } else {
            &self.entries[self.entries.len() - n..]
        }
    }
}

pub fn detect_drift(
    history: &BenchmarkHistory,
    current: &BenchmarkRun,
    metrics: &EvaluationMetrics,
    drift_threshold: f64,
) -> DriftReport {
    let baseline = match history.latest() {
        Some(e) => e,
        None => {
            return DriftReport {
                domain: current.domain.clone(),
                baseline_run_id: "none".to_string(),
                current_run_id: current.run_id.clone(),
                accuracy_drift: 0.0,
                precision_drift: 0.0,
                recall_drift: 0.0,
                f1_drift: 0.0,
                fpr_drift: 0.0,
                fnr_drift: 0.0,
                is_degraded: false,
                degraded_dimensions: Vec::new(),
                improved_dimensions: Vec::new(),
                warning_dimensions: Vec::new(),
            };
        }
    };

    let accuracy_drift = metrics.accuracy - baseline.accuracy;
    let precision_drift = metrics.precision - baseline.precision;
    let recall_drift = metrics.recall - baseline.recall;
    let f1_drift = metrics.f1_score - baseline.f1_score;
    let fpr_drift = metrics.false_positive_rate - baseline.fpr;
    let fnr_drift = metrics.false_negative_rate - baseline.fnr;

    let mut degraded = Vec::new();
    let mut improved = Vec::new();
    let mut warnings = Vec::new();

    if accuracy_drift < -drift_threshold {
        degraded.push(format!("accuracy: {:+.1}%", accuracy_drift * 100.0));
    } else if accuracy_drift > drift_threshold {
        improved.push(format!("accuracy: {:+.1}%", accuracy_drift * 100.0));
    } else if accuracy_drift < 0.0 {
        warnings.push(format!("accuracy: {:+.1}%", accuracy_drift * 100.0));
    }

    if precision_drift < -drift_threshold {
        degraded.push(format!("precision: {:+.1}%", precision_drift * 100.0));
    } else if precision_drift > drift_threshold {
        improved.push(format!("precision: {:+.1}%", precision_drift * 100.0));
    } else if precision_drift < 0.0 {
        warnings.push(format!("precision: {:+.1}%", precision_drift * 100.0));
    }

    if recall_drift < -drift_threshold {
        degraded.push(format!("recall: {:+.1}%", recall_drift * 100.0));
    } else if recall_drift > drift_threshold {
        improved.push(format!("recall: {:+.1}%", recall_drift * 100.0));
    } else if recall_drift < 0.0 {
        warnings.push(format!("recall: {:+.1}%", recall_drift * 100.0));
    }

    if f1_drift < -drift_threshold {
        degraded.push(format!("f1: {:+.1}%", f1_drift * 100.0));
    } else if f1_drift > drift_threshold {
        improved.push(format!("f1: {:+.1}%", f1_drift * 100.0));
    } else if f1_drift < 0.0 {
        warnings.push(format!("f1: {:+.1}%", f1_drift * 100.0));
    }

    if fpr_drift > drift_threshold {
        degraded.push(format!("fpr: {:+.1}%", fpr_drift * 100.0));
    } else if fpr_drift < -drift_threshold {
        improved.push(format!("fpr: {:+.1}%", fpr_drift * 100.0));
    }

    if fnr_drift > drift_threshold {
        degraded.push(format!("fnr: {:+.1}%", fnr_drift * 100.0));
    } else if fnr_drift < -drift_threshold {
        improved.push(format!("fnr: {:+.1}%", fnr_drift * 100.0));
    }

    DriftReport {
        domain: current.domain.clone(),
        baseline_run_id: baseline.run_id.clone(),
        current_run_id: current.run_id.clone(),
        accuracy_drift,
        precision_drift,
        recall_drift,
        f1_drift,
        fpr_drift,
        fnr_drift,
        is_degraded: !degraded.is_empty(),
        degraded_dimensions: degraded,
        improved_dimensions: improved,
        warning_dimensions: warnings,
    }
}

pub fn render_drift_report(report: &DriftReport) -> String {
    let mut md = String::new();
    md.push_str("# BALONCORE Benchmark Drift Report\n\n");
    md.push_str(&format!("**Domain:** {}  \n", report.domain.as_str()));
    md.push_str(&format!("**Baseline:** {}  \n", report.baseline_run_id));
    md.push_str(&format!("**Current:** {}  \n", report.current_run_id));
    md.push_str(&format!("**Degraded:** {}  \n\n", report.is_degraded));

    md.push_str("| Dimension | Drift | Status |\n");
    md.push_str("|-----------|-------|--------|\n");
    md.push_str(&format!(
        "| Accuracy | {:+.1}% | {} |\n",
        report.accuracy_drift * 100.0,
        drift_status(report.accuracy_drift, false)
    ));
    md.push_str(&format!(
        "| Precision | {:+.1}% | {} |\n",
        report.precision_drift * 100.0,
        drift_status(report.precision_drift, false)
    ));
    md.push_str(&format!(
        "| Recall | {:+.1}% | {} |\n",
        report.recall_drift * 100.0,
        drift_status(report.recall_drift, false)
    ));
    md.push_str(&format!(
        "| F1 | {:+.1}% | {} |\n",
        report.f1_drift * 100.0,
        drift_status(report.f1_drift, false)
    ));
    md.push_str(&format!(
        "| FPR | {:+.1}% | {} |\n",
        report.fpr_drift * 100.0,
        drift_status(report.fpr_drift, true)
    ));
    md.push_str(&format!(
        "| FNR | {:+.1}% | {} |\n",
        report.fnr_drift * 100.0,
        drift_status(report.fnr_drift, true)
    ));

    if !report.degraded_dimensions.is_empty() {
        md.push_str("\n## Degraded Dimensions\n\n");
        for d in &report.degraded_dimensions {
            md.push_str(&format!("- {}\n", d));
        }
    }

    if !report.improved_dimensions.is_empty() {
        md.push_str("\n## Improved Dimensions\n\n");
        for i in &report.improved_dimensions {
            md.push_str(&format!("- {}\n", i));
        }
    }

    if !report.warning_dimensions.is_empty() {
        md.push_str("\n## Warnings\n\n");
        for w in &report.warning_dimensions {
            md.push_str(&format!("- {}\n", w));
        }
    }

    md
}

fn drift_status(drift: f64, inverted: bool) -> &'static str {
    let threshold = 0.05;
    if inverted {
        if drift > threshold {
            "degraded"
        } else if drift < -threshold {
            "improved"
        } else if drift > 0.0 {
            "warning"
        } else {
            "stable"
        }
    } else {
        if drift < -threshold {
            "degraded"
        } else if drift > threshold {
            "improved"
        } else if drift < 0.0 {
            "warning"
        } else {
            "stable"
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CrossDomainCorrelation {
    pub domain_pairs: Vec<DomainPairCorrelation>,
    pub overall_health: f64,
    pub weakest_domain: Option<BenchmarkDomain>,
    pub strongest_domain: Option<BenchmarkDomain>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DomainPairCorrelation {
    pub domain_a: String,
    pub domain_b: String,
    pub correlation: f64,
}

pub fn compute_cross_domain_correlation(
    runs: &[BenchmarkRun],
    suites: &[BenchmarkSuite],
) -> CrossDomainCorrelation {
    let mut domain_accuracies: BTreeMap<String, f64> = BTreeMap::new();

    for run in runs {
        if let Some(suite) = suites.iter().find(|s| s.suite_id == run.suite_id) {
            let metrics = compute_evaluation_metrics(suite, run);
            domain_accuracies.insert(run.domain.as_str().to_string(), metrics.accuracy);
        }
    }

    let domains: Vec<&String> = domain_accuracies.keys().collect();
    let mut pairs = Vec::new();

    for i in 0..domains.len() {
        for j in (i + 1)..domains.len() {
            let acc_a = domain_accuracies.get(domains[i]).unwrap_or(&0.0);
            let acc_b = domain_accuracies.get(domains[j]).unwrap_or(&0.0);
            let correlation = 1.0 - (acc_a - acc_b).abs();
            pairs.push(DomainPairCorrelation {
                domain_a: domains[i].clone(),
                domain_b: domains[j].clone(),
                correlation,
            });
        }
    }

    let overall_health = if domain_accuracies.is_empty() {
        0.0
    } else {
        domain_accuracies.values().sum::<f64>() / domain_accuracies.len() as f64
    };

    let weakest = domain_accuracies
        .iter()
        .min_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal));
    let strongest = domain_accuracies
        .iter()
        .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal));

    CrossDomainCorrelation {
        domain_pairs: pairs,
        overall_health,
        weakest_domain: weakest.map(|(d, _)| BenchmarkDomain::from_str_lossy(d)),
        strongest_domain: strongest.map(|(d, _)| BenchmarkDomain::from_str_lossy(d)),
    }
}

pub fn save_history(history: &BenchmarkHistory, path: &Path) -> Result<(), String> {
    let json = serde_json::to_string_pretty(history).map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, json).map_err(|e| e.to_string())
}

pub fn load_history(path: &Path) -> Result<BenchmarkHistory, String> {
    let data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&data).map_err(|e| e.to_string())
}

pub fn append_to_history(
    path: &Path,
    run: &BenchmarkRun,
    metrics: &EvaluationMetrics,
    grade: &EvaluationGrade,
) -> Result<BenchmarkHistory, String> {
    let mut history = if path.exists() {
        load_history(path)?
    } else {
        BenchmarkHistory::new(run.domain.clone())
    };
    history.add_run(run, metrics, grade);
    save_history(&history, path)?;
    Ok(history)
}

pub fn render_history(history: &BenchmarkHistory) -> String {
    let mut md = String::new();
    md.push_str(&format!(
        "# BALONCORE Benchmark History — {}\n\n",
        history.domain.as_str()
    ));
    md.push_str(&format!("**Runs:** {}  \n\n", history.entries.len()));

    if history.entries.is_empty() {
        md.push_str("No benchmark runs recorded yet.\n");
        return md;
    }

    md.push_str("| Date | Run | Grade | Accuracy | Precision | Recall | F1 | FPR |\n");
    md.push_str("|------|-----|-------|----------|-----------|--------|----|-----|\n");

    for entry in &history.entries {
        let date = if entry.timestamp > 0 {
            chrono_like(entry.timestamp)
        } else {
            "—".to_string()
        };
        md.push_str(&format!(
            "| {} | {} | {} | {:.1}% | {:.1}% | {:.1}% | {:.1}% | {:.1}% |\n",
            date,
            entry.run_id,
            entry.grade,
            entry.accuracy * 100.0,
            entry.precision * 100.0,
            entry.recall * 100.0,
            entry.f1_score * 100.0,
            entry.fpr * 100.0,
        ));
    }

    if let Some(best) = history.best_accuracy() {
        md.push_str(&format!(
            "\n**Best accuracy:** {:.1}% (run {})\n",
            best.accuracy * 100.0,
            best.run_id
        ));
    }

    if let Some(latest) = history.latest() {
        md.push_str(&format!(
            "**Latest:** {:.1}% accuracy, grade {}\n",
            latest.accuracy * 100.0,
            latest.grade
        ));
    }

    md
}

fn chrono_like(timestamp: u64) -> String {
    let days = timestamp / 86400;
    let hours = (timestamp % 86400) / 3600;
    let minutes = (timestamp % 3600) / 60;
    format!("day {} {:02}:{:02}", days, hours, minutes)
}

#[cfg(test)]
mod p2s3_tests {
    use super::*;

    #[test]
    fn history_add_run_and_latest() {
        let suite = web_api_benchmark_suite();
        let mut history = BenchmarkHistory::new(BenchmarkDomain::WebApi);
        assert!(history.latest().is_none());

        let run1 = generate_golden_baseline(&suite);
        let metrics1 = compute_evaluation_metrics(&suite, &run1);
        history.add_run(&run1, &metrics1, &EvaluationGrade::APlus);
        assert!(history.latest().is_some());
        assert_eq!(history.entries.len(), 1);

        let run2 = generate_golden_baseline(&suite);
        let metrics2 = compute_evaluation_metrics(&suite, &run2);
        history.add_run(&run2, &metrics2, &EvaluationGrade::APlus);
        assert_eq!(history.entries.len(), 2);
        assert_eq!(history.latest().unwrap().grade, "A+");
    }

    #[test]
    fn history_best_accuracy_and_trend() {
        let suite = web_api_benchmark_suite();
        let mut history = BenchmarkHistory::new(BenchmarkDomain::WebApi);

        let run1 = generate_golden_baseline(&suite);
        let metrics1 = compute_evaluation_metrics(&suite, &run1);
        history.add_run(&run1, &metrics1, &EvaluationGrade::APlus);

        assert!(history.best_accuracy().is_some());
        assert_eq!(history.best_accuracy().unwrap().accuracy, 1.0);

        let trend = history.trend();
        assert_eq!(trend.len(), 1);
        assert_eq!(trend[0].0, run1.run_id);
    }

    #[test]
    fn drift_detection_no_baseline() {
        let suite = web_api_benchmark_suite();
        let history = BenchmarkHistory::new(BenchmarkDomain::WebApi);
        let run = generate_golden_baseline(&suite);
        let metrics = compute_evaluation_metrics(&suite, &run);

        let report = detect_drift(&history, &run, &metrics, 0.05);
        assert!(!report.is_degraded);
        assert!(report.degraded_dimensions.is_empty());
    }

    #[test]
    fn drift_detection_perfect_match() {
        let suite = web_api_benchmark_suite();
        let mut history = BenchmarkHistory::new(BenchmarkDomain::WebApi);
        let run = generate_golden_baseline(&suite);
        let metrics = compute_evaluation_metrics(&suite, &run);
        history.add_run(&run, &metrics, &EvaluationGrade::APlus);

        let report = detect_drift(&history, &run, &metrics, 0.05);
        assert!(!report.is_degraded);
        assert!((report.accuracy_drift).abs() < 0.001);
    }

    #[test]
    fn drift_detection_degradation() {
        let suite = web_api_benchmark_suite();
        let mut history = BenchmarkHistory::new(BenchmarkDomain::WebApi);
        let good_run = generate_golden_baseline(&suite);
        let good_metrics = compute_evaluation_metrics(&suite, &good_run);
        history.add_run(&good_run, &good_metrics, &EvaluationGrade::APlus);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let bad_results: Vec<BenchmarkResult> = suite
            .cases
            .iter()
            .map(|case| BenchmarkResult {
                result_id: format!("result_{}", case.case_id),
                suite_id: suite.suite_id.clone(),
                case_id: case.case_id.clone(),
                domain: case.domain.clone(),
                actual_classification: None,
                actual_severity: None,
                actual_state: Some("hypothesis".to_string()),
                prediction: GroundTruthLabel::Inconclusive,
                confidence: 0.3,
                evidence_found: vec![],
                time_to_result_ms: 5000,
                error: Some("validator timeout".to_string()),
            })
            .collect();

        let bad_run = BenchmarkRun {
            run_id: "bad_run".to_string(),
            suite_id: suite.suite_id.clone(),
            suite_version: suite.version.clone(),
            domain: suite.domain.clone(),
            started_at: now,
            completed_at: now + 5000,
            config_snapshot: BenchmarkConfig::default(),
            results: bad_results,
        };

        let bad_metrics = compute_evaluation_metrics(&suite, &bad_run);
        let report = detect_drift(&history, &bad_run, &bad_metrics, 0.05);
        assert!(report.is_degraded, "Should detect degradation");
        assert!(!report.degraded_dimensions.is_empty());
        assert!(report.accuracy_drift < 0.0);
    }

    #[test]
    fn drift_detection_improvement() {
        let suite = web_api_benchmark_suite();
        let mut history = BenchmarkHistory::new(BenchmarkDomain::WebApi);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let bad_results: Vec<BenchmarkResult> = suite
            .cases
            .iter()
            .map(|case| BenchmarkResult {
                result_id: format!("result_{}", case.case_id),
                suite_id: suite.suite_id.clone(),
                case_id: case.case_id.clone(),
                domain: case.domain.clone(),
                actual_classification: None,
                actual_severity: None,
                actual_state: Some("hypothesis".to_string()),
                prediction: GroundTruthLabel::Inconclusive,
                confidence: 0.3,
                evidence_found: vec![],
                time_to_result_ms: 5000,
                error: None,
            })
            .collect();

        let bad_run = BenchmarkRun {
            run_id: "bad_baseline".to_string(),
            suite_id: suite.suite_id.clone(),
            suite_version: suite.version.clone(),
            domain: suite.domain.clone(),
            started_at: now,
            completed_at: now + 5000,
            config_snapshot: BenchmarkConfig::default(),
            results: bad_results,
        };

        let bad_metrics = compute_evaluation_metrics(&suite, &bad_run);
        history.add_run(&bad_run, &bad_metrics, &EvaluationGrade::D);

        let good_run = generate_golden_baseline(&suite);
        let good_metrics = compute_evaluation_metrics(&suite, &good_run);
        let report = detect_drift(&history, &good_run, &good_metrics, 0.05);

        assert!(!report.improved_dimensions.is_empty());
        assert!(report.accuracy_drift > 0.0);
    }

    #[test]
    fn cross_domain_correlation() {
        let web_suite = web_api_benchmark_suite();
        let cloud_suite = cloud_iam_benchmark_suite();
        let run1 = generate_golden_baseline(&web_suite);
        let run2 = generate_golden_baseline(&cloud_suite);

        let correlation =
            compute_cross_domain_correlation(&[run1, run2], &[web_suite, cloud_suite]);

        assert!(!correlation.domain_pairs.is_empty());
        assert!(correlation.overall_health > 0.0);
        assert!(correlation.strongest_domain.is_some());
        assert!(correlation.weakest_domain.is_some());
    }

    #[test]
    fn save_and_load_history() {
        let suite = web_api_benchmark_suite();
        let mut history = BenchmarkHistory::new(BenchmarkDomain::WebApi);
        let run = generate_golden_baseline(&suite);
        let metrics = compute_evaluation_metrics(&suite, &run);
        history.add_run(&run, &metrics, &EvaluationGrade::APlus);

        let dir = std::env::temp_dir().join("baloncore-history-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("history.json");
        save_history(&history, &path).unwrap();
        let loaded = load_history(&path).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.domain, BenchmarkDomain::WebApi);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn append_to_history_creates_new() {
        let suite = web_api_benchmark_suite();
        let run = generate_golden_baseline(&suite);
        let metrics = compute_evaluation_metrics(&suite, &run);

        let dir = std::env::temp_dir().join("baloncore-history-append-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("history.json");
        assert!(!path.exists());

        let history = append_to_history(&path, &run, &metrics, &EvaluationGrade::APlus).unwrap();
        assert_eq!(history.entries.len(), 1);

        let history2 = append_to_history(&path, &run, &metrics, &EvaluationGrade::APlus).unwrap();
        assert_eq!(history2.entries.len(), 2);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn render_drift_report_produces_markdown() {
        let suite = web_api_benchmark_suite();
        let mut history = BenchmarkHistory::new(BenchmarkDomain::WebApi);
        let run = generate_golden_baseline(&suite);
        let metrics = compute_evaluation_metrics(&suite, &run);
        history.add_run(&run, &metrics, &EvaluationGrade::APlus);

        let report = detect_drift(&history, &run, &metrics, 0.05);
        let md = render_drift_report(&report);
        assert!(md.contains("Drift Report"));
        assert!(md.contains("Accuracy"));
        assert!(md.contains("Precision"));
    }

    #[test]
    fn render_history_produces_markdown() {
        let suite = web_api_benchmark_suite();
        let mut history = BenchmarkHistory::new(BenchmarkDomain::WebApi);
        let run = generate_golden_baseline(&suite);
        let metrics = compute_evaluation_metrics(&suite, &run);
        history.add_run(&run, &metrics, &EvaluationGrade::APlus);

        let md = render_history(&history);
        assert!(md.contains("Benchmark History"));
        assert!(md.contains("A+"));
    }

    #[test]
    fn drift_status_classifies_correctly() {
        assert_eq!(drift_status(0.1, false), "improved");
        assert_eq!(drift_status(-0.1, false), "degraded");
        assert_eq!(drift_status(-0.01, false), "warning");
        assert_eq!(drift_status(0.01, false), "stable");
        assert_eq!(drift_status(0.1, true), "degraded");
        assert_eq!(drift_status(-0.1, true), "improved");
    }
}

#[cfg(test)]
mod p2s4_tests {
    use super::*;

    #[test]
    fn leaderboard_generates_from_golden_runs() {
        let suites = all_benchmark_suites();
        let runs: Vec<BenchmarkRun> = suites.iter().map(|s| generate_golden_baseline(s)).collect();

        let report = generate_leaderboard(&suites, &runs);

        assert!(!report.runs.is_empty());
        assert!(report.aggregate.accuracy > 0.0);
        assert!(report.aggregate.total_cases > 0);
        assert!(!report.per_case.is_empty());
        assert!(!report.vuln_class_breakdown.is_empty());
        assert_eq!(report.attribution.provider, "fixture");
    }

    #[test]
    fn leaderboard_aggregates_across_domains() {
        let web_suite = web_api_benchmark_suite();
        let cloud_suite = cloud_iam_benchmark_suite();
        let web_run = generate_golden_baseline(&web_suite);
        let cloud_run = generate_golden_baseline(&cloud_suite);

        let report = generate_leaderboard(
            &[web_suite.clone(), cloud_suite.clone()],
            &[web_run, cloud_run],
        );

        assert_eq!(report.runs.len(), 2);
        assert!(report.aggregate.total_cases >= 10);
    }

    #[test]
    fn leaderboard_per_case_results_correct() {
        let suite = web_api_benchmark_suite();
        let run = generate_golden_baseline(&suite);
        let report = generate_leaderboard(&[suite.clone()], &[run]);

        let first_case = report
            .per_case
            .first()
            .expect("should have per-case results");
        assert!(!first_case.case_id.is_empty());
        assert!(!first_case.vuln_class.is_empty());
        assert!(first_case.correct);
    }

    #[test]
    fn leaderboard_vuln_class_breakdown() {
        let suite = web_api_benchmark_suite();
        let run = generate_golden_baseline(&suite);
        let report = generate_leaderboard(&[suite.clone()], &[run]);

        assert!(!report.vuln_class_breakdown.is_empty());
        for vc in &report.vuln_class_breakdown {
            assert!(!vc.vuln_class.is_empty());
            assert!(vc.total_cases > 0);
            assert!(vc.precision >= 0.0 && vc.precision <= 1.0);
            assert!(vc.recall >= 0.0 && vc.recall <= 1.0);
        }
    }

    #[test]
    fn leaderboard_render_produces_markdown() {
        let suite = web_api_benchmark_suite();
        let run = generate_golden_baseline(&suite);
        let report = generate_leaderboard(&[suite], &[run]);

        let md = render_leaderboard(&report);
        assert!(md.contains("Leaderboard"));
        assert!(md.contains("Aggregate"));
        assert!(md.contains("Per-Run"));
        assert!(md.contains("Per-Vuln-Class"));
        assert!(md.contains("Per-Case"));
        assert!(md.contains("fixture"));
        assert!(md.contains("Precision"));
    }

    #[test]
    fn render_run_diff_shows_changes() {
        let suite = web_api_benchmark_suite();
        let baseline_run = generate_golden_baseline(&suite);
        let current_run = generate_golden_baseline(&suite);

        let baseline_report = generate_leaderboard(&[suite.clone()], &[baseline_run]);
        let current_report = generate_leaderboard(&[suite.clone()], &[current_run]);

        let diff = render_run_diff(&baseline_report, &current_report);
        assert!(diff.contains("Leaderboard Diff"));
        assert!(diff.contains("Aggregate Delta"));
    }

    #[test]
    fn leaderboard_attribution_tracks_provider() {
        let suite = web_api_benchmark_suite();
        let mut run = generate_golden_baseline(&suite);
        run.config_snapshot.provider = "anthropic".to_string();
        run.config_snapshot.model = "claude-sonnet-4-20250514".to_string();
        run.config_snapshot.prompt_version = "v2".to_string();
        run.config_snapshot.git_commit = "abc123".to_string();
        run.config_snapshot.corpus_hash = "sha256:abc".to_string();

        let report = generate_leaderboard(&[suite], &[run]);
        assert_eq!(report.attribution.provider, "anthropic");
        assert_eq!(report.attribution.model, "claude-sonnet-4-20250514");
        assert_eq!(report.attribution.prompt_version, "v2");
        assert_eq!(report.attribution.git_commit, "abc123");
        assert_eq!(report.attribution.corpus_hash, "sha256:abc");
    }

    #[test]
    fn save_and_load_leaderboard() {
        let suite = web_api_benchmark_suite();
        let run = generate_golden_baseline(&suite);
        let report = generate_leaderboard(&[suite], &[run]);

        let dir = std::env::temp_dir().join("baloncore-leaderboard-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("leaderboard.json");
        save_leaderboard(&report, &path).unwrap();
        let loaded = load_leaderboard(&path).unwrap();
        assert_eq!(loaded.report_id, report.report_id);
        assert_eq!(loaded.runs.len(), report.runs.len());
        assert!((loaded.aggregate.accuracy - report.aggregate.accuracy).abs() < 0.001);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn leaderboard_diff_detects_regression() {
        let suite = web_api_benchmark_suite();
        let baseline_run = generate_golden_baseline(&suite);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let bad_results: Vec<BenchmarkResult> = suite
            .cases
            .iter()
            .map(|case| BenchmarkResult {
                result_id: format!("result_{}", case.case_id),
                suite_id: suite.suite_id.clone(),
                case_id: case.case_id.clone(),
                domain: case.domain.clone(),
                actual_classification: None,
                actual_severity: None,
                actual_state: Some("hypothesis".to_string()),
                prediction: GroundTruthLabel::Inconclusive,
                confidence: 0.3,
                evidence_found: vec![],
                time_to_result_ms: 5000,
                error: Some("validator timeout".to_string()),
            })
            .collect();

        let current_run = BenchmarkRun {
            run_id: "bad_run".to_string(),
            suite_id: suite.suite_id.clone(),
            suite_version: suite.version.clone(),
            domain: suite.domain.clone(),
            started_at: now,
            completed_at: now + 5000,
            config_snapshot: BenchmarkConfig::default(),
            results: bad_results,
        };

        let baseline_report = generate_leaderboard(&[suite.clone()], &[baseline_run]);
        let current_report = generate_leaderboard(&[suite.clone()], &[current_run]);

        let diff = render_run_diff(&baseline_report, &current_report);
        assert!(diff.contains("Aggregate Delta"));
        assert!(current_report.aggregate.accuracy < baseline_report.aggregate.accuracy);
    }
}

#[cfg(test)]
mod p2s5_tests {
    use super::*;

    #[test]
    fn determinism_check_two_runs_identical_scores() {
        let suite = web_api_benchmark_suite();
        let result = verify_determinism(&suite, 2);
        assert!(
            result.scores_identical,
            "Two golden baseline runs should produce identical scores"
        );
        assert!(
            result.byte_identical_json || result.scores_identical,
            "Scores should be identical even if run IDs differ"
        );
        assert_eq!(result.runs_compared, 2);
    }

    #[test]
    fn determinism_check_three_runs_identical_scores() {
        let suite = cloud_iam_benchmark_suite();
        let result = verify_determinism(&suite, 3);
        assert!(
            result.scores_identical,
            "Three golden baseline runs should produce identical scores"
        );
        assert_eq!(result.runs_compared, 3);
    }

    #[test]
    fn determinism_check_insufficient_runs() {
        let suite = web_api_benchmark_suite();
        let result = verify_determinism(&suite, 1);
        assert!(!result.scores_identical, "1 run cannot be compared");
        assert_eq!(result.runs_compared, 0);
        assert!(result.details.contains("at least 2"));
    }

    #[test]
    fn determinism_render_produces_markdown() {
        let suite = web_api_benchmark_suite();
        let result = verify_determinism(&suite, 2);
        let md = render_determinism_check(&result);
        assert!(md.contains("Determinism Check"));
        assert!(md.contains("Scores Identical"));
        assert!(md.contains("Byte-Identical JSON"));
        assert!(md.contains("baseline"));
    }

    #[test]
    fn repetition_stats_three_runs() {
        let suite = web_api_benchmark_suite();
        let runs: Vec<BenchmarkRun> = (0..3).map(|_| generate_golden_baseline(&suite)).collect();
        let result = compute_repetition_stats(&suite, &runs);

        assert_eq!(result.k, 3);
        assert_eq!(result.run_ids.len(), 3);
        assert!(
            result.deterministic,
            "Golden baselines should be deterministic"
        );
        assert!(
            (result.accuracy_stats.stddev - 0.0).abs() < 0.0001,
            "Stddev should be 0 for deterministic runs"
        );
        assert!(
            (result.accuracy_stats.mean - 1.0).abs() < 0.0001,
            "Mean accuracy should be 1.0"
        );
    }

    #[test]
    fn repetition_stats_variance_detected() {
        let suite = web_api_benchmark_suite();
        let good_run = generate_golden_baseline(&suite);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let bad_results: Vec<BenchmarkResult> = suite
            .cases
            .iter()
            .map(|case| BenchmarkResult {
                result_id: format!("result_{}", case.case_id),
                suite_id: suite.suite_id.clone(),
                case_id: case.case_id.clone(),
                domain: case.domain.clone(),
                actual_classification: None,
                actual_severity: None,
                actual_state: Some("hypothesis".to_string()),
                prediction: GroundTruthLabel::Inconclusive,
                confidence: 0.3,
                evidence_found: vec![],
                time_to_result_ms: 8000,
                error: Some("timeout".to_string()),
            })
            .collect();

        let bad_run = BenchmarkRun {
            run_id: "bad_run".to_string(),
            suite_id: suite.suite_id.clone(),
            suite_version: suite.version.clone(),
            domain: suite.domain.clone(),
            started_at: now,
            completed_at: now + 5000,
            config_snapshot: BenchmarkConfig::default(),
            results: bad_results,
        };

        let result = compute_repetition_stats(&suite, &[good_run, bad_run]);
        assert_eq!(result.k, 2);
        assert!(
            !result.deterministic,
            "Mixed good/bad runs should not be deterministic"
        );
        assert!(
            result.accuracy_stats.stddev > 0.0,
            "Should detect variance in accuracy"
        );
    }

    #[test]
    fn repetition_render_produces_markdown() {
        let suite = web_api_benchmark_suite();
        let runs: Vec<BenchmarkRun> = (0..2).map(|_| generate_golden_baseline(&suite)).collect();
        let result = compute_repetition_stats(&suite, &runs);
        let md = render_repetition_result(&result);
        assert!(md.contains("Repetition Result"));
        assert!(md.contains("Metric Statistics"));
        assert!(md.contains("DETERMINISTIC"));
    }

    #[test]
    fn save_and_load_determinism_check() {
        let suite = web_api_benchmark_suite();
        let result = verify_determinism(&suite, 2);
        let dir = std::env::temp_dir().join("baloncore-determinism-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("determinism.json");
        save_determinism_check(&result, &path).unwrap();
        let loaded = load_determinism_check(&path).unwrap();
        assert_eq!(loaded.scores_identical, result.scores_identical);
        assert_eq!(loaded.runs_compared, result.runs_compared);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_and_load_repetition_result() {
        let suite = web_api_benchmark_suite();
        let runs: Vec<BenchmarkRun> = (0..2).map(|_| generate_golden_baseline(&suite)).collect();
        let result = compute_repetition_stats(&suite, &runs);
        let dir = std::env::temp_dir().join("baloncore-repetition-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("repetition.json");
        save_repetition_result(&result, &path).unwrap();
        let loaded = load_repetition_result(&path).unwrap();
        assert_eq!(loaded.k, result.k);
        assert_eq!(loaded.deterministic, result.deterministic);
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod p2s6_tests {
    use super::*;

    #[test]
    fn eval_gate_passes_golden_baseline() {
        let suite = web_api_benchmark_suite();
        let run = generate_golden_baseline(&suite);
        let result = eval_gate(&run, &suite, 0.70, 0, 0.10, None, None);
        assert!(
            result.passed,
            "Golden baseline should pass eval gate: {}",
            result.summary
        );
        assert!(
            result.decoy_false_positive_count == 0,
            "No decoy FPs expected"
        );
        assert!(result.recall_drop_violations.is_empty());
    }

    #[test]
    fn eval_gate_fails_on_low_precision() {
        let suite = web_api_benchmark_suite();
        let run = generate_golden_baseline(&suite);
        let result = eval_gate(&run, &suite, 1.01, 0, 0.10, None, None);
        assert!(!result.passed, "Impossible precision threshold should fail");
        assert!(result.summary.contains("precision"));
    }

    #[test]
    fn eval_gate_catches_decoy_false_positive() {
        let mut suite = web_api_benchmark_suite();
        let decoy_case = BenchmarkCase {
            case_id: "webapi-decoy-fake-vulnerability".to_string(),
            domain: BenchmarkDomain::WebApi,
            name: "Decoy: scanner flags non-existent vulnerability".to_string(),
            description: "A deliberately planted decoy that a naive scanner would flag."
                .to_string(),
            target: "/api/decoy/endpoint".to_string(),
            ground_truth: GroundTruthLabel::FalsePositive,
            expected_classification: Some("NoVulnerability".to_string()),
            expected_severity: Some("info".to_string()),
            expected_evidence_keys: vec![],
            difficulty: BenchmarkDifficulty::Basic,
            tags: vec!["decoy".to_string(), "bola".to_string()],
            fixture_path: None,
            metadata: BTreeMap::new(),
        };
        suite.cases.push(decoy_case);

        let mut run = generate_golden_baseline(&suite);
        let decoy_idx = run
            .results
            .iter()
            .position(|r| r.case_id == "webapi-decoy-fake-vulnerability")
            .expect("Should find decoy case result");
        run.results[decoy_idx].prediction = GroundTruthLabel::TruePositive;

        let result = eval_gate(&run, &suite, 0.70, 0, 0.10, None, None);
        assert!(
            !result.passed,
            "Should fail with decoy FP: passed={}, decoy_fps={}, summary={}",
            result.passed, result.decoy_false_positive_count, result.summary
        );
        assert!(
            result.decoy_false_positive_count > 0,
            "Should count decoy FP"
        );
    }

    #[test]
    fn eval_gate_detects_recall_drop_against_baseline() {
        let suite = web_api_benchmark_suite();
        let baseline_run = generate_golden_baseline(&suite);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let bad_results: Vec<BenchmarkResult> = suite
            .cases
            .iter()
            .map(|case| BenchmarkResult {
                result_id: format!("result_{}", case.case_id),
                suite_id: suite.suite_id.clone(),
                case_id: case.case_id.clone(),
                domain: case.domain.clone(),
                actual_classification: None,
                actual_severity: None,
                actual_state: Some("hypothesis".to_string()),
                prediction: GroundTruthLabel::Inconclusive,
                confidence: 0.3,
                evidence_found: vec![],
                time_to_result_ms: 5000,
                error: Some("timeout".to_string()),
            })
            .collect();

        let bad_run = BenchmarkRun {
            run_id: "bad_run".to_string(),
            suite_id: suite.suite_id.clone(),
            suite_version: suite.version.clone(),
            domain: suite.domain.clone(),
            started_at: now,
            completed_at: now + 5000,
            config_snapshot: BenchmarkConfig::default(),
            results: bad_results,
        };

        let result = eval_gate(
            &bad_run,
            &suite,
            0.0,
            100,
            0.10,
            Some(&baseline_run),
            Some(&suite),
        );
        assert!(
            !result.recall_drop_violations.is_empty(),
            "Should detect recall drop"
        );
        assert!(result.baseline_comparison.is_some());
    }

    #[test]
    fn eval_gate_render_produces_markdown() {
        let suite = web_api_benchmark_suite();
        let run = generate_golden_baseline(&suite);
        let result = eval_gate(&run, &suite, 0.70, 0, 0.10, None, None);
        let md = render_eval_gate_result(&result);
        assert!(md.contains("Eval Gate"));
        assert!(md.contains("PASSED"));
        assert!(md.contains("Decoy False Positives"));
    }

    #[test]
    fn eval_gate_render_with_baseline() {
        let suite = web_api_benchmark_suite();
        let baseline_run = generate_golden_baseline(&suite);
        let current_run = generate_golden_baseline(&suite);
        let result = eval_gate(
            &current_run,
            &suite,
            0.70,
            0,
            0.10,
            Some(&baseline_run),
            Some(&suite),
        );
        let md = render_eval_gate_result(&result);
        assert!(md.contains("Baseline Comparison"));
        assert!(md.contains("Precision"));
    }

    #[test]
    fn eval_gate_save_and_load() {
        let suite = web_api_benchmark_suite();
        let run = generate_golden_baseline(&suite);
        let result = eval_gate(&run, &suite, 0.70, 0, 0.10, None, None);
        let dir = std::env::temp_dir().join("baloncore-eval-gate-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("eval_gate.json");
        save_eval_gate_result(&result, &path).unwrap();
        let loaded = load_eval_gate_result(&path).unwrap();
        assert_eq!(loaded.passed, result.passed);
        assert_eq!(
            loaded.decoy_false_positive_count,
            result.decoy_false_positive_count
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn threshold_check_precision_failure() {
        let suite = web_api_benchmark_suite();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut results: Vec<BenchmarkResult> = suite
            .cases
            .iter()
            .map(|case| {
                let prediction = if case.ground_truth == GroundTruthLabel::TruePositive {
                    GroundTruthLabel::TruePositive
                } else {
                    GroundTruthLabel::TruePositive
                };
                BenchmarkResult {
                    result_id: format!("result_{}", case.case_id),
                    suite_id: suite.suite_id.clone(),
                    case_id: case.case_id.clone(),
                    domain: case.domain.clone(),
                    actual_classification: None,
                    actual_severity: None,
                    actual_state: None,
                    prediction,
                    confidence: 0.5,
                    evidence_found: vec![],
                    time_to_result_ms: 1000,
                    error: None,
                }
            })
            .collect();

        let run = BenchmarkRun {
            run_id: "low_precision_run".to_string(),
            suite_id: suite.suite_id.clone(),
            suite_version: suite.version.clone(),
            domain: suite.domain.clone(),
            started_at: now,
            completed_at: now + 5000,
            config_snapshot: BenchmarkConfig::default(),
            results,
        };

        let result = eval_gate(&run, &suite, 0.90, 100, 1.0, None, None);
        assert!(!result.passed, "Should fail due to low precision");
        assert!(result.summary.contains("precision"));
    }
}

#[cfg(test)]
mod p2s7_tests {
    use super::*;

    #[test]
    fn methodology_doc_generates_with_headline_numbers() {
        let suites = all_benchmark_suites();
        let runs: Vec<BenchmarkRun> = suites.iter().map(|s| generate_golden_baseline(s)).collect();
        let doc = generate_methodology_doc(&suites, &runs);

        assert!(doc.contains("BALONCORE Benchmark Methodology"));
        assert!(doc.contains("Headline Numbers"));
        assert!(doc.contains("100.0%"));
        assert!(doc.contains("web_api") || doc.contains("Web"));
        assert!(doc.contains("cloud_iam") || doc.contains("Cloud"));
        assert!(doc.contains("Determinism"));
        assert!(doc.contains("Limitations"));
        assert!(doc.contains("Ground Truth Distribution"));
        assert!(doc.contains("Difficulty Distribution"));
    }

    #[test]
    fn benchmark_doc_generates_with_results() {
        let suites = all_benchmark_suites();
        let runs: Vec<BenchmarkRun> = suites.iter().map(|s| generate_golden_baseline(s)).collect();
        let doc = generate_benchmark_doc(&suites, &runs);

        assert!(doc.contains("Diligence Documentation"));
        assert!(doc.contains("Verification"));
        assert!(doc.contains("run_benchmarks.sh"));
        assert!(doc.contains("Eval Gate Thresholds"));
        assert!(doc.contains("PASSED"));
        assert!(doc.contains("Decoy FP"));
    }

    #[test]
    fn methodology_doc_matches_scorecard_numbers() {
        let suite = web_api_benchmark_suite();
        let run = generate_golden_baseline(&suite);
        let metrics = compute_evaluation_metrics(&suite, &run);
        let scorecard = generate_scorecard(&suite, &run, None, None);

        let doc = generate_methodology_doc(&[suite.clone()], &[run]);

        let accuracy_str = format!("{:.1}%", metrics.accuracy * 100.0);
        assert!(
            doc.contains(&accuracy_str),
            "Methodology doc should contain accuracy {}",
            accuracy_str
        );

        let grade_str = scorecard.metrics.grade.as_str();
        assert!(
            doc.contains(grade_str),
            "Methodology doc should contain grade {}",
            grade_str
        );
    }

    #[test]
    fn benchmark_doc_includes_attribution() {
        let suites = all_benchmark_suites();
        let runs: Vec<BenchmarkRun> = suites.iter().map(|s| generate_golden_baseline(s)).collect();
        let doc = generate_benchmark_doc(&suites, &runs);

        assert!(doc.contains("Attribution"));
        assert!(doc.contains("provider"));
    }
}
