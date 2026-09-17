#!/usr/bin/env python3
"""Combine the five external-corpus benchmark runs into one scorecard/leaderboard.

Reads each target's BenchmarkRun JSON (produced by the bench-* commands) plus its
case.toml, and emits:
  - a per-target table: pinned commit, confirmed SPDX license, precision, recall,
    decoy false-positives, counts;
  - an aggregate row;
  - a machine-readable JSON leaderboard.

Pure reporting: it never invents results — if a run file is missing it says so.
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TARGETS = [
    ("VAmPI", "REST API BOLA (vulnerable/secure toggle)",
     ".baloncore/bench-vampi/benchmark_run.json", "benchmarks/cases/vampi-bola-books/case.toml"),
    ("DVGA", "GraphQL JWT-identity auth bypass",
     ".baloncore/bench-dvga/benchmark_run.json", "benchmarks/cases/dvga-graphql-bola/case.toml"),
    ("crAPI", "Multi-service vehicle-location BOLA",
     ".baloncore/bench-crapi/benchmark_run.json", "benchmarks/cases/crapi-bola-vehicle/case.toml"),
    ("TerraGoat", "Offline Terraform HCL (public SG + over-priv IAM)",
     ".baloncore/bench-terragoat/benchmark_run.json", "benchmarks/cases/terragoat-iam/case.toml"),
    ("Cfngoat", "Offline CloudFormation (public SG + over-priv IAM)",
     ".baloncore/bench-cfngoat/benchmark_run.json", "benchmarks/cases/cfngoat-iam/case.toml"),
]


def toml_get(path, key):
    try:
        with open(os.path.join(ROOT, path)) as f:
            for line in f:
                m = re.match(rf'\s*{re.escape(key)}\s*=\s*"([^"]*)"', line)
                if m:
                    return m.group(1)
    except FileNotFoundError:
        return None
    return None


def score(run):
    """Confusion-matrix counts + metrics from a BenchmarkRun's results."""
    tp = fp = fn = tn = 0
    decoy_fp = 0
    for r in run["results"]:
        p = r["prediction"]
        if p == "TruePositive":
            tp += 1
        elif p == "FalsePositive":
            fp += 1
            decoy_fp += 1
        elif p == "FalseNegative":
            fn += 1
        elif p == "TrueNegative":
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, decoy_fp=decoy_fp,
                decoy_total=tn + fp,  # decoys are the TrueNegative-labelled probes
                precision=precision, recall=recall)


rows = []
agg = dict(tp=0, fp=0, fn=0, tn=0, decoy_fp=0, decoy_total=0)
missing = []
for name, desc, run_path, case_path in TARGETS:
    full = os.path.join(ROOT, run_path)
    if not os.path.exists(full):
        missing.append((name, run_path))
        continue
    with open(full) as f:
        run = json.load(f)
    s = score(run)
    commit = toml_get(case_path, "source_commit") or "?"
    lic = toml_get(case_path, "license") or "?"
    rows.append((name, desc, commit, lic, s, len(run["results"])))
    for k in agg:
        agg[k] += s[k]

agg_precision = agg["tp"] / (agg["tp"] + agg["fp"]) if (agg["tp"] + agg["fp"]) else 1.0
agg_recall = agg["tp"] / (agg["tp"] + agg["fn"]) if (agg["tp"] + agg["fn"]) else 1.0

out = []
out.append("# BALONCORE External Benchmark Corpus — Combined Scorecard\n")
out.append("Each target: brought up (or parsed offline) by its `bench-*` command, probed through the\n"
           "real validator/analyzer, and scored against a hand-labelled ground truth with realistic\n"
           "decoys. Precision/recall are over the curated probes; decoy-FP counts correctly-configured\n"
           "or bug-off probes that were wrongly flagged.\n")
out.append("\n| Target | Vertical | Pinned commit | SPDX license | P | R | TP | FN | Decoy-FP |")
out.append("|---|---|---|---|---|---|---|---|---|")
for name, desc, commit, lic, s, n in rows:
    out.append(f"| {name} | {desc} | `{commit[:12]}` | {lic} | "
               f"{s['precision']*100:.0f}% | {s['recall']*100:.0f}% | {s['tp']} | {s['fn']} | "
               f"{s['decoy_fp']}/{s['decoy_total']} |")
out.append(f"| **AGGREGATE** | 5 targets | — | — | "
           f"**{agg_precision*100:.0f}%** | **{agg_recall*100:.0f}%** | "
           f"**{agg['tp']}** | **{agg['fn']}** | **{agg['decoy_fp']}/{agg['decoy_total']}** |")

out.append("\n## Per-probe detail\n")
for name, desc, commit, lic, s, n in rows:
    out.append(f"- **{name}**: {s['tp']} TP, {s['tn']} TN, {s['fp']} FP, {s['fn']} FN "
               f"({n} probes) — commit `{commit[:12]}`, license `{lic}`")

if missing:
    out.append("\n## MISSING runs (bench-* not run / artifact absent)\n")
    for name, p in missing:
        out.append(f"- {name}: {p} not found — run the corresponding bench-* command.")

leaderboard = {
    "corpus": "baloncore-external-p2s3",
    "targets": [
        dict(name=name, vertical=desc, source_commit=commit, license=lic,
             precision=s["precision"], recall=s["recall"],
             tp=s["tp"], fp=s["fp"], fn=s["fn"], tn=s["tn"],
             decoy_fp=s["decoy_fp"], decoy_total=s["decoy_total"], probes=n)
        for name, desc, commit, lic, s, n in rows
    ],
    "aggregate": dict(precision=agg_precision, recall=agg_recall, **agg),
}

md = "\n".join(out) + "\n"
print(md)
out_dir = os.path.join(ROOT, ".baloncore", "corpus-scorecard")
os.makedirs(out_dir, exist_ok=True)
with open(os.path.join(out_dir, "combined_scorecard.md"), "w") as f:
    f.write(md)
with open(os.path.join(out_dir, "leaderboard.json"), "w") as f:
    json.dump(leaderboard, f, indent=2)
print(f"\n(written to {out_dir}/combined_scorecard.md and leaderboard.json)")
if missing:
    sys.exit(1)
