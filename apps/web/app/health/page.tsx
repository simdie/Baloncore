"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  MetricsSummary,
  MetricsTrend,
  MetricsDrilldown,
  api,
} from "../../lib/baloncore";

type DrillState = {
  metric: string;
  period: string | null;
};

function formatNum(value: number, decimals = 1): string {
  if (Number.isNaN(value) || !Number.isFinite(value)) return "—";
  if (value >= 1) return value.toFixed(decimals);
  if (value >= 0.01) return value.toFixed(2);
  return value.toFixed(3);
}

function formatMs(ms: number): string {
  if (ms <= 0 || !Number.isFinite(ms)) return "—";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function StatCard({
  label,
  value,
  unit,
  drill,
  onClick,
}: {
  label: string;
  value: string;
  unit?: string;
  drill?: DrillState | null;
  onClick?: (d: DrillState) => void;
}) {
  const clickable = drill && onClick;
  return (
    <button
      className="stat-card"
      disabled={!clickable}
      style={clickable ? { cursor: "pointer" } : { cursor: "default" }}
      onClick={() => clickable && onClick(drill)}
      type="button"
    >
      <span>{label}</span>
      <strong>{value}</strong>
      {unit && <small>{unit}</small>}
    </button>
  );
}

export default function HealthPage() {
  const [summary, setSummary] = useState<MetricsSummary | null>(null);
  const [trend, setTrend] = useState<MetricsTrend | null>(null);
  const [drilldown, setDrilldown] = useState<MetricsDrilldown | null>(null);
  const [drillTarget, setDrillTarget] = useState<DrillState | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [trendMetric, setTrendMetric] = useState("verified_findings");
  const [trendBucket, setTrendBucket] = useState("day");

  async function refreshSummary() {
    try {
      const data = await api<MetricsSummary>("/api/metrics/summary");
      setSummary(data);
      setError(null);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  async function refreshTrend(metric: string, bucket: string) {
    try {
      const data = await api<MetricsTrend>(
        `/api/metrics/trend?metric=${encodeURIComponent(metric)}&bucket=${encodeURIComponent(bucket)}`,
      );
      setTrend(data);
    } catch {
      setTrend(null);
    }
  }

  async function refreshDrilldown(target: DrillState) {
    setDrilldown(null);
    try {
      let url = `/api/metrics/drilldown?metric=${encodeURIComponent(target.metric)}`;
      if (target.period) url += `&period=${encodeURIComponent(target.period)}`;
      const data = await api<MetricsDrilldown>(url);
      setDrilldown(data);
    } catch {
      setDrilldown(null);
    }
  }

  function handleDrill(target: DrillState) {
    setDrillTarget(target);
    refreshDrilldown(target);
  }

  function handleTrendChange(metric: string, bucket: string) {
    setTrendMetric(metric);
    setTrendBucket(bucket);
    refreshTrend(metric, bucket);
  }

  useEffect(() => {
    refreshSummary();
    refreshTrend(trendMetric, trendBucket);
    const timer = window.setInterval(() => {
      refreshSummary();
      refreshTrend(trendMetric, trendBucket);
    }, 8000);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    refreshTrend(trendMetric, trendBucket);
  }, [trendMetric, trendBucket]);

  if (loading) {
    return (
      <main className="product-shell">
        <aside className="sidebar">
          <Link className="wordmark" href="/">
            BALONCORE
          </Link>
          <nav>
            <a href="#summary">Summary</a>
            <a href="#trends">Trends</a>
            <Link href="/dashboard">Dashboard</Link>
            <Link href="/admin">Admin</Link>
          </nav>
        </aside>
        <section className="workspace">
          <div className="panel-neo">
            <h2>Loading program health...</h2>
          </div>
        </section>
      </main>
    );
  }

  const s = summary ?? {
    total_scans: 0,
    total_findings: 0,
    verified_findings: 0,
    verified_findings_per_scan: 0,
    rejected_hypotheses: 0,
    false_positive_reduction_rate: 0,
    retest_success_rate: 0,
    ci_blocked_criticals: 0,
    model_calls_per_verified: 0,
    tokens_per_verified: 0,
    per_vuln_class: [],
    time_to_proof: { mean_ms: 0, median_ms: 0, p90_ms: 0, min_ms: 0, max_ms: 0, sample_count: 0 },
    time_to_fix: { mean_ms: 0, median_ms: 0, p90_ms: 0, min_ms: 0, max_ms: 0, sample_count: 0 },
  };

  const hasData = s.total_scans > 0;

  return (
    <main className="product-shell">
      <aside className="sidebar">
        <Link className="wordmark" href="/">
          BALONCORE
        </Link>
        <nav>
          <a href="#summary">Summary</a>
          <a href="#trends">Trends</a>
          <a href="#drilldown">Drill-down</a>
          <a href="#vuln">By class</a>
          <Link href="/dashboard">Dashboard</Link>
          <Link href="/admin">Admin</Link>
        </nav>
        <div className="side-status">
          <span>API</span>
          <strong>{error ? "error" : "connected"}</strong>
        </div>
      </aside>

      <section className="workspace">
        <header className="workspace-top">
          <div>
            <span className="eyebrow">Program Health</span>
            <h1>Metrics &amp; evidence trends</h1>
          </div>
        </header>

        {error && (
          <div className="panel-neo" style={{ borderColor: "var(--rose)" }}>
            <h2>Connection error</h2>
            <p style={{ color: "var(--rose)" }}>{error}</p>
          </div>
        )}

        <section className="stat-grid board-metrics" id="summary">
          <StatCard
            label="Verified findings / scan"
            value={hasData ? formatNum(s.verified_findings_per_scan) : "—"}
            unit={hasData ? "avg" : undefined}
            drill={hasData ? { metric: "verified_findings", period: null } : null}
            onClick={handleDrill}
          />
          <StatCard
            label="FP reduction rate"
            value={hasData ? formatNum(s.false_positive_reduction_rate * 100, 0) : "—"}
            unit={hasData ? "%" : undefined}
            drill={hasData ? { metric: "rejected_hypotheses", period: null } : null}
            onClick={handleDrill}
          />
          <StatCard
            label="Median time-to-proof"
            value={hasData ? formatMs(s.time_to_proof.median_ms) : "—"}
            unit={hasData && s.time_to_proof.sample_count > 0 ? `n=${s.time_to_proof.sample_count}` : undefined}
            drill={hasData ? { metric: "verified_findings", period: null } : null}
            onClick={handleDrill}
          />
          <StatCard
            label="Retest success rate"
            value={hasData ? formatNum(s.retest_success_rate * 100, 0) : "—"}
            unit={hasData ? "%" : undefined}
            drill={hasData ? { metric: "verified_findings", period: null } : null}
            onClick={handleDrill}
          />
          <StatCard
            label="CI-blocked criticals"
            value={hasData ? String(s.ci_blocked_criticals) : "—"}
            drill={hasData ? { metric: "verified_findings", period: null } : null}
            onClick={handleDrill}
          />
        </section>

        {!hasData && (
          <div className="panel-neo">
            <h2>No metrics data yet</h2>
            <p>Run an indexed scan with <code>baloncore index-evidence-run</code> to populate program health metrics. Every number on this page traces to source evidence.</p>
          </div>
        )}

        <section className="panel-neo" id="trends">
          <div className="panel-head">
            <h2>Time-series trends</h2>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <select
                value={trendMetric}
                onChange={(e) => handleTrendChange(e.target.value, trendBucket)}
                style={{ width: "auto", padding: "6px 10px", fontSize: 13 }}
              >
                <option value="verified_findings">Verified findings</option>
                <option value="rejected_hypotheses">Rejected hypotheses</option>
                <option value="suppressed_findings">Suppressed findings</option>
                <option value="total_candidates">Total candidates</option>
              </select>
              <select
                value={trendBucket}
                onChange={(e) => handleTrendChange(trendMetric, e.target.value)}
                style={{ width: "auto", padding: "6px 10px", fontSize: 13 }}
              >
                <option value="hour">Hour</option>
                <option value="day">Day</option>
                <option value="week">Week</option>
                <option value="month">Month</option>
              </select>
            </div>
          </div>

          {!trend || trend.points.length === 0 ? (
            <div className="trend-empty">
              <p>No trend data for this metric and bucket. Index scan runs to populate trends.</p>
            </div>
          ) : (
            <div className="trend-table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Period</th>
                    <th>Value</th>
                    <th>Scans</th>
                  </tr>
                </thead>
                <tbody>
                  {trend.points.map((point) => (
                    <tr key={point.period}>
                      <td>{point.period}</td>
                      <td className="trend-value">{formatNum(point.value)}</td>
                      <td>{point.sample_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {hasData && s.time_to_proof.sample_count > 0 && (
          <section className="panel-neo">
            <div className="panel-head">
              <h2>Time-to-proof distribution</h2>
              <span className="mini-pill">n={s.time_to_proof.sample_count}</span>
            </div>
            <div className="time-bar-grid">
              <div className="time-bar-row">
                <span>Min</span>
                <strong>{formatMs(s.time_to_proof.min_ms)}</strong>
              </div>
              <div className="time-bar-row">
                <span>Median</span>
                <strong>{formatMs(s.time_to_proof.median_ms)}</strong>
              </div>
              <div className="time-bar-row">
                <span>p90</span>
                <strong>{formatMs(s.time_to_proof.p90_ms)}</strong>
              </div>
              <div className="time-bar-row">
                <span>Max</span>
                <strong>{formatMs(s.time_to_proof.max_ms)}</strong>
              </div>
            </div>
          </section>
        )}

        {hasData && s.per_vuln_class.length > 0 && (
          <section className="panel-neo" id="vuln">
            <div className="panel-head">
              <h2>By vulnerability class</h2>
              <span className="mini-pill">{s.per_vuln_class.length} classes</span>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Class</th>
                    <th>Verified</th>
                    <th>Rejected</th>
                    <th>Suppressed</th>
                    <th>FP reduction</th>
                    <th>Time-to-proof</th>
                  </tr>
                </thead>
                <tbody>
                  {s.per_vuln_class.map((vc) => (
                    <tr key={vc.vuln_class}>
                      <td><span className="mini-pill">{vc.vuln_class}</span></td>
                      <td>{vc.verified}</td>
                      <td>{vc.rejected}</td>
                      <td>{vc.suppressed}</td>
                      <td>{formatNum(vc.fp_reduction_rate * 100, 0)}%</td>
                      <td>{formatMs(vc.time_to_proof_ms)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        <section className="panel-neo" id="drilldown">
          <div className="panel-head">
            <h2>Drill-down</h2>
            {drillTarget && (
              <span className="mini-pill">
                {drillTarget.metric}
                {drillTarget.period ? ` / ${drillTarget.period}` : ""}
              </span>
            )}
          </div>

          {drillTarget ? (
            drilldown ? (
              drilldown.entries.length === 0 ? (
                <p>No source entries for this metric.</p>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Scan</th>
                        <th>Metric</th>
                        <th>Value</th>
                        <th>Findings</th>
                        <th>Started</th>
                      </tr>
                    </thead>
                    <tbody>
                      {drilldown.entries.map((entry) => (
                        <tr key={entry.scan_id}>
                          <td className="path">{entry.scan_id}</td>
                          <td>{entry.metric}</td>
                          <td className="trend-value">{formatNum(entry.value)}</td>
                          <td>{entry.findings_count}</td>
                          <td>{entry.started_at ? new Date(entry.started_at * 1000).toLocaleDateString() : "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )
            ) : (
              <p>Loading drill-down...</p>
            )
          ) : (
            <p>Click any headline metric above to see the source runs and findings that produced it. Every number traces to evidence.</p>
          )}
        </section>

        <section className="panel-neo">
          <h2>Model efficiency</h2>
          <div className="stat-grid" style={{ marginTop: 12 }}>
            <StatCard
              label="Model calls / verified"
              value={hasData && s.model_calls_per_verified > 0 ? formatNum(s.model_calls_per_verified, 0) : "—"}
              drill={hasData ? { metric: "verified_findings", period: null } : null}
              onClick={handleDrill}
            />
            <StatCard
              label="Tokens / verified"
              value={hasData && s.tokens_per_verified > 0 ? formatNum(s.tokens_per_verified, 0) : "—"}
              drill={hasData ? { metric: "verified_findings", period: null } : null}
              onClick={handleDrill}
            />
            <StatCard
              label="Total scans"
              value={hasData ? String(s.total_scans) : "—"}
            />
            <StatCard
              label="Total findings"
              value={hasData ? String(s.total_findings) : "—"}
            />
          </div>
        </section>
      </section>
    </main>
  );
}