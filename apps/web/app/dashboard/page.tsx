"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  Artifact,
  ArtifactPreview,
  CommandCenter,
  JobRecord,
  SaasOverview,
  StatusPayload,
  api,
  compactPath,
  readinessLabel,
} from "../../lib/baloncore";

export default function DashboardPage() {
  const [status, setStatus] = useState<StatusPayload | null>(null);
  const [jobs, setJobs] = useState<JobRecord[]>([]);
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [overview, setOverview] = useState<SaasOverview | null>(null);
  const [command, setCommand] = useState<CommandCenter | null>(null);
  const [preview, setPreview] = useState<ArtifactPreview | null>(null);
  const [busy, setBusy] = useState(false);
  const [output, setOutput] = useState("Ready for authorized validation.");
  const [repoPath, setRepoPath] = useState("");
  const [baseUrl, setBaseUrl] = useState("http://127.0.0.1:3000");
  const [openapiUrl, setOpenapiUrl] = useState("http://127.0.0.1:3000/openapi.json");
  const [ownerProfile, setOwnerProfile] = useState("user_b");

  const latest = jobs[0];
  const score =
    command?.proof_twin.score ??
    latest?.result?.run_intelligence?.score ??
    overview?.summary.latest_score ??
    0;
  const readiness = readinessLabel(
    command?.proof_twin.readiness ?? latest?.result?.run_intelligence?.readiness,
  );
  const research = command?.research_engine;
  const topHypotheses = research?.hypotheses.slice(0, 6) ?? [];
  const topProofPlans = research?.proof_plans.slice(0, 5) ?? [];
  const blockingChallenges = research?.challenges.filter((challenge) => challenge.blocking) ?? [];
  const signalCards = useMemo(() => {
    const signals = command?.proof_twin.signals ?? latest?.result?.run_intelligence?.signals ?? {};
    return [
      ["Verified findings", signals.verified_webapi_findings ?? 0],
      ["Proof packages", signals.proof_packages ?? 0],
      ["Evidence manifests", signals.evidence_manifests ?? 0],
      ["Defense artifacts", signals.remediation_artifacts ?? 0],
    ];
  }, [command, latest]);

  async function refreshAll() {
    const [statusData, jobsData, artifactsData, overviewData, commandData] =
      await Promise.all([
        api<StatusPayload>("/api/status"),
        api<{ jobs: JobRecord[] }>("/api/jobs"),
        api<{ artifacts: Artifact[] }>("/api/artifacts"),
        api<SaasOverview>("/api/saas/overview"),
        api<CommandCenter>("/api/security/command-center"),
      ]);
    setStatus(statusData);
    setJobs(jobsData.jobs ?? []);
    setArtifacts(artifactsData.artifacts ?? []);
    setOverview(overviewData);
    setCommand(commandData);
    if (!repoPath && statusData.workbench_root) {
      setRepoPath(statusData.workbench_root.replace(/\/\.baloncore\/workbench$/, ""));
    }
  }

  useEffect(() => {
    refreshAll().catch((error) => setOutput(String(error)));
    const timer = window.setInterval(() => {
      refreshAll().catch(() => undefined);
    }, 4000);
    return () => window.clearInterval(timer);
  }, []);

  async function submitJob(type: "repo_scan" | "webapi_scan", payload: Record<string, unknown>) {
    setBusy(true);
    setPreview(null);
    try {
      const job = await api<JobRecord>("/api/jobs", {
        method: "POST",
        body: JSON.stringify({ type, payload }),
      });
      setOutput(`Queued ${job.job_id}`);
      await refreshAll();
    } catch (error) {
      setOutput(String(error));
    } finally {
      setBusy(false);
    }
  }

  function submitRepo(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    submitJob("repo_scan", { authorized: true, path: repoPath });
  }

  function submitWeb(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    submitJob("webapi_scan", {
      authorized: true,
      base_url: baseUrl,
      openapi_url: openapiUrl,
      owner_profile: ownerProfile,
      noise_mode: "quiet",
      max_active_requests: 250,
    });
  }

  async function inspectArtifact(path: string) {
    setBusy(true);
    try {
      const data = await api<ArtifactPreview>(`/api/artifact?path=${encodeURIComponent(path)}`);
      setPreview(data);
      setOutput(JSON.stringify(data.json ?? data, null, 2));
    } catch (error) {
      setOutput(String(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="product-shell">
      <aside className="sidebar">
        <Link className="wordmark" href="/">
          BALONCORE
        </Link>
        <nav>
          <a href="#overview">Overview</a>
          <a href="#run">Run Center</a>
          <a href="#proof">Proof</a>
          <a href="#research">Research</a>
          <a href="#board">Board</a>
          <a href="#risk">Risk</a>
          <a href="#defense">Defense</a>
          <a href="#rules">Rules</a>
          <a href="#artifacts">Artifacts</a>
          <Link href="/health">Health</Link>
          <Link href="/admin">Admin</Link>
        </nav>
        <div className="side-status">
          <span>API</span>
          <strong>{status?.mode ?? "connecting"}</strong>
        </div>
      </aside>

      <section className="workspace">
        <header className="workspace-top">
          <div>
            <span className="eyebrow">Customer workspace</span>
            <h1>Autonomous proof operations</h1>
          </div>
          <Link className="secondary-action" href="/login">
            Switch account
          </Link>
        </header>

        <section className="proof-hero" id="overview">
          <div>
            <span className="eyebrow">Proof Twin</span>
            <h2>{score}/100 exploitability confidence</h2>
            <p>{command?.proof_twin.policy ?? "Deterministic validation is the source of truth."}</p>
          </div>
          <div className="score-ring">
            <strong>{score}</strong>
            <span>{readiness}</span>
          </div>
        </section>

        <section className="stat-grid">
          {signalCards.map(([label, value]) => (
            <div className="stat-card" key={label}>
              <span>{label}</span>
              <strong>{value}</strong>
            </div>
          ))}
        </section>

        <section className="two-column" id="board">
          <div className="panel-neo board-brief">
            <div className="panel-head">
              <h2>Board-ready security brief</h2>
              <span className="mini-pill">{readinessLabel(command?.executive_brief?.verdict)}</span>
            </div>
            <p>{command?.executive_brief?.headline}</p>
            <div className="brief-risk">
              <span>{command?.executive_brief?.top_risk?.severity ?? "Info"}</span>
              <strong>{command?.executive_brief?.top_risk?.title ?? "No promoted risk yet"}</strong>
              <em>{command?.executive_brief?.top_risk?.surface ?? "Coverage"}</em>
            </div>
            <small>{command?.executive_brief?.assurance_statement}</small>
          </div>

          <div className="panel-neo board-brief">
            <h2>Next 72 hours</h2>
            <div className="action-stack">
              {(command?.executive_brief?.next_72_hours ?? []).map((item) => (
                <div className="action-row" key={item}>
                  <span />
                  <p>{item}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="stat-grid board-metrics">
          {(command?.executive_brief?.board_metrics ?? []).map((metric) => (
            <div className="stat-card" key={metric.label}>
              <span>{metric.label}</span>
              <strong>{metric.value}</strong>
              <small>{metric.unit}</small>
            </div>
          ))}
        </section>

        <section className="two-column" id="run">
          <div className="panel-neo">
            <h2>Authorized web/API validation</h2>
            <form onSubmit={submitWeb}>
              <label htmlFor="baseUrl">Base URL</label>
              <input id="baseUrl" onChange={(e) => setBaseUrl(e.target.value)} value={baseUrl} />
              <label htmlFor="openapiUrl">OpenAPI URL</label>
              <input
                id="openapiUrl"
                onChange={(e) => setOpenapiUrl(e.target.value)}
                value={openapiUrl}
              />
              <label htmlFor="ownerProfile">Owner profile</label>
              <input
                id="ownerProfile"
                onChange={(e) => setOwnerProfile(e.target.value)}
                value={ownerProfile}
              />
              <div className="scope-line">
                <input checked readOnly type="checkbox" />
                <span>Authorized scope confirmed</span>
              </div>
              <button disabled={busy} type="submit">
                Launch proof run
              </button>
            </form>
          </div>

          <div className="panel-neo">
            <h2>Repository and Web3 review</h2>
            <form onSubmit={submitRepo}>
              <label htmlFor="repoPath">Repository path</label>
              <input id="repoPath" onChange={(e) => setRepoPath(e.target.value)} value={repoPath} />
              <div className="scope-line">
                <input checked readOnly type="checkbox" />
                <span>Repository authorization confirmed</span>
              </div>
              <button disabled={busy || !repoPath} type="submit">
                Run repo intelligence
              </button>
            </form>
          </div>
        </section>

        <section className="panel-neo" id="proof">
          <div className="panel-head">
            <h2>Autonomous security lanes</h2>
            <button className="ghost-button" onClick={refreshAll} type="button">
              Refresh
            </button>
          </div>
          <div className="lane-grid">
            {(command?.autonomous_lanes ?? []).map((lane) => (
              <div className="lane-card" key={lane.lane}>
                <div>
                  <h3>{lane.lane}</h3>
                  <span>{lane.state}</span>
                </div>
                <p>{lane.role}</p>
                <strong>{lane.confidence}%</strong>
              </div>
            ))}
          </div>
        </section>

        <section className="panel-neo research-engine" id="research">
          <div className="panel-head">
            <div>
              <span className="eyebrow">Autonomous research engine</span>
              <h2>Recon graph to proof queue</h2>
            </div>
            <span className="mini-pill">
              {research?.summary.readiness_score ?? 0}/100 research readiness
            </span>
          </div>
          <div className="research-summary-grid">
            {[
              ["Recon nodes", research?.summary.recon_nodes ?? 0],
              ["Hypotheses", research?.summary.hypotheses ?? 0],
              ["Proof plans", research?.summary.proof_plans ?? 0],
              ["Blocking challenges", research?.summary.blocking_challenges ?? 0],
            ].map(([label, value]) => (
              <div className="research-metric" key={label}>
                <span>{label}</span>
                <strong>{value}</strong>
              </div>
            ))}
          </div>

          <div className="research-workbench">
            <div className="research-column">
              <div className="mini-head">
                <h3>Hypothesis forge</h3>
                <span>{topHypotheses.length} queued</span>
              </div>
              <div className="hypothesis-stack">
                {topHypotheses.map((hypothesis) => (
                  <article className="hypothesis-card" key={hypothesis.id}>
                    <div>
                      <span>{hypothesis.class}</span>
                      <strong>{hypothesis.confidence}%</strong>
                    </div>
                    <h4>{hypothesis.title}</h4>
                    <p>{hypothesis.target}</p>
                    <small>{hypothesis.expected_validator}</small>
                  </article>
                ))}
              </div>
            </div>

            <div className="research-column">
              <div className="mini-head">
                <h3>Proof executor</h3>
                <span>{topProofPlans.length} plans</span>
              </div>
              <div className="proof-plan-list">
                {topProofPlans.map((plan) => (
                  <article className="proof-plan-row" key={plan.id}>
                    <div>
                      <strong>{plan.validator}</strong>
                      <span>{plan.mode}</span>
                    </div>
                    <p>{plan.hypothesis_id}</p>
                    <small>{plan.active_requests_budget} active request budget</small>
                  </article>
                ))}
              </div>
            </div>

            <div className="research-column">
              <div className="mini-head">
                <h3>False-positive killer</h3>
                <span>{blockingChallenges.length} blocking</span>
              </div>
              <div className="challenge-list">
                {(blockingChallenges.length ? blockingChallenges : research?.challenges.slice(0, 5) ?? [])
                  .slice(0, 5)
                  .map((challenge) => (
                    <article
                      className={`challenge-row ${challenge.blocking ? "challenge-blocking" : ""}`}
                      key={`${challenge.hypothesis_id}-${challenge.challenge_type}`}
                    >
                      <span>{challenge.challenge_type}</span>
                      <p>{challenge.reason}</p>
                    </article>
                  ))}
              </div>
            </div>
          </div>

          <div className="research-bottom">
            <div>
              <h3>Surface pressure</h3>
              <div className="surface-strip">
                {Object.entries(research?.summary.surface_counts ?? {}).map(([surface, count]) => (
                  <span key={surface}>
                    {surface}: {count}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <h3>Next proof moves</h3>
              <div className="action-stack compact-actions">
                {(research?.next_actions ?? []).slice(0, 4).map((item) => (
                  <div className="action-row" key={item}>
                    <span />
                    <p>{item}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section className="two-column">
          <div className="panel-neo">
            <div className="panel-head">
              <h2>Exploitability attack graph</h2>
              <span className="mini-pill">risk pressure {command?.attack_graph?.risk_pressure ?? 0}</span>
            </div>
            <p className="panel-copy">{command?.attack_graph?.moat}</p>
            <div className="graph-grid">
              {(command?.attack_graph?.nodes ?? []).map((node) => (
                <div className={`graph-node graph-${node.kind}`} key={node.id}>
                  <span>{node.kind}</span>
                  <strong>{node.label}</strong>
                  <em>{node.state}</em>
                </div>
              ))}
            </div>
          </div>

          <div className="panel-neo">
            <h2>Policy gates</h2>
            <div className="gate-list">
              {(command?.policy_gates?.gates ?? []).map((gate) => (
                <div className={`gate-row gate-${gate.status}`} key={gate.name}>
                  <span>{gate.status}</span>
                  <strong>{gate.name}</strong>
                  <p>{gate.detail}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="panel-neo" id="risk">
          <div className="panel-head">
            <h2>Risk register</h2>
            <span className="mini-pill">{command?.risk_register?.count ?? 0} tracked risks</span>
          </div>
          <div className="risk-grid">
            {(command?.risk_register?.risks ?? []).slice(0, 6).map((risk) => (
              <article className={`risk-card risk-${risk.severity.toLowerCase()}`} key={risk.id}>
                <div>
                  <span>{risk.severity}</span>
                  <strong>
                    {risk.surface} · {risk.recurrence_count ?? 1}x
                  </strong>
                </div>
                <h3>{risk.title}</h3>
                <p>{risk.evidence}</p>
                <small>{risk.next_action}</small>
              </article>
            ))}
          </div>
        </section>

        <section className="panel-neo" id="defense">
          <div className="panel-head">
            <h2>Proof-to-Defense Autopilot</h2>
            <span className="mini-pill">{command?.defense_plan?.actions.length ?? 0} actions</span>
          </div>
          <div className="defense-grid">
            {(command?.defense_plan?.actions ?? []).map((action) => (
              <article className="defense-card" key={action.id}>
                <span>{action.priority}</span>
                <h3>{action.title}</h3>
                <p>{action.impact}</p>
                <small>
                  {action.owner} · {action.status}
                </small>
              </article>
            ))}
          </div>
        </section>

        <section className="panel-neo" id="rules">
          <div className="panel-head">
            <h2>Defense rule packs</h2>
            <span className="mini-pill">{command?.defense_rules?.count ?? 0} generated</span>
          </div>
          <div className="rule-grid">
            {(command?.defense_rules?.packs ?? []).map((pack) => (
              <article className="rule-card" key={pack.id}>
                <div>
                  <span>{pack.priority}</span>
                  <strong>{pack.surface}</strong>
                  <em>{pack.status}</em>
                </div>
                <h3>{pack.name}</h3>
                <p>{pack.summary}</p>
                <code>{pack.snippet}</code>
                <small>{pack.outputs.join(" / ")}</small>
              </article>
            ))}
          </div>
        </section>

        <section className="panel-neo">
          <div className="panel-head">
            <h2>Sector threat model</h2>
            <span className="mini-pill">buyer-aware controls</span>
          </div>
          <p className="panel-copy">{command?.sector_threat_model?.positioning}</p>
          <div className="sector-grid">
            {(command?.sector_threat_model?.packs ?? []).map((pack) => (
              <article className="sector-card" key={pack.sector}>
                <span>{pack.sector}</span>
                <h3>{pack.focus}</h3>
                <p>{pack.baloncore_edge}</p>
                <small>{pack.primary_controls.join(" / ")}</small>
              </article>
            ))}
          </div>
        </section>

        <section className="panel-neo">
          <h2>Durable job ledger</h2>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Job</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Score</th>
                  <th>Readiness</th>
                  <th>Run</th>
                </tr>
              </thead>
              <tbody>
                {jobs.slice(0, 10).map((job) => (
                  <tr key={job.job_id}>
                    <td>{job.job_id}</td>
                    <td>{job.type}</td>
                    <td className={job.status === "succeeded" ? "status-good" : "status-warn"}>
                      {job.status}
                    </td>
                    <td>{job.result?.run_intelligence?.score ?? ""}</td>
                    <td>{readinessLabel(job.result?.run_intelligence?.readiness)}</td>
                    <td className="path">{compactPath(job.result?.run_dir)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="two-column" id="artifacts">
          <div className="panel-neo">
            <h2>Evidence artifacts</h2>
            <div className="artifact-list">
              {artifacts.slice(0, 12).map((artifact) => (
                <button
                  className="artifact-row"
                  disabled={busy}
                  key={artifact.path}
                  onClick={() => inspectArtifact(artifact.path)}
                  type="button"
                >
                  <span>{artifact.kind}</span>
                  <strong>{compactPath(artifact.relative_path)}</strong>
                </button>
              ))}
            </div>
          </div>
          <div className="panel-neo output-panel">
            <h2>{preview ? `Preview: ${preview.kind}` : "Operator output"}</h2>
            <pre>{preview?.text ?? output}</pre>
          </div>
        </section>
      </section>
    </main>
  );
}
