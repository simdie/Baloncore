"use client";

import { FormEvent, useEffect, useState } from "react";
import Link from "next/link";
import {
  BackboneStatus,
  CommandCenter,
  CustomerRecord,
  SaasOverview,
  WorkerQueue,
  api,
  readinessLabel,
} from "../../lib/baloncore";

export default function AdminPage() {
  const [overview, setOverview] = useState<SaasOverview | null>(null);
  const [command, setCommand] = useState<CommandCenter | null>(null);
  const [backbone, setBackbone] = useState<BackboneStatus | null>(null);
  const [queue, setQueue] = useState<WorkerQueue | null>(null);
  const [status, setStatus] = useState("Loading BALONCORE SaaS control plane...");
  const [form, setForm] = useState({
    company_name: "Helio Systems",
    contact_email: "security@helio.example",
    sector: "SaaS",
    plan: "Growth",
    asset_count: 22,
  });

  async function refresh() {
    const [data, commandData, backboneData, queueData] = await Promise.all([
      api<SaasOverview>("/api/saas/overview"),
      api<CommandCenter>("/api/security/command-center"),
      api<BackboneStatus>("/api/saas/backbone"),
      api<WorkerQueue>("/api/workers/queue"),
    ]);
    setOverview(data);
    setCommand(commandData);
    setBackbone(backboneData);
    setQueue(queueData);
    setStatus("Control plane synced.");
  }

  useEffect(() => {
    refresh().catch((error) => setStatus(String(error)));
  }, []);

  async function onboard(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setStatus("Creating organization...");
    try {
      const record = await api<CustomerRecord>("/api/saas/onboard", {
        method: "POST",
        body: JSON.stringify(form),
      });
      setStatus(`Onboarded ${record.company_name}. Scope contract pending.`);
      await refresh();
    } catch (error) {
      setStatus(String(error));
    }
  }

  async function approveScope(orgId: string) {
    setStatus("Signing scope contract...");
    try {
      const record = await api<CustomerRecord>("/api/saas/scope-contract", {
        method: "POST",
        body: JSON.stringify({
          org_id: orgId,
          scope_contract: "signed",
          authorized_assets: ["api", "web_app", "repository", "cloud_iam"],
        }),
      });
      setStatus(`Scope contract signed for ${record.company_name}.`);
      await refresh();
    } catch (error) {
      setStatus(String(error));
    }
  }

  return (
    <main className="product-shell">
      <aside className="sidebar admin-side">
        <Link className="wordmark" href="/">
          BALONCORE
        </Link>
        <nav>
          <a href="#command">Command</a>
          <a href="#backbone">Backbone</a>
          <a href="#workers">Workers</a>
          <a href="#companies">Companies</a>
          <a href="#audit">Audit</a>
          <a href="#plans">Plans</a>
          <Link href="/dashboard">Customer view</Link>
        </nav>
        <div className="side-status">
          <span>Mode</span>
          <strong>{overview?.mode ?? "syncing"}</strong>
        </div>
      </aside>

      <section className="workspace">
        <header className="workspace-top">
          <div>
            <span className="eyebrow">Admin control plane</span>
            <h1>Tenant, proof, and revenue operations</h1>
          </div>
          <Link className="secondary-action" href="/login">
            Sign out
          </Link>
        </header>

        <section className="admin-command" id="command">
          <div>
            <span className="eyebrow">Company health</span>
            <h2>{overview?.summary.active_organizations ?? 0} active organizations</h2>
            <p>{status}</p>
          </div>
          <div className="admin-stats">
            <div>
              <span>Organizations</span>
              <strong>{overview?.summary.organizations ?? 0}</strong>
            </div>
            <div>
              <span>Verified findings</span>
              <strong>{overview?.summary.verified_findings ?? 0}</strong>
            </div>
            <div>
              <span>Evidence bundles</span>
              <strong>{overview?.summary.signed_evidence_bundles ?? 0}</strong>
            </div>
          </div>
        </section>

        <section className="two-column">
          <div className="panel-neo board-brief">
            <div className="panel-head">
              <h2>Investor posture</h2>
              <span className="mini-pill">{readinessLabel(command?.executive_brief?.verdict)}</span>
            </div>
            <p>{command?.executive_brief?.headline}</p>
            <div className="brief-risk">
              <span>{command?.executive_brief?.top_risk?.severity ?? "Info"}</span>
              <strong>{command?.executive_brief?.top_risk?.title ?? "No promoted risk yet"}</strong>
              <em>{command?.executive_brief?.top_risk?.surface ?? "Coverage"}</em>
            </div>
          </div>

          <div className="panel-neo">
            <div className="panel-head">
              <h2>Defense rule factory</h2>
              <span className="mini-pill">{command?.defense_rules?.count ?? 0} packs</span>
            </div>
            <div className="queue-list">
              {(command?.defense_rules?.packs ?? []).slice(0, 4).map((pack) => (
                <div className="queue-row" key={pack.id}>
                  <span>{pack.name}</span>
                  <strong>{pack.priority}</strong>
                  <em>{pack.status}</em>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="panel-neo" id="backbone">
          <div className="panel-head">
            <h2>Production SaaS backbone</h2>
            <span className="mini-pill">{backbone?.storage_mode ?? "syncing"}</span>
          </div>
          <div className="backbone-grid">
            <div className="backbone-card">
              <span>Organizations</span>
              <strong>{backbone?.domain_model.organizations ?? 0}</strong>
              <p>tenant root</p>
            </div>
            <div className="backbone-card">
              <span>Projects</span>
              <strong>{backbone?.domain_model.projects ?? 0}</strong>
              <p>security programs</p>
            </div>
            <div className="backbone-card">
              <span>Assets</span>
              <strong>{backbone?.domain_model.assets ?? 0}</strong>
              <p>scoped targets</p>
            </div>
            <div className="backbone-card">
              <span>Queue</span>
              <strong>{queue?.summary.total ?? 0}</strong>
              <p>durable jobs</p>
            </div>
            <div className="backbone-card">
              <span>Workers</span>
              <strong>{backbone?.queue_model.registered_workers ?? 0}</strong>
              <p>registered nodes</p>
            </div>
            <div className="backbone-card">
              <span>SQL tables</span>
              <strong>{backbone?.postgres_schema.migrations[0]?.tables_declared ?? 0}</strong>
              <p>Postgres migration</p>
            </div>
          </div>
          <div className="gate-list backbone-gates">
            {(backbone?.hardening_gates ?? []).map((gate) => (
              <div className={`gate-row gate-${gate.status === "implemented" ? "pass" : "warn"}`} key={gate.name}>
                <span>{gate.status}</span>
                <strong>{gate.name}</strong>
                <p>{gate.proof}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="two-column" id="workers">
          <div className="panel-neo">
            <div className="panel-head">
              <h2>Worker pools</h2>
              <span className="mini-pill">{backbone?.queue_model.worker_pools.length ?? 0} pools</span>
            </div>
            <div className="worker-grid">
              {(backbone?.queue_model.worker_pools ?? []).map((pool) => (
                <article className="worker-card" key={pool.id}>
                  <span>{pool.status}</span>
                  <h3>{pool.id}</h3>
                  <p>{pool.isolation}</p>
                  <small>{pool.job_types.join(" / ")}</small>
                </article>
              ))}
            </div>
          </div>

          <div className="panel-neo">
            <div className="panel-head">
              <h2>Durable queue</h2>
              <span className="mini-pill">{queue?.summary.attempt_records ?? 0} attempts</span>
            </div>
            <div className="queue-list">
              {(queue?.jobs ?? []).slice(0, 6).map((job) => (
                <div className="queue-row" key={job.job_id}>
                  <span>{job.worker_pool}</span>
                  <strong>{job.queue_state}</strong>
                  <em>{job.job_id}</em>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="two-column">
          <div className="panel-neo">
            <h2>Onboard organization</h2>
            <form onSubmit={onboard}>
              <label htmlFor="company">Company</label>
              <input
                id="company"
                onChange={(e) => setForm({ ...form, company_name: e.target.value })}
                value={form.company_name}
              />
              <label htmlFor="email">Security contact</label>
              <input
                id="email"
                onChange={(e) => setForm({ ...form, contact_email: e.target.value })}
                value={form.contact_email}
              />
              <div className="form-grid">
                <div>
                  <label htmlFor="sector">Sector</label>
                  <input
                    id="sector"
                    onChange={(e) => setForm({ ...form, sector: e.target.value })}
                    value={form.sector}
                  />
                </div>
                <div>
                  <label htmlFor="plan">Plan</label>
                  <input
                    id="plan"
                    onChange={(e) => setForm({ ...form, plan: e.target.value })}
                    value={form.plan}
                  />
                </div>
              </div>
              <label htmlFor="assets">Asset count</label>
              <input
                id="assets"
                onChange={(e) => setForm({ ...form, asset_count: Number(e.target.value) })}
                type="number"
                value={form.asset_count}
              />
              <button type="submit">Create tenant</button>
            </form>
          </div>

          <div className="panel-neo">
            <h2>Admin queues</h2>
            <div className="queue-list">
              {(overview?.admin_queues ?? []).map((queue) => (
                <div className="queue-row" key={queue.name}>
                  <span>{queue.name}</span>
                  <strong>{queue.count}</strong>
                  <em>{queue.sla}</em>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="panel-neo">
          <h2>Security modules</h2>
          <div className="module-status-grid">
            {(overview?.modules ?? []).map((module) => (
              <article className="module-status" key={module.name}>
                <span>{module.status}</span>
                <h3>{module.name}</h3>
                <p>{module.signal}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="panel-neo" id="companies">
          <div className="panel-head">
            <h2>Onboarded companies</h2>
            <button className="ghost-button" onClick={refresh} type="button">
              Refresh
            </button>
          </div>
          <div className="company-grid">
            {(overview?.customers ?? []).map((customer) => (
              <article className="company-card" key={customer.id}>
                <div>
                  <h3>{customer.company_name}</h3>
                  <span>{customer.contact_email}</span>
                </div>
                <div className="company-meta">
                  <strong>{customer.plan}</strong>
                  <span>{customer.sector}</span>
                  <span>{customer.asset_count} assets</span>
                  <span>{customer.scope_contract}</span>
                </div>
                <p>{customer.risk_posture}</p>
                {customer.scope_contract !== "signed" ? (
                  <button onClick={() => approveScope(customer.id)} type="button">
                    Sign scope
                  </button>
                ) : null}
              </article>
            ))}
          </div>
        </section>

        <section className="panel-neo" id="audit">
          <div className="panel-head">
            <h2>Tenant audit trail</h2>
            <span className="mini-pill">{overview?.audit_events?.length ?? 0} recent events</span>
          </div>
          <div className="audit-list">
            {(overview?.audit_events ?? []).map((event) => (
              <article className="audit-row" key={event.id}>
                <span>{event.created_at}</span>
                <strong>{event.event_type}</strong>
                <p>
                  {event.actor} → {event.target}
                </p>
              </article>
            ))}
          </div>
        </section>

        <section className="panel-neo" id="plans">
          <h2>Pricing and packaging</h2>
          <div className="plan-grid">
            {(overview?.plans ?? []).map((plan) => (
              <article className="plan-card" key={plan.name}>
                <span>{plan.name}</span>
                <strong>{plan.price}</strong>
                <p>{plan.fit}</p>
                <small>{plan.limits}</small>
              </article>
            ))}
          </div>
        </section>
      </section>
    </main>
  );
}
