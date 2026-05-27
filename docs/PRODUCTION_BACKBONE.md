# BALONCORE Production Backbone

BALONCORE now has a production-shaped SaaS control-plane backbone.

The local developer runtime still uses durable JSON files under
`.baloncore/workbench/saas`, but those files now mirror the Postgres schema in
`crates/baloncore-api/migrations/0001_saas_control_plane.sql`.

## Implemented

- Postgres schema for organizations, members, projects, scope contracts, assets,
  scan jobs, queue leases, worker nodes, job attempts, artifacts, evidence
  bundles, and audit events.
- Rust API endpoints for the control-plane backbone:
  - `GET /api/saas/backbone`
  - `GET /api/saas/projects`
  - `GET /api/saas/assets`
  - `GET /api/workers`
  - `GET /api/workers/queue`
  - `POST /api/saas/projects`
  - `POST /api/saas/assets`
  - `POST /api/workers/register`
  - `POST /api/workers/reconcile`
- Durable queue metadata added to every new job:
  worker pool, priority, attempts, max attempts, lease owner, and idempotency key.
- Local worker abstraction:
  worker pools, worker registry, local worker heartbeat state, and job attempt
  records.
- Worker hardening:
  command timeout enforcement and stale lease reconciliation so jobs do not stay
  running forever after worker failure.
- Next.js admin control-plane panels for production backbone, worker pools, and
  durable queue visibility.

## Production Swap Path

1. Run the migration in managed Postgres.
2. Replace JSON load/write helpers with a SQL repository layer.
3. Move local worker threads into isolated queue consumers.
4. Enforce real SSO/RBAC and tenant scoping at every API boundary.
5. Store artifacts and evidence in tenant-scoped object storage.
6. Add deployment manifests, secrets management, observability, and billing.

## Current Safety Boundary

The local API still binds to `127.0.0.1` and active validation still requires
`authorized=true`. Hosted workers must preserve that boundary with signed scope
contracts, target allowlists, per-tenant egress controls, request budgets, and
audit logs.
