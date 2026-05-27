# BALONCORE Vulnerable SaaS Lab

Multi-tenant SaaS target with org-scoped roles and planted cross-tenant BOLA.

## Quick Start

```bash
node server.js
# Server starts on http://127.0.0.1:3010
```

## Organizations & Roles

| Profile         | Org   | Role   | Token / Cookie / API Key              |
|-----------------|-------|--------|---------------------------------------|
| org_a_admin     | Org A | admin  | lab-org-a-admin-token                |
| org_a_member    | Org A | member | lab-org-a-member-token               |
| org_a_viewer    | Org A | viewer | lab-org-a-viewer-token               |
| org_b_admin     | Org B | admin  | lab-org-b-admin-token                |
| org_b_member    | Org B | member | lab-org-b-member-token               |
| anonymous       | -     | -      | (no auth)                            |

Cookie session: `session=lab-session-org-a-member` etc.
API key: `X-API-Key: lab-apikey-org-a-member` etc.

## Intentional Vulnerabilities

- **Cross-tenant BOLA**: Org A member can read an Org B project via `/api/orgs/org-b/projects/proj-b-001`
- **Correctly blocked decoy**: Org A member CANNOT read `/api/orgs/org-b/projects/proj-b-secret` (returns 403)

## Auth Endpoints

- `POST /auth/login` - Cookie session login
- `GET /auth/csrf-token` - CSRF token for current session