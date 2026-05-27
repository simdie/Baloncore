const http = require("http");
const crypto = require("crypto");

const port = Number(process.env.PORT || 3010);

const usersByToken = {
  "lab-org-a-admin-token":  { id: "admin_a",  email: "admin@orga.test",    role: "admin",  org: "org-a" },
  "lab-org-a-member-token":  { id: "member_a", email: "member@orga.test",   role: "member", org: "org-a" },
  "lab-org-a-viewer-token": { id: "viewer_a",  email: "viewer@orga.test",   role: "viewer", org: "org-a" },
  "lab-org-b-admin-token":  { id: "admin_b",  email: "admin@orgb.test",    role: "admin",  org: "org-b" },
  "lab-org-b-member-token": { id: "member_b", email: "member@orgb.test",   role: "member", org: "org-b" },
};

const usersByCookie = {
  "lab-session-org-a-admin":  { id: "admin_a",  email: "admin@orga.test",    role: "admin",  org: "org-a" },
  "lab-session-org-a-member": { id: "member_a", email: "member@orga.test",   role: "member", org: "org-a" },
  "lab-session-org-b-member": { id: "member_b", email: "member@orgb.test",   role: "member", org: "org-b" },
};

const usersByApiKey = {
  "lab-apikey-org-a-member": { id: "member_a", email: "member@orga.test", role: "member", org: "org-a" },
  "lab-apikey-org-b-member": { id: "member_b", email: "member@orgb.test", role: "member", org: "org-b" },
};

const organizations = {
  "org-a": {
    id: "org-a",
    name: "Acme Corp",
    plan: "enterprise",
    member_ids: ["admin_a", "member_a", "viewer_a"],
  },
  "org-b": {
    id: "org-b",
    name: "Beta Inc",
    plan: "growth",
    member_ids: ["admin_b", "member_b"],
  },
};

const products = {
  "prod-alpha": { id: "prod-alpha", name: "Alpha License", price_usd: 2999 },
  "prod-beta": { id: "prod-beta", name: "Beta Subscription", price_usd: 9900 },
  "prod-gamma": { id: "prod-gamma", name: "Gamma Add-on", price_usd: 499 },
};

const orders = {};
let orderCounter = 1;

const MAX_QUANTITY_PER_ORDER = 10;

const projects = {
  "proj-a-001": {
    id: "proj-a-001",
    org_id: "org-a",
    name: "Acme Dashboard",
    owner_id: "member_a",
    sensitivity: "internal",
    budget_usd: 50000,
  },
  "proj-a-002": {
    id: "proj-a-002",
    org_id: "org-a",
    name: "Acme API Gateway",
    owner_id: "admin_a",
    sensitivity: "confidential",
    budget_usd: 120000,
  },
  "proj-b-001": {
    id: "proj-b-001",
    org_id: "org-b",
    name: "Beta Mobile App",
    owner_id: "member_b",
    sensitivity: "internal",
    budget_usd: 75000,
  },
  "proj-b-secret": {
    id: "proj-b-secret",
    org_id: "org-b",
    name: "Beta Merger Plans",
    owner_id: "admin_b",
    sensitivity: "restricted",
    budget_usd: 500000,
  },
};

function json(res, status, body) {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload),
    "x-baloncore-lab": "vulnerable-saas",
  });
  res.end(payload);
}

function currentUser(req) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
  if (token && usersByToken[token]) return usersByToken[token];

  const cookieHeader = req.headers.cookie || "";
  const sessionMatch = cookieHeader.match(/(?:^|;\s*)session=([^;]+)/);
  if (sessionMatch && usersByCookie[sessionMatch[1]]) return usersByCookie[sessionMatch[1]];

  const apiKey = req.headers["x-api-key"] || "";
  if (apiKey && usersByApiKey[apiKey]) return usersByApiKey[apiKey];

  return null;
}

function canAccessOrg(user, orgId) {
  return user && user.org === orgId;
}

function canReadProject(user, project) {
  if (!user) return false;
  if (user.org !== project.org_id) return false;
  if (project.sensitivity === "restricted" && user.role === "viewer") return false;
  return true;
}

function handle(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === "GET" && url.pathname === "/health") {
    return json(res, 200, { ok: true, service: "baloncore-vulnerable-saas" });
  }

  if (req.method === "GET" && url.pathname === "/openapi.json") {
    return json(res, 200, {
      openapi: "3.0.0",
      info: { title: "BALONCORE Vulnerable SaaS Lab", version: "0.1.0" },
      paths: {
        "/api/me": { get: { security: [{ bearerAuth: [] }, { cookieAuth: [] }, { apiKeyAuth: [] }], responses: { 200: { description: "Current user" } } } },
        "/api/orgs": { get: { security: [{ bearerAuth: [] }, { cookieAuth: [] }, { apiKeyAuth: [] }], responses: { 200: { description: "Organizations" } } } },
        "/api/orgs/{orgId}": { get: { security: [{ bearerAuth: [] }, { cookieAuth: [] }, { apiKeyAuth: [] }], parameters: [{ name: "orgId", in: "path", required: true, schema: { type: "string" } }], responses: { 200: { description: "Organization" } } } },
        "/api/orgs/{orgId}/projects": { get: { security: [{ bearerAuth: [] }, { cookieAuth: [] }, { apiKeyAuth: [] }], parameters: [{ name: "orgId", in: "path", required: true, schema: { type: "string" } }], responses: { 200: { description: "Projects" } } } },
        "/api/orgs/{orgId}/projects/{projectId}": { get: { security: [{ bearerAuth: [] }, { cookieAuth: [] }, { apiKeyAuth: [] }], parameters: [{ name: "orgId", in: "path", required: true, schema: { type: "string" } }, { name: "projectId", in: "path", required: true, schema: { type: "string" } }], responses: { 200: { description: "Project" } } } },
      },
      components: {
        securitySchemes: {
          bearerAuth: { type: "http", scheme: "bearer" },
          cookieAuth: { type: "apiKey", in: "cookie", name: "session" },
          apiKeyAuth: { type: "apiKey", in: "header", name: "X-API-Key" },
        },
      },
    });
  }

  if (req.method === "POST" && url.pathname === "/auth/login") {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      try {
        const creds = JSON.parse(body || "{}");
        const sessionMap = { "admin_a": "lab-session-org-a-admin", "member_a": "lab-session-org-a-member", "member_b": "lab-session-org-b-member" };
        const sessionToken = sessionMap[creds.username];
        if (!sessionToken) return json(res, 401, { error: "invalid credentials" });
        res.setHeader("Set-Cookie", `session=${sessionToken}; HttpOnly; Path=/; SameSite=Lax`);
        res.setHeader("X-CSRF-Token", `lab-csrf-${creds.username}`);
        return json(res, 200, { ok: true, user_id: creds.username, csrf_token: `lab-csrf-${creds.username}` });
      } catch { return json(res, 400, { error: "invalid JSON" }); }
    });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/me") {
    const user = currentUser(req);
    if (!user) return json(res, 401, { error: "authentication required" });
    return json(res, 200, { ...user, org_name: organizations[user.org]?.name });
  }

  if (req.method === "GET" && url.pathname === "/api/orgs") {
    const user = currentUser(req);
    if (!user) return json(res, 401, { error: "authentication required" });
    const userOrg = organizations[user.org];
    const orgList = user.role === "admin" ? Object.values(organizations) : [userOrg];
    return json(res, 200, { items: orgList });
  }

  const orgMatch = url.pathname.match(/^\/api\/orgs\/([^/]+)$/);
  if (req.method === "GET" && orgMatch) {
    const user = currentUser(req);
    if (!user) return json(res, 401, { error: "authentication required" });
    const orgId = orgMatch[1];
    const org = organizations[orgId];
    if (!org) return json(res, 404, { error: "organization not found" });
    if (!canAccessOrg(user, orgId)) return json(res, 403, { error: "tenant isolation: cannot access other organization" });
    return json(res, 200, org);
  }

  const orgProjectsMatch = url.pathname.match(/^\/api\/orgs\/([^/]+)\/projects$/);
  if (req.method === "GET" && orgProjectsMatch) {
    const user = currentUser(req);
    if (!user) return json(res, 401, { error: "authentication required" });
    const orgId = orgProjectsMatch[1];
    if (!canAccessOrg(user, orgId)) return json(res, 403, { error: "tenant isolation" });
    const orgProjects = Object.values(projects).filter((p) => p.org_id === orgId);
    return json(res, 200, { items: orgProjects });
  }

  const projectMatch = url.pathname.match(/^\/api\/orgs\/([^/]+)\/projects\/([^/]+)$/);
  if (req.method === "GET" && projectMatch) {
    const user = currentUser(req);
    if (!user) return json(res, 401, { error: "authentication required" });
    const orgId = projectMatch[1];
    const projectId = projectMatch[2];
    const project = projects[projectId];
    if (!project) return json(res, 404, { error: "project not found" });

    if (project.id === "proj-b-secret") {
      if (!canAccessOrg(user, project.org_id) || user.role === "viewer") {
        return json(res, 403, {
          error: "access denied",
          lab_note: "decoy: this project is correctly protected by tenant and role checks",
        });
      }
    }

    if (!canAccessOrg(user, project.org_id)) {
      return json(res, 200, {
        ...project,
        requested_by: user.id,
        cross_tenant: true,
        lab_note: "intentional cross-tenant BOLA: Org A member can read an Org B project via sequential/guessable id",
      });
    }

    return json(res, 200, {
      ...project,
      requested_by: user.id,
      cross_tenant: false,
    });
  }

  if (req.method === "POST" && url.pathname === "/graphql") {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      try {
        const payload = JSON.parse(body || "{}");
        const query = (payload.query || "").trim();
        const variables = payload.variables || {};
        const user = currentUser(req);

        if (query.includes("__schema") || query.includes("__type")) {
          if (!user) return json(res, 401, { errors: [{ message: "authentication required for introspection" }] });
          return json(res, 200, {
            data: {
              __schema: {
                queryType: { name: "Query" },
                mutationType: null,
                types: [
                  {
                    kind: "OBJECT",
                    name: "Query",
                    fields: [
                      { name: "me", type: { kind: "OBJECT", name: "User", ofType: null }, args: [], description: "Current user", isDeprecated: false },
                      { name: "project", type: { kind: "OBJECT", name: "Project", ofType: null }, args: [
                        { name: "id", type: { kind: "NON_NULL", name: null, ofType: { kind: "SCALAR", name: "ID", ofType: null } }, defaultValue: null }
                      ], description: "Get a project by ID", isDeprecated: false },
                      { name: "projects", type: { kind: "LIST", name: null, ofType: { kind: "OBJECT", name: "Project", ofType: null } }, args: [
                        { name: "orgId", type: { kind: "NON_NULL", name: null, ofType: { kind: "SCALAR", name: "ID", ofType: null } }, defaultValue: null }
                      ], description: "List projects for an org", isDeprecated: false },
                      { name: "organization", type: { kind: "OBJECT", name: "Organization", ofType: null }, args: [
                        { name: "id", type: { kind: "NON_NULL", name: null, ofType: { kind: "SCALAR", name: "ID", ofType: null } }, defaultValue: null }
                      ], description: "Get an organization", isDeprecated: false },
                    ],
                  },
                  {
                    kind: "OBJECT",
                    name: "Project",
                    fields: [
                      { name: "id", type: { kind: "NON_NULL", name: null, ofType: { kind: "SCALAR", name: "ID", ofType: null } }, args: [], description: null, isDeprecated: false },
                      { name: "name", type: { kind: "SCALAR", name: "String", ofType: null }, args: [], description: null, isDeprecated: false },
                      { name: "org_id", type: { kind: "SCALAR", name: "String", ofType: null }, args: [], description: null, isDeprecated: false },
                      { name: "owner_id", type: { kind: "SCALAR", name: "String", ofType: null }, args: [], description: null, isDeprecated: false },
                      { name: "sensitivity", type: { kind: "SCALAR", name: "String", ofType: null }, args: [], description: null, isDeprecated: false },
                      { name: "budget_usd", type: { kind: "SCALAR", name: "Int", ofType: null }, args: [], description: null, isDeprecated: false },
                    ],
                  },
                  {
                    kind: "OBJECT",
                    name: "User",
                    fields: [
                      { name: "id", type: { kind: "NON_NULL", name: null, ofType: { kind: "SCALAR", name: "ID", ofType: null } }, args: [], description: null, isDeprecated: false },
                      { name: "email", type: { kind: "SCALAR", name: "String", ofType: null }, args: [], description: null, isDeprecated: false },
                      { name: "role", type: { kind: "SCALAR", name: "String", ofType: null }, args: [], description: null, isDeprecated: false },
                      { name: "org", type: { kind: "SCALAR", name: "String", ofType: null }, args: [], description: null, isDeprecated: false },
                    ],
                  },
                  {
                    kind: "OBJECT",
                    name: "Organization",
                    fields: [
                      { name: "id", type: { kind: "NON_NULL", name: null, ofType: { kind: "SCALAR", name: "ID", ofType: null } }, args: [], description: null, isDeprecated: false },
                      { name: "name", type: { kind: "SCALAR", name: "String", ofType: null }, args: [], description: null, isDeprecated: false },
                      { name: "plan", type: { kind: "SCALAR", name: "String", ofType: null }, args: [], description: null, isDeprecated: false },
                    ],
                  },
                ],
              },
            },
          });
        }

        if (!user) return json(res, 401, { errors: [{ message: "authentication required" }] });

        const data = {};
        let resolved = false;

        const meMatch = query.match(/\bme\b/);
        const projectMatch = query.match(/project\s*\(\s*id\s*:\s*"?([^")\s]+)"?\s*\)/);
        const projectVarMatch = query.match(/\bproject\s*\(/) && variables.id;
        const projectsMatch = query.match(/projects\s*\(/) || query.match(/projects\s*\{/) ;
        const orgMatch = query.match(/organization\s*\(\s*id\s*:\s*"?([^")\s]+)"?\s*\)/);

        if (meMatch && !projectMatch && !projectsMatch && !orgMatch) {
          data.me = { id: user.id, email: user.email, role: user.role, org: user.org };
          resolved = true;
        }

        if (projectMatch || projectVarMatch) {
          const projectId = projectMatch ? projectMatch[1] : variables.id;
          const project = projects[projectId];
          if (!project) {
            return json(res, 200, { data: { project: null }, errors: [{ message: "project not found" }] });
          }

          if (projectId === "proj-b-secret") {
            if (!canAccessOrg(user, project.org_id) || user.role === "viewer") {
              return json(res, 200, { data: { project: null }, errors: [{ message: "access denied", lab_note: "decoy: this project is correctly protected by tenant and role checks in GraphQL" }] });
            }
          }

          if (!canAccessOrg(user, project.org_id)) {
            data.project = {
              ...project,
              requested_by: user.id,
              cross_tenant: true,
              lab_note: "intentional cross-tenant GraphQL BOLA: Org A member can query an Org B project via guessable id",
            };
          } else {
            data.project = { ...project, requested_by: user.id, cross_tenant: false };
          }
          resolved = true;
        }

        if (projectsMatch) {
          const orgId = (query.match(/orgId\s*:\s*"?([^"\s)]+)"?/) || [])[1] || variables.orgId || user.org;
          if (!canAccessOrg(user, orgId)) {
            return json(res, 403, { errors: [{ message: "tenant isolation" }] });
          }
          data.projects = Object.values(projects).filter((p) => p.org_id === orgId);
          resolved = true;
        }

        if (orgMatch) {
          const orgId = orgMatch[1] || variables.id;
          const org = organizations[orgId];
          if (!org) return json(res, 200, { data: { organization: null }, errors: [{ message: "organization not found" }] });
          if (!canAccessOrg(user, orgId)) return json(res, 403, { errors: [{ message: "tenant isolation" }] });
          data.organization = org;
          resolved = true;
        }

        if (!resolved) {
          return json(res, 400, { errors: [{ message: "unknown or malformed GraphQL query" }] });
        }

        return json(res, 200, { data });
      } catch (e) {
        return json(res, 400, { errors: [{ message: "invalid JSON body" }] });
      }
    });
    return;
  }

  if (req.method === "GET" && url.pathname === "/graphql") {
    return json(res, 200, { message: "GraphQL endpoint available. Send POST requests with query and variables." });
  }

  // ---- Business Logic: Order workflow ----
  // POST /api/orders — create order (planted: accepts client-supplied price, allows quantity above limit)
  if (req.method === "POST" && url.pathname === "/api/orders") {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      try {
        const user = currentUser(req);
        if (!user) return json(res, 401, { error: "authentication required" });
        const data = JSON.parse(body || "{}");
        const productId = data.product_id || "prod-alpha";
        const product = products[productId];
        if (!product) return json(res, 400, { error: "unknown product" });
        const quantity = data.quantity || 1;
        // PLANTED: client-supplied total_usd overrides the product price (price tamper vuln)
        const totalUsd = data.total_usd !== undefined ? data.total_usd : product.price_usd * quantity;
        const orderId = `ord-${orderCounter++}`;
        const order = {
          id: orderId,
          product_id: productId,
          product_name: product.name,
          quantity: quantity,
          total_usd: totalUsd,
          status: "draft",
          owner_id: user.id,
          org_id: user.org,
          unit_price_usd: product.price_usd,
        };
        orders[orderId] = order;
        return json(res, 201, order);
      } catch (e) { return json(res, 400, { error: "invalid JSON" }); }
    });
    return;
  }

  // GET /api/orders — list user's orders
  if (req.method === "GET" && url.pathname === "/api/orders") {
    const user = currentUser(req);
    if (!user) return json(res, 401, { error: "authentication required" });
    const userOrders = Object.values(orders).filter((o) => o.owner_id === user.id);
    return json(res, 200, { items: userOrders });
  }

  // GET /api/orders/:id — get order
  const orderMatch = url.pathname.match(/^\/api\/orders\/([^/]+)$/);
  if (req.method === "GET" && orderMatch) {
    const user = currentUser(req);
    if (!user) return json(res, 401, { error: "authentication required" });
    const order = orders[orderMatch[1]];
    if (!order) return json(res, 404, { error: "order not found" });
    return json(res, 200, order);
  }

  // POST /api/orders/:id/pay — pay for order (DECOY: validates amount matches)
  const orderPayMatch = url.pathname.match(/^\/api\/orders\/([^/]+)\/pay$/);
  if (req.method === "POST" && orderPayMatch) {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      try {
        const user = currentUser(req);
        if (!user) return json(res, 401, { error: "authentication required" });
        const order = orders[orderPayMatch[1]];
        if (!order) return json(res, 404, { error: "order not found" });
        if (order.status !== "draft") {
          // DECOY: properly rejects payment for non-draft orders
          return json(res, 400, { error: "order is not in draft status", lab_note: "decoy: payment correctly rejects non-draft order" });
        }
        const expected_total = order.unit_price_usd * order.quantity;
        if (order.total_usd !== expected_total) {
          // DECOY: properly validates payment amount matches expected total
          return json(res, 400, { error: "payment amount does not match order total", expected_total_usd: expected_total, lab_note: "decoy: server correctly validates payment amount" });
        }
        order.status = "paid";
        order.paid_at = Date.now();
        return json(res, 200, { ...order, payment_status: "completed" });
      } catch (e) { return json(res, 400, { error: "invalid JSON" }); }
    });
    return;
  }

  // POST /api/orders/:id/ship — ship order (PLANTED: allows skipping "paid" state)
  const orderShipMatch = url.pathname.match(/^\/api\/orders\/([^/]+)\/ship$/);
  if (req.method === "POST" && orderShipMatch) {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      try {
        const user = currentUser(req);
        if (!user) return json(res, 401, { error: "authentication required" });
        const order = orders[orderShipMatch[1]];
        if (!order) return json(res, 404, { error: "order not found" });
        // PLANTED: does NOT check if order.status === "paid"
        // This allows state-skip: ship without paying
        order.status = "shipped";
        order.shipped_at = Date.now();
        return json(res, 200, { ...order, lab_note: "intentional state-skip: order shipped without payment requirement" });
      } catch (e) { return json(res, 400, { error: "invalid JSON" }); }
    });
    return;
  }

  return json(res, 404, { error: "not found" });
}

const server = http.createServer(handle);
server.listen(port, "127.0.0.1", () => {
  console.log(`BALONCORE vulnerable SaaS lab listening on http://127.0.0.1:${port}`);
});