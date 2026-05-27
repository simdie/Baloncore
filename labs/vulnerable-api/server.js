const http = require("http");

const port = Number(process.env.PORT || 3000);

const usersByToken = {
  "lab-user-a-token": {
    id: "user_a",
    email: "user_a@example.test",
    role: "user",
  },
  "lab-user-b-token": {
    id: "user_b",
    email: "user_b@example.test",
    role: "user",
  },
  "lab-admin-token": {
    id: "admin",
    email: "admin@example.test",
    role: "admin",
  },
};

const usersByCookie = {
  "lab-session-user-a": {
    id: "user_a",
    email: "user_a@example.test",
    role: "user",
  },
  "lab-session-user-b": {
    id: "user_b",
    email: "user_b@example.test",
    role: "user",
  },
  "lab-session-admin": {
    id: "admin",
    email: "admin@example.test",
    role: "admin",
  },
};

const usersByApiKey = {
  "lab-apikey-user-a": {
    id: "user_a",
    email: "user_a@example.test",
    role: "user",
  },
  "lab-apikey-user-b": {
    id: "user_b",
    email: "user_b@example.test",
    role: "user",
  },
  "lab-apikey-admin": {
    id: "admin",
    email: "admin@example.test",
    role: "admin",
  },
};

const csrfTokens = {
  "lab-csrf-token-user-a": "user_a",
  "lab-csrf-token-user-b": "user_b",
  "lab-csrf-token-admin": "admin",
};

const invoices = {
  inv_1001: {
    id: "inv_1001",
    owner_id: "user_a",
    owner_email: "user_a@example.test",
    amount_cents: 1299,
    status: "paid",
  },
  inv_2002: {
    id: "inv_2002",
    owner_id: "user_b",
    owner_email: "user_b@example.test",
    amount_cents: 4200,
    status: "due",
  },
};

const adminReports = {
  adm_9001: {
    id: "adm_9001",
    owner_id: "admin",
    owner_email: "admin@example.test",
    title: "Quarterly security exceptions",
    sensitivity: "admin-only",
  },
};

function json(res, status, body) {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload),
    "x-baloncore-lab": "vulnerable-api",
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

function openapi(req, res) {
  json(res, 200, {
    openapi: "3.0.0",
    info: { title: "BALONCORE Vulnerable API Lab", version: "0.2.0" },
    paths: {
      "/auth/login": {
        post: {
          summary: "Session login endpoint for cookie/session auth",
          requestBody: {
            content: { "application/json": { schema: { type: "object", properties: { username: { type: "string" }, password: { type: "string" } } } } },
          },
          responses: { 200: { description: "Set-Cookie session token" }, 401: { description: "Invalid credentials" } },
        },
      },
      "/auth/csrf-token": {
        get: {
          summary: "Returns a CSRF token for the current session",
          security: [{ cookieAuth: [] }],
          responses: { 200: { description: "CSRF token" }, 401: { description: "No session" } },
        },
      },
      "/api/me": {
        get: { security: [{ bearerAuth: [] }, { cookieAuth: [] }, { apiKeyAuth: [] }], responses: { 200: { description: "Current user" } } },
      },
      "/api/invoices": {
        get: {
          security: [{ bearerAuth: [] }, { cookieAuth: [] }, { apiKeyAuth: [] }],
          responses: { 200: { description: "Invoices owned by the current user" }, 401: { description: "Unauthorized" } },
        },
      },
      "/api/invoices/{id}": {
        get: {
          security: [{ bearerAuth: [] }, { cookieAuth: [] }, { apiKeyAuth: [] }],
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
          responses: { 200: { description: "Invoice by ID" }, 403: { description: "Forbidden" } },
        },
      },
      "/api/admin/reports": {
        get: {
          tags: ["admin"],
          security: [{ bearerAuth: [] }, { cookieAuth: [] }, { apiKeyAuth: [] }],
          responses: { 200: { description: "Admin-owned reports" }, 403: { description: "Forbidden" } },
        },
      },
      "/api/admin/reports/{id}": {
        get: {
          tags: ["admin"],
          security: [{ bearerAuth: [] }, { cookieAuth: [] }, { apiKeyAuth: [] }],
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
          responses: { 200: { description: "Admin report by ID" }, 403: { description: "Forbidden" } },
        },
      },
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

function handle(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === "GET" && url.pathname === "/health") {
    return json(res, 200, { ok: true, service: "baloncore-vulnerable-api" });
  }

  if (req.method === "GET" && url.pathname === "/openapi.json") {
    return openapi(req, res);
  }

  if (req.method === "POST" && url.pathname === "/auth/login") {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      try {
        const creds = JSON.parse(body || "{}");
        const sessionMap = {
          "user_a": "lab-session-user-a",
          "user_b": "lab-session-user-b",
          "admin": "lab-session-admin",
        };
        const sessionToken = sessionMap[creds.username];
        if (!sessionToken) {
          return json(res, 401, { error: "invalid credentials" });
        }
        res.setHeader("Set-Cookie", `session=${sessionToken}; HttpOnly; Path=/; SameSite=Lax`);
        res.setHeader("X-CSRF-Token", `lab-csrf-token-${creds.username}`);
        return json(res, 200, { ok: true, user_id: creds.username, csrf_token: `lab-csrf-token-${creds.username}` });
      } catch {
        return json(res, 400, { error: "invalid JSON" });
      }
    });
    return;
  }

  if (req.method === "GET" && url.pathname === "/auth/csrf-token") {
    const user = currentUser(req);
    if (!user) {
      return json(res, 401, { error: "authentication required" });
    }
    const csrfMap = { "user_a": "lab-csrf-token-user-a", "user_b": "lab-csrf-token-user-b", "admin": "lab-csrf-token-admin" };
    const token = csrfMap[user.id] || "lab-csrf-token-unknown";
    return json(res, 200, { csrf_token: token });
  }

  if (req.method === "GET" && url.pathname === "/api/me") {
    const user = currentUser(req);
    if (!user) {
      return json(res, 401, { error: "authentication required" });
    }
    return json(res, 200, user);
  }

  if (req.method === "GET" && url.pathname === "/api/invoices") {
    const user = currentUser(req);
    if (!user) {
      return json(res, 401, { error: "authentication required" });
    }
    return json(res, 200, {
      items: Object.values(invoices).filter((invoice) => invoice.owner_id === user.id),
    });
  }

  if (req.method === "GET" && url.pathname === "/api/admin/reports") {
    const user = currentUser(req);
    if (!user) {
      return json(res, 401, { error: "authentication required" });
    }
    if (user.role !== "admin") {
      return json(res, 403, { error: "admin role required" });
    }
    return json(res, 200, {
      items: Object.values(adminReports),
    });
  }

  const invoiceMatch = url.pathname.match(/^\/api\/invoices\/([^/]+)$/);
  if (req.method === "GET" && invoiceMatch) {
    const user = currentUser(req);
    if (!user) {
      return json(res, 401, { error: "authentication required" });
    }

    const invoice = invoices[invoiceMatch[1]];
    if (!invoice) {
      return json(res, 404, { error: "invoice not found" });
    }

    // Intentionally vulnerable: this should check invoice.owner_id === user.id.
    return json(res, 200, {
      ...invoice,
      requested_by: user.id,
      lab_note: "intentional BOLA/IDOR: authenticated users can read another user's invoice",
    });
  }

  const adminReportMatch = url.pathname.match(/^\/api\/admin\/reports\/([^/]+)$/);
  if (req.method === "GET" && adminReportMatch) {
    const user = currentUser(req);
    if (!user) {
      return json(res, 401, { error: "authentication required" });
    }

    const report = adminReports[adminReportMatch[1]];
    if (!report) {
      return json(res, 404, { error: "admin report not found" });
    }

    // Intentionally vulnerable: this should require user.role === "admin".
    return json(res, 200, {
      ...report,
      requested_by: user.id,
      lab_note: "intentional BFLA: any authenticated user can read an admin report",
    });
  }

  return json(res, 404, { error: "not found" });
}

const server = http.createServer(handle);
server.listen(port, "127.0.0.1", () => {
  console.log(`BALONCORE vulnerable API lab listening on http://127.0.0.1:${port}`);
});
