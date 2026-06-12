import express from "express";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

vi.mock("../db/repositories/api-keys.repo", () => ({
  ApiKeysRepository: class {
    async validateApiKey() {
      return { valid: false };
    }
  },
}));

import { authenticateApiKey } from "./api-key-oauth.middleware";

// Keep a reference to the native fetch for talking to the test server,
// since the global is stubbed to fake the introspection endpoint.
const realFetch = globalThis.fetch.bind(globalThis);

const ENDPOINT_OAUTH_ONLY = {
  uuid: "endpoint-uuid-1",
  name: "test-endpoint",
  enable_api_key_auth: false,
  enable_oauth: true,
  use_query_param_auth: false,
  user_id: "user-1",
};

const ENDPOINT_BOTH = {
  ...ENDPOINT_OAUTH_ONLY,
  uuid: "endpoint-uuid-2",
  enable_api_key_auth: true,
};

function buildApp(endpoint: Record<string, unknown>) {
  const app = express();
  app.use((req, _res, next) => {
    (req as express.Request & { endpoint: unknown }).endpoint = endpoint;
    next();
  });
  app.use(authenticateApiKey);
  app.get("/", (_req, res) => res.json({ ok: true }));
  return app;
}

async function listen(app: express.Express) {
  const server = app.listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  const port = (server.address() as { port: number }).port;
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

describe("authenticateApiKey OAuth challenge headers", () => {
  let oauthOnly: Awaited<ReturnType<typeof listen>>;
  let both: Awaited<ReturnType<typeof listen>>;

  beforeAll(async () => {
    process.env.APP_URL = "https://metamcp.example.com";
    oauthOnly = await listen(buildApp(ENDPOINT_OAUTH_ONLY));
    both = await listen(buildApp(ENDPOINT_BOTH));
  });

  afterAll(() => {
    oauthOnly?.server.close();
    both?.server.close();
    vi.unstubAllGlobals();
  });

  beforeEach(() => {
    // Introspection endpoint reports any token as inactive (expired/unknown)
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(JSON.stringify({ active: false }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
      ),
    );
  });

  it("sends WWW-Authenticate challenge when no token is provided", async () => {
    const res = await realFetch(`${oauthOnly.baseUrl}/`);
    expect(res.status).toBe(401);
    const header = res.headers.get("www-authenticate");
    expect(header).toContain('Bearer realm="MetaMCP"');
    expect(header).toContain(
      'resource_metadata="https://metamcp.example.com/.well-known/oauth-protected-resource"',
    );
  });

  it("includes WWW-Authenticate with error=invalid_token on expired OAuth token (oauth-only endpoint)", async () => {
    const res = await realFetch(`${oauthOnly.baseUrl}/`, {
      headers: { Authorization: "Bearer mcp_token_expired_abc" },
    });
    expect(res.status).toBe(401);
    const header = res.headers.get("www-authenticate");
    expect(header).toBeTruthy();
    expect(header).toContain('error="invalid_token"');
    expect(header).toContain(
      'resource_metadata="https://metamcp.example.com/.well-known/oauth-protected-resource"',
    );
  });

  it("includes WWW-Authenticate with error=invalid_token when both auth methods fail (api-key+oauth endpoint)", async () => {
    const res = await realFetch(`${both.baseUrl}/`, {
      headers: { Authorization: "Bearer mcp_token_expired_def" },
    });
    expect(res.status).toBe(401);
    const header = res.headers.get("www-authenticate");
    expect(header).toBeTruthy();
    expect(header).toContain('error="invalid_token"');
  });
});
