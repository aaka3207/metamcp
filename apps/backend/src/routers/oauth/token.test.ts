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

const mocks = vi.hoisted(() => ({
  getRefreshToken: vi.fn(),
  setRefreshToken: vi.fn(),
  deleteRefreshToken: vi.fn(),
  updateRefreshTokenExpiry: vi.fn(),
  setAccessToken: vi.fn(),
  getAuthCode: vi.fn(),
  deleteAuthCode: vi.fn(),
  getClient: vi.fn(),
  getAccessToken: vi.fn(),
  deleteAccessToken: vi.fn(),
}));

vi.mock("../../db/repositories", () => ({
  oauthRepository: mocks,
}));

import tokenRouter from "./token";

const DAY_MS = 24 * 3600 * 1000;

async function listen() {
  const app = express();
  app.use(express.json());
  app.use(tokenRouter);
  const server = app.listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  const port = (server.address() as { port: number }).port;
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

describe("POST /oauth/token refresh_token grant", () => {
  let ctx: Awaited<ReturnType<typeof listen>>;

  beforeAll(async () => {
    ctx = await listen();
  });

  afterAll(() => {
    ctx?.server.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  function postToken(body: Record<string, unknown>) {
    return fetch(`${ctx.baseUrl}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  it("returns invalid_grant when refresh token is unknown", async () => {
    mocks.getRefreshToken.mockResolvedValue(null);
    const res = await postToken({
      grant_type: "refresh_token",
      refresh_token: "mcp_refresh_unknown",
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_grant");
  });

  it("issues access token with longer lifetime than 30 days and refresh token outliving it", async () => {
    mocks.getRefreshToken.mockResolvedValue({
      client_id: "client-1",
      user_id: "user-1",
      scope: "admin",
      expires_at: new Date(Date.now() + 100 * DAY_MS),
    });

    const before = Date.now();
    const res = await postToken({
      grant_type: "refresh_token",
      refresh_token: "mcp_refresh_valid",
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      access_token: string;
      refresh_token: string;
      expires_in: number;
    };

    // Access token must live at least 90 days
    expect(body.expires_in).toBeGreaterThanOrEqual(90 * 24 * 3600);

    // Refresh token must outlive the access token
    const refreshCall = mocks.setRefreshToken.mock.calls[0];
    expect(refreshCall).toBeDefined();
    const refreshExpiresAt = refreshCall[1].expires_at as number;
    const accessExpiryMs = before + body.expires_in * 1000;
    expect(refreshExpiresAt).toBeGreaterThan(accessExpiryMs);
  });

  it("keeps the old refresh token valid for a grace period instead of deleting it immediately", async () => {
    mocks.getRefreshToken.mockResolvedValue({
      client_id: "client-1",
      user_id: "user-1",
      scope: "admin",
      expires_at: new Date(Date.now() + 100 * DAY_MS),
    });

    const before = Date.now();
    const res = await postToken({
      grant_type: "refresh_token",
      refresh_token: "mcp_refresh_valid",
    });
    expect(res.status).toBe(200);

    // Old token must NOT be hard-deleted (that bricks clients on lost responses)
    expect(mocks.deleteRefreshToken).not.toHaveBeenCalled();

    // Instead its expiry is shortened to a small grace window
    expect(mocks.updateRefreshTokenExpiry).toHaveBeenCalledTimes(1);
    const [oldToken, newExpiry] = mocks.updateRefreshTokenExpiry.mock.calls[0];
    expect(oldToken).toBe("mcp_refresh_valid");
    const graceMs = (newExpiry as Date).getTime() - before;
    expect(graceMs).toBeGreaterThan(0);
    expect(graceMs).toBeLessThanOrEqual(5 * 60 * 1000); // well under 5 minutes
  });

  it("does not extend the grace window beyond the token's original expiry", async () => {
    // Token already within its grace window (expires in 20s)
    mocks.getRefreshToken.mockResolvedValue({
      client_id: "client-1",
      user_id: "user-1",
      scope: "admin",
      expires_at: new Date(Date.now() + 20_000),
    });

    const res = await postToken({
      grant_type: "refresh_token",
      refresh_token: "mcp_refresh_in_grace",
    });
    expect(res.status).toBe(200);

    const [, newExpiry] = mocks.updateRefreshTokenExpiry.mock.calls[0];
    // Must not be extended past the original 20s remaining
    expect((newExpiry as Date).getTime()).toBeLessThanOrEqual(
      Date.now() + 21_000,
    );
  });
});
