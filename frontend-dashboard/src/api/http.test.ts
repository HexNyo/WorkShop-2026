import { ApiError, api, configureAuth } from "./http";

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

describe("api client", () => {
  let token: string | null;
  let refreshes: number;
  let lost: number;

  beforeEach(() => {
    token = "expired";
    refreshes = 0;
    lost = 0;
    configureAuth({
      getToken: () => token,
      refresh: async () => {
        refreshes += 1;
        token = "fresh";
        return token;
      },
      onSessionLost: () => {
        lost += 1;
      },
    });
  });

  afterEach(() => vi.unstubAllGlobals());

  it("refreshes once on 401 and replays the request with the new token", async () => {
    const seen: (string | null)[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, init: RequestInit) => {
        const auth = (init.headers as Record<string, string>).Authorization ?? null;
        seen.push(auth);
        return auth === "Bearer fresh" ? jsonResponse(200, { ok: true }) : jsonResponse(401, { code: "UNAUTHENTICATED" });
      }),
    );
    const { data } = await api<{ ok: boolean }>("/api/payment/v1/accounts");
    expect(data.ok).toBe(true);
    expect(refreshes).toBe(1);
    expect(seen).toEqual(["Bearer expired", "Bearer fresh"]);
  });

  it("signals a lost session when the refresh cannot help", async () => {
    configureAuth({ getToken: () => "t", refresh: async () => null, onSessionLost: () => (lost += 1) });
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(401, { code: "UNAUTHENTICATED" })));
    await expect(api("/api/supervision/v1/overview")).rejects.toMatchObject({ status: 401 });
    expect(lost).toBe(1);
  });

  it("maps RFC 9457 problems to ApiError, including Retry-After", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse(
          503,
          { code: "WRITE_MODE_RESTRICTED", title: "Write operations restricted", detail: "SYNTHETIC_ONLY mode" },
          { "Retry-After": "10" },
        ),
      ),
    );
    const error = (await api("/api/payment/v1/transactions", { method: "POST", body: {} }).catch((e) => e)) as ApiError;
    expect(error).toBeInstanceOf(ApiError);
    expect(error.code).toBe("WRITE_MODE_RESTRICTED");
    expect(error.retryAfter).toBe(10);
    expect(error.isUnavailable).toBe(true);
  });

  it("turns network failures into a typed unavailable error", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new TypeError("Failed to fetch"))));
    const error = (await api("/api/auth/v1/me").catch((e) => e)) as ApiError;
    expect(error.code).toBe("NETWORK_ERROR");
    expect(error.status).toBe(0);
  });

  it("does not attach credentials to anonymous calls", async () => {
    const fetchMock = vi.fn(async () => jsonResponse(200, {}));
    vi.stubGlobal("fetch", fetchMock);
    await api("/api/auth/v1/auth/login", { method: "POST", body: { username: "a" }, auth: false });
    const init = (fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1];
    expect((init.headers as Record<string, string>).Authorization).toBeUndefined();
  });
});
