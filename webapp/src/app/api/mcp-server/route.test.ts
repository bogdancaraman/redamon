/**
 * The inbound MCP route's transport guards.
 *
 * Everything here is about what reaches the tools at all. The route is BEARER
 * ONLY, and the two credentials it must refuse are the interesting cases:
 *
 *  - the session cookie, because honouring it would make this
 *    middleware-exempt, state-changing POST CSRF-reachable from a logged-in
 *    operator's browser
 *  - X-Scanner-Key, because every spawned scan container holds one and that is
 *    the least-trusted tier; accepting it would invert the trust model
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  resolve: vi.fn(),
  audit: vi.fn(),
  build: vi.fn(),
  connect: vi.fn(),
  close: vi.fn(),
  handleRequest: vi.fn(),
  transportOptions: vi.fn(),
  instructions: vi.fn(),
}))

vi.mock('@/lib/mcpAuth', () => ({
  resolveMcpUser: (...a: unknown[]) => h.resolve(...a),
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
// Mocked for the same reason @/lib/mcp/server is: this file is about the
// transport guards, and the real module builds the whole tool registry to
// compose its string. instructions.test.ts owns that behaviour.
vi.mock('@/lib/mcp/instructions', () => ({
  buildInstructions: (...a: unknown[]) => h.instructions(...a),
}))
vi.mock('@/lib/mcp/server', () => ({
  buildMcpServer: (...a: unknown[]) => {
    h.build(...a)
    return { connect: h.connect, close: h.close }
  },
}))
vi.mock('@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js', () => ({
  WebStandardStreamableHTTPServerTransport: class {
    constructor(opts: unknown) { h.transportOptions(opts) }
    handleRequest(...a: unknown[]) { return h.handleRequest(...a) }
  },
}))

import { POST, GET, DELETE, MCP_DISABLED_MESSAGE, mcpServerEnabled, __resetAuthAuditThrottle } from './route'

const TOKEN = {
  tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
  name: 'agent', scopes: ['recon:read'],
}

const rpc = { jsonrpc: '2.0', method: 'tools/list', id: 1 }

function req(opts: {
  body?: unknown
  raw?: string
  headers?: Record<string, string>
  url?: string
} = {}) {
  const headers = new Headers({
    'content-type': 'application/json',
    authorization: 'Bearer rdmn_mcp_' + 'a'.repeat(48),
    ...(opts.headers ?? {}),
  })
  const body = opts.raw ?? JSON.stringify(opts.body ?? rpc)
  return new Request(opts.url ?? 'https://redamon.example/api/mcp-server', {
    method: 'POST', headers, body,
  }) as never
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.unstubAllEnvs()
  vi.stubEnv('MCP_SERVER_ENABLED', 'true')
  h.resolve.mockResolvedValue({ ok: true, token: TOKEN, prefix: TOKEN.tokenPrefix })
  h.connect.mockResolvedValue(undefined)
  h.close.mockResolvedValue(undefined)
  h.handleRequest.mockResolvedValue(
    new Response(JSON.stringify({ jsonrpc: '2.0', result: { tools: [] }, id: 1 }), {
      status: 200, headers: { 'content-type': 'application/json' },
    })
  )
  h.audit.mockResolvedValue(undefined)
  h.instructions.mockResolvedValue('ONBOARDING')
  __resetAuthAuditThrottle()
})

// --- the feature flag ------------------------------------------------------------

describe('MCP_SERVER_ENABLED defaults off', () => {
  test('unset means disabled', () => {
    vi.stubEnv('MCP_SERVER_ENABLED', '')
    expect(mcpServerEnabled()).toBe(false)
  })

  test.each(['false', '0', 'yes', 'TRUE', 'on'])('%s does not enable it', v => {
    vi.stubEnv('MCP_SERVER_ENABLED', v)
    expect(mcpServerEnabled()).toBe(false)
  })

  test.each(['true', '1'])('%s enables it', v => {
    vi.stubEnv('MCP_SERVER_ENABLED', v)
    expect(mcpServerEnabled()).toBe(true)
  })

  test('a disabled deployment answers 404 and does no auth work', async () => {
    vi.stubEnv('MCP_SERVER_ENABLED', 'false')
    const res = await POST(req())
    expect(res.status).toBe(404)
    // It must not reveal whether a token is valid.
    expect(h.resolve).not.toHaveBeenCalled()
  })
})

// =============================================================================
// REGRESSION: a disabled server read as a wrong URL
// =============================================================================
//
// It answered `-32601 "Not found"`, byte-identical with and without a token,
// which is exactly what a nonexistent route looks like. An operator spent an
// hour on paths, auth schemes and TLS before finding the flag in the source.

describe('REGRESSION: the disabled answer names the switch', () => {
  async function disabledBody(headers?: Record<string, string>) {
    vi.stubEnv('MCP_SERVER_ENABLED', 'false')
    const res = await POST(req({ headers }))
    expect(res.status).toBe(404)
    return (await res.json()) as { jsonrpc: string; id: null; error: { code: number; message: string } }
  }

  test('the message says the server is disabled and names the flag', async () => {
    const body = await disabledBody()
    expect(body.jsonrpc).toBe('2.0')
    expect(body.id).toBeNull()
    expect(body.error.message).toBe(MCP_DISABLED_MESSAGE)
    expect(body.error.message).toMatch(/disabled/i)
    expect(body.error.message).toContain('MCP_SERVER_ENABLED=true')
    // A plain `docker compose restart` keeps the old environment, so the fix
    // it names must be the one that re-reads it.
    expect(body.error.message).toContain('docker compose up -d webapp')
  })

  test('it is not -32601 "method not found" nor a bare "Not found"', async () => {
    const body = await disabledBody()
    expect(body.error.code).toBe(-32000)
    expect(body.error.message).not.toBe('Not found')
  })

  test('the answer is identical whatever credential is sent, and none is read', async () => {
    // Naming the switch must not become a token oracle: no header, a
    // well-formed bearer and garbage all get the same bytes, and the resolver
    // is never reached.
    const bearer = await disabledBody()
    const none = await disabledBody({ authorization: '' })
    const garbage = await disabledBody({ authorization: 'Basic Zm9vOmJhcg==' })
    expect(none).toEqual(bearer)
    expect(garbage).toEqual(bearer)
    expect(h.resolve).not.toHaveBeenCalled()
    expect(h.audit).not.toHaveBeenCalled()
    expect(h.build).not.toHaveBeenCalled()
  })

  test('an enabled server does not use the disabled message', async () => {
    h.resolve.mockResolvedValue({ ok: false, failure: 'invalid', prefix: 'rdmn_mcp_aaaaaaaa' })
    const res = await POST(req())
    expect(res.status).toBe(401)
    expect(JSON.stringify(await res.json())).not.toContain('MCP_SERVER_ENABLED')
  })
})

// --- bearer only -------------------------------------------------------------------

describe('the route is bearer-only', () => {
  test('a valid bearer builds the server with the resolved token', async () => {
    const res = await POST(req())
    expect(res.status).toBe(200)
    // The second argument is the connect-time onboarding, absent for anything
    // that is not an `initialize`.
    expect(h.build).toHaveBeenCalledWith({ token: TOKEN }, undefined)
  })

  test('a missing bearer is rejected', async () => {
    h.resolve.mockResolvedValue({ ok: false, failure: 'missing' })
    const res = await POST(req({ headers: { authorization: '' } }))
    expect(res.status).toBe(401)
    expect(h.build).not.toHaveBeenCalled()
  })

  test('a session COOKIE alone authenticates nothing (CSRF)', async () => {
    h.resolve.mockResolvedValue({ ok: false, failure: 'missing' })
    const res = await POST(req({
      headers: { authorization: '', cookie: 'redamon-auth=a.valid.jwt' },
    }))
    expect(res.status).toBe(401)
  })

  test('X-Scanner-Key alone authenticates nothing (trust inversion)', async () => {
    h.resolve.mockResolvedValue({ ok: false, failure: 'missing' })
    const res = await POST(req({
      headers: { authorization: '', 'x-scanner-key': 'scan-tok' },
    }))
    expect(res.status).toBe(401)
  })

  test('X-Internal-Key alone authenticates nothing', async () => {
    h.resolve.mockResolvedValue({ ok: false, failure: 'missing' })
    const res = await POST(req({
      headers: { authorization: '', 'x-internal-key': 'master-key' },
    }))
    expect(res.status).toBe(401)
  })

  test.each(['revoked', 'expired', 'invalid', 'bad_scopes'])(
    'a %s token is rejected with the same stable message',
    async failure => {
      h.resolve.mockResolvedValue({ ok: false, failure, prefix: 'rdmn_mcp_aaaaaaaa' })
      const res = await POST(req())
      expect(res.status).toBe(401)
      const body = await res.json()
      // The reason goes to the log, not the caller.
      expect(body.error.message).toBe('Unauthorized')
    }
  )

  test('an auth failure is audited by PREFIX, never by token', async () => {
    h.resolve.mockResolvedValue({ ok: false, failure: 'revoked', prefix: 'rdmn_mcp_aaaaaaaa' })
    await POST(req())
    expect(h.audit).toHaveBeenCalledWith(expect.objectContaining({
      action: 'mcp.auth.denied',
      targetId: 'rdmn_mcp_aaaaaaaa',
    }))
    expect(JSON.stringify(h.audit.mock.calls[0][0])).not.toContain('a'.repeat(48))
  })
})

// --- request shape guards -------------------------------------------------------------

describe('request shape', () => {
  test('a non-JSON content type is refused', async () => {
    // A plain HTML form post cannot set application/json, so it cannot drive
    // this endpoint.
    const res = await POST(req({ headers: { 'content-type': 'application/x-www-form-urlencoded' } }))
    expect(res.status).toBe(415)
    expect(h.resolve).not.toHaveBeenCalled()
  })

  test('a JSON content type with a charset is accepted', async () => {
    const res = await POST(req({ headers: { 'content-type': 'application/json; charset=utf-8' } }))
    expect(res.status).toBe(200)
  })

  test('a JSON-RPC BATCH array is refused', async () => {
    // A batch would let one authenticated call fan out past every per-call
    // budget the tools enforce.
    const res = await POST(req({ body: [rpc, rpc] }))
    expect(res.status).toBe(400)
    expect(h.build).not.toHaveBeenCalled()
  })

  test('an over-large body is refused before parsing', async () => {
    const res = await POST(req({ raw: JSON.stringify({ x: 'y'.repeat(1_100_000) }) }))
    expect(res.status).toBe(413)
    expect(h.resolve).not.toHaveBeenCalled()
  })

  test('unparseable JSON is a 400, not a 500', async () => {
    const res = await POST(req({ raw: '{not json' }))
    expect(res.status).toBe(400)
  })
})

describe('Origin handling (DNS rebinding / browser-driven abuse)', () => {
  test('a foreign Origin is refused', async () => {
    const res = await POST(req({ headers: { origin: 'https://evil.example' } }))
    expect(res.status).toBe(403)
    expect(h.resolve).not.toHaveBeenCalled()
  })

  test('our own Origin is allowed', async () => {
    const res = await POST(req({ headers: { origin: 'https://redamon.example' } }))
    expect(res.status).toBe(200)
  })

  test('an ABSENT Origin is allowed: MCP clients are not browsers', async () => {
    const res = await POST(req())
    expect(res.status).toBe(200)
  })

  test('a malformed Origin is refused', async () => {
    const res = await POST(req({ headers: { origin: 'not-a-url' } }))
    expect(res.status).toBe(403)
  })
})

// --- transport mode -----------------------------------------------------------------

describe('stateless JSON mode', () => {
  test('no session id generator is configured', async () => {
    await POST(req())
    const opts = h.transportOptions.mock.calls[0][0]
    expect(opts.sessionIdGenerator).toBeUndefined()
    expect(opts.enableJsonResponse).toBe(true)
  })

  test('the server is closed after every request', async () => {
    await POST(req())
    expect(h.close).toHaveBeenCalled()
  })

  test('the server is closed even when handling throws', async () => {
    h.handleRequest.mockRejectedValue(new Error('boom'))
    const res = await POST(req())
    expect(res.status).toBe(500)
    expect(h.close).toHaveBeenCalled()
  })

  test('a handling failure does not leak the error to the caller', async () => {
    h.handleRequest.mockRejectedValue(new Error('ECONNREFUSED 10.0.0.5:7687'))
    const body = await (await POST(req())).json()
    expect(JSON.stringify(body)).not.toMatch(/ECONNREFUSED|10\.0\.0\.5/)
  })

  test.each([
    ['GET', GET],
    ['DELETE', DELETE],
  ])('%s answers 405: there is no stream to manage', async (_m, fn) => {
    expect((await fn()).status).toBe(405)
  })
})

describe('caching', () => {
  test('every response is no-store, not relying on the edge', async () => {
    // A plain `docker compose up` has no nginx, so the header is set here.
    expect((await POST(req())).headers.get('Cache-Control')).toBe('no-store')
    vi.stubEnv('MCP_SERVER_ENABLED', 'false')
    expect((await POST(req())).headers.get('Cache-Control')).toBe('no-store')
  })
})

// =============================================================================
// REGRESSION: pre-auth resource exhaustion (audit finding F4)
// =============================================================================
//
// This route is in PUBLIC_PATHS, so both of these ran for an ANONYMOUS caller:
// the whole body was buffered before the Authorization header was looked at,
// and every failed auth inserted an audit row into the Postgres the whole
// platform shares. Neither had a bound.

describe('REGRESSION: the body is bounded BEFORE auth', () => {
  test('an oversized declared length is refused without reading the body', async () => {
    const res = await POST(req({ headers: { 'content-length': String(50 * 1024 * 1024) } }))
    expect(res.status).toBe(413)
    // Refused before the token lookup: an anonymous flood costs no DB work.
    expect(h.resolve).not.toHaveBeenCalled()
  })

  test('the cap counts BYTES, not UTF-16 code units', async () => {
    // 400k three-byte characters is ~1.2 MB but String.length is only 400k, so
    // a length-based check passes a body documented as capped at 1 MiB.
    const body = JSON.stringify({ jsonrpc: '2.0', method: 'x', id: 1, pad: '\u4e2d'.repeat(400_000) })
    expect(body.length).toBeLessThan(1024 * 1024)
    expect(new TextEncoder().encode(body).byteLength).toBeGreaterThan(1024 * 1024)

    const res = await POST(req({ raw: body }))
    expect(res.status).toBe(413)
  })

  test('a normal-sized body still passes', async () => {
    expect((await POST(req())).status).toBe(200)
  })
})

describe('REGRESSION: the failed-auth audit is throttled', () => {
  beforeEach(() => {
    h.resolve.mockResolvedValue({ ok: false, failure: 'invalid', prefix: 'rdmn_mcp_aaaaaaaa' })
  })

  test('the first failure for a prefix IS audited', async () => {
    await POST(req())
    expect(h.audit).toHaveBeenCalledOnce()
  })

  test('a flood from one prefix writes ONE row, not one per request', async () => {
    for (let i = 0; i < 50; i++) await POST(req())
    expect(h.audit).toHaveBeenCalledOnce()
  })

  test('a DISTINCT prefix is still audited (the signal survives)', async () => {
    await POST(req())
    h.resolve.mockResolvedValue({ ok: false, failure: 'invalid', prefix: 'rdmn_mcp_bbbbbbbb' })
    await POST(req())
    expect(h.audit).toHaveBeenCalledTimes(2)
  })

  test('every request is still REJECTED, whether or not it was audited', async () => {
    for (let i = 0; i < 5; i++) {
      expect((await POST(req())).status).toBe(401)
    }
  })
})

// =============================================================================
// REGRESSION: the Origin check behind a reverse proxy (deploy finding F8)
// =============================================================================
//
// nginx forwards `Host $host`, and $host DROPS THE PORT. On a deploy with a
// non-default HTTPS_PORT, a client sending its own correct origin
// (https://redamon.example:8443) was compared against "redamon.example" and
// 403'd against itself, with only "[mcp] rejected cross-origin request" as a
// clue. The deploy now passes the public origin explicitly.

describe('REGRESSION: MCP_ALLOWED_ORIGIN wins over the request-derived host', () => {
  test('a non-default-port origin is accepted when configured', async () => {
    vi.stubEnv('MCP_ALLOWED_ORIGIN', 'https://redamon.example:8443')
    const res = await POST(req({
      url: 'https://redamon.example/api/mcp-server',   // nginx dropped the port
      headers: { origin: 'https://redamon.example:8443' },
    }))
    expect(res.status).toBe(200)
  })

  test('a foreign origin is still refused when configured', async () => {
    vi.stubEnv('MCP_ALLOWED_ORIGIN', 'https://redamon.example:8443')
    const res = await POST(req({ headers: { origin: 'https://evil.example' } }))
    expect(res.status).toBe(403)
  })

  test('the SCHEME must match too, so a plaintext origin cannot pass', async () => {
    // Comparing host alone would let http://redamon.example:8443 through on an
    // https deployment.
    vi.stubEnv('MCP_ALLOWED_ORIGIN', 'https://redamon.example:8443')
    const res = await POST(req({ headers: { origin: 'http://redamon.example:8443' } }))
    expect(res.status).toBe(403)
  })

  test('the right host on the WRONG port is refused', async () => {
    vi.stubEnv('MCP_ALLOWED_ORIGIN', 'https://redamon.example:8443')
    const res = await POST(req({ headers: { origin: 'https://redamon.example:9999' } }))
    expect(res.status).toBe(403)
  })

  test('an absent Origin still passes (MCP clients are not browsers)', async () => {
    vi.stubEnv('MCP_ALLOWED_ORIGIN', 'https://redamon.example:8443')
    expect((await POST(req())).status).toBe(200)
  })

  test('a MISCONFIGURED value fails closed rather than allowing everything', async () => {
    vi.stubEnv('MCP_ALLOWED_ORIGIN', 'not-a-url')
    const res = await POST(req({ headers: { origin: 'https://redamon.example' } }))
    expect(res.status).toBe(403)
  })

  test('unset falls back to the request-derived check (correct with no proxy)', async () => {
    vi.stubEnv('MCP_ALLOWED_ORIGIN', '')
    expect((await POST(req({ headers: { origin: 'https://redamon.example' } }))).status).toBe(200)
    expect((await POST(req({ headers: { origin: 'https://evil.example' } }))).status).toBe(403)
  })
})

// --- connect-time onboarding -------------------------------------------------------

describe('the instructions string is composed only at initialize', () => {
  const initialize = {
    jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'c', version: '1' } },
  }

  test('an initialize request gets onboarding, built for that token', async () => {
    await POST(req({ body: initialize }))
    expect(h.instructions).toHaveBeenCalledOnce()
    expect(h.instructions.mock.calls[0]).toEqual([TOKEN.tokenId, TOKEN.scopes])
    expect(h.build.mock.calls[0][1]).toBe('ONBOARDING')
  })

  test('an ordinary tool call composes NOTHING', async () => {
    // The transport is stateless, so the server is rebuilt for every request.
    // Composing this per call would add a database read and a tool-list build to
    // every call, for a string the client never reads again.
    await POST(req({ body: rpc }))
    expect(h.instructions).not.toHaveBeenCalled()
    expect(h.build.mock.calls[0][1]).toBeUndefined()
  })

  test('onboarding is composed only AFTER the token resolves', async () => {
    h.resolve.mockResolvedValue({ ok: false, failure: 'invalid', prefix: 'rdmn_mcp_bbbbbbbb' })
    const res = await POST(req({ body: initialize }))
    expect(res.status).toBe(401)
    expect(h.instructions).not.toHaveBeenCalled()
  })

  test('a failure to compose onboarding does not fail the connection', async () => {
    h.instructions.mockResolvedValue(undefined)
    const res = await POST(req({ body: initialize }))
    expect(res.status).toBe(200)
    expect(h.build.mock.calls[0][1]).toBeUndefined()
  })
})
