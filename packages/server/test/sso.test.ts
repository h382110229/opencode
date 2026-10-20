import { expect, test } from "bun:test"
import { ServerSso } from "@opencode/server/sso"
import { createSign, generateKeyPairSync } from "node:crypto"

const ISSUER = "https://oci-sso.hawkren.online"
const EMAIL = "huangliang@hawkren.online"

function makeConfig(overrides: Partial<ServerSso.Input> = {}, password = "password") {
  const config = ServerSso.make({ issuer: ISSUER, clientSecret: "client-secret", ...overrides }, password)
  if (!config) throw new Error("expected an SSO config")
  return config
}

test("SSO stays off until an issuer, client secret, and server password are configured", () => {
  expect(ServerSso.make({}, "password")).toBeUndefined()
  expect(ServerSso.make({ issuer: ISSUER }, "password")).toBeUndefined()
  expect(ServerSso.make({ issuer: ISSUER, clientSecret: "client-secret" }, undefined)).toBeUndefined()
  const config = makeConfig()
  expect(config.clientId).toBe("opencode")
  expect(config.enforce).toBe(true)
  expect(config.allowEmails).toEqual([EMAIL])
  // The issuer is normalized so a trailing slash cannot produce a second, mismatched identity in tokens.
  expect(makeConfig({ issuer: `${ISSUER}/` }).issuer).toBe(ISSUER)
  expect(makeConfig({ allowEmails: ["other@example.com"] }).allowEmails).toEqual(["other@example.com"])
  expect(makeConfig({ enforce: false }).enforce).toBe(false)
})

test("sessions carry the identity, expire, and resist tampering", () => {
  const config = makeConfig()
  const now = Date.now()
  const session = ServerSso.issueSession(config, { sub: "user-1", email: EMAIL }, now)
  expect(ServerSso.verifySession(config, session, now)).toEqual({ sub: "user-1", email: EMAIL })

  const [payload, signature] = session.split(".")
  // Editing the payload invalidates the signature.
  const forged = Buffer.from(JSON.stringify({ sub: "user-1", email: "admin@example.com", exp: Number(payload) }))
  expect(ServerSso.verifySession(config, `${forged.toString("base64url")}.${signature}`, now)).toBeUndefined()
  // Expired sessions and garbage are rejected.
  expect(ServerSso.verifySession(config, session, now + ServerSso.SESSION_TTL_SECONDS * 1000)).toBeUndefined()
  expect(ServerSso.verifySession(config, `${payload}.tampered`, now)).toBeUndefined()
  expect(ServerSso.verifySession(config, "not-a-session", now)).toBeUndefined()
  expect(ServerSso.verifySession(config, undefined, now)).toBeUndefined()
})

test("rotating the server password revokes existing sessions", () => {
  const session = ServerSso.issueSession(makeConfig(), { sub: "user-1", email: EMAIL })
  expect(ServerSso.verifySession(makeConfig({}, "rotated"), session)).toBeUndefined()
})

test("removing an address from the allow list kills its live session", () => {
  const config = makeConfig({ allowEmails: [EMAIL, "second@example.com"] })
  const session = ServerSso.issueSession(config, { sub: "user-1", email: "second@example.com" })
  expect(ServerSso.verifySession(config, session)).toBeDefined()
  // The allow list is re-read on every request rather than trusted from the cookie.
  const narrowed = makeConfig({ allowEmails: [EMAIL] })
  expect(ServerSso.verifySession(narrowed, session)).toBeUndefined()
})

test("state only ever returns to a same-site path", () => {
  const config = makeConfig()
  const now = Date.now()
  expect(ServerSso.verifyState(config, ServerSso.issueState(config, "/workspace/example?x=1", now), now)).toBe(
    "/workspace/example?x=1",
  )
  expect(ServerSso.verifyState(config, ServerSso.issueState(config, "/", now), now + ServerSso.STATE_TTL_SECONDS * 1000))
    .toBeUndefined()
  for (const hostile of ["https://evil.example.com", "//evil.example.com", "/\\evil.example.com"]) {
    const forged = Buffer.from(JSON.stringify({ redirect: hostile, exp: Math.floor(now / 1000) + 60 })).toString(
      "base64url",
    )
    expect(ServerSso.verifyState(config, `${forged}.${ServerSso.issueState(config, "/", now).split(".")[1]}`, now))
      .toBeUndefined()
  }
  expect(ServerSso.verifyState(config, undefined)).toBeUndefined()
})

test("sign-in URL targets the provider with a redirect back to this server's callback", () => {
  const config = makeConfig()
  const url = new URL(ServerSso.signInURL(config, "https://opencode.hawkren.online", "state-value"))
  expect(url.origin + url.pathname).toBe(`${ISSUER}/api/oidc/authorize`)
  expect(url.searchParams.get("client_id")).toBe("opencode")
  expect(url.searchParams.get("redirect_uri")).toBe("https://opencode.hawkren.online/auth/oidc/callback")
  expect(url.searchParams.get("response_type")).toBe("code")
  expect(url.searchParams.get("scope")).toBe("openid email profile")
  expect(url.searchParams.get("state")).toBe("state-value")
})

test("origin prefers the forwarded protocol from the reverse proxy", () => {
  expect(ServerSso.origin({ host: "opencode.hawkren.online", "x-forwarded-proto": "https" })).toBe(
    "https://opencode.hawkren.online",
  )
  expect(ServerSso.origin({ host: "127.0.0.1:4001" })).toBe("http://127.0.0.1:4001")
  expect(ServerSso.origin({})).toBeUndefined()
})

test("the session cookie is http-only, secure, and same-site", () => {
  const cookie = ServerSso.sessionCookie("value")
  expect(cookie).toContain(`${ServerSso.SESSION_COOKIE}=value`)
  expect(cookie).toContain("HttpOnly")
  expect(cookie).toContain("Secure")
  expect(cookie).toContain("SameSite=Lax")
  expect(cookie).toContain("Path=/")
})

// RS256 identity verification, exercised against a real key pair instead of the live provider.
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 })
const jwk = publicKey.export({ format: "jwk" })
const jwks = [{ kty: jwk.kty, n: jwk.n, e: jwk.e, kid: "test-key" }]

function idToken(config: ServerSso.Info, payload: Record<string, unknown>, header: Record<string, unknown> = {}) {
  const head = Buffer.from(JSON.stringify({ alg: "RS256", kid: "test-key", ...header })).toString("base64url")
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url")
  const signer = createSign("RSA-SHA256")
  signer.update(`${head}.${body}`)
  return `${head}.${body}.${signer.sign(privateKey).toString("base64url")}`
}

function claims(config: ServerSso.Info, overrides: Record<string, unknown> = {}) {
  return {
    iss: config.issuer,
    aud: config.clientId,
    sub: "user-1",
    email: EMAIL,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    ...overrides,
  }
}

test("a valid RS256 id_token from the provider yields the identity", async () => {
  const config = makeConfig()
  const result = await ServerSso.verifyIdentity(config, idToken(config, claims(config)), Date.now(), jwks)
  expect(result).toEqual({ ok: true, identity: { sub: "user-1", email: EMAIL } })
})

test("id_tokens are rejected for a bad signature, issuer, audience, expiry, or algorithm", async () => {
  const config = makeConfig()
  const now = Date.now()
  const valid = idToken(config, claims(config))
  const [head, body, signature] = valid.split(".")
  const flipped = `${head}.${body}.${signature.slice(0, -2)}${signature.endsWith("A") ? "B" : "A"}`

  const rejected = await Promise.all([
    ServerSso.verifyIdentity(config, flipped, now, jwks),
    ServerSso.verifyIdentity(config, idToken(config, claims(config, { iss: "https://evil.example.com" })), now, jwks),
    ServerSso.verifyIdentity(config, idToken(config, claims(config, { aud: "someone-else" })), now, jwks),
    ServerSso.verifyIdentity(config, idToken(config, claims(config, { exp: Math.floor(now / 1000) - 60 })), now, jwks),
    ServerSso.verifyIdentity(config, idToken(config, claims(config), { alg: "HS256" }), now, jwks),
    ServerSso.verifyIdentity(config, undefined, now, jwks),
    ServerSso.verifyIdentity(config, "not.a.jwt", now, jwks),
  ])
  for (const result of rejected) expect(result).toEqual({ ok: false, reason: "verify" })
})

test("an address outside the allow list is distinguished from a broken token", async () => {
  const config = makeConfig()
  const result = await ServerSso.verifyIdentity(
    config,
    idToken(config, claims(config, { email: "stranger@example.com" })),
    Date.now(),
    jwks,
  )
  expect(result).toEqual({ ok: false, reason: "whitelist" })
})
