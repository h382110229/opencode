export * as ServerSso from "./sso"

import { createHmac, createPublicKey, timingSafeEqual, verify } from "node:crypto"

// OpenID Connect sign-in against an external identity provider (OCI-SSO).
//
// Browsers are redirected to the provider on a page navigation and return on /auth/oidc/callback with an
// authorization code. Everything else — CLI clients, API calls, and every request while OPENCODE_SSO_ISSUER is
// unset — keeps the Basic/session auth in auth.ts, so the upstream behavior stays available as a fallback.
//
// The session cookie carries the identity, and the email whitelist is re-checked on every verification rather
// than only at sign-in, so removing an address from OPENCODE_SSO_ALLOW_EMAILS kicks that browser out immediately
// instead of leaving a 30-day cookie behind.

export const SESSION_COOKIE = "opencode_sso"
export const CALLBACK_PATH = "/auth/oidc/callback"
export const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60
export const STATE_TTL_SECONDS = 15 * 60

// OCI-SSO issues an account to each registered address; sign-in is limited to these unless overridden.
const DEFAULT_ALLOW_EMAILS = ["huangliang@hawkren.online"]

export type Info = {
  readonly issuer: string
  readonly clientId: string
  readonly clientSecret: string
  readonly allowEmails: readonly string[]
  readonly enforce: boolean
  readonly secret: string
}

export type Input = {
  readonly issuer?: string | undefined
  readonly clientId?: string | undefined
  readonly clientSecret?: string | undefined
  readonly allowEmails?: readonly string[] | undefined
  readonly enforce?: boolean | undefined
}

export type Identity = {
  readonly sub: string
  readonly email: string
}

export type IdentityResult =
  | { readonly ok: true; readonly identity: Identity }
  | { readonly ok: false; readonly reason: "whitelist" | "verify" }

type Claims = Record<string, unknown>

type Jwk = {
  readonly kty?: string
  readonly kid?: string
  readonly n?: string
  readonly e?: string
}

// SSO is off unless an issuer and client secret are configured; an empty issuer restores upstream auth exactly.
export function make(input: Input, password: string | undefined): Info | undefined {
  const issuer = input.issuer?.trim().replace(/\/+$/, "")
  if (!issuer || !input.clientSecret || !password) return
  return {
    issuer,
    clientId: input.clientId?.trim() || "opencode",
    clientSecret: input.clientSecret,
    allowEmails: input.allowEmails?.length ? input.allowEmails : DEFAULT_ALLOW_EMAILS,
    enforce: input.enforce ?? true,
    secret: password,
  }
}

export function sessionCookie(value: string) {
  return `${SESSION_COOKIE}=${value}; Path=/; Max-Age=${SESSION_TTL_SECONDS}; HttpOnly; Secure; SameSite=Lax`
}

export function issueSession(config: Info, identity: Identity, now = Date.now()) {
  const payload = base64url(JSON.stringify({ ...identity, exp: Math.floor(now / 1000) + SESSION_TTL_SECONDS }))
  return `${payload}.${signature(config, payload)}`
}

// Returns the identity only when the signature, expiry, and (again) the email whitelist all hold.
export function verifySession(config: Info, value: string | undefined, now = Date.now()): Identity | undefined {
  if (!value) return undefined
  const parts = value.split(".")
  if (parts.length !== 2) return undefined
  if (!validSignature(config, parts[0], parts[1])) return undefined
  const claims = decode(parts[0])
  if (!claims) return undefined
  const exp = claims["exp"]
  if (typeof exp !== "number" || exp * 1000 <= now) return undefined
  const email = claims["email"]
  if (typeof email !== "string" || !allowed(config, email)) return undefined
  return { sub: String(claims["sub"] ?? ""), email }
}

export function allowed(config: Info, email: string) {
  const normalized = email.trim().toLowerCase()
  return config.allowEmails.some((entry) => entry.trim().toLowerCase() === normalized)
}

// The state binds the round trip to the page that started it without server-side storage: it is signed, expires
// in minutes, and only ever yields a same-site path, so a forged state cannot bounce the browser off-site.
export function issueState(config: Info, redirect: string, now = Date.now()) {
  const payload = base64url(JSON.stringify({ redirect, exp: Math.floor(now / 1000) + STATE_TTL_SECONDS }))
  return `${payload}.${signature(config, payload)}`
}

export function verifyState(config: Info, state: string | undefined, now = Date.now()): string | undefined {
  if (!state) return undefined
  const parts = state.split(".")
  if (parts.length !== 2) return undefined
  if (!validSignature(config, parts[0], parts[1])) return undefined
  const claims = decode(parts[0])
  if (!claims) return undefined
  const exp = claims["exp"]
  if (typeof exp !== "number" || exp * 1000 <= now) return undefined
  const redirect = claims["redirect"]
  if (typeof redirect !== "string" || !redirect.startsWith("/") || redirect.startsWith("//")) return undefined
  return redirect
}

export function origin(headers: { readonly [key: string]: string | undefined }) {
  const host = headers["host"]
  if (!host) return undefined
  return `${headers["x-forwarded-proto"] === "https" ? "https" : "http"}://${host}`
}

export function signInURL(config: Info, origin: string, state: string) {
  const url = new URL(`${config.issuer}/api/oidc/authorize`)
  url.searchParams.set("client_id", config.clientId)
  url.searchParams.set("redirect_uri", `${origin}${CALLBACK_PATH}`)
  url.searchParams.set("response_type", "code")
  url.searchParams.set("scope", "openid email profile")
  url.searchParams.set("state", state)
  return url.toString()
}

export async function exchangeCode(config: Info, code: string, redirectURI: string) {
  const response = await fetch(`${config.issuer}/api/oidc/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectURI,
      client_id: config.clientId,
      client_secret: config.clientSecret,
    }),
    signal: AbortSignal.timeout(10_000),
  })
  if (!response.ok) return undefined
  const body = (await response.json().catch(() => undefined)) as { id_token?: string } | undefined
  return body?.id_token
}

// RS256 verification against the provider's JWKS with node:crypto, so the patch adds no dependency.
export async function verifyIdentity(
  config: Info,
  idToken: string | undefined,
  now = Date.now(),
  jwks?: readonly Jwk[],
): Promise<IdentityResult> {
  const failure: IdentityResult = { ok: false, reason: "verify" }
  if (!idToken) return failure
  const parts = idToken.split(".")
  if (parts.length !== 3) return failure
  const header = decode(parts[0])
  const claims = decode(parts[1])
  if (!header || !claims || header["alg"] !== "RS256") return failure
  const keys = jwks ?? (await publicKeys(config))
  const jwk = keys?.find((key) => !header["kid"] || key.kid === header["kid"]) ?? keys?.[0]
  if (!jwk || jwk.kty !== "RSA" || !jwk.n || !jwk.e) return failure
  const signed = verify(
    "RSA-SHA256",
    Buffer.from(`${parts[0]}.${parts[1]}`),
    createPublicKey({ key: { kty: jwk.kty, n: jwk.n, e: jwk.e }, format: "jwk" }),
    Buffer.from(parts[2], "base64url"),
  )
  if (!signed) return failure
  if (claims["iss"] !== config.issuer) return failure
  const audience = claims["aud"]
  const audiences = typeof audience === "string" ? [audience] : Array.isArray(audience) ? audience : []
  if (!audiences.includes(config.clientId)) return failure
  const exp = claims["exp"]
  // A small skew keeps a token that expired mid-flight from being accepted on the way back.
  if (typeof exp !== "number" || exp * 1000 <= now - 30_000) return failure
  const email = claims["email"]
  if (typeof email !== "string" || !email) return failure
  const identity = { sub: String(claims["sub"] ?? ""), email }
  if (!allowed(config, email)) return { ok: false, reason: "whitelist" }
  return { ok: true, identity }
}

const jwkCache = new Map<string, { readonly fetched: number; readonly keys: readonly Jwk[] }>()
const JWK_CACHE_TTL = 60 * 60 * 1000

async function publicKeys(config: Info) {
  const cached = jwkCache.get(config.issuer)
  if (cached && Date.now() - cached.fetched < JWK_CACHE_TTL) return cached.keys
  const response = await fetch(`${config.issuer}/api/oidc/jwks`, { signal: AbortSignal.timeout(10_000) })
  if (!response.ok) return undefined
  const body = (await response.json().catch(() => undefined)) as { keys?: Jwk[] } | undefined
  if (!body?.keys?.length) return undefined
  jwkCache.set(config.issuer, { fetched: Date.now(), keys: body.keys })
  return body.keys
}

function validSignature(config: Info, payload: string, provided: string) {
  const expected = Buffer.from(signature(config, payload))
  const actual = Buffer.from(provided)
  return actual.length === expected.length && timingSafeEqual(actual, expected)
}

// Same two-step derivation as auth.ts, so rotating OPENCODE_PASSWORD revokes every session at once.
function signature(config: Info, payload: string) {
  const key = createHmac("sha256", config.secret).update("opencode-sso-v1").digest()
  return createHmac("sha256", key).update(payload).digest("base64url")
}

function base64url(input: string) {
  return Buffer.from(input).toString("base64url")
}

function decode(input: string): Claims | undefined {
  try {
    const parsed: unknown = JSON.parse(Buffer.from(input, "base64url").toString())
    return typeof parsed === "object" && parsed !== null ? (parsed as Claims) : undefined
  } catch {
    return undefined
  }
}
