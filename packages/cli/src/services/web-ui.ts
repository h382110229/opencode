import { FSUtil } from "@opencode/util/fs-util"
import { Effect, FileSystem } from "effect"
import { HttpServerError, HttpServerRequest, HttpServerResponse } from "effect/http"
import { createHash } from "node:crypto"
import { load, type AssetMap, type BrotliMap } from "../app-assets"
import { ServerSso } from "@opencode/server/sso"

export const handler = Effect.fn("cli.web-ui.handler")(function* (options?: {
  readonly assets?: AssetMap
  readonly brotli?: BrotliMap
  readonly sso?: ServerSso.Info
}) {
  const fileSystem = yield* FileSystem.FileSystem
  const assets = options?.assets
    ? Effect.succeed({ files: options.assets, brotli: options.brotli })
    : yield* Effect.cached(load().pipe(Effect.provideService(FileSystem.FileSystem, fileSystem)))
  const sso = options?.sso
  return <E, R>(api: Effect.Effect<HttpServerResponse.HttpServerResponse, E, R>) =>
    Effect.gen(function* () {
      const request = yield* HttpServerRequest.HttpServerRequest
      const url = new URL(request.url, "http://localhost")
      // SSO sign-in rides ahead of the shell: the callback consumes the authorization code, and an
      // unauthenticated page load is sent to the identity provider instead of reaching the sign-in screen.
      if (sso !== undefined && url.pathname === ServerSso.CALLBACK_PATH) return yield* callback(sso, request, url)
      if (
        sso?.enforce === true &&
        !apiPath(url) &&
        navigation(request) &&
        ServerSso.verifySession(sso, request.cookies[ServerSso.SESSION_COOKIE]) === undefined
      ) {
        const redirected = redirect(sso, request, url)
        if (redirected !== undefined) return redirected
      }
      // Serve the web shell before API authentication so a signed-out browser gets the app's sign-in screen.
      if (apiPath(url))
        return yield* api.pipe(
          Effect.catchIf(isRouteNotFound, () => Effect.succeed(HttpServerResponse.empty({ status: 404 }))),
        )
      return yield* assets.pipe(Effect.flatMap((loaded) => serveUI(request, url, loaded.files, loaded.brotli)))
    })
})

function apiPath(url: URL) {
  return (
    url.pathname === "/api" ||
    url.pathname.startsWith("/api/") ||
    url.pathname.startsWith("/auth/") ||
    url.pathname === "/openapi.json"
  )
}

// Only page loads are sent to the identity provider; fetches, WebSocket upgrades, and CLI clients keep their
// 401s, so API behavior stays byte-identical to upstream.
function navigation(request: HttpServerRequest.HttpServerRequest) {
  return (
    request.method === "GET" &&
    request.headers["sec-fetch-mode"] === "navigate" &&
    (request.headers["accept"] ?? "").includes("text/html")
  )
}

function redirect(sso: ServerSso.Info, request: HttpServerRequest.HttpServerRequest, url: URL) {
  const origin = ServerSso.origin(request.headers)
  if (!origin) return undefined
  const state = ServerSso.issueState(sso, `${url.pathname}${url.search}`)
  return HttpServerResponse.empty({
    status: 302,
    headers: { location: ServerSso.signInURL(sso, origin, state) },
  })
}

function callback(sso: ServerSso.Info, request: HttpServerRequest.HttpServerRequest, url: URL) {
  return Effect.gen(function* () {
    const origin = ServerSso.origin(request.headers)
    const state = url.searchParams.get("state") ?? undefined
    const code = url.searchParams.get("code")
    if (url.searchParams.get("error") !== null)
      return failure("The identity provider denied the sign-in request. Return to the start page and try again.")
    if (!code || !origin)
      return failure("The sign-in response was incomplete. Return to the start page and try again.")
    const redirect = ServerSso.verifyState(sso, state)
    if (redirect === undefined)
      return failure("The sign-in response did not match this server. Return to the start page and try again.")
    const idToken = yield* Effect.promise(() =>
      ServerSso.exchangeCode(sso, code, `${origin}${ServerSso.CALLBACK_PATH}`).catch(() => undefined),
    )
    if (idToken === undefined)
      return failure("The identity provider rejected the sign-in code. It may have expired — try again.")
    const result = yield* Effect.promise(() =>
      ServerSso.verifyIdentity(sso, idToken).catch(
        (): ServerSso.IdentityResult => ({ ok: false, reason: "verify" }),
      ),
    )
    if (!result.ok)
      return failure(
        result.reason === "whitelist"
          ? "This account is not authorized to use this server."
          : "The identity provider token could not be verified. Return to the start page and try again.",
      )
    return HttpServerResponse.empty({
      status: 302,
      headers: {
        location: redirect,
        "set-cookie": ServerSso.sessionCookie(ServerSso.issueSession(sso, result.identity)),
      },
    })
  })
}

function failure(message: string) {
  return HttpServerResponse.text(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sign-in failed</title></head>` +
      `<body style="font-family:system-ui;background:#080b0c;color:#e8e8e8;display:grid;place-items:center;height:100vh;margin:0">` +
      `<main style="text-align:center"><h1 style="font-size:1.1rem;font-weight:600">Sign-in failed</h1>` +
      `<p style="max-width:32rem;color:#a8a8a8">${message}</p>` +
      `<p><a style="color:#d6ad5c" href="/">Back to the start page</a></p></main></body></html>`,
    { status: 403, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } },
  )
}

function serveUI(
  request: HttpServerRequest.HttpServerRequest,
  url: URL,
  assets: AssetMap,
  brotli: BrotliMap | undefined,
) {
  const key = url.pathname.replace(/^\//, "")
  // A browser that takes brotli gets the embedded bytes as they are, so the server decompresses nothing. The HTML stays
  // decoded, because its CSP hashes the inline theme script.
  const encoded = key !== "index.html" && acceptsBrotli(request.headers["accept-encoding"]) ? brotli?.[key] : undefined
  const requested = encoded ?? assets[key]
  if ((key.startsWith("_assets/") || key.startsWith("icons/")) && requested === undefined)
    return Effect.succeed(HttpServerResponse.empty({ status: 404, headers: { "cache-control": "no-store" } }))
  const name = requested !== undefined ? key : "index.html"
  const file = requested ?? assets["index.html"]
  if (file === undefined) return Effect.succeed(HttpServerResponse.empty({ status: 404 }))
  if (request.method !== "GET" && request.method !== "HEAD")
    return Effect.succeed(HttpServerResponse.empty({ status: 405 }))
  const html = name === "index.html"
  const revalidate = html || name === "sw.js" || name === "registerSW.js"
  const headers = {
    "content-type": FSUtil.mimeType(name),
    "cache-control": revalidate ? "no-cache" : "public, max-age=31536000, immutable",
    "content-security-policy": html
      ? cspForHtml(typeof file === "string" ? file : Buffer.from(file).toString())
      : csp(),
    "x-content-type-options": "nosniff",
    ...(!html && brotli?.[name] !== undefined ? { vary: "accept-encoding" } : {}),
    ...(encoded ? { "content-encoding": "br" } : {}),
  }
  return Effect.succeed(
    request.method === "HEAD"
      ? HttpServerResponse.empty({ status: 200, headers })
      : HttpServerResponse.raw(file, { headers, contentType: headers["content-type"] }),
  )
}

function acceptsBrotli(header: string | undefined) {
  return (header ?? "").split(",").some((entry) => {
    const parts = entry.split(";").map((part) => part.trim().toLowerCase())
    return parts[0] === "br" && !parts.slice(1).some((part) => /^q=0(?:\.0*)?$/.test(part))
  })
}

function isRouteNotFound(error: unknown) {
  return error instanceof HttpServerError.HttpServerError && error.reason._tag === "RouteNotFound"
}

// qr-scanner decodes in a worker it creates from a blob: URL whenever the browser has no BarcodeDetector (Safari, desktop
// Chrome on Windows and Linux). Without worker-src that worker falls under script-src 'self' and never starts.
function csp(hash = "") {
  return `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'${hash ? ` 'sha256-${hash}'` : ""}; style-src 'self' 'unsafe-inline'; img-src 'self' data: https: blob:; font-src 'self' data:; media-src 'self' data:; connect-src * data: blob:; worker-src 'self' blob:`
}

function cspForHtml(body: string) {
  const match = body.match(
    /<script\b(?![^>]*\bsrc\s*=)[^>]*\bid=(["'])oc-theme-preload-script\1[^>]*>([\s\S]*?)<\/script>/i,
  )
  return csp(match ? createHash("sha256").update(match[2]).digest("base64") : "")
}

export * as WebUi from "./web-ui"
