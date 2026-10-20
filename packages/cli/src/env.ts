import { Config } from "effect"

// Every environment variable the CLI reads, in one place. Consumers yield
// these instead of touching process.env so the full surface stays visible,
// typed, and redacted where secret.

// The opencode server password: sent by clients connecting to an explicit
// --server, and adopted by a manually run or standalone server. The legacy
// name is still honored.
export const password = Config.Redacted("OPENCODE_PASSWORD").pipe(
  Config.orElse(() => Config.Redacted("OPENCODE_SERVER_PASSWORD")),
  Config.withDefault(undefined),
)

// OIDC sign-in against an external provider (e.g. OCI-SSO). Leaving OPENCODE_SSO_ISSUER unset turns SSO off and
// leaves upstream Basic/session auth untouched. The client secret is redacted like the server password.
export const sso = Config.all({
  issuer: Config.String("OPENCODE_SSO_ISSUER").pipe(Config.withDefault(undefined)),
  clientId: Config.String("OPENCODE_SSO_CLIENT_ID").pipe(Config.withDefault(undefined)),
  clientSecret: Config.Redacted("OPENCODE_SSO_CLIENT_SECRET").pipe(Config.withDefault(undefined)),
  allowEmails: Config.String("OPENCODE_SSO_ALLOW_EMAILS").pipe(Config.withDefault(undefined)),
  enforce: Config.String("OPENCODE_SSO_ENFORCE").pipe(Config.withDefault(undefined)),
})

export function session() {
  return Object.fromEntries(
    Object.entries(process.env).filter(
      (entry): entry is [string, string] =>
        entry[1] !== undefined && entry[0] !== "OPENCODE_PASSWORD" && entry[0] !== "OPENCODE_SERVER_PASSWORD",
    ),
  )
}

export * as Env from "./env"
