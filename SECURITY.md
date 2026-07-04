# Security Policy

## Supported versions

Security fixes are provided for the **latest released minor** of ProxyBuff.
Please upgrade to the newest release before reporting.

| Version | Supported |
| ------- | --------- |
| 1.4.x   | ✅        |
| < 1.4   | ❌        |

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue or PR.

- Preferred: GitHub → **Security** tab → **Report a vulnerability** (private advisory).
- Include: affected version, a description, reproduction steps or a proof of concept, and
  the impact you observed.

You can expect an initial acknowledgement within a few days. Once a fix is available, we
will coordinate a release and credit reporters who wish to be named.

## Scope & hardening notes

ProxyBuff is a caching reverse proxy; a few operational settings have security impact:

- **Only cache paths that are safe to share across all clients.** By design ProxyBuff will
  not cache responses that set cookies, are marked `no-store`/`private`, `Vary` on request
  headers, or answer requests carrying `Authorization` — but choosing narrow cache patterns
  is still your responsibility.
- **`--insecure-skip-verify`** disables TLS verification to the origin and is auto-enabled
  when the origin is a raw IP that speaks TLS. Prefer a verifiable origin certificate in
  production.
- Keep the instance behind the intended network boundary and expose only the listeners you
  need (port 80 is required for ACME HTTP-01 challenges when HTTPS is enabled).
