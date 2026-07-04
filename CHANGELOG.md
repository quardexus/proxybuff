# Changelog

All notable changes to **ProxyBuff** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] — unreleased

### Added
- **Multi-host routing.** A single instance can serve multiple domains, each with its own
  origin, cache rules, TTL and TLS certificate. Configured via `hosts[]` in the JSON config.
  Fully backward compatible: with no `hosts`, behavior is identical to a single-origin proxy.
- **Wildcard host matching** (`*.example.com`) for routing and the ACME host policy. Certificates
  are issued per subdomain on demand via HTTP-01 (a single true wildcard certificate would
  require DNS-01, which is out of scope).
- Flags `--cache-vary-host` and `--cache-key-query` (both **on by default**) controlling whether
  the request Host and query string are part of the cache key.
- First unit-test suite: host matching, request routing, config parsing/inheritance, cache-key
  derivation, response cacheability, and Range parsing.

### Security
- `Set-Cookie` is **never** stored in cache metadata nor replayed to other clients from cache.
- Responses with `Cache-Control: no-store | no-cache | private`, responses that `Vary` on
  anything other than `Accept-Encoding`, and any request carrying `Authorization` are no longer
  cached.
- Added read-header and idle timeouts to the HTTP listener (Slowloris mitigation).
- Bounded and time-capped the background full-file downloads triggered by Range misses.
- Log a warning when TLS certificate verification is auto-disabled for a raw-IP origin.

### Changed
- Cache entries are namespaced per configured host, so different origins never collide on the
  same path. **Note:** the on-disk cache-key format changed; existing cache entries are ignored
  after upgrade and refill on demand.
- `X-ProxyBuff-Cache: MISS` is now set on every pass-through path (non-cacheable, lock bypass, HEAD).

## [1.3.2] — 2026-02-03
### Added
- `status` command: show cache statistics and list cached files without running the server.

## [1.3.1] — 2026-01-29
### Changed
- Version bump / maintenance release.

## [1.3.0] — 2026-01-27
### Added
- Serve a single byte range (`206`) directly from cached files.
- Background disk garbage collection that removes expired entries even without client traffic.

## [1.2.0] — 2026-01-27
### Added
- Background recache (refresh-ahead): refresh cached entries shortly before they expire.

## [1.1.1] — 2026-01-25
### Changed
- Non-blocking cache fill and asynchronous disk writes.

## [1.1.0] — 2026-01-23
### Added
- Optional HTTPS listener with automatic ACME (Let's Encrypt) certificates and HTTP→HTTPS redirect.

## [1.0.0] — 2026-01-23
### Added
- Initial release: caching reverse proxy with a disk-backed TTL cache and path-pattern matching.

[1.4.0]: https://github.com/quardexus/proxybuff/compare/v1.3.2...HEAD
[1.3.2]: https://github.com/quardexus/proxybuff/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/quardexus/proxybuff/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/quardexus/proxybuff/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/quardexus/proxybuff/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/quardexus/proxybuff/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/quardexus/proxybuff/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/quardexus/proxybuff/releases/tag/v1.0.0
