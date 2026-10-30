# Changelog

All notable changes to **ProxyBuff** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] — 2026-10-31

### Added
- **PROXY protocol (v1 and v2) from trusted peers.** `--proxy-protocol-from` (repeatable or
  comma-separated IPs/CIDRs) and the JSON field `proxyProtocolFrom` let ProxyBuff run behind an
  L4 proxy such as nginx `stream` with `ssl_preread` + `proxy_protocol on`. The header is read
  on both the HTTP and HTTPS listeners, below TLS (so ACME/autocert keeps working), and its
  client address becomes the request `RemoteAddr` and therefore the `X-Forwarded-For` value
  sent to the origin. Empty (the default) leaves behaviour unchanged.
- `--proxy-protocol-on` / JSON `proxyProtocolOn` (`both` by default, or `https`): require the
  header on the HTTPS listener only, so an edge can forward `:80` (ACME HTTP-01 + redirects) by
  `Host` with the nginx `http` module. `https` requires HTTPS to be enabled.
- Startup warnings for `proxyProtocolFrom` entries wider than one address (e.g. a whole Docker
  subnet, which includes the gateway used by `docker-proxy` and every sibling container), and a
  notice that the HTTP listener (ACME HTTP-01) must receive the PROXY header too; rejection log
  lines on that listener say so as well.

### Security
- Connections from listed peers **must** start with a valid header within 5 seconds; a missing,
  malformed, oversized or late header closes the connection (rejections are logged at most once
  per 10 seconds). Connections from all other peers are never parsed, so a `PROXY` line sent by
  an untrusted client cannot spoof its address.
- Strict parsing: v1 is limited to 107 bytes with exact field counts, address families that match
  `TCP4`/`TCP6`, and plain decimal ports; v2 requires the exact signature, version 2, a
  `LOCAL`/`PROXY` command, TCP over IPv4/IPv6 (or `UNSPEC`), and a payload of at most 2048 bytes
  (TLVs are skipped). Header parsing happens per connection, so a slow peer cannot stall `Accept`.
- Invalid `proxyProtocolFrom` entries fail startup with an error naming the entry; blank entries
  (an unset variable in `--proxy-protocol-from "$X"`, `""` in JSON, a stray comma) are rejected
  instead of silently turning the feature off.
- With `proxyProtocolFrom` set, ProxyBuff is the first HTTP hop and **owns the forwarding
  headers**: client-supplied `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, `X-Forwarded-Host` and
  `X-Forwarded-Proto` are dropped and rebuilt from the verified client address
  (`X-Forwarded-For`/`X-Real-IP: <ip>`, `Forwarded: for=…;proto=…;host=…`) on the pass-through,
  cache-fill and background range-fill paths, so a client cannot pick the IP an IAM throttles on.
  `Connection:` tokens naming these headers are ignored so they cannot be stripped. Without the
  option the previous append behaviour is unchanged, except that background range fills now send
  `X-Forwarded-For`/`-Host`/`-Proto` like every other origin request.

### Performance
- Trusted PROXY-protocol connections keep `io.ReaderFrom`, so cache hits on plain HTTP still use
  `sendfile`.

## [1.4.2] — 2026-10-27

### Fixed
- Recache now refreshes entries when their refresh-ahead deadline is reached,
  instead of skipping all entries until their TTL expires and repeatedly scheduling
  an already-due task. Entries renewed by another request still avoid duplicate fetches.
- Close cached body files opened while checking whether a background refresh is needed.
- Publish refreshed bodies and metadata together with respect to cache readers, so
  concurrent HIT and Range responses cannot combine an old header with a new body.
  Existing readers can finish their original snapshot during replacement on Windows too.
- When `recache-ahead` is at least a site's TTL, use half that TTL and log the
  adjustment so successful refreshes do not immediately trigger another download.
- Add regression coverage for early refresh, concurrent renewal, expired entries,
  retries, zero/oversized lead times, and background scheduler operation.

## [1.4.1] — 2026-07-07

### Added
- `clear-cache` and `clear-certs` commands, with previews unless `--yes` is passed.
  Clearing HTTP entries preserves certificates, and clearing certificates preserves HTTP entries.

## [1.4.0] — 2026-07-04

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

[1.5.0]: https://github.com/quardexus/proxybuff/compare/v1.4.2...v1.5.0
[1.4.2]: https://github.com/quardexus/proxybuff/compare/ac5a3bc...v1.4.2
[1.4.1]: https://github.com/quardexus/proxybuff/compare/c1902f6...ac5a3bc
[1.4.0]: https://github.com/quardexus/proxybuff/compare/v1.3.2...c1902f6
[1.3.2]: https://github.com/quardexus/proxybuff/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/quardexus/proxybuff/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/quardexus/proxybuff/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/quardexus/proxybuff/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/quardexus/proxybuff/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/quardexus/proxybuff/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/quardexus/proxybuff/releases/tag/v1.0.0
