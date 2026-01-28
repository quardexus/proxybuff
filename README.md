# ProxyBuff

High-load HTTP reverse proxy with disk-backed TTL cache for selected paths and automatic Let's Encrypt TLS (auto-issue + auto-renew).

Developed by **Quardexus**. Version **v1.3.0**.

## What it does

- Runs an HTTP service that **proxies** requests to a required upstream **origin**.
- For paths matching configured cache patterns, it **stores the response body on disk** and serves it from cache until TTL expires.
- On **cache HIT**, it performs **zero requests** to the origin.

## Terms used in this README

- **Public domain**: the hostname clients use to reach ProxyBuff (e.g. `multidex.online`).
- **Origin / upstream**: the backend ProxyBuff proxies to (flag `--origin`), e.g. `https://81.177.139.61:443`.
- **TLS domain**: domain name(s) ProxyBuff requests Let's Encrypt certificates for (flag `--tls-domain`). This must be the **public domain**, not the origin.

## Caching rules (v1.3.1)

- **Methods**: only `GET` is cached. `HEAD` can be served from an existing cached `GET` entry, but **does not populate** the cache.
- **Status codes**: only `200 OK` responses are cached.
- **Range requests** (`Range:` header):
  - If the full file is already cached, ProxyBuff serves a **single byte range** (`206`) from disk.
  - Otherwise, ProxyBuff proxies the range request and downloads the full file in the background to populate cache for next time.
  - **Multi-range** requests (e.g. `bytes=0-99,200-299`) are **not supported** for cache serving and are proxied.
- **Cache key**: **path only** (`/some/file.png`). Query string is **ignored for the cache key**, but is still forwarded to the origin.
- **Response headers**:
  - On HIT, headers come from cached metadata and are sent “as stored”.
  - ProxyBuff always adds `X-ProxyBuff-Cache: HIT|MISS`.
  - `Age` header is **optional** (enabled via `--age-header`) and is computed from the cached entry creation time.

- **Cache cleanup (GC)**:
  - ProxyBuff runs a best-effort garbage collector about **once per TTL** that removes expired cached entries from disk even without client traffic.
  - It scans `meta.json` files and deletes the corresponding `meta.json` and `body` when `ExpiresAt` is in the past.
  - GC stops on shutdown (it is tied to the app's background context).

## Cache patterns

Patterns match the request **path** only.

- `*` matches **any characters including `/`** (nested paths).
- `/` matches **only** the root request path.

Examples:

- `/` caches only `GET /`
- `*.png` caches `/a.png` and `/assets/img/b.png`
- `/assets/*` caches `/assets/anything/inside/here`

## Auto-refresh cache (recache)

ProxyBuff can proactively **refresh** cached entries in the background even when there are **no client requests**.

How it works:

- You configure `--recache` patterns (same syntax as `--cache`).
- For each cached entry matching `--recache`, ProxyBuff schedules a refresh at:
  - `expiresAt - recacheAhead`
- Refresh is done by a background worker pool (`--recache-workers`) and uses non-blocking per-key locking so it does not stall user traffic.
- Cached entries survive restarts because the scheduler reads `meta.json` from disk on startup.

Defaults:

- `--recache-ahead=5m`
- `--recache-workers=4`

## Install / build locally

```bash
go test ./...
go build -o proxybuff ./cmd/proxybuff
```

## Run locally (binary)

```bash
./proxybuff \
  --origin https://origin.example.com \
  --http=3128 \
  --ttl 10m \
  --cache "/" \
  --cache "*.png" \
  --recache "/assets/*" \
  --recache-ahead 5m \
  --recache-workers 2 \
  --cache-dir ./cache
```

## Docker

### Build

```bash
docker build -t proxybuff:local .
```

### Run

Run the container from the locally built image:

```bash
docker run -d --name proxybuff \
  --restart unless-stopped \
  -p 3128:3128 \
  -v proxybuff-cache:/var/lib/proxybuff/cache \
  proxybuff:local \
  --origin https://origin.example.com \
  --ttl 10m \
  --cache "/" \
  --cache "*.png" \
  --recache "/assets/*"
```

You can also pass multiple patterns as a comma-separated list:

```bash
docker run -d --name proxybuff \
  --restart unless-stopped \
  -p 3128:3128 \
  -v proxybuff-cache:/var/lib/proxybuff/cache \
  proxybuff:local \
  --origin https://origin.example.com \
  --ttl 10m \
  --cache "/,*.png,*.jpg,*.webp,/assets/*"
```

Notes:

- Container entrypoint writes the effective config to `/etc/proxybuff/config.json` and starts the service.

### HTTPS (automatic Let's Encrypt certificates)

If you enable HTTPS, ProxyBuff will obtain and renew certificates automatically using ACME (Let's Encrypt).

Requirements:

- Your **public domain** must point to this server (public DNS).
- Port **80/tcp** must be reachable from the Internet for HTTP-01 challenges.
- Port **443/tcp** (or your chosen HTTPS port) must be reachable for clients.

Behavior:

- When HTTPS is enabled, the HTTP listener is used for ACME HTTP-01 challenges and redirects all other requests to HTTPS.
- Certificates are cached on disk (under `cache/certs` inside the cache dir) and are renewed automatically before expiry.

Example (container):

```bash
docker run -d --name proxybuff \
  --restart unless-stopped \
  -p 443:443 \
  -p 80:3128 \
  -v proxybuff-cache:/var/lib/proxybuff/cache \
  proxybuff:local \
  --origin https://origin.example.com \
  --https=443 \
  --tls-domain public.example.com
```

### Clear cache (inside container)

```bash
docker exec -it <container_name_or_id> proxybuff-clear-cache
```

Optionally specify a directory:

```bash
docker exec -it <container_name_or_id> proxybuff-clear-cache /var/lib/proxybuff/cache
```

## Flags

- `--origin` (required): upstream origin URL. You can pass a full URL (`https://example.com:443`) or omit the scheme.
  - If scheme is omitted and origin is a **hostname**, it defaults to `http://` (port 80).
  - If scheme is omitted and origin is an **IP**, ProxyBuff probes the port once on startup to detect TLS and picks `http://` or `https://`.
    If it detects TLS, it also enables `--insecure-skip-verify` by default.
- `--listen` (deprecated): alias for `--http`
- `--http` (required): HTTP listener. Accepts port/address (e.g. `8080`, `:8080`, `127.0.0.1:8080`)
- `--https` (default `false`): HTTPS listener. Accepts `true|false` or port/address (e.g. `443`, `:443`, `127.0.0.1:443`)
- `--tls-domain` (repeatable): domain(s) to request and renew ACME certificates for when HTTPS is enabled
- `--cache` (repeatable, default empty): cache patterns
- `--recache` (repeatable, default empty): auto-refresh patterns (also implies caching those patterns)
- `--recache-ahead` (default `5m`): how long before expiry to refresh an entry
- `--recache-workers` (default `4`): max concurrent background refresh workers
- `--ttl` (default `10m`): cache TTL duration
- `--cache-dir` (default `./cache`): cache directory (in Docker defaults to `/var/lib/proxybuff/cache`)
- `--log-file` (default empty): optional log file path (also logs to stdout)
- `--age-header` (default `false`): add standard `Age` header on cache HIT
- `--use-origin-host` (default `false`): send `Host` from `--origin` (by default forwards the original client `Host`)
- `--insecure-skip-verify` (default `false`): skip TLS certificate verification for https origins (dangerous)

## License

Apache-2.0. See `LICENSE`.
