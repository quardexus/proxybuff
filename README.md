# ProxyBuff

High-load HTTP reverse proxy with disk-backed TTL cache for selected paths.

Developed by **Quardexus**. Version **v1.1.0**.

## What it does

- Runs an HTTP service that **proxies** requests to a required upstream **origin**.
- For paths matching configured cache patterns, it **stores the response body on disk** and serves it from cache until TTL expires.
- On **cache HIT**, it performs **zero requests** to the origin.

## Caching rules (v1.0.0)

- **Methods**: only `GET` is cached. `HEAD` can be served from an existing cached `GET` entry, but **does not populate** the cache.
- **Status codes**: only `200 OK` responses are cached.
- **Range requests** (`Range:` header): never cached (proxied directly).
- **Cache key**: **path only** (`/some/file.png`). Query string is **ignored for the cache key**, but is still forwarded to the origin.
- **Response headers**:
  - On HIT, headers come from cached metadata and are sent “as stored”.
  - ProxyBuff always adds `X-ProxyBuff-Cache: HIT|MISS`.
  - `Age` header is **optional** (enabled via `--age-header`) and is computed from the cached entry creation time.

## Cache patterns

Patterns match the request **path** only.

- `*` matches **any characters including `/`** (nested paths).
- `/` matches **only** the root request path.

Examples:

- `/` caches only `GET /`
- `*.png` caches `/a.png` and `/assets/img/b.png`
- `/assets/*` caches `/assets/anything/inside/here`

## Install / build locally

```bash
go test ./...
go build -o proxybuff ./cmd/proxybuff
```

## Run locally (binary)

```bash
./proxybuff \
  --origin https://example.com \
  --listen 0.0.0.0:3128 \
  --ttl 10m \
  --cache "/" \
  --cache "*.png" \
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
  --origin https://example.com \
  --ttl 10m \
  --cache "/" \
  --cache "*.png"
```

You can also pass multiple patterns as a comma-separated list:

```bash
docker run -d --name proxybuff \
  --restart unless-stopped \
  -p 3128:3128 \
  -v proxybuff-cache:/var/lib/proxybuff/cache \
  proxybuff:local \
  --origin https://example.com \
  --ttl 10m \
  --cache "/,*.png,*.jpg,*.webp,/assets/*"
```

Notes:

- Container entrypoint writes the effective config to `/etc/proxybuff/config.json` and starts the service.

### HTTPS (automatic Let's Encrypt certificates)

If you enable HTTPS, ProxyBuff will obtain and renew certificates automatically using ACME (Let's Encrypt).

Requirements:

- Your domain must point to this server (public DNS).
- Port **80/tcp** must be reachable from the Internet for HTTP-01 challenges.
- Port **443/tcp** (or your chosen HTTPS port) must be reachable for clients.

Example (container):

```bash
docker run -d --name proxybuff \
  --restart unless-stopped \
  -p 80:80 \
  -p 443:443 \
  -v proxybuff-cache:/var/lib/proxybuff/cache \
  proxybuff:local \
  --origin https://example.com \
  --https=443 \
  --http=80
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
- `--http` (default `true`): HTTP listener. Accepts `true|false` or port/address (e.g. `8080`, `:8080`, `127.0.0.1:8080`)
- `--https` (default `false`): HTTPS listener. Accepts `true|false` or port/address (e.g. `443`, `:443`, `127.0.0.1:443`)
- `--cache` (repeatable, default empty): cache patterns
- `--ttl` (default `10m`): cache TTL duration
- `--cache-dir` (default `./cache`): cache directory (in Docker defaults to `/var/lib/proxybuff/cache`)
- `--log-file` (default empty): optional log file path (also logs to stdout)
- `--age-header` (default `false`): add standard `Age` header on cache HIT
- `--use-origin-host` (default `false`): send `Host` from `--origin` (by default forwards the original client `Host`)
- `--insecure-skip-verify` (default `false`): skip TLS certificate verification for https origins (dangerous)

## License

Apache-2.0. See `LICENSE`.
