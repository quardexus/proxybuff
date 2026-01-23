# ProxyBuff

High-load HTTP reverse proxy with disk-backed TTL cache for selected paths.

Developed by **Quardexus**. Version **v1.0.0**.

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

### One-shot run (pull + run)

Image:

- `docker.q-server.net:5000/quardexus/proxybuff:v1.0.0`

Run:

```bash
docker run --rm \
  -p 3128:3128 \
  -v proxybuff-cache:/var/lib/proxybuff/cache \
  docker.q-server.net:5000/quardexus/proxybuff:v1.0.0 \
  --origin https://example.com \
  --ttl 10m \
  --cache "/" \
  --cache "*.png"
```

Notes:

- This registry listens on **HTTP port 5000**. Your Docker daemon may require `insecure-registries` configuration to pull from it.
- Container entrypoint writes the effective config to `/etc/proxybuff/config.json` and starts the service.

### Clear cache (inside container)

```bash
docker exec -it <container_name_or_id> proxybuff-clear-cache
```

Optionally specify a directory:

```bash
docker exec -it <container_name_or_id> proxybuff-clear-cache /var/lib/proxybuff/cache
```

## Flags

- `--origin` (required): upstream origin URL, e.g. `https://example.com:443`
- `--listen` (default `0.0.0.0:3128`): listen address
- `--cache` (repeatable, default empty): cache patterns
- `--ttl` (default `10m`): cache TTL duration
- `--cache-dir` (default `./cache`): cache directory (in Docker defaults to `/var/lib/proxybuff/cache`)
- `--age-header` (default `false`): add standard `Age` header on cache HIT

## License

Apache-2.0. See `LICENSE`.
