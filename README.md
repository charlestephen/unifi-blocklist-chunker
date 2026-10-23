# unifi-blocklist-chunker

Fetches any number of upstream IP and DNS blocklists, merges and deduplicates
them, and re-serves them as plain-text chunks sized for the UniFi Network
Controller (which rejects oversized external blocklists).

## How it works

1. Every URL in `BLOCKLIST_URLS` is fetched on startup and then periodically
   (`REFRESH_INTERVAL`). Formats are detected by file extension, content type,
   or content sniffing: **txt** (plain, hosts-file, and adblock-style lines),
   **JSON** (array of strings, or any object containing string arrays),
   **YAML**, and **TOML**.
2. Entries are normalized (lowercased, wildcards/schemes/hosts prefixes
   stripped, CIDRs masked) and classified as **domains**, **IPv4**, or
   **IPv6** (IPv4-mapped IPv6 addresses like `::ffff:a.b.c.d` count as IPv4).
3. Entries are deduplicated **across all source lists** per class, sorted, and
   split into separate domain / IPv4 / IPv6 chunk streams of at most
   `CHUNK_SIZE` entries each. Domains sort by label from the TLD leftward
   (`cloudflare.com` before `google.com` before `mail.google.com`; `.com`
   before `.nyc`). IPv4 and IPv6 sort numerically (128-bit for IPv6, so
   `2006::1` before `2006:0:1::1` before `2006:1::1`; compressed forms like
   `2006:0::1` normalize to `2006::1`). Chunk count is purely a function of
   unique-entry count vs. chunk size — there are no fixed endpoints.
4. A failed source never takes the service down: other sources still apply,
   and a refresh yielding zero entries keeps the previous snapshot.

## Endpoints

| Endpoint | Description |
| --- | --- |
| `GET /` | Plain-text index of all chunk URLs (generated from the request's public origin) |
| `GET /lists/dns-<n>.txt` | Domain chunk `n` (1-based), one entry per line |
| `GET /lists/ipv4-<n>.txt` | IPv4/CIDR chunk `n` (1-based), one entry per line |
| `GET /lists/ipv6-<n>.txt` | IPv6/CIDR chunk `n` (1-based), one entry per line |
| `GET /stats` | JSON: entry/chunk counts, source health, chunk URLs, exclusion counts |
| `GET /healthz` | `ok` once any snapshot is loaded, else 503 |
| `POST /refresh` | Trigger an immediate re-fetch |
| `GET /search?q=<entry>` | JSON: whether a domain/IP/CIDR is served, in which chunk, whether it is excluded, and any broader served entry covering it (parent domain / containing CIDR) |
| `GET /manage` | Browser UI for search/remove/restore (admin auth) |
| `GET /exclusions` | JSON: recorded exclusions (admin auth) |
| `POST /exclusions` | Record an exclusion; JSON body `{"entry": "example.com"}` (admin auth) |
| `DELETE /exclusions/<entry>` | Restore an entry; CIDRs keep their `/` — or send `{"entry": …}` as a JSON body to `DELETE /exclusions` (admin auth) |

## Search and exclusions

Exclusions are an allowlist layered over the upstream lists — upstream data
is never edited. Matching is **exact only**: excluding `example.com` does not
affect `sub.example.com`, and excluding `1.2.3.4` does not affect a served
`1.2.0.0/16` (search reports that broader entry as `covered_by` so the effect
is visible before acting). Excluding an entry that no upstream list currently
contains is allowed and blocks it if a source adds it later.

Exclusions apply immediately (chunks are rebuilt without a refetch), are
re-applied on every refresh, and are persisted as JSON to `EXCLUSIONS_FILE`
(written atomically), so they survive restarts when that path is on a volume.
Restoring an entry re-serves it immediately if an upstream list still
contains it.

Admin endpoints require `ADMIN_TOKEN`, sent as `Authorization: Bearer <token>`
or as the password of HTTP Basic auth (any username; the Basic form is what
the `/manage` page uses in a browser). When `ADMIN_TOKEN` is unset, the admin
endpoints return `503` rather than operating unauthenticated. `/search`, the
chunk URLs, and `/stats` remain public.

Examples (`<host>` is the service origin, `<token>` is `ADMIN_TOKEN`):

```sh
# Is an entry served, and in which chunk?
curl 'http://<host>:8080/search?q=example.com'
curl 'http://<host>:8080/search?q=1.2.3.4'

# Remove an entry (exact match; takes effect immediately)
curl -X POST -H 'Authorization: Bearer <token>' \
  -d '{"entry":"example.com"}' http://<host>:8080/exclusions

# List recorded exclusions
curl -H 'Authorization: Bearer <token>' http://<host>:8080/exclusions

# Restore an entry (CIDRs keep their / in the path form)
curl -X DELETE -H 'Authorization: Bearer <token>' \
  http://<host>:8080/exclusions/example.com
curl -X DELETE -H 'Authorization: Bearer <token>' \
  -d '{"entry":"1.2.0.0/16"}' http://<host>:8080/exclusions
```

Or open `http://<host>:8080/manage` in a browser (any username, password is
`ADMIN_TOKEN`) for the same operations interactively.

Chunk URLs carry no secrets and are safe to paste into UniFi's external
blocklist fields; one URL per chunk is needed, and the number of URLs changes
as upstream lists grow or shrink.

## Configuration (environment)

Every runtime knob is an environment variable. There is no config file besides
the exclusions JSON written by the process itself.

| Variable | Default | Required | Description |
| --- | --- | --- | --- |
| `BLOCKLIST_URLS` | *(none)* | **yes** | Upstream list URLs. Separators: comma, space, tab, or newline. Each URL is fetched independently; a failed URL is logged and skipped. Formats: txt / hosts / adblock, JSON, YAML, TOML (detected by extension, `Content-Type`, or sniffing). |
| `CHUNK_SIZE` | `100000` | no | Max entries per served chunk file. UniFi's external-blocklist field commonly caps around 100000; lower it if a controller rejects a chunk. Must be a positive integer. |
| `PORT` | `8080` | no | Listen port inside the container. Keep in sync with published/mapped ports. |
| `REFRESH_INTERVAL` | `6h` | no | How often sources are re-fetched. Go duration (`30m`, `6h`, `24h`, …). `0` disables the ticker (manual `POST /refresh` only). |
| `BASE_URL` | *(unset)* | no | Public origin used when generating chunk URLs on `/` and `/stats` (no trailing slash), e.g. `https://lists.example.com`. When unset, the request's `X-Forwarded-Proto` / `X-Forwarded-Host` / `X-Forwarded-Prefix` (or the request's own scheme/host) are used — the usual Traefik / reverse-proxy path. |
| `ADMIN_TOKEN` | *(unset)* | no | Shared secret for `GET /manage` and all `/exclusions` mutations. Send as `Authorization: Bearer <token>` or as the **password** of HTTP Basic auth (any username). **Unset = fail-closed:** those endpoints return `503`; public chunk/search/stats endpoints stay open. Set this whenever `/manage` or on-the-fly removals should work. |
| `EXCLUSIONS_FILE` | `exclusions.json` | no | Path of the persisted exclusions JSON (atomic write-rename). Put it on a volume so removals survive restarts. In the published image the conventional path is `/data/exclusions.json` (see Compose / `podman run` examples). Corrupt file → log + start empty (file rewritten on the next change). |
| `EXCLUSIONS_URLS` | *(unset)* | no | Remote exclusion list URLs (same separators and formats as `BLOCKLIST_URLS`). Fetched on every refresh; entries are unioned with the persistent file. Remote lists are not written to `EXCLUSIONS_FILE` — edit the remote file (e.g. `https://lists.example.com/excluded.txt`) to add/remove URL-sourced exclusions. A total fetch failure keeps the previous URL-sourced set. |

### Notes

- Fetch size limit (128 MiB per source) is compile-time, not configurable.
- `BLOCKLIST_URLS` must be non-empty or the process exits on startup.
- Effective exclusions = persistent file ∪ `EXCLUSIONS_URLS`. Seed via API /
  `/manage`, a JSON file at `EXCLUSIONS_FILE`, and/or remote exclusion lists.
- Changing env vars requires a container restart. Persistent exclusion
  add/remove via API takes effect immediately; URL-sourced exclusions update
  on the next refresh.

## Reverse proxy

Behind a proxy that terminates HTTPS (Traefik, nginx, Caddy, …):

1. Leave `BASE_URL` unset so generated chunk links pick up the public
   origin from `X-Forwarded-*` headers.
2. Or set `BASE_URL` to the exact public origin if your proxy does not
   forward those headers reliably.
3. Open `https://<public-host>/` for the plain-text index of chunk URLs to
   paste into UniFi; open `https://<public-host>/manage` (Basic auth,
   password = `ADMIN_TOKEN`) to search and exclude entries on the fly.

## Run

Published multi-arch (`linux/amd64`, `linux/arm64`) images:

- GHCR: `ghcr.io/charlestephen/unifi-blocklist-chunker:latest`
- Docker Hub: `docker.io/charlestephen/unifi-blocklist-chunker:latest`

Podman:

```sh
podman run -d --name unifi-blocklist-chunker \
  --restart=unless-stopped \
  -p 8080:8080 \
  -v unifi-blocklist-chunker-data:/data \
  -e BLOCKLIST_URLS="https://example.com/list1.txt,https://example.com/list2.json" \
  -e CHUNK_SIZE=100000 \
  -e ADMIN_TOKEN="example-admin-token" \
  -e EXCLUSIONS_FILE="/data/exclusions.json" \
  ghcr.io/charlestephen/unifi-blocklist-chunker:latest
```

Docker (identical, from Docker Hub):

```sh
docker run -d --name unifi-blocklist-chunker \
  --restart unless-stopped \
  -p 8080:8080 \
  -v unifi-blocklist-chunker-data:/data \
  -e BLOCKLIST_URLS="https://example.com/list1.txt,https://example.com/list2.json" \
  -e CHUNK_SIZE=100000 \
  -e ADMIN_TOKEN="example-admin-token" \
  -e EXCLUSIONS_FILE="/data/exclusions.json" \
  docker.io/charlestephen/unifi-blocklist-chunker:latest
```

The `/data` volume is what makes exclusions survive container recreation;
without it (or without `EXCLUSIONS_FILE` pointed at mounted storage) they
last only for the life of the container filesystem. `ADMIN_TOKEN` can be
omitted, in which case the admin endpoints are disabled and only the public
chunk/search/stats endpoints work.

Then open `http://<host>:8080/` for the chunk URLs to paste into UniFi,
`http://<host>:8080/stats` for counts, or `http://<host>:8080/manage` to
search and remove entries. Tags: `latest` tracks `main`; releases
publish semver tags (e.g. `1.2.3`, `1.2`), and every build also publishes a
`sha-<short>` tag.

With Compose: `compose.yaml` already wires every variable above — source
URLs, sizes, and intervals are set inline, the exclusions file lives on the
`blocklist-data` volume — except `ADMIN_TOKEN`, which it interpolates from
the caller's environment (`${ADMIN_TOKEN:-}`, empty disables the admin
endpoints):

```sh
ADMIN_TOKEN='example-admin-token' podman compose up -d
# (or: ADMIN_TOKEN='example-admin-token' docker compose up -d)
```

Build from source instead: `podman build -t unifi-blocklist-chunker .`
(or `docker build -f Containerfile -t unifi-blocklist-chunker .`).
