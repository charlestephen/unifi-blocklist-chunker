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
   stripped, CIDRs masked) and classified as DNS names or IPs/CIDRs.
3. Entries are deduplicated **across all source lists** per class, sorted, and
   split into chunks of at most `CHUNK_SIZE` entries. Chunk count is purely a
   function of unique-entry count vs. chunk size — there are no fixed
   endpoints.
4. A failed source never takes the service down: other sources still apply,
   and a refresh yielding zero entries keeps the previous snapshot.

## Endpoints

| Endpoint | Description |
| --- | --- |
| `GET /` | Plain-text index of all chunk URLs (generated from the request's public origin) |
| `GET /lists/dns-<n>.txt` | DNS chunk `n` (1-based), one entry per line |
| `GET /lists/ip-<n>.txt` | IP/CIDR chunk `n` (1-based), one entry per line |
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

Chunk URLs carry no secrets and are safe to paste into UniFi's external
blocklist fields; one URL per chunk is needed, and the number of URLs changes
as upstream lists grow or shrink.

## Configuration (environment)

| Variable | Default | Description |
| --- | --- | --- |
| `BLOCKLIST_URLS` | *(required)* | Source list URLs, separated by commas, spaces, or newlines |
| `CHUNK_SIZE` | `100000` | Max entries per output chunk |
| `PORT` | `8080` | Listen port |
| `REFRESH_INTERVAL` | `6h` | Re-fetch interval (Go duration; `0` disables periodic refresh) |
| `BASE_URL` | *(unset)* | Public base URL for generated chunk links, e.g. `https://lists.example.com` |
| `ADMIN_TOKEN` | *(unset)* | Token gating `GET /manage` and the exclusion endpoints; unset disables them (`503`) |
| `EXCLUSIONS_FILE` | `exclusions.json` | Where exclusions are persisted; put it on a volume to survive restarts (published image: `/data/exclusions.json`) |

## Reverse proxy

Behind a proxy that terminates HTTPS, leave `BASE_URL` unset: generated URLs
are derived from `X-Forwarded-Proto`, `X-Forwarded-Host`, and
`X-Forwarded-Prefix` (falling back to the request's own scheme/host). Set
`BASE_URL` to pin an exact public origin regardless of headers.

## Run

Published multi-arch (`linux/amd64`, `linux/arm64`) images:

- GHCR: `ghcr.io/charlestephen/unifi-blocklist-chunker:latest`
- Docker Hub: `docker.io/charlestephen/unifi-blocklist-chunker:latest`

Podman:

```sh
podman run -d --name unifi-blocklist-chunker \
  --restart=unless-stopped \
  -p 8080:8080 \
  -e BLOCKLIST_URLS="https://example.com/list1.txt,https://example.com/list2.json" \
  -e CHUNK_SIZE=100000 \
  ghcr.io/charlestephen/unifi-blocklist-chunker:latest
```

Docker (identical, from Docker Hub):

```sh
docker run -d --name unifi-blocklist-chunker \
  --restart unless-stopped \
  -p 8080:8080 \
  -e BLOCKLIST_URLS="https://example.com/list1.txt,https://example.com/list2.json" \
  -e CHUNK_SIZE=100000 \
  docker.io/charlestephen/unifi-blocklist-chunker:latest
```

Then open `http://<host>:8080/` for the chunk URLs to paste into UniFi, or
`http://<host>:8080/stats` for counts. Tags: `latest` tracks `main`; releases
publish semver tags (e.g. `1.2.3`, `1.2`), and every build also publishes a
`sha-<short>` tag.

With Compose: edit the environment in `compose.yaml` (it already references
the GHCR image; a Docker Hub alternative is noted inside), then
`podman compose up -d` (or `docker compose up -d`).

Build from source instead: `podman build -t unifi-blocklist-chunker .`
(or `docker build -f Containerfile -t unifi-blocklist-chunker .`).
