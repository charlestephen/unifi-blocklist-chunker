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
| `GET /stats` | JSON: entry/chunk counts, source health, chunk URLs |
| `GET /healthz` | `ok` once any snapshot is loaded, else 503 |
| `POST /refresh` | Trigger an immediate re-fetch |

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

## Reverse proxy

Behind a proxy that terminates HTTPS, leave `BASE_URL` unset: generated URLs
are derived from `X-Forwarded-Proto`, `X-Forwarded-Host`, and
`X-Forwarded-Prefix` (falling back to the request's own scheme/host). Set
`BASE_URL` to pin an exact public origin regardless of headers.

## Run

```sh
podman build -t unifi-blocklist-chunker .
podman run --rm -p 8080:8080 \
  -e BLOCKLIST_URLS="https://example.com/list1.txt,https://example.com/list2.json" \
  -e CHUNK_SIZE=100000 \
  unifi-blocklist-chunker
```

Or with Compose: edit the environment in `compose.yaml`, then
`podman compose up -d` (or `docker compose up -d`).
