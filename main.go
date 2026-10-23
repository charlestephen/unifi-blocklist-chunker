package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type config struct {
	port           string
	chunkSize      int
	sources        []string
	exclusionURLs  []string
	refresh        time.Duration
	baseURL        string
	fetchLimit     int64
	adminToken     string
	exclusionsFile string
}

func splitURLs(raw string) []string {
	var out []string
	for _, u := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\t' || r == ' '
	}) {
		if u != "" {
			out = append(out, u)
		}
	}
	return out
}

func loadConfig() (config, error) {
	cfg := config{
		port:           envOr("PORT", "8080"),
		chunkSize:      100000,
		refresh:        6 * time.Hour,
		baseURL:        strings.TrimSuffix(os.Getenv("BASE_URL"), "/"),
		fetchLimit:     128 << 20,
		adminToken:     os.Getenv("ADMIN_TOKEN"),
		exclusionsFile: envOr("EXCLUSIONS_FILE", "exclusions.json"),
	}
	if v := os.Getenv("CHUNK_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return cfg, fmt.Errorf("CHUNK_SIZE must be a positive integer, got %q", v)
		}
		cfg.chunkSize = n
	}
	if v := os.Getenv("REFRESH_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			return cfg, fmt.Errorf("REFRESH_INTERVAL must be a duration >= 0, got %q", v)
		}
		cfg.refresh = d
	}
	cfg.sources = splitURLs(os.Getenv("BLOCKLIST_URLS"))
	if len(cfg.sources) == 0 {
		return cfg, fmt.Errorf("BLOCKLIST_URLS is required (comma-separated list URLs)")
	}
	cfg.exclusionURLs = splitURLs(os.Getenv("EXCLUSIONS_URLS"))
	return cfg, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

type snapshot struct {
	// *All are the full sorted upstream entries; *Served are the same
	// minus persistent exclusions. Chunks serve the latter so an
	// exclusion can be applied or undone by re-chunking without a refetch.
	// IPs are split by address family — UniFi expects IPv4 and IPv6 lists
	// separately from domain lists.
	dnsAll     []string
	ipv4All    []string
	ipv6All    []string
	dnsServed  []string
	ipv4Served []string
	ipv6Served []string
	dnsChunks  [][]string
	ipv4Chunks [][]string
	ipv6Chunks [][]string
	dnsCount   int
	ipv4Count  int
	ipv6Count  int
	excluded   int // entries currently withheld by exclusions
	sourcesOK  int
	updatedAt  time.Time // last upstream refresh
	builtAt    time.Time // when these chunks were built (ETag source)
}

type store struct {
	cfg    config
	client *http.Client
	excl   *exclusionStore
	// urlDNS/urlIPs are rebuilt from EXCLUSIONS_URLS on each successful
	// exclusion-list fetch. They are not persisted; remote lists are the
	// source of truth. Effective exclusions = persistent ∪ URL-sourced.
	urlExclMu sync.RWMutex
	urlDNS    map[string]struct{}
	urlIPs    map[string]struct{}
	cur       atomic.Pointer[snapshot]
	mu        sync.Mutex // serializes refreshes and exclusion-driven rebuilds
}

// effectiveExclusions merges persistent file exclusions with the latest
// URL-seeded set.
func (s *store) effectiveExclusions() (dns, ips map[string]struct{}) {
	if s.excl != nil {
		dns, ips = s.excl.sets()
	} else {
		dns, ips = map[string]struct{}{}, map[string]struct{}{}
	}
	s.urlExclMu.RLock()
	defer s.urlExclMu.RUnlock()
	for k := range s.urlDNS {
		dns[k] = struct{}{}
	}
	for k := range s.urlIPs {
		ips[k] = struct{}{}
	}
	return dns, ips
}

func (s *store) isExcluded(entry string, isIP bool) bool {
	if s.excl != nil && s.excl.contains(entry, isIP) {
		return true
	}
	s.urlExclMu.RLock()
	defer s.urlExclMu.RUnlock()
	if isIP {
		_, ok := s.urlIPs[entry]
		return ok
	}
	_, ok := s.urlDNS[entry]
	return ok
}

func (s *store) urlExclusionCount() int {
	s.urlExclMu.RLock()
	defer s.urlExclMu.RUnlock()
	return len(s.urlDNS) + len(s.urlIPs)
}

func (s *store) urlExclusionSets() (dns, ips map[string]struct{}) {
	s.urlExclMu.RLock()
	defer s.urlExclMu.RUnlock()
	dns = make(map[string]struct{}, len(s.urlDNS))
	for k := range s.urlDNS {
		dns[k] = struct{}{}
	}
	ips = make(map[string]struct{}, len(s.urlIPs))
	for k := range s.urlIPs {
		ips[k] = struct{}{}
	}
	return dns, ips
}

// isIPv4Entry reports whether a normalized IP/CIDR belongs on the IPv4
// chunk stream. IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) count as IPv4.
func isIPv4Entry(entry string) bool {
	if p, err := netip.ParsePrefix(entry); err == nil {
		return p.Addr().Unmap().Is4()
	}
	if a, err := netip.ParseAddr(entry); err == nil {
		return a.Unmap().Is4()
	}
	return false
}

func splitByIPFamily(ips []string) (v4, v6 []string) {
	for _, e := range ips {
		if isIPv4Entry(e) {
			v4 = append(v4, e)
		} else {
			v6 = append(v6, e)
		}
	}
	return v4, v6
}

// buildSnapshot derives served chunks from the full sorted entries by
// dropping exact-match exclusions (persistent file ∪ EXCLUSIONS_URLS).
// IP entries are split into IPv4 and IPv6 chunk streams.
func (s *store) buildSnapshot(dnsAll, ipv4All, ipv6All []string, sourcesOK int, updatedAt time.Time) *snapshot {
	sortDomains(dnsAll)
	sortIPs(ipv4All)
	sortIPs(ipv6All)
	exclDNS, exclIPs := s.effectiveExclusions()
	dnsServed, dnsDropped := filterExcluded(dnsAll, exclDNS)
	ipv4Served, ipv4Dropped := filterExcluded(ipv4All, exclIPs)
	ipv6Served, ipv6Dropped := filterExcluded(ipv6All, exclIPs)
	return &snapshot{
		dnsAll:     dnsAll,
		ipv4All:    ipv4All,
		ipv6All:    ipv6All,
		dnsServed:  dnsServed,
		ipv4Served: ipv4Served,
		ipv6Served: ipv6Served,
		dnsChunks:  chunkStrings(dnsServed, s.cfg.chunkSize),
		ipv4Chunks: chunkStrings(ipv4Served, s.cfg.chunkSize),
		ipv6Chunks: chunkStrings(ipv6Served, s.cfg.chunkSize),
		dnsCount:   len(dnsServed),
		ipv4Count:  len(ipv4Served),
		ipv6Count:  len(ipv6Served),
		excluded:   dnsDropped + ipv4Dropped + ipv6Dropped,
		sourcesOK:  sourcesOK,
		updatedAt:  updatedAt,
		builtAt:    time.Now(),
	}
}

// rebuild re-derives the served chunks from the current snapshot's full
// entries after an exclusion change. No-op when nothing is loaded yet.
func (s *store) rebuild() {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.cur.Load()
	if snap == nil {
		return
	}
	s.cur.Store(s.buildSnapshot(snap.dnsAll, snap.ipv4All, snap.ipv6All, snap.sourcesOK, snap.updatedAt))
}

func chunkStrings(entries []string, size int) [][]string {
	var chunks [][]string
	for start := 0; start < len(entries); start += size {
		chunks = append(chunks, entries[start:min(start+size, len(entries))])
	}
	return chunks
}

func (s *store) fetchOne(ctx context.Context, url string) (dns, ips []string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "unifi-blocklist-chunker/1.0")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, s.cfg.fetchLimit))
	if err != nil {
		return nil, nil, err
	}
	return parseList(url, resp.Header.Get("Content-Type"), body)
}

// refreshExclusionURLs fetches EXCLUSIONS_URLS and replaces the in-memory
// URL-sourced exclusion sets when at least one URL succeeds. Total failure
// keeps the previous URL-sourced set. No URLs configured clears them.
func (s *store) refreshExclusionURLs(ctx context.Context) {
	if len(s.cfg.exclusionURLs) == 0 {
		s.urlExclMu.Lock()
		s.urlDNS, s.urlIPs = nil, nil
		s.urlExclMu.Unlock()
		return
	}
	dnsSet := make(map[string]struct{})
	ipSet := make(map[string]struct{})
	ok := 0
	var failures []string
	for _, url := range s.cfg.exclusionURLs {
		fetchCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		dns, ips, err := s.fetchOne(fetchCtx, url)
		cancel()
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", url, err))
			continue
		}
		ok++
		for _, e := range dns {
			dnsSet[e] = struct{}{}
		}
		for _, e := range ips {
			ipSet[e] = struct{}{}
		}
	}
	for _, f := range failures {
		log.Printf("exclusion source failed (others still applied): %s", f)
	}
	if ok == 0 {
		log.Printf("exclusion sources: all %d failed; keeping previous URL exclusions", len(s.cfg.exclusionURLs))
		return
	}
	s.urlExclMu.Lock()
	s.urlDNS, s.urlIPs = dnsSet, ipSet
	s.urlExclMu.Unlock()
	log.Printf("exclusion sources: loaded %d DNS + %d IP from %d/%d URL(s)",
		len(dnsSet), len(ipSet), ok, len(s.cfg.exclusionURLs))
}

// refresh fetches every source, deduplicates across all of them (separately
// per entry class), sorts, and atomically swaps in the new chunked snapshot.
// A refresh that yields zero entries keeps the previous snapshot.
func (s *store) refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.refreshExclusionURLs(ctx)

	dnsSet := make(map[string]struct{})
	ipSet := make(map[string]struct{})
	okCount := 0
	var failures []string
	for _, url := range s.cfg.sources {
		fetchCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		dns, ips, err := s.fetchOne(fetchCtx, url)
		cancel()
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", url, err))
			continue
		}
		okCount++
		for _, e := range dns {
			dnsSet[e] = struct{}{}
		}
		for _, e := range ips {
			ipSet[e] = struct{}{}
		}
	}
	if len(dnsSet)+len(ipSet) == 0 {
		if s.cur.Load() != nil {
			return fmt.Errorf("refresh produced no entries (keeping previous lists); failures: %s", strings.Join(failures, "; "))
		}
		return fmt.Errorf("refresh produced no entries; failures: %s", strings.Join(failures, "; "))
	}

	dns := make([]string, 0, len(dnsSet))
	for e := range dnsSet {
		dns = append(dns, e)
	}
	sortDomains(dns)
	ips := make([]string, 0, len(ipSet))
	for e := range ipSet {
		ips = append(ips, e)
	}
	sortIPs(ips)
	ipv4, ipv6 := splitByIPFamily(ips)

	s.cur.Store(s.buildSnapshot(dns, ipv4, ipv6, okCount, time.Now()))
	for _, f := range failures {
		log.Printf("source failed (others still applied): %s", f)
	}
	snap := s.cur.Load()
	log.Printf("refreshed: %d DNS + %d IPv4 + %d IPv6 unique entries from %d/%d sources -> %d DNS / %d IPv4 / %d IPv6 chunk(s) of <= %d (%d withheld by exclusions)",
		len(dns), len(ipv4), len(ipv6), okCount, len(s.cfg.sources),
		len(snap.dnsChunks), len(snap.ipv4Chunks), len(snap.ipv6Chunks), s.cfg.chunkSize, snap.excluded)
	return nil
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	excl, err := loadExclusions(cfg.exclusionsFile)
	if err != nil {
		log.Printf("exclusions: %v (starting with none; file will be rewritten on first change)", err)
		excl = emptyExclusions(cfg.exclusionsFile)
	} else if n := excl.count(); n > 0 {
		log.Printf("exclusions: loaded %d from %s", n, cfg.exclusionsFile)
	}
	st := &store{cfg: cfg, client: &http.Client{}, excl: excl}
	if n := len(cfg.exclusionURLs); n > 0 {
		log.Printf("exclusions: %d URL source(s) configured (fetched on each refresh)", n)
	}

	ctx := context.Background()
	if err := st.refresh(ctx); err != nil {
		log.Printf("initial refresh: %v", err)
	}
	if cfg.refresh > 0 {
		go func() {
			t := time.NewTicker(cfg.refresh)
			defer t.Stop()
			for range t.C {
				if err := st.refresh(ctx); err != nil {
					log.Printf("scheduled refresh: %v", err)
				}
			}
		}()
	}

	srv := &http.Server{
		Addr:              ":" + cfg.port,
		Handler:           st.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("listening on :%s (chunk size %d, %d source(s), refresh %s)", cfg.port, cfg.chunkSize, len(cfg.sources), cfg.refresh)
	log.Fatal(srv.ListenAndServe())
}
