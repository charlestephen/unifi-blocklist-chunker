package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type config struct {
	port       string
	chunkSize  int
	sources    []string
	refresh    time.Duration
	baseURL    string
	fetchLimit int64
}

func loadConfig() (config, error) {
	cfg := config{
		port:       envOr("PORT", "8080"),
		chunkSize:  100000,
		refresh:    6 * time.Hour,
		baseURL:    strings.TrimSuffix(os.Getenv("BASE_URL"), "/"),
		fetchLimit: 128 << 20,
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
	for _, u := range strings.FieldsFunc(os.Getenv("BLOCKLIST_URLS"), func(r rune) bool {
		return r == ',' || r == '\n' || r == '\t' || r == ' '
	}) {
		if u != "" {
			cfg.sources = append(cfg.sources, u)
		}
	}
	if len(cfg.sources) == 0 {
		return cfg, fmt.Errorf("BLOCKLIST_URLS is required (comma-separated list URLs)")
	}
	return cfg, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

type snapshot struct {
	dnsChunks [][]string
	ipChunks  [][]string
	dnsCount  int
	ipCount   int
	sourcesOK int
	updatedAt time.Time
}

type store struct {
	cfg    config
	client *http.Client
	cur    atomic.Pointer[snapshot]
	mu     sync.Mutex // serializes refreshes
}

func chunkStrings(entries []string, size int) [][]string {
	var chunks [][]string
	for start := 0; start < len(entries); start += size {
		chunks = append(chunks, entries[start:min(start+size, len(entries))])
	}
	return chunks
}

func sortIPs(entries []string) {
	type keyed struct {
		text string
		addr netip.Addr
		bits int
	}
	ks := make([]keyed, len(entries))
	for i, e := range entries {
		k := keyed{text: e, bits: -1}
		if p, err := netip.ParsePrefix(e); err == nil {
			k.addr, k.bits = p.Addr(), p.Bits()
		} else if a, err := netip.ParseAddr(e); err == nil {
			k.addr = a
		}
		ks[i] = k
	}
	sort.Slice(ks, func(i, j int) bool {
		if c := ks[i].addr.Compare(ks[j].addr); c != 0 {
			return c < 0
		}
		return ks[i].bits < ks[j].bits
	})
	for i := range ks {
		entries[i] = ks[i].text
	}
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

// refresh fetches every source, deduplicates across all of them (separately
// per entry class), sorts, and atomically swaps in the new chunked snapshot.
// A refresh that yields zero entries keeps the previous snapshot.
func (s *store) refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

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
	sort.Strings(dns)
	ips := make([]string, 0, len(ipSet))
	for e := range ipSet {
		ips = append(ips, e)
	}
	sortIPs(ips)

	s.cur.Store(&snapshot{
		dnsChunks: chunkStrings(dns, s.cfg.chunkSize),
		ipChunks:  chunkStrings(ips, s.cfg.chunkSize),
		dnsCount:  len(dns),
		ipCount:   len(ips),
		sourcesOK: okCount,
		updatedAt: time.Now(),
	})
	for _, f := range failures {
		log.Printf("source failed (others still applied): %s", f)
	}
	log.Printf("refreshed: %d DNS + %d IP unique entries from %d/%d sources -> %d DNS chunk(s), %d IP chunk(s) of <= %d",
		len(dns), len(ips), okCount, len(s.cfg.sources),
		len(s.cur.Load().dnsChunks), len(s.cur.Load().ipChunks), s.cfg.chunkSize)
	return nil
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	st := &store{cfg: cfg, client: &http.Client{}}

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
