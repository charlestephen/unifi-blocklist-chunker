package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// baseURLFor reconstructs the public base URL for generated chunk links.
// BASE_URL wins; otherwise reverse-proxy forwarding headers are honored so
// the app works unchanged behind an HTTPS-terminating proxy.
func (s *store) baseURLFor(r *http.Request) string {
	if s.cfg.baseURL != "" {
		return s.cfg.baseURL
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		scheme = strings.TrimSpace(strings.Split(p, ",")[0])
	}
	host := r.Host
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		host = strings.TrimSpace(strings.Split(h, ",")[0])
	}
	prefix := strings.TrimSuffix(r.Header.Get("X-Forwarded-Prefix"), "/")
	return scheme + "://" + host + prefix
}

func chunkURLs(base string, snap *snapshot) (dnsURLs, ipURLs []string) {
	for i := range snap.dnsChunks {
		dnsURLs = append(dnsURLs, fmt.Sprintf("%s/lists/dns-%d.txt", base, i+1))
	}
	for i := range snap.ipChunks {
		ipURLs = append(ipURLs, fmt.Sprintf("%s/lists/ip-%d.txt", base, i+1))
	}
	return dnsURLs, ipURLs
}

func (s *store) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /lists/{name}", s.handleChunk)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /stats", s.handleStats)
	mux.HandleFunc("POST /refresh", s.handleRefresh)
	mux.HandleFunc("GET /search", s.handleSearch)
	mux.HandleFunc("GET /exclusions", s.handleListExclusions)
	mux.HandleFunc("POST /exclusions", s.handleAddExclusion)
	mux.HandleFunc("DELETE /exclusions", s.handleRemoveExclusion)
	mux.HandleFunc("DELETE /exclusions/{entry...}", s.handleRemoveExclusion)
	mux.HandleFunc("GET /manage", s.handleManage)
	return mux
}

func (s *store) handleIndex(w http.ResponseWriter, r *http.Request) {
	snap := s.cur.Load()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if snap == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, "# no lists loaded yet")
		return
	}
	dnsURLs, ipURLs := chunkURLs(s.baseURLFor(r), snap)
	fmt.Fprintf(w, "# %d DNS entries in %d chunk(s)\n", snap.dnsCount, len(dnsURLs))
	for _, u := range dnsURLs {
		fmt.Fprintln(w, u)
	}
	fmt.Fprintf(w, "# %d IP entries in %d chunk(s)\n", snap.ipCount, len(ipURLs))
	for _, u := range ipURLs {
		fmt.Fprintln(w, u)
	}
}

func (s *store) handleChunk(w http.ResponseWriter, r *http.Request) {
	snap := s.cur.Load()
	if snap == nil {
		http.Error(w, "no lists loaded yet", http.StatusServiceUnavailable)
		return
	}
	name := r.PathValue("name")
	var chunks [][]string
	var rest string
	switch {
	case strings.HasPrefix(name, "dns-"):
		chunks, rest = snap.dnsChunks, strings.TrimPrefix(name, "dns-")
	case strings.HasPrefix(name, "ip-"):
		chunks, rest = snap.ipChunks, strings.TrimPrefix(name, "ip-")
	default:
		http.NotFound(w, r)
		return
	}
	n, err := strconv.Atoi(strings.TrimSuffix(rest, ".txt"))
	if !strings.HasSuffix(rest, ".txt") || err != nil || n < 1 || n > len(chunks) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("ETag", fmt.Sprintf(`"%d-%s"`, snap.builtAt.UnixNano(), name))
	for _, e := range chunks[n-1] {
		fmt.Fprintln(w, e)
	}
}

func (s *store) handleHealth(w http.ResponseWriter, r *http.Request) {
	if s.cur.Load() == nil {
		http.Error(w, "no lists loaded yet", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "ok")
}

func (s *store) handleStats(w http.ResponseWriter, r *http.Request) {
	snap := s.cur.Load()
	w.Header().Set("Content-Type", "application/json")
	if snap == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, `{"status":"no lists loaded yet"}`)
		return
	}
	dnsURLs, ipURLs := chunkURLs(s.baseURLFor(r), snap)
	exclusionsTotal := 0
	if s.excl != nil {
		exclusionsTotal = s.excl.count()
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"chunk_size":          s.cfg.chunkSize,
		"dns_entries":         snap.dnsCount,
		"ip_entries":          snap.ipCount,
		"dns_entries_total":   len(snap.dnsAll),
		"ip_entries_total":    len(snap.ipAll),
		"exclusions_total":    exclusionsTotal,
		"exclusions_active":   snap.excluded,
		"admin_auth_required": s.cfg.adminToken != "",
		"dns_chunks":          len(dnsURLs),
		"ip_chunks":           len(ipURLs),
		"sources_ok":          snap.sourcesOK,
		"sources":             len(s.cfg.sources),
		"updated_at":          snap.updatedAt.Format(time.RFC3339),
		"dns_urls":            dnsURLs,
		"ip_urls":             ipURLs,
		"refresh_secs":        int(s.cfg.refresh.Seconds()),
	})
}

func (s *store) handleRefresh(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	if err := s.refresh(ctx); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "refreshed")
}
