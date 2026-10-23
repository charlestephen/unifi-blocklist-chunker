package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// adminAuthorized reports whether the request carries ADMIN_TOKEN, as a
// Bearer token or as the password of HTTP Basic auth (any username; the
// Basic form is what makes the /manage page usable in a browser).
func (s *store) adminAuthorized(r *http.Request) bool {
	token := s.cfg.adminToken
	if token == "" {
		return false
	}
	provided := ""
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		provided = strings.TrimPrefix(h, "Bearer ")
	} else if _, pw, ok := r.BasicAuth(); ok {
		provided = pw
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(token)) == 1
}

// requireAdmin gates a handler on ADMIN_TOKEN. When no token is
// configured the mutation surface fails closed (503) instead of open.
func (s *store) requireAdmin(w http.ResponseWriter, r *http.Request, basicChallenge bool) bool {
	if s.cfg.adminToken == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "ADMIN_TOKEN is not configured; admin endpoints are disabled",
		})
		return false
	}
	if !s.adminAuthorized(r) {
		if basicChallenge {
			w.Header().Set("WWW-Authenticate", `Basic realm="unifi-blocklist-chunker"`)
		} else {
			w.Header().Set("WWW-Authenticate", "Bearer")
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return false
	}
	return true
}

// --- search ---

func findIP(entries []string, target string) int {
	i, found := slices.BinarySearchFunc(entries, target, ipCompare)
	if found {
		return i
	}
	return -1
}

func findDomain(entries []string, target string) int {
	i, found := slices.BinarySearchFunc(entries, target, domainCompare)
	if found {
		return i
	}
	return -1
}

func findEntry(snap *snapshot, entry string, isIP bool) (inAll, inServed int) {
	if isIP {
		if isIPv4Entry(entry) {
			return findIP(snap.ipv4All, entry), findIP(snap.ipv4Served, entry)
		}
		return findIP(snap.ipv6All, entry), findIP(snap.ipv6Served, entry)
	}
	return findDomain(snap.dnsAll, entry), findDomain(snap.dnsServed, entry)
}

// coveredBy returns the served entry that covers the query without being
// it: a parent domain for DNS names, or a containing CIDR for IPs of the
// same family. Informational only — exclusions remain exact-match.
func coveredBy(snap *snapshot, entry string, isIP bool) string {
	if isIP {
		var addr netip.Addr
		bits := 0
		if p, err := netip.ParsePrefix(entry); err == nil {
			addr, bits = p.Addr(), p.Bits()
		} else if a, err := netip.ParseAddr(entry); err == nil {
			addr, bits = a, a.BitLen()
		} else {
			return ""
		}
		served := snap.ipv6Served
		if isIPv4Entry(entry) {
			served = snap.ipv4Served
		}
		for _, e := range served {
			p, err := netip.ParsePrefix(e)
			if err != nil || p.Bits() > bits {
				continue
			}
			if p.Contains(addr) {
				return e
			}
		}
		return ""
	}
	rest := entry
	for {
		i := strings.Index(rest, ".")
		if i < 0 {
			return ""
		}
		rest = rest[i+1:]
		if !strings.Contains(rest, ".") {
			return ""
		}
		if findDomain(snap.dnsServed, rest) >= 0 {
			return rest
		}
	}
}

// entryType is the chunk-stream label for a normalized entry.
func entryType(entry string, isIP bool) string {
	if !isIP {
		return "dns"
	}
	if isIPv4Entry(entry) {
		return "ipv4"
	}
	return "ipv6"
}

type searchResult struct {
	Query      string `json:"query"`
	Normalized string `json:"normalized"`
	Type       string `json:"type"` // "dns", "ipv4", or "ipv6"
	Found      bool   `json:"found"`
	InSnapshot bool   `json:"in_snapshot"`
	Excluded   bool   `json:"excluded"`
	Chunk      int    `json:"chunk,omitempty"`
	ChunkURL   string `json:"chunk_url,omitempty"`
	CoveredBy  string `json:"covered_by,omitempty"`
}

func (s *store) search(snap *snapshot, base, raw string) (searchResult, bool) {
	entry, isIP, ok := normalizeEntry(raw)
	if !ok {
		return searchResult{}, false
	}
	res := searchResult{Query: raw, Normalized: entry, Type: entryType(entry, isIP)}
	res.Excluded = s.excl != nil && s.excl.contains(entry, isIP)
	inAll, inServed := findEntry(snap, entry, isIP)
	res.InSnapshot = inAll >= 0
	if inServed >= 0 {
		res.Found = true
		if s.cfg.chunkSize > 0 {
			res.Chunk = inServed/s.cfg.chunkSize + 1
			res.ChunkURL = fmt.Sprintf("%s/lists/%s-%d.txt", base, res.Type, res.Chunk)
		}
	} else if !res.InSnapshot {
		res.CoveredBy = coveredBy(snap, entry, isIP)
	}
	return res, true
}

func (s *store) handleSearch(w http.ResponseWriter, r *http.Request) {
	snap := s.cur.Load()
	if snap == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "no lists loaded yet"})
		return
	}
	q := r.URL.Query().Get("q")
	if strings.TrimSpace(q) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing q parameter"})
		return
	}
	res, ok := s.search(snap, s.baseURLFor(r), q)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "not a valid domain or IP/CIDR", "query": q,
		})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// --- exclusions ---

type entryRequest struct {
	Entry string `json:"entry"`
}

// entryFromRequest resolves the target entry for a remove/restore call:
// path wildcard (DELETE /exclusions/<entry>, CIDRs keep their slash),
// then ?entry=, then a JSON body.
func entryFromRequest(r *http.Request) string {
	if v := r.PathValue("entry"); v != "" {
		return v
	}
	if v := r.URL.Query().Get("entry"); v != "" {
		return v
	}
	var body entryRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err == nil {
		return body.Entry
	}
	return ""
}

func (s *store) handleListExclusions(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, false) {
		return
	}
	var dns, ips []string
	if s.excl != nil {
		dns, ips = s.excl.list()
	}
	if dns == nil {
		dns = []string{}
	}
	if ips == nil {
		ips = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"dns": dns, "ips": ips, "count": len(dns) + len(ips)})
}

func (s *store) handleAddExclusion(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, false) {
		return
	}
	raw := entryFromRequest(r)
	entry, isIP, ok := normalizeEntry(raw)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "not a valid domain or IP/CIDR", "entry": raw,
		})
		return
	}
	changed, err := s.excl.add(entry, isIP)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "persist exclusion: " + err.Error()})
		return
	}
	s.rebuild()
	status := http.StatusOK
	if changed {
		status = http.StatusCreated
	}
	resp := map[string]any{"entry": entry, "type": entryType(entry, isIP), "excluded": true, "changed": changed}
	if snap := s.cur.Load(); snap != nil {
		inAll, _ := findEntry(snap, entry, isIP)
		resp["in_snapshot"] = inAll >= 0
	}
	writeJSON(w, status, resp)
}

func (s *store) handleRemoveExclusion(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, false) {
		return
	}
	raw := entryFromRequest(r)
	entry, isIP, ok := normalizeEntry(raw)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "not a valid domain or IP/CIDR", "entry": raw,
		})
		return
	}
	if !s.excl.contains(entry, isIP) {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error": "entry is not excluded", "entry": entry,
		})
		return
	}
	if _, err := s.excl.remove(entry, isIP); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "persist exclusion: " + err.Error()})
		return
	}
	s.rebuild()
	resp := map[string]any{"entry": entry, "type": entryType(entry, isIP), "excluded": false, "restored": true}
	if snap := s.cur.Load(); snap != nil {
		inAll, inServed := findEntry(snap, entry, isIP)
		resp["in_snapshot"] = inAll >= 0
		resp["found"] = inServed >= 0
	}
	writeJSON(w, http.StatusOK, resp)
}
