package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testStore(t *testing.T, token string) *store {
	t.Helper()
	excl, err := loadExclusions(filepath.Join(t.TempDir(), "exclusions.json"))
	if err != nil {
		t.Fatal(err)
	}
	st := &store{
		cfg:    config{chunkSize: 2, adminToken: token, exclusionsFile: excl.path},
		client: &http.Client{},
		excl:   excl,
	}
	dns := []string{"ads.example.com", "example.com", "tracker.example.com"}
	ips := []string{"1.2.0.0/16", "9.9.9.9"}
	st.cur.Store(st.buildSnapshot(dns, ips, 1, time.Now()))
	return st
}

func doReq(st *store, method, target, body, auth string) *httptest.ResponseRecorder {
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, target, rdr)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	st.routes().ServeHTTP(rec, req)
	return rec
}

func TestExclusionsPersistAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "exclusions.json")
	excl, err := loadExclusions(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := excl.add("example.com", false); err != nil {
		t.Fatal(err)
	}
	if _, err := excl.add("1.2.3.4", true); err != nil {
		t.Fatal(err)
	}
	again, err := loadExclusions(path)
	if err != nil {
		t.Fatal(err)
	}
	if !again.contains("example.com", false) || !again.contains("1.2.3.4", true) || again.count() != 2 {
		t.Fatalf("reloaded exclusions wrong: dns/ips not preserved")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f exclusionFile
	if err := json.Unmarshal(body, &f); err != nil {
		t.Fatalf("persisted file is not the expected JSON: %v", err)
	}
}

func TestLoadExclusionsCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exclusions.json")
	if err := os.WriteFile(path, []byte("{nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadExclusions(path); err == nil {
		t.Fatal("expected error for corrupt exclusions file")
	}
}

func TestExcludeRebuildRestore(t *testing.T) {
	st := testStore(t, "secret")
	if _, err := st.excl.add("example.com", false); err != nil {
		t.Fatal(err)
	}
	st.rebuild()
	snap := st.cur.Load()
	if snap.dnsCount != 2 || snap.excluded != 1 {
		t.Fatalf("after exclude: dnsCount=%d excluded=%d", snap.dnsCount, snap.excluded)
	}
	if _, inServed := findEntry(snap, "example.com", false); inServed >= 0 {
		t.Fatal("excluded entry still served")
	}
	// Restore is instant: no refresh needed.
	if _, err := st.excl.remove("example.com", false); err != nil {
		t.Fatal(err)
	}
	st.rebuild()
	if _, inServed := findEntry(st.cur.Load(), "example.com", false); inServed < 0 {
		t.Fatal("restored entry not served again")
	}
}

func TestExcludeSurvivesRefreshRebuild(t *testing.T) {
	st := testStore(t, "secret")
	if _, err := st.excl.add("9.9.9.9", true); err != nil {
		t.Fatal(err)
	}
	// Simulate a refresh swapping in the same upstream entries.
	st.cur.Store(st.buildSnapshot(
		[]string{"example.com"}, []string{"9.9.9.9"}, 1, time.Now()))
	snap := st.cur.Load()
	if snap.ipCount != 0 || snap.excluded != 1 {
		t.Fatalf("after rebuild: ipCount=%d excluded=%d", snap.ipCount, snap.excluded)
	}
}

func TestSearchExactAndCovered(t *testing.T) {
	st := testStore(t, "secret")
	rec := doReq(st, "GET", "/search?q=EXAMPLE.com.", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("search status %d: %s", rec.Code, rec.Body)
	}
	var res searchResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.Found || res.Normalized != "example.com" || res.Chunk != 1 || res.Type != "dns" {
		t.Fatalf("bad exact search: %+v", res)
	}

	rec = doReq(st, "GET", "/search?q=sub.example.com", "", "")
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res.Found || res.CoveredBy != "example.com" {
		t.Fatalf("bad parent-covered search: %+v", res)
	}

	rec = doReq(st, "GET", "/search?q=1.2.3.4", "", "")
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res.Found || res.CoveredBy != "1.2.0.0/16" || res.Type != "ip" {
		t.Fatalf("bad CIDR-covered search: %+v", res)
	}

	rec = doReq(st, "GET", "/search?q=not%20a%20domain", "", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid search status %d", rec.Code)
	}
}

func TestAdminAuthAndExclusionEndpoints(t *testing.T) {
	st := testStore(t, "secret")

	if rec := doReq(st, "POST", "/exclusions", `{"entry":"example.com"}`, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: status %d", rec.Code)
	}
	if rec := doReq(st, "POST", "/exclusions", `{"entry":"example.com"}`, "Bearer wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status %d", rec.Code)
	}
	rec := doReq(st, "POST", "/exclusions", `{"entry":"https://Example.COM/path"}`, "Bearer secret")
	if rec.Code != http.StatusCreated {
		t.Fatalf("add exclusion: status %d: %s", rec.Code, rec.Body)
	}
	if _, inServed := findEntry(st.cur.Load(), "example.com", false); inServed >= 0 {
		t.Fatal("entry still served after POST /exclusions")
	}
	// Idempotent re-add.
	if rec := doReq(st, "POST", "/exclusions", `{"entry":"example.com"}`, "Bearer secret"); rec.Code != http.StatusOK {
		t.Fatalf("re-add: status %d", rec.Code)
	}
	// Basic auth (password = token) also works, as /manage relies on it.
	if rec := doReq(st, "GET", "/exclusions", "", "Basic dXNlcjpzZWNyZXQ="); rec.Code != http.StatusOK {
		t.Fatalf("basic auth list: status %d: %s", rec.Code, rec.Body)
	}
	// CIDR restore via path keeps its slash.
	doReq(st, "POST", "/exclusions", `{"entry":"1.2.0.0/16"}`, "Bearer secret")
	if rec := doReq(st, "DELETE", "/exclusions/1.2.0.0/16", "", "Bearer secret"); rec.Code != http.StatusOK {
		t.Fatalf("path restore CIDR: status %d: %s", rec.Code, rec.Body)
	}
	if rec := doReq(st, "DELETE", "/exclusions", `{"entry":"example.com"}`, "Bearer secret"); rec.Code != http.StatusOK {
		t.Fatalf("restore: status %d: %s", rec.Code, rec.Body)
	}
	if _, inServed := findEntry(st.cur.Load(), "example.com", false); inServed < 0 {
		t.Fatal("entry not served after restore")
	}
	if rec := doReq(st, "DELETE", "/exclusions", `{"entry":"example.com"}`, "Bearer secret"); rec.Code != http.StatusNotFound {
		t.Fatalf("restore of non-excluded: status %d", rec.Code)
	}
	if rec := doReq(st, "POST", "/exclusions", `{"entry":"999.999.999.999"}`, "Bearer secret"); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid entry: status %d", rec.Code)
	}
}

func TestAdminDisabledWithoutToken(t *testing.T) {
	st := testStore(t, "")
	if rec := doReq(st, "POST", "/exclusions", `{"entry":"example.com"}`, "Bearer anything"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("mutations without ADMIN_TOKEN: status %d", rec.Code)
	}
	if rec := doReq(st, "GET", "/manage", "", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/manage without ADMIN_TOKEN: status %d", rec.Code)
	}
	// Search stays open.
	if rec := doReq(st, "GET", "/search?q=example.com", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("search without token config: status %d", rec.Code)
	}
}

func TestManagePage(t *testing.T) {
	st := testStore(t, "secret")
	if rec := doReq(st, "GET", "/manage", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("/manage unauthenticated: status %d", rec.Code)
	}
	rec := doReq(st, "GET", "/manage", "", "Basic dXNlcjpzZWNyZXQ=")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Blocklist search") {
		t.Fatalf("/manage: status %d", rec.Code)
	}
}

func TestStatsExclusionCounts(t *testing.T) {
	st := testStore(t, "secret")
	doReq(st, "POST", "/exclusions", `{"entry":"9.9.9.9"}`, "Bearer secret")
	rec := doReq(st, "GET", "/stats", "", "")
	var stats map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if stats["exclusions_total"] != float64(1) || stats["exclusions_active"] != float64(1) || stats["ip_entries"] != float64(1) || stats["ip_entries_total"] != float64(2) {
		t.Fatalf("bad stats: %v", stats)
	}
}
