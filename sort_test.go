package main

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestSortDomainsRootFirst(t *testing.T) {
	in := []string{
		"mail.google.com",
		"google.com",
		"cloudflare.com",
		"a.example.nyc",
		"example.com",
		"b.example.nyc",
		"example.nyc",
	}
	sortDomains(in)
	want := []string{
		"cloudflare.com",
		"example.com",
		"google.com",
		"mail.google.com",
		"example.nyc",
		"a.example.nyc",
		"b.example.nyc",
	}
	if !reflect.DeepEqual(in, want) {
		t.Fatalf("sortDomains =\n%v\nwant\n%v", in, want)
	}
}

func TestSortIPv4Numeric(t *testing.T) {
	in := []string{"10.0.0.1", "2.2.2.2", "1.2.3.4", "1.2.0.0/16", "9.9.9.9"}
	sortIPs(in)
	want := []string{"1.2.0.0/16", "1.2.3.4", "2.2.2.2", "9.9.9.9", "10.0.0.1"}
	if !reflect.DeepEqual(in, want) {
		t.Fatalf("sortIPs v4 =\n%v\nwant\n%v", in, want)
	}
}

func TestSortIPv6Numeric(t *testing.T) {
	// Numeric 128-bit order. netip normalizes 2006:0::1 → 2006::1 (same
	// address as 2006::1), so the user-facing list stores one entry; the
	// distinct hextet steps below are what UniFi sees after normalization.
	in := []string{
		"2006:1::1",
		"2006::1",
		"2006:0:1::1",
		"2001:db8::1",
		"fe80::1",
		"2006:0::1", // collapses to 2006::1 via ParseAddr in normalize; here as raw list text
	}
	// Force canonical forms the way refresh does after normalizeEntry.
	for i, e := range in {
		if a, err := netip.ParseAddr(e); err == nil {
			in[i] = a.String()
		}
	}
	// Dedup as refresh would after string-normalized equality.
	seen := map[string]struct{}{}
	var uniq []string
	for _, e := range in {
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		uniq = append(uniq, e)
	}
	sortIPs(uniq)
	want := []string{
		"2001:db8::1",
		"2006::1",
		"2006:0:1::1",
		"2006:1::1",
		"fe80::1",
	}
	if !reflect.DeepEqual(uniq, want) {
		t.Fatalf("sortIPs v6 =\n%v\nwant\n%v", uniq, want)
	}
	// Explicit hextet progression the user called out:
	// 2006::1 < 2006:0:1::1 < 2006:1::1 (2006:0::1 ≡ 2006::1).
	if ipCompare("2006::1", "2006:0:1::1") >= 0 || ipCompare("2006:0:1::1", "2006:1::1") >= 0 {
		t.Fatal("expected 2006::1 < 2006:0:1::1 < 2006:1::1")
	}
	if a, _ := netip.ParseAddr("2006:0::1"); a.String() != "2006::1" {
		t.Fatalf("2006:0::1 should normalize to 2006::1, got %s", a)
	}
}

func TestFindDomainRespectsSortOrder(t *testing.T) {
	entries := []string{"mail.google.com", "cloudflare.com", "google.com", "example.nyc"}
	sortDomains(entries)
	if findDomain(entries, "google.com") < 0 || findDomain(entries, "missing.com") >= 0 {
		t.Fatalf("findDomain failed on %#v", entries)
	}
}
