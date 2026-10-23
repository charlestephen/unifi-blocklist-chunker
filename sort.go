package main

import (
	"net/netip"
	"sort"
	"strings"
)

// domainCompare orders domains by label from the root (right) leftward:
// TLD first (com before nyc), then the next label (cloudflare.com before
// google.com), and so on. When one name is a proper suffix of the other
// under that order, the shorter (closer to the root) comes first —
// example.com before mail.example.com.
func domainCompare(a, b string) int {
	if a == b {
		return 0
	}
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	for i := 1; ; i++ {
		aOK := i <= len(aParts)
		bOK := i <= len(bParts)
		if !aOK && !bOK {
			return 0
		}
		if !aOK {
			return -1
		}
		if !bOK {
			return 1
		}
		al := aParts[len(aParts)-i]
		bl := bParts[len(bParts)-i]
		if al < bl {
			return -1
		}
		if al > bl {
			return 1
		}
	}
}

func domainLess(a, b string) bool { return domainCompare(a, b) < 0 }

func sortDomains(entries []string) {
	sort.Slice(entries, func(i, j int) bool { return domainLess(entries[i], entries[j]) })
}

// ipSortKey is the numeric sort key for an IP or CIDR. Addresses are
// compared as integers (IPv4 as 32-bit, IPv6 as 128-bit); IPv4-mapped
// IPv6 forms are Unmapped so they order with other IPv4 entries. Prefix
// length is the tie-breaker (hosts use -1 so a bare address sorts before
// the same address written as a /32 or /128).
func ipSortKey(entry string) (netip.Addr, int) {
	if p, err := netip.ParsePrefix(entry); err == nil {
		return p.Addr().Unmap(), p.Bits()
	}
	if a, err := netip.ParseAddr(entry); err == nil {
		return a.Unmap(), -1
	}
	return netip.Addr{}, -1
}

func ipCompare(a, b string) int {
	aa, ab := ipSortKey(a)
	ba, bb := ipSortKey(b)
	switch {
	case !aa.IsValid() && !ba.IsValid():
		return strings.Compare(a, b)
	case !aa.IsValid():
		return 1
	case !ba.IsValid():
		return -1
	}
	if c := aa.Compare(ba); c != 0 {
		return c
	}
	switch {
	case ab < bb:
		return -1
	case ab > bb:
		return 1
	default:
		return 0
	}
}

func sortIPs(entries []string) {
	sort.SliceStable(entries, func(i, j int) bool {
		return ipCompare(entries[i], entries[j]) < 0
	})
}
