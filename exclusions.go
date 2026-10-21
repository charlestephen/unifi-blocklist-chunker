package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// exclusionStore is the persistent allowlist layered over the upstream
// blocklists: an entry recorded here is removed (exact match only) from
// the served chunks on every refresh, until it is restored. It never
// edits upstream data.
type exclusionStore struct {
	mu   sync.RWMutex
	path string
	dns  map[string]struct{}
	ips  map[string]struct{}
}

type exclusionFile struct {
	DNS []string `json:"dns"`
	IPs []string `json:"ips"`
}

// loadExclusions reads path. A missing file yields an empty store; a
// corrupt file is an error so the caller can decide to start empty
// (and say so) rather than silently discarding exclusions later.
func loadExclusions(path string) (*exclusionStore, error) {
	s := &exclusionStore{
		path: path,
		dns:  make(map[string]struct{}),
		ips:  make(map[string]struct{}),
	}
	body, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	var f exclusionFile
	if err := json.Unmarshal(body, &f); err != nil {
		return s, fmt.Errorf("parse %s: %w", path, err)
	}
	for _, raw := range append(append([]string{}, f.DNS...), f.IPs...) {
		entry, isIP, ok := normalizeEntry(raw)
		if !ok {
			continue
		}
		if isIP {
			s.ips[entry] = struct{}{}
		} else {
			s.dns[entry] = struct{}{}
		}
	}
	return s, nil
}

func emptyExclusions(path string) *exclusionStore {
	return &exclusionStore{path: path, dns: make(map[string]struct{}), ips: make(map[string]struct{})}
}

// sets returns copies of the current exclusion sets.
func (e *exclusionStore) sets() (dns, ips map[string]struct{}) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	dns = make(map[string]struct{}, len(e.dns))
	for k := range e.dns {
		dns[k] = struct{}{}
	}
	ips = make(map[string]struct{}, len(e.ips))
	for k := range e.ips {
		ips[k] = struct{}{}
	}
	return dns, ips
}

func (e *exclusionStore) contains(entry string, isIP bool) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if isIP {
		_, ok := e.ips[entry]
		return ok
	}
	_, ok := e.dns[entry]
	return ok
}

func (e *exclusionStore) count() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.dns) + len(e.ips)
}

// list returns the recorded exclusions, sorted like the served lists.
func (e *exclusionStore) list() (dns, ips []string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	dns = make([]string, 0, len(e.dns))
	for k := range e.dns {
		dns = append(dns, k)
	}
	sort.Strings(dns)
	ips = make([]string, 0, len(e.ips))
	for k := range e.ips {
		ips = append(ips, k)
	}
	sortIPs(ips)
	return dns, ips
}

// add records entry and persists. It reports whether the store changed.
// The entry must already be normalized (see normalizeEntry).
func (e *exclusionStore) add(entry string, isIP bool) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	set := e.dns
	if isIP {
		set = e.ips
	}
	if _, ok := set[entry]; ok {
		return false, nil
	}
	set[entry] = struct{}{}
	if err := e.saveLocked(); err != nil {
		delete(set, entry)
		return false, err
	}
	return true, nil
}

// remove drops entry and persists. It reports whether the store changed.
func (e *exclusionStore) remove(entry string, isIP bool) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	set := e.dns
	if isIP {
		set = e.ips
	}
	if _, ok := set[entry]; !ok {
		return false, nil
	}
	delete(set, entry)
	if err := e.saveLocked(); err != nil {
		set[entry] = struct{}{}
		return false, err
	}
	return true, nil
}

// saveLocked writes the file atomically (temp file in the same directory,
// then rename) so a crash mid-write never leaves a truncated exclusions
// file. Caller must hold e.mu.
func (e *exclusionStore) saveLocked() error {
	dns := make([]string, 0, len(e.dns))
	for k := range e.dns {
		dns = append(dns, k)
	}
	sort.Strings(dns)
	ips := make([]string, 0, len(e.ips))
	for k := range e.ips {
		ips = append(ips, k)
	}
	sortIPs(ips)
	body, err := json.MarshalIndent(exclusionFile{DNS: dns, IPs: ips}, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(e.path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dirOrDot(dir), ".exclusions-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(append(body, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, e.path)
}

func dirOrDot(dir string) string {
	if dir == "" {
		return "."
	}
	return dir
}

// filterExcluded returns entries minus the given exclusion set, and how
// many were removed. Input order (sorted) is preserved.
func filterExcluded(entries []string, excluded map[string]struct{}) ([]string, int) {
	if len(excluded) == 0 {
		return entries, 0
	}
	out := make([]string, 0, len(entries))
	removed := 0
	for _, e := range entries {
		if _, drop := excluded[e]; drop {
			removed++
			continue
		}
		out = append(out, e)
	}
	return out, removed
}
