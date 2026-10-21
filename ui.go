package main

import "net/http"

// handleManage serves the embedded admin page. Browsers cannot set a
// Bearer header on navigation, so the page accepts Basic auth (token as
// the password) and then rides on it for its API calls.
func (s *store) handleManage(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, true) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(managePage))
}

const managePage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Blocklist manager</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 44rem; margin: 2rem auto; padding: 0 1rem; }
  input[type=text] { width: 70%; padding: .5rem; }
  button { padding: .5rem 1rem; cursor: pointer; }
  #result, #exclusions { margin-top: 1.5rem; }
  li { margin: .25rem 0; }
  .err { color: #b00; }
  code { background: #eee; padding: .1rem .3rem; }
</style>
</head>
<body>
<h1>Blocklist search &amp; remove</h1>
<p>Removals are exact-match exclusions: they are persisted, re-applied on
every refresh, and never edit upstream lists. Restoring re-serves an entry
immediately if an upstream list still contains it.</p>
<form id="searchForm">
  <input type="text" id="q" placeholder="example.com or 1.2.3.4 or 10.0.0.0/8" required>
  <button type="submit">Search</button>
</form>
<div id="result"></div>
<h2>Current exclusions</h2>
<div id="exclusions">Loading…</div>
<script>
"use strict";
const resultEl = document.getElementById("result");
const exclEl = document.getElementById("exclusions");

function el(tag, text) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  return e;
}

async function api(path, opts) {
  const resp = await fetch(path, opts);
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.error || ("HTTP " + resp.status));
  return data;
}

async function exclude(entry) {
  await api("/exclusions", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({entry: entry})
  });
  await refresh();
}

async function restore(entry) {
  await api("/exclusions", {
    method: "DELETE",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({entry: entry})
  });
  await refresh();
}

function actionButton(label, entry, fn) {
  const b = el("button", label);
  b.addEventListener("click", async () => {
    b.disabled = true;
    try { await fn(entry); } catch (e) { resultEl.replaceChildren(el("p", e.message)); resultEl.firstChild.className = "err"; }
  });
  return b;
}

function showSearch(res) {
  const frag = document.createDocumentFragment();
  const p = el("p");
  p.append("Normalized: ");
  const c = el("code", res.normalized); p.append(c);
  p.append(" (" + res.type + ")");
  frag.append(p);
  if (res.found) {
    const f = el("p");
    f.append("Served in chunk " + res.chunk + " — ");
    const a = el("a", res.chunk_url); a.href = res.chunk_url;
    f.append(a);
    frag.append(f);
    frag.append(actionButton("Remove (exclude) this entry", res.normalized, exclude));
  } else if (res.excluded) {
    frag.append(el("p", "Excluded: not currently served."));
    frag.append(actionButton("Restore this entry", res.normalized, restore));
  } else if (res.in_snapshot) {
    frag.append(el("p", "Present upstream but not served."));
  } else {
    frag.append(el("p", "Not in any upstream list."));
    if (res.covered_by) frag.append(el("p", "Covered by served entry: " + res.covered_by + " (exact-match removal only affects the queried entry itself)"));
    frag.append(actionButton("Exclude anyway (blocks future upstream additions)", res.normalized, exclude));
  }
  resultEl.replaceChildren(frag);
}

async function loadExclusions() {
  try {
    const data = await api("/exclusions");
    const frag = document.createDocumentFragment();
    if (!data.count) {
      frag.append(el("p", "None."));
    } else {
      const ul = el("ul");
      for (const entry of data.dns.concat(data.ips)) {
        const li = el("li");
        const c = el("code", entry); li.append(c); li.append(" ");
        li.append(actionButton("Restore", entry, restore));
        ul.append(li);
      }
      frag.append(ul);
    }
    exclEl.replaceChildren(frag);
  } catch (e) {
    exclEl.replaceChildren(el("p", e.message));
    exclEl.firstChild.className = "err";
  }
}

async function refresh() {
  const q = document.getElementById("q").value.trim();
  if (q) {
    try { showSearch(await api("/search?q=" + encodeURIComponent(q))); } catch (e) { /* result area already reports via submit */ }
  }
  await loadExclusions();
}

document.getElementById("searchForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const q = document.getElementById("q").value;
  try {
    showSearch(await api("/search?q=" + encodeURIComponent(q)));
  } catch (e) {
    const p = el("p", e.message); p.className = "err";
    resultEl.replaceChildren(p);
  }
});

loadExclusions();
</script>
</body>
</html>
`
