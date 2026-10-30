# HELLHOUND

```
██   ██  ███████  ██       ██       ██   ██  ███████  ██   ██  ██   ██  ██████
██   ██  ██       ██       ██       ██   ██  ██   ██  ██   ██  ███  ██  ██   ██
███████  █████    ██       ██       ███████  ██   ██  ██   ██  ██ █ ██  ██   ██
██   ██  ██       ██       ██       ██   ██  ██   ██  ██   ██  ██  ███  ██   ██
██   ██  ███████  ███████  ███████  ██   ██  ███████  ███████  ██   ██  ██████
```

**Calibrated recon that hunts, finds, and classifies what actually matters.**

[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-100%2B%20passing-brightgreen)](#testing)
[![Fuzz Tested](https://img.shields.io/badge/fuzz--tested-yes-blueviolet)](#testing)
[![Status: authorized testing only](https://img.shields.io/badge/use-authorized%20testing%20only-critical)](#legal--ethics)

`ffuf` fuzzes. `katana` crawls. **Hellhound calibrates, hunts, classifies, and tells you what's actually dangerous** — it auto-learns what "not found" looks like on *this specific target* so you read a handful of real hits instead of hand-tuning `-fc`/`-fs` against a wall of noise, and then it labels the dangerous ones: `[HIGH]` on an exposed `.env` or `.git/config`, `[MEDIUM]` on an open-redirect or dir-listing, `[LOW]` on `Server: nginx/1.21.3`.

---

## Why Hellhound exists

Pure brute force (ffuf) and pure crawling (katana) both treat every endpoint the same way. Hellhound doesn't:

| | ffuf / katana | **Hellhound** |
|---|---|---|
| Soft-404 filtering | Manual `-fc`/`-fs` tuning, or none | **Auto-calibrated** per directory — probes random paths first, learns the real "not found" shape |
| Duplicate findings | One line per hit, even for 200 identical templated pages | **Clustered** by response shape — 200 blog posts become 1 line with a count |
| Wordlist | Static, supplied by you | **Mined from the target itself** — robots.txt, linked JS, tech fingerprinting |
| API surface | Guessed path by path | **Reads the target's own OpenAPI/Swagger spec or GraphQL schema directly** when exposed — one hit yields the entire route map |
| Virtual hosts | Not covered | **Calibrated Host-header fuzzing** finds internal vhosts DNS never advertised |
| Link crawling | katana crawls, ffuf can't | **Both, and they feed each other**: calibrated fuzzing *and* same-origin multi-hop crawling (`-crawl`) — a page reached by following a link also seeds the fuzz wordlist, so each phase strengthens the other |
| Mid-scan blocking | floods findings when a WAF/bot-wall kicks in partway | **Detects the hit-rate spike, re-calibrates against the target's new behavior, and drops the block-page flood** — the Vercel failure, handled automatically |
| **Dangerous classification** | discovers endpoints and stops | **Tier-A security checks**: exposed `.env` / `.git/config` / backup SQL / private keys (HIGH), directory listings, open-redirects, dangerous HTTP methods (OPTIONS → PUT/DELETE/PATCH/TRACE) (MEDIUM), framework-version headers (LOW) — findings land in the same report with severity labels so you triage the dangerous stuff first |
| **Tech-aware wordlists** | one static list for every target | **Auto-detects the stack** (WordPress, Drupal, Joomla, Django, Rails, Laravel, Spring Boot, ASP.NET, PHP, Node) from one homepage fetch, then injects a curated path list for each (e.g. `/actuator/*` for Spring, `/rails/info/routes` for Rails, `wp-admin` / `xmlrpc.php` for WordPress) |
| Output | text / JSON | text, JSON, **CSV, and SARIF 2.1.0** (CI / GitHub code scanning) — SARIF rules split per finding type so a GitHub dashboard shows the real problems in red, discovery noise in gray |
| Engagement fit | ffuf has `-x`/`-rate`; katana limited | **Proxy (`-x`) for Burp/ZAP + true requests/sec rate limit (`-rate`)** to stay under WAF/bot thresholds |
| Resilience | — | Survives WAF deny pages, redirect-everything proxies, dead targets, and malformed input *by design*, not by luck (see [Testing](#testing)) |

---

## How calibration actually works

Before Hellhound ever fuzzes a directory, it sends a handful of requests for paths that are almost certainly fake — then fingerprints the response (status code + a SimHash of the body, with the requested path itself redacted so an echoed-back "not found: /your-guess" page doesn't look unique every time). Every real candidate gets compared against that learned baseline. Only genuine deviations get reported.

```mermaid
flowchart LR
    A[Target] --> B["Calibrator<br/>(probe random fake paths)"]
    B --> C["Learned baseline<br/>(status + SimHash shape)"]
    A --> D["Wordlist engine<br/>(seed + mined from JS/robots.txt)"]
    D --> E["Discovery engine<br/>(concurrent, backoff-aware)"]
    C --> F{Classify}
    E --> F
    F -->|matches baseline| G[discarded as noise]
    F -->|genuinely different| H["Clustering<br/>(dedupe by shape)"]
    H --> I[Report]
    A --> J["API probe<br/>(OpenAPI / GraphQL)"]
    A --> K["VHost probe<br/>(Host-header fuzzing)"]
    J --> I
    K --> I
```

---

## Install

```bash
go install github.com/securewithharshitrajput/hellhound/cmd/hellhound@v0.6.0
```

(Pin to a tagged version like `@v0.6.0` rather than `@latest` — Go's module proxy caches version lookups, and `@latest` against an untagged commit can serve a stale result until the proxy's cache naturally refreshes. A tagged release doesn't have that problem.)

This drops a `hellhound` binary into `$(go env GOBIN)` (usually `~/go/bin`) — the same place `ffuf`/`katana` live. Make sure that's on your `PATH` and you're done:

```bash
hellhound -u http://target.tld
```

**From source:**

```bash
git clone https://github.com/securewithharshitrajput/hellhound.git
cd hellhound
go install ./cmd/hellhound
```

---

## Quick start

```bash
# Basic scan — calibration, mining, clustering, API + nothing else needed
hellhound -u http://target.tld

# Bring your own wordlist, try backup extensions, raise concurrency
hellhound -u https://target.tld -w wordlist.txt -ext .bak,.old,.zip -c 60

# Hunt internal virtual hosts on a box you already have an IP for
hellhound -u http://10.0.0.5 -vhosts vhosts.txt

# Fuzz AND crawl — find guessable paths and link-only pages in one run
hellhound -u https://target.tld -crawl

# Route through Burp for inspection, throttled to stay under WAF thresholds
hellhound -u https://target.tld -x http://127.0.0.1:8080 -k -rate 20

# Authenticated scan behind an auth header, self-signed dev cert
hellhound -u https://staging.internal -H "Authorization: Bearer <token>" -k

# Save structured output — JSON, CSV, and SARIF (for CI code scanning) at once
hellhound -u http://target.tld -json out.json -csv out.csv -sarif out.sarif
```

Sample run:

```
hellhound: mining robots.txt + homepage + linked JS for target-derived words...
hellhound: mined 3 additional word(s) from the target itself
hellhound: detected stack(s): wordpress, php
hellhound: injected 24 tech-specific word(s)
hellhound: calibrating + scanning http://target.tld with 115 words x 2 extensions (depth=2, concurrency=40)
hellhound: done in 591ms, sent 13208 requests (0 backoff pauses)

hellhound: running Tier-A security checks (sensitive files, dir listings, dangerous methods, open-redirect, info-disclosure)...
hellhound: security checks done in 94ms — 6 finding(s)

hellhound: 21 findings in 9 cluster(s) for http://target.tld

  [200] http://target.tld/admin/users                    len=88     status 200 does not match any calibrated baseline shape
  [200] http://target.tld/api/internal/billing-export    len=104    status 200 does not match any calibrated baseline shape (+2 similar)
  [200] http://target.tld/swagger.json                   len=117    status 200 does not match any calibrated baseline shape

[security] 6 finding(s):
  [HIGH  ] sensitive-file  http://target.tld/.env
        environment file commonly contains database and API credentials
        evidence: DB_PASSWORD=hunter2 SECRET_KEY=abc...
  [HIGH  ] sensitive-file  http://target.tld/.git/config
        .git directory exposed — attacker can reconstruct full source tree
        evidence: [core]  repositoryformatversion = 0 [remote "o
  [MEDIUM] dangerous-methods  http://target.tld/api/users
        server advertises PUT, DELETE, PATCH via OPTIONS Allow header
        evidence: GET, POST, PUT, DELETE, PATCH, OPTIONS
  [MEDIUM] dir-listing  http://target.tld/uploads/
        directory listing enabled — every filename in this directory is enumerable
  [MEDIUM] open-redirect  http://target.tld/go?url=https://legit.example.com/
        parameter url is reflected into the Location header without validation
  [LOW   ] info-disclosure  http://target.tld
        Server header exposes server software and version: nginx/1.21.3

[openapi] spec found at /swagger.json — 5 routes declared:
    GET     /orders
    GET     /users
    POST    /users
    DELETE  /users/{id}
    GET     /users/{id}

[graphql] introspection enabled at /graphql — 3 root fields exposed:
    Mutation.deleteUser
    Query.listOrders
    Query.user
```

The banner at the top is randomized per run (Metasploit-style rotating tips) and auto-switches to a plain single line when stdout isn't a real terminal, so piping output never pollutes your logs.

---

## Flags

| Flag | Default | What it does |
|---|---|---|
| `-u` | *(required)* | Target base URL |
| `-w` | — | Wordlist file, one word per line — merged with the built-in seed and mined words |
| `-c` | `40` | Concurrent requests |
| `-depth` | `2` | Max recursion depth (`0` = scan only the given directory) |
| `-calibrate` | `6` | Calibration probes per directory |
| `-ext` | — | Comma-separated extensions to try, e.g. `.php,.bak,.old` |
| `-H` | — | Custom header, repeatable: `-H "Name: value"` |
| `-k` | `false` | Skip TLS verification (self-signed dev/staging certs **only** — never on production scope) |
| `-x` | — | Route all requests through an HTTP proxy, e.g. `http://127.0.0.1:8080` for Burp/ZAP (HTTPS through Burp usually also needs `-k`) |
| `-rate` | `0` | Max requests/sec across all workers (0 = unlimited) — stay under a target's rate-based WAF/bot thresholds |
| `-timeout` | `10s` | Per-request timeout |
| `-maxbody` | `512` (KB) | Max response body to read — raise it if a large OpenAPI/GraphQL spec looks truncated |
| `-vhosts` | — | Candidate-hostnames file for virtual-host discovery against `-u` |
| `-crawl` | `false` | Crawl real `<a href>`/`src`/`action` links (same-origin, multi-hop) to find linked pages no wordlist could guess |
| `-crawl-depth` | `3` | Max link-following depth when `-crawl` is set |
| `-crawl-max` | `500` | Max total pages to fetch when `-crawl` is set |
| `-no-mine` | `false` | Skip mining robots.txt/homepage/JS for target-derived words |
| `-no-tech` | `false` | Skip tech-stack fingerprinting + tech-specific wordlist injection |
| `-no-security` | `false` | Skip Tier-A security checks (sensitive files, dir listing, dangerous HTTP methods, open-redirect, info-disclosure headers) |
| `-no-banner` | `false` | Suppress the startup banner |
| `-json` | — | Write the full clustered JSON report (incl. security findings) to this path |
| `-csv` | — | Write findings as CSV (one row per finding, security findings tagged `security`) to this path |
| `-sarif` | — | Write findings as SARIF 2.1.0 to this path (for CI / GitHub code scanning) |

### Tier-A security findings

Hellhound classifies each endpoint it discovers against a dedicated set of security probes and content checks. Everything that triggers lands in the `[security]` block of stdout and (with their severity preserved) in the JSON/CSV/SARIF outputs. The checks are:

| Check | What it looks for | Typical severity |
|---|---|---|
| **sensitive-file** | `.env`, `.git/config`, `.htpasswd`, `backup.sql`, `/id_rsa`, `wp-config.php.bak`, Terraform state, `/credentials.json`, 40+ well-known dangerous paths — each confirmed by content markers (no soft-404 false positives) | HIGH |
| **dir-listing** | Response body matches Apache/nginx/Python-SimpleHTTPServer's directory-index fingerprint — every filename enumerable, non-linked backups exposed | MEDIUM |
| **dangerous-methods** | `OPTIONS` on each discovered endpoint; flags any `Allow:` header advertising `PUT` / `DELETE` / `PATCH` (MEDIUM) or `TRACE` alone (LOW, XST primitive) | MEDIUM / LOW |
| **open-redirect** | Any discovered URL whose query carries a redirect-shaped parameter (`url`, `next`, `redirect`, `redirect_uri`, `goto`, `return`, `callback`, …) is re-sent with a canary external URL; a 3xx `Location:` reflecting it is flagged | MEDIUM |
| **info-disclosure** | `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Rails-Version`, `X-Generator`, `X-Application-Context`, etc. — deduplicated per host so a 10,000-request scan doesn't flood with the same banner | LOW / INFO |

---

## Testing

This isn't "it compiled, ship it." The analyzer and engine were deliberately put through conditions that find real bugs, not just happy paths:

- **Fuzz testing** (`go test -fuzz`) on the core normalizer, calibrator, and OpenAPI/GraphQL parsers — millions of executions against adversarial and malformed input, including invalid UTF-8 (which did crash an earlier version — fixed and locked in with a regression test)
- **Race detector** (`-race`) on every test, including the concurrent worker pool and backoff/pause logic
- **Real blackhole/timeout targets** — verified the tool doesn't silently hang for minutes against an unresponsive host (found and fixed a sequential-probing bug that did exactly that)
- **WAF/deny-page and redirect-everything targets** — verified calibration suppresses the noise instead of flooding the report
- **50,000-word stress test** against a live server — found and fixed a ~0.1% false-positive edge case in redaction ordering
- **Goroutine leak checks** across repeated scans

100+ tests passing (every new Tier-A detector carries its own fingerprint and false-positive-rejection regression tests), `go vet` and `gofmt` clean, zero known crashes.

```bash
go test ./...
go test ./... -race
go test ./internal/analyze/ -fuzz FuzzSimHash -fuzztime 30s
```

---

## Legal & ethics

Hellhound sends real HTTP requests to real servers. **Only point it at targets you are explicitly authorized to test** — your own infrastructure, a scope you have written permission for, or a CTF/lab environment built for this purpose. Unauthorized scanning of systems you don't own or have permission to test is illegal in most jurisdictions.

`-k` (skip TLS verification) exists for self-signed dev/staging certificates you control. Never use it to bypass certificate checks against a production target.

---

## Contributing

Issues and PRs welcome. If you're adding a feature, add the test that would have caught the bug it's meant to prevent — that's the standard the rest of this codebase holds itself to.

## License

[MIT](LICENSE)
