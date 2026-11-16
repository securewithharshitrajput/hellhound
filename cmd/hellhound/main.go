// hellhound is a calibrated content-discovery tool: it auto-learns each
// target directory's "not found" fingerprint before fuzzing it (so you
// don't hand-tune -fc/-fs like you would with ffuf), clusters near-
// identical hits so a templated section doesn't flood the output, mines
// the target's own JS/robots.txt for real path fragments to extend the
// wordlist, and can read OpenAPI/GraphQL schemas directly when exposed.
//
// For authorized security testing only.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/securewithharshitrajput/hellhound/internal/banner"
	"github.com/securewithharshitrajput/hellhound/internal/discover"
	"github.com/securewithharshitrajput/hellhound/internal/engine"
	"github.com/securewithharshitrajput/hellhound/internal/report"
	"github.com/securewithharshitrajput/hellhound/internal/wordlist"
)

// headerFlag lets -H be repeated on the command line (flag.String only
// keeps the last value), e.g. -H "Authorization: Bearer x" -H "X-Foo: bar".
type headerFlag map[string]string

func (h headerFlag) String() string {
	return fmt.Sprintf("%d header(s)", len(h))
}

func (h headerFlag) Set(v string) error {
	k, val, ok := strings.Cut(v, ":")
	if !ok {
		return fmt.Errorf("expected \"Name: value\", got %q", v)
	}
	k, val = strings.TrimSpace(k), strings.TrimSpace(val)
	if k == "" || strings.ContainsAny(k, " \t\r\n\"(),/:;<=>?@[\\]{}") {
		return fmt.Errorf("%q is not a valid header name", k)
	}
	if strings.ContainsAny(val, "\r\n\x00") {
		return fmt.Errorf("header %s: the value must be a single line", k)
	}
	h[k] = val
	return nil
}

func main() {
	headers := headerFlag{}
	var (
		target       = flag.String("u", "", "target base URL, e.g. http://localhost:8080")
		wordlistPath = flag.String("w", "", "wordlist file (one word per line); merged with hellhound's built-in seed + target-derived words")
		concurrency  = flag.Int("c", 40, "concurrent requests")
		depth        = flag.Int("depth", 2, "max recursion depth")
		calibN       = flag.Int("calibrate", 6, "calibration probes per directory")
		extStr       = flag.String("ext", "", "comma-separated extensions to try, e.g. .php,.bak,.old")
		jsonOut      = flag.String("json", "", "write the full clustered JSON report to this path")
		csvOut       = flag.String("csv", "", "write findings as CSV to this path (one row per finding)")
		sarifOut     = flag.String("sarif", "", "write findings as SARIF 2.1.0 to this path (for CI / GitHub code scanning)")
		timeout      = flag.Duration("timeout", 10*time.Second, "per-request timeout")
		insecure     = flag.Bool("k", false, "skip TLS certificate verification (only for authorized testing of a target with a self-signed/dev cert)")
		noMine       = flag.Bool("no-mine", false, "skip mining robots.txt/homepage/JS for target-derived wordlist words")
		maxBodyKB    = flag.Int("maxbody", 512, "max response body size to read, in KB (raise this if a large OpenAPI/GraphQL spec is being truncated)")
		vhostFile    = flag.String("vhosts", "", "candidate-hostnames file for virtual-host discovery against -u (one hostname per line); runs in addition to content discovery")
		proxyURL     = flag.String("x", "", "route all requests through this HTTP proxy (e.g. http://127.0.0.1:8080 for Burp/ZAP); HTTPS through Burp usually also needs -k")
		rate         = flag.Int("rate", 0, "max requests per second across all workers (0 = unlimited); use this to stay under a target's rate-based WAF/bot thresholds")
		crawl        = flag.Bool("crawl", false, "crawl real <a href> links from the target to find linked pages no wordlist could guess (same-origin, multi-hop)")
		crawlDepth   = flag.Int("crawl-depth", 3, "max link-following depth when -crawl is set")
		crawlMax     = flag.Int("crawl-max", 500, "max total pages to fetch when -crawl is set")
		noBanner     = flag.Bool("no-banner", false, "suppress the startup banner")
		noSecurity   = flag.Bool("no-security", false, "skip Tier-A security checks (sensitive files, dir listing, dangerous HTTP methods, open-redirect, info-disclosure headers)")
		noTechMine   = flag.Bool("no-tech", false, "skip tech-stack fingerprinting + tech-specific wordlist injection (WordPress/Django/Rails/Laravel/Spring/etc.)")
	)
	flag.Var(headers, "H", `custom header, repeatable, format "Name: value" (e.g. -H "Authorization: Bearer xyz")`)
	flag.Parse()

	banner.Print(*noBanner)

	if *target == "" {
		fmt.Fprintln(os.Stderr, "usage: hellhound -u http://target [-w wordlist.txt] [-H \"Name: value\"] [-k] [-depth 2] [-ext .bak,.old] [-json out.json]")
		fmt.Fprintln(os.Stderr, "\nFor authorized security testing only — only point this at targets you are authorized to test.")
		os.Exit(2)
	}
	if err := validateFlags(*concurrency, *depth, *calibN, *rate, *maxBodyKB, *crawlDepth, *crawlMax, *timeout); err != nil {
		fmt.Fprintf(os.Stderr, "hellhound: %v\n", err)
		os.Exit(2)
	}
	baseURL, err := normalizeTarget(*target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hellhound: invalid target %q: %v\n", *target, err)
		os.Exit(2)
	}
	// Input and output files are checked before anything is sent: a typo in
	// -w must not silently fall back to the built-in list, and an
	// unwritable report path must not be discovered after the scan.
	userWords, err := readListFile("-w", *wordlistPath)
	if err == nil && *vhostFile != "" {
		_, err = readListFile("-vhosts", *vhostFile)
	}
	if err == nil {
		err = checkWritable(*jsonOut, *csvOut, *sarifOut)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "hellhound: %v\n", err)
		os.Exit(2)
	}

	cfg := engine.DefaultConfig()
	cfg.Concurrency = *concurrency
	cfg.Timeout = *timeout
	cfg.InsecureSkipVerify = *insecure
	cfg.DefaultHeaders = headers
	cfg.MaxBodyBytes = int64(*maxBodyKB) * 1024
	cfg.ProxyURL = *proxyURL
	cfg.RatePerSec = *rate
	eng, err := engine.NewErr(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hellhound: %v\n", err)
		os.Exit(2)
	}
	defer eng.Close() // not load-bearing for a one-shot process (the OS reclaims everything on exit), but correct practice and free

	if *proxyURL != "" {
		fmt.Fprintf(os.Stderr, "hellhound: routing all requests through proxy %s\n", *proxyURL)
	}
	if *rate > 0 {
		fmt.Fprintf(os.Stderr, "hellhound: rate limited to %d request(s)/sec\n", *rate)
	}

	// A plain context.Background() here would mean Ctrl+C just kills the
	// process outright — no partial results, no cleanup, matching neither
	// ffuf's nor katana's behavior (both print what they have so far on
	// interrupt). signal.NotifyContext cancels ctx on SIGINT/SIGTERM instead;
	// Engine and Discoverer already check ctx.Done() throughout, so an
	// in-progress scan winds down and whatever was found before the
	// interrupt still gets reported below.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The first interrupt winds the scan down and prints partial results.
	// Restore default signal handling as soon as it arrives, so a second
	// Ctrl+C always terminates the process immediately.
	go func() {
		<-ctx.Done()
		stop()
	}()

	// Fail fast on an unreachable target. Without this every phase runs
	// against nothing and the run ends with a clean-looking "0 findings",
	// exit 0 — indistinguishable from a real scan of a clean target.
	if pre := eng.DoAll(ctx, []engine.Request{{Method: "GET", URL: baseURL + "/"}}); len(pre) == 1 && pre[0].Err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "hellhound: target is not reachable: %v\n", pre[0].Err)
		fmt.Fprintln(os.Stderr, "hellhound: nothing was scanned (check the URL, scheme and port; use -k for a self-signed certificate on an authorized dev/staging target)")
		os.Exit(1)
	}

	seed := wordlist.Merge(wordlist.Seed, userWords)
	words := seed
	if !*noMine {
		fmt.Fprintf(os.Stderr, "hellhound: mining robots.txt + homepage + linked JS for target-derived words...\n")
		words = discover.BuildWordlist(ctx, eng, baseURL, seed)
		if extra := len(words) - len(seed); extra > 0 {
			fmt.Fprintf(os.Stderr, "hellhound: mined %d additional word(s) from the target itself\n", extra)
		}
	}

	// Tech fingerprinting + smart wordlist injection. One homepage fetch,
	// then zero further cost — the detected stacks' curated path lists just
	// merge into the wordlist the main fuzz loop will use.
	var detectedTechs []discover.Tech
	if ctx.Err() == nil && !*noTechMine {
		detectedTechs = discover.DetectTech(ctx, eng, baseURL)
		if len(detectedTechs) > 0 {
			names := make([]string, len(detectedTechs))
			for i, t := range detectedTechs {
				names[i] = string(t)
			}
			fmt.Fprintf(os.Stderr, "hellhound: detected stack(s): %s\n", strings.Join(names, ", "))
			if tw := discover.WordsForTechs(detectedTechs); len(tw) > 0 {
				before := len(words)
				words = wordlist.Merge(words, tw)
				if added := len(words) - before; added > 0 {
					fmt.Fprintf(os.Stderr, "hellhound: injected %d tech-specific word(s)\n", added)
				}
			}
		}
	}

	// Crawl runs BEFORE fuzzing (when enabled) so its discoveries feed the
	// fuzz wordlist: a path segment the crawler reached by following a real
	// link becomes a word the fuzzer then tries in every directory. The two
	// phases reinforce each other instead of running independently — and
	// because a crawl-found page's segments are now fuzzed, those pages also
	// land in the structured report/output files, not just the [crawl] text.
	var crawlResults []discover.CrawlResult
	if ctx.Err() == nil && *crawl {
		crawlResults = runCrawl(ctx, eng, baseURL, *crawlDepth, *crawlMax)
		if cw := discover.WordsFromCrawl(crawlResults); len(cw) > 0 {
			before := len(words)
			words = wordlist.Merge(words, cw)
			if added := len(words) - before; added > 0 {
				fmt.Fprintf(os.Stderr, "hellhound: crawl contributed %d new fuzz word(s)\n", added)
			}
		}
	}

	exts := []string{""}
	if *extStr != "" {
		for _, e := range strings.Split(*extStr, ",") {
			e = strings.TrimSpace(e)
			if e == "" {
				continue
			}
			if !validExt(e) {
				fmt.Fprintf(os.Stderr, "hellhound: invalid -ext entry %q: an extension starts with '.' or '~' and contains only letters, digits, '.', '_', '-' and '~' (e.g. .bak,.old,~)\n", e)
				os.Exit(2)
			}
			exts = append(exts, e)
		}
	}

	d := discover.New(eng, discover.Options{
		BaseURL:      baseURL,
		Wordlist:     words,
		CalibrationN: *calibN,
		MaxDepth:     *depth,
		Extensions:   exts,
		OnWarning: func(dir string, err error) {
			fmt.Fprintf(os.Stderr, "hellhound: warning: scanning %s: %s (continuing)\n", report.Clean(dir), report.Clean(err.Error()))
		},
	})

	fmt.Fprintf(os.Stderr, "hellhound: calibrating + scanning %s with %d words x %d extensions (depth=%d, concurrency=%d)\n",
		*target, len(words), len(exts), *depth, *concurrency)

	start := time.Now()
	results, err := d.Run(ctx, "/")
	if err != nil {
		fmt.Fprintf(os.Stderr, "hellhound: error: %v\n", err)
		os.Exit(1)
	}
	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "hellhound: interrupted after %s, sent %d requests — showing partial results below\n\n",
			time.Since(start).Round(time.Millisecond), eng.Sent.Load())
	} else {
		fmt.Fprintf(os.Stderr, "hellhound: done in %s, sent %d requests (%d backoff pauses)\n\n",
			time.Since(start).Round(time.Millisecond), eng.Sent.Load(), eng.Backoffs.Load())
	}

	rep := report.Build(*target, results)

	// Tier-A security phases. Each one is independent and skippable; the
	// combined findings land in the same report so stdout/CSV/SARIF all
	// surface them uniformly. These phases DO issue extra requests (sensitive
	// probes + per-discovered-endpoint OPTIONS + per-redirect-param probe), so
	// -no-security turns the whole thing off for a pure discovery run.
	// Both fuzz-discovered AND crawl-discovered URLs are classified — a page
	// reached only by following a link still deserves open-redirect/method
	// checks and still leaks headers worth capturing.
	if !*noSecurity && ctx.Err() == nil {
		allResults := append([]discover.Result{}, results...)
		allResults = append(allResults, discover.AsResults(crawlResults)...)
		rep.SecurityFindings = report.CleanFindings(runSecurityScans(ctx, eng, baseURL, allResults))
	}

	report.WriteSummary(os.Stdout, rep)

	if ctx.Err() == nil {
		runAPIDiscovery(ctx, eng, baseURL)
	}

	if ctx.Err() == nil && *vhostFile != "" {
		runVHostScan(ctx, eng, baseURL, *vhostFile, *calibN)
	}

	writeOutput("JSON", *jsonOut, rep, report.WriteJSON)
	writeOutput("CSV", *csvOut, rep, report.WriteCSV)
	writeOutput("SARIF", *sarifOut, rep, report.WriteSARIF)

	if ctx.Err() != nil {
		// Partial results were printed and written, but the scan did not
		// finish: exit like any interrupted program so scripts and CI do
		// not mistake it for a completed run.
		os.Exit(130)
	}
}

// runSecurityScans runs every Tier-A detector concurrently and merges the
// findings. Order of lines in stderr is not critical; findings land in the
// returned slice with their severities intact so the reporter can sort.
func runSecurityScans(ctx context.Context, eng *engine.Engine, baseURL string, results []discover.Result) []discover.SecurityFinding {
	start := time.Now()
	fmt.Fprintf(os.Stderr, "\nhellhound: running Tier-A security checks (sensitive files, dir listings, dangerous methods, open-redirect, info-disclosure)...\n")

	var findings []discover.SecurityFinding

	// 1) Sensitive file probes (dedicated path list, concurrent batch).
	sens, skipped := discover.ScanSensitiveAll(ctx, eng, baseURL, results)
	findings = append(findings, sens...)
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "hellhound: sensitive-file probes ran at the root and the first 10 discovered directories; %d more directories were not probed\n", skipped)
	}

	// 2) Dir-listing classification (zero extra requests, uses already-captured bodies).
	findings = append(findings, discover.ClassifyDirListings(results)...)

	// 3) Info-disclosure header capture (zero extra requests, uses already-captured headers).
	findings = append(findings, discover.CaptureInfoDisclosure(results)...)

	// 4) Dangerous HTTP methods (one OPTIONS per unique discovered URL).
	urls := make([]string, 0, len(results))
	for _, r := range results {
		if r.Status >= 200 && r.Status < 400 {
			urls = append(urls, r.URL)
		}
	}
	findings = append(findings, discover.ScanDangerousMethods(ctx, eng, urls)...)

	// 5) Open-redirect classification (probes any discovered URL carrying a
	// redirect-shaped parameter — most discovered URLs have no query string,
	// so the extra request volume is small).
	findings = append(findings, discover.ScanOpenRedirects(ctx, eng, urls)...)

	fmt.Fprintf(os.Stderr, "hellhound: security checks done in %s — %d finding(s)\n", time.Since(start).Round(time.Millisecond), len(findings))
	return findings
}

// validateFlags rejects numeric flag values that cannot produce a meaningful
// scan, with a message naming the flag, instead of hanging, panicking or
// silently doing something else.
func validateFlags(concurrency, depth, calibN, rate, maxBodyKB, crawlDepth, crawlMax int, timeout time.Duration) error {
	switch {
	case concurrency < 1 || concurrency > 1000:
		return fmt.Errorf("-c must be between 1 and 1000 (got %d)", concurrency)
	case depth < 0:
		return fmt.Errorf("-depth must be 0 or more (got %d)", depth)
	case calibN < 2:
		return fmt.Errorf("-calibrate must be at least 2 (got %d): fewer probes cannot tell a stable not-found page from a changing one", calibN)
	case rate < 0:
		return fmt.Errorf("-rate must be 0 (unlimited) or more (got %d)", rate)
	case maxBodyKB < 1:
		return fmt.Errorf("-maxbody must be at least 1 KB (got %d)", maxBodyKB)
	case crawlDepth < 1:
		return fmt.Errorf("-crawl-depth must be at least 1 (got %d)", crawlDepth)
	case crawlMax < 1:
		return fmt.Errorf("-crawl-max must be at least 1 (got %d)", crawlMax)
	case timeout < 100*time.Millisecond:
		return fmt.Errorf("-timeout must be at least 100ms (got %s)", timeout)
	}
	return nil
}

// normalizeTarget validates -u and returns the base URL every phase builds
// on: an absolute http(s) URL with a lowercase scheme, an optional path
// prefix, no trailing slash, and nothing that cannot be scanned as a
// directory (query string, fragment) or that would end up in reports
// (embedded credentials).
func normalizeTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	lower := strings.ToLower(raw)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return "", fmt.Errorf("URL must start with http:// or https://")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	switch {
	case u.Hostname() == "":
		return "", fmt.Errorf("URL has no host")
	case u.RawQuery != "" || u.ForceQuery:
		return "", fmt.Errorf("URL must not contain a query string — give the base URL to scan under, e.g. %s://%s%s", strings.ToLower(u.Scheme), u.Host, u.Path)
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return "", fmt.Errorf("URL must not contain a #fragment")
	case u.User != nil:
		return "", fmt.Errorf("URL must not embed credentials (they would be written into every report line); pass them with -H \"Authorization: Basic <base64 user:pass>\"")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/"), nil
}

// validExt reports whether e is a plausible file extension or backup suffix.
func validExt(e string) bool {
	if e[0] != '.' && e[0] != '~' {
		return false
	}
	for i := 0; i < len(e); i++ {
		c := e[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' || c == '~') {
			return false
		}
	}
	return !strings.Contains(e, "..")
}

// readListFile loads a one-entry-per-line file given with a flag. Unlike a
// warning-and-continue, a file that was asked for but cannot be read is an
// error: the scan the operator wanted is not the scan that would run.
func readListFile(flagName, path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	if st, err := os.Stat(path); err == nil && st.IsDir() {
		return nil, fmt.Errorf("%s %s is a directory, not a file", flagName, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s file: %v", flagName, err)
	}
	out := parseList(data)
	if len(out) == 0 {
		return nil, fmt.Errorf("%s %s contains no usable entries", flagName, path)
	}
	return out, nil
}

// checkWritable makes sure each requested report file can be created,
// without truncating an existing one yet.
func checkWritable(paths ...string) error {
	for _, p := range paths {
		if p == "" {
			continue
		}
		_, statErr := os.Stat(p)
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			return fmt.Errorf("cannot write report file: %v", err)
		}
		f.Close()
		if os.IsNotExist(statErr) {
			os.Remove(p) // leave no empty file behind if the scan is aborted
		}
	}
	return nil
}

// writeOutput writes rep to path using the given format writer, exiting on
// any error. A no-op when path is empty, so each -json/-csv/-sarif flag is
// independent and any combination can be produced in one run.
func writeOutput(label, path string, rep report.JSONReport, write func(io.Writer, report.JSONReport) error) {
	if path == "" {
		return
	}
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hellhound: could not write %s report: %v\n", label, err)
		os.Exit(1)
	}
	defer f.Close()
	if err := write(f, rep); err != nil {
		fmt.Fprintf(os.Stderr, "hellhound: error encoding %s report: %v\n", label, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "hellhound: wrote %s report to %s\n", label, path)
}

// runAPIDiscovery actively probes conventional OpenAPI/Swagger and GraphQL
// locations and, if one responds with a real spec, parses it for the full
// route/field map and prints it — this is the "read the target's own
// documentation of itself" advantage over pure brute force: one hit here
// yields every route in the API, not just the one path that was guessed.
// apiProbeKind tags each request in the single combined batch below so
// responses can be routed back to the right parser after DoAll returns.
type apiProbeKind int

const (
	probeOpenAPI apiProbeKind = iota
	probeGraphQL
)

// runAPIDiscovery probes every conventional OpenAPI/Swagger and GraphQL
// location in ONE combined DoAll batch, not two sequential ones.
//
// An earlier version looped one request at a time over 9 spec paths + 5
// GraphQL paths — against a healthy target the difference is invisible,
// but against an unresponsive one, 14 sequential requests at a 10s
// timeout is 140 seconds of silent hanging well after the tool already
// printed "done" for the main scan. A first fix ran the two groups
// concurrently WITHIN each group via two separate DoAll calls — better,
// but still two sequential rounds back-to-back (confirmed by timing it
// against a real blackhole target: exactly 2x one timeout, not 1x).
// Merging both groups into a single DoAll call collapses the worst case
// to roughly one timeout, period, regardless of how the 14 paths split
// between GET spec probes and POST GraphQL probes.
func runAPIDiscovery(ctx context.Context, eng *engine.Engine, baseURL string) {
	total := len(discover.CommonSpecPaths) + len(discover.CommonGraphQLPaths)
	start := time.Now()
	fmt.Fprintf(os.Stderr, "hellhound: probing %d common OpenAPI/GraphQL locations...\n", total)

	reqs := make([]engine.Request, 0, total)
	kinds := make([]apiProbeKind, 0, total)
	paths := make([]string, 0, total)

	for _, p := range discover.CommonSpecPaths {
		reqs = append(reqs, engine.Request{Method: "GET", URL: baseURL + p})
		kinds = append(kinds, probeOpenAPI)
		paths = append(paths, p)
	}
	for _, p := range discover.CommonGraphQLPaths {
		reqs = append(reqs, engine.Request{
			Method: "POST",
			URL:    baseURL + p,
			Header: map[string]string{"Content-Type": "application/json"},
			Body:   []byte(discover.GraphQLIntrospectionQuery),
		})
		kinds = append(kinds, probeGraphQL)
		paths = append(paths, p)
	}

	resps := eng.DoAll(ctx, reqs)

	for i, resp := range resps {
		p := paths[i]
		if resp.Err != nil || resp.Status != 200 || len(resp.Body) == 0 {
			continue
		}
		switch kinds[i] {
		case probeOpenAPI:
			routes, err := discover.ParseOpenAPI(resp.Body)
			if err != nil {
				if resp.Truncated {
					fmt.Fprintf(os.Stderr, "hellhound: warning: %s looked like it might be an OpenAPI spec but was truncated at %d bytes — raise -maxbody and retry\n", p, resp.Length)
				}
				continue
			}
			if len(routes) == 0 {
				continue
			}
			fmt.Printf("\n[openapi] spec found at %s — %d routes declared:\n", p, len(routes))
			for _, r := range routes {
				fmt.Printf("    %-7s %s\n", report.Clean(r.Method), report.Clean(r.Path))
			}
		case probeGraphQL:
			fields, err := discover.ParseGraphQLIntrospection(resp.Body)
			if err != nil {
				if resp.Truncated {
					fmt.Fprintf(os.Stderr, "hellhound: warning: %s response was truncated at %d bytes — raise -maxbody and retry\n", p, resp.Length)
				}
				continue
			}
			if len(fields) == 0 {
				continue
			}
			fmt.Printf("\n[graphql] introspection enabled at %s — %d root fields exposed:\n", p, len(fields))
			for _, f := range fields {
				fmt.Printf("    %s.%s\n", report.Clean(f.ParentType), report.Clean(f.Field))
			}
		}
	}
	fmt.Fprintf(os.Stderr, "hellhound: API probing done in %s\n", time.Since(start).Round(time.Millisecond))
}

// runVHostScan probes -u with each candidate hostname as the Host header,
// looking for virtual hosts not advertised in DNS (an internal admin panel,
// a staging environment, anything else reachable on the same IP but only
// reachable by name). ffuf supports this via -H "Host: FUZZ", but leaves
// filtering the default-vhost noise to the operator; here it's calibrated
// automatically the same way path discovery is.
func runVHostScan(ctx context.Context, eng *engine.Engine, baseURL, vhostFile string, calibN int) {
	candidates := loadWordlistFile(vhostFile)
	if len(candidates) == 0 {
		fmt.Fprintf(os.Stderr, "hellhound: warning: -vhosts file %s had no usable entries, skipping vhost scan\n", vhostFile)
		return
	}
	fmt.Fprintf(os.Stderr, "\nhellhound: vhost scanning %s with %d candidate hostname(s)...\n", baseURL, len(candidates))
	results := discover.VHostScan(ctx, eng, baseURL, candidates, calibN)
	if len(results) == 0 {
		fmt.Println("\n[vhost] no distinct virtual hosts found (every candidate matched the default-vhost baseline)")
		return
	}
	fmt.Printf("\n[vhost] %d distinct virtual host(s) found:\n", len(results))
	for _, r := range results {
		fmt.Printf("    %-40s [%d] len=%d  %s\n", report.Clean(r.Host), r.Status, r.Length, report.Clean(r.Reason))
	}
}

// runCrawl follows real links from the target to surface pages no wordlist
// could guess — the one job a pure fuzzer structurally can't do, and the
// gap this closes versus katana.
func runCrawl(ctx context.Context, eng *engine.Engine, baseURL string, depth, maxPages int) []discover.CrawlResult {
	start := time.Now()
	fmt.Fprintf(os.Stderr, "\nhellhound: crawling %s for linked pages (max depth %d, max %d pages)...\n", baseURL, depth, maxPages)
	results := discover.Crawl(ctx, eng, baseURL, depth, maxPages)
	if len(results) == 0 {
		fmt.Println("\n[crawl] no additional linked pages found")
	} else {
		fmt.Printf("\n[crawl] %d linked page(s) found by following links:\n", len(results))
		for _, r := range results {
			fmt.Printf("    [%d] (depth %d) %s\n", r.Status, r.Depth, report.Clean(r.URL))
		}
	}
	fmt.Fprintf(os.Stderr, "hellhound: crawl done in %s\n", time.Since(start).Round(time.Millisecond))
	return results
}

func loadWordlistFile(path string) []string {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hellhound: warning: could not read wordlist %s: %v\n", path, err)
		return nil
	}
	return parseList(data)
}

// parseList splits a list file into entries: one per line, surrounding
// whitespace and a UTF-8 byte-order mark removed, blank lines and
// #-comments skipped, duplicates dropped.
func parseList(data []byte) []string {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	return out
}
