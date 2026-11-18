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
	"github.com/securewithharshitrajput/hellhound/internal/render"
	"github.com/securewithharshitrajput/hellhound/internal/report"
	"github.com/securewithharshitrajput/hellhound/internal/scope"
	"github.com/securewithharshitrajput/hellhound/internal/wordlist"
	"path"
	"sort"
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
		matchCodes   = flag.String("mc", "", "always report these status codes, even when calibration judged them to be the not-found page (e.g. 401,403 or 500-599)")
		filterCodes  = flag.String("fc", "", "never report these status codes (e.g. 404,418 or 300-399); wins over -mc")
		filterSizes  = flag.String("fs", "", "never report responses whose body is exactly this many bytes (e.g. 0,1234)")
		scopeFile    = flag.String("scope", "", "scope file: hosts/paths the scan may touch and '!' exclusions; enforced on every request (see README)")
		resumeFile   = flag.String("resume", "", "state file: saved after every completed directory; if it already exists the scan continues from it instead of starting over")
		noProgress   = flag.Bool("no-progress", false, "do not draw the live progress line (it is only drawn on a terminal anyway)")
		renderJS     = flag.Bool("render", false, "with -crawl: also render each page in a local headless Chrome/Chromium and follow links that only exist after its JavaScript ran (single-page apps)")
		renderBin    = flag.String("render-browser", "", "path or name of the Chrome/Chromium binary for -render (default: auto-detect)")
		showVersion  = flag.Bool("version", false, "print the version and exit")
		maxTime      = flag.Duration("max-time", 0, "stop discovery (mining, crawl, fuzzing) after this long, e.g. 10m, then run the security checks and report; 0 = no limit")
		crawlSimilar = flag.Int("crawl-similar", 5, "follow at most this many links per URL pattern (/products/{id}, /blog/{id}...); 0 = unlimited")
		showAssets   = flag.Bool("show-assets", false, "list every static asset (JS, CSS, fonts, images) found by -crawl instead of one summary line")
		noThrottle   = flag.Bool("no-auto-throttle", false, "do not slow down automatically when the target starts timing out")
		showKnown    = flag.Bool("show-known", false, "also list pages the site already publishes (sitemap, crawled links, homepage assets); by default only discoveries are listed")
	)
	flag.String("config", "", "config file with one \"name = value\" per line (any flag); the command line overrides it")
	flag.String("profile", "", "preset of defaults: quick, deep or gentle; a config file and the command line override it")
	flag.Var(headers, "H", `custom header, repeatable, format "Name: value" (e.g. -H "Authorization: Bearer xyz")`)
	args, argErr := expandArgs(flag.CommandLine, os.Args[1:])
	if argErr != nil {
		fmt.Fprintf(os.Stderr, "hellhound: %v\n", argErr)
		os.Exit(2)
	}
	flag.CommandLine.Parse(args)

	if *showVersion {
		fmt.Printf("hellhound %s\n", banner.Version)
		return
	}
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
	if err != nil && *wordlistPath != "" && os.IsNotExist(errUnwrapPath(*wordlistPath)) && strings.Contains(strings.ToLower(*wordlistPath), "seclists") {
		err = fmt.Errorf("%v\n  SecLists is not installed at that path. Get it with:\n    git clone --depth 1 https://github.com/danielmiessler/SecLists ~/SecLists\n  then use e.g. -w ~/SecLists/Discovery/Web-Content/raft-medium-directories.txt", err)
	}
	if err == nil && *vhostFile != "" {
		_, err = readListFile("-vhosts", *vhostFile)
	}
	if err == nil {
		err = checkWritable(*jsonOut, *csvOut, *sarifOut)
	}
	var mcSet, fcSet, fsSet map[int]bool
	if err == nil {
		mcSet, err = parseIntSet("-mc", *matchCodes, 100, 599)
	}
	if err == nil {
		fcSet, err = parseIntSet("-fc", *filterCodes, 100, 599)
	}
	if err == nil {
		fsSet, err = parseIntSet("-fs", *filterSizes, 0, 1<<31-1)
	}
	var sc *scope.Scope
	if err == nil && *scopeFile != "" {
		sc, err = loadScope(*scopeFile, baseURL)
	}
	var state *scanState
	if err == nil && *resumeFile != "" {
		if state, err = loadState(*resumeFile, baseURL); err == nil && state == nil {
			err = checkWritable(*resumeFile)
		}
	}
	var renderer discover.Renderer
	if err == nil && *renderJS {
		if !*crawl {
			*crawl = true
			fmt.Fprintln(os.Stderr, "hellhound: -render implies -crawl; crawling enabled")
		}
		renderer, err = newRenderer(*renderBin, *proxyURL, *insecure, *timeout, len(headers) > 0)
	}
	if err == nil && *maxTime < 0 {
		err = fmt.Errorf("-max-time must be 0 (no limit) or positive (got %s)", *maxTime)
	}
	if err == nil && *crawlSimilar < 0 {
		err = fmt.Errorf("-crawl-similar must be 0 (unlimited) or more (got %d)", *crawlSimilar)
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
	// Every request passes this guard. Even without a scope file the scan
	// is confined to the target's own host and port: nothing a page links
	// to, redirects to or lists in a sitemap can pull requests elsewhere.
	targetHost := hostOf(baseURL)
	cfg.Allow = func(rawURL string) bool {
		return hostOf(rawURL) == targetHost && sc.Allows(rawURL)
	}
	var prog *progress
	cfg.AutoThrottle = !*noThrottle
	cfg.OnThrottle = func(newRate, timeouts int) {
		prog.Println("hellhound: warning: %d requests timed out within 15s — the target is struggling or throttling the scan; slowing down to %d request(s)/sec (disable with -no-auto-throttle)", timeouts, newRate)
	}
	eng, err := engine.NewErr(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hellhound: %v\n", err)
		os.Exit(2)
	}
	prog = newProgress(os.Stderr, !*noProgress, eng.Sent.Load)
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
	//
	// Ctrl+C also reaches every other program in the pipeline: in
	// "hellhound ... | tee scan.txt", tee exits at once, and the next write
	// to stdout would kill hellhound with SIGPIPE before it wrote its
	// -json/-csv/-sarif files. Ignoring SIGPIPE from then on turns those
	// writes into ordinary errors, so the report files are still written.
	go func() {
		<-ctx.Done()
		stop()
		signal.Ignore(syscall.SIGPIPE)
	}()
	// -max-time bounds the discovery phases only. Security checks and
	// reporting run afterwards on ctx, so a time-limited scan still ends
	// with a complete report of what it found.
	scanCtx, cancelScan := ctx, context.CancelFunc(func() {})
	if *maxTime > 0 {
		scanCtx, cancelScan = context.WithTimeout(ctx, *maxTime)
	}
	defer cancelScan()

	// Fail fast on an unreachable target. Without this every phase runs
	// against nothing and the run ends with a clean-looking "0 findings",
	// exit 0 — indistinguishable from a real scan of a clean target.
	pre := eng.DoAll(ctx, []engine.Request{{Method: "GET", URL: baseURL + "/"}})
	if len(pre) == 1 && pre[0].Err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "hellhound: target is not reachable: %v\n", pre[0].Err)
		fmt.Fprintln(os.Stderr, "hellhound: nothing was scanned (check the URL, scheme and port; use -k for a self-signed certificate on an authorized dev/staging target)")
		os.Exit(1)
	}

	seed := wordlist.Merge(wordlist.Seed, userWords)
	words := seed
	if state != nil {
		// Continuing a saved scan: use exactly the inputs it started with,
		// so the remaining directories are tested with the same candidates,
		// and do not repeat the preparation phases.
		words, *depth, *calibN = state.Words, state.MaxDepth, state.CalibN
		*noMine, *noTechMine, *crawl = true, true, false
		fmt.Fprintf(os.Stderr, "hellhound: resuming from %s — %d director(ies) already done, %d queued, %d finding(s) so far (wordlist, -ext, -depth and -calibrate are taken from the saved scan)\n",
			*resumeFile, state.Checkpoint.DirsDone, len(state.Checkpoint.Pending), len(state.Checkpoint.Results))
	}
	// Words taken from the target itself (sitemap, robots.txt, links) are
	// expected to exist; the discoverer keeps them out of its "implausibly
	// high hit rate" alarm.
	expected := map[string]bool{}
	// known holds pages the site itself publishes (sitemap, crawled links).
	// Fuzzing confirms them too, but they are not discoveries, so they are
	// kept out of the findings list unless -show-known is set.
	known := map[string]bool{}
	markExpected := func(before, after []string) {
		had := make(map[string]bool, len(before))
		for _, w := range before {
			had[w] = true
		}
		for _, w := range after {
			if !had[w] {
				expected[w] = true
			}
		}
	}
	if !*noMine {
		fmt.Fprintf(os.Stderr, "hellhound: mining robots.txt + sitemap.xml + homepage + linked JS for target-derived words...\n")
		var ms discover.MineStats
		words, ms = discover.BuildWordlistStats(scanCtx, eng, baseURL, seed)
		markExpected(seed, words)
		origin := baseURL
		if u, err := url.Parse(baseURL); err == nil {
			origin = u.Scheme + "://" + u.Host
		}
		for _, p := range append(append([]string(nil), ms.SitemapPaths...), ms.HomeLinks...) {
			known[knownKey(origin+p)] = true
		}
		if extra := len(words) - len(seed); extra > 0 {
			fmt.Fprintf(os.Stderr, "hellhound: mined %d additional word(s) from the target itself\n", extra)
		}
		if len(ms.Failed) > 0 && scanCtx.Err() == nil {
			fmt.Fprintf(os.Stderr, "hellhound: warning: could not read %s — the target may be blocking or throttling this client, so fewer words were mined and tech detection may miss the stack\n", strings.Join(ms.Failed, ", "))
		}
	}

	// Tech fingerprinting + smart wordlist injection. One homepage fetch,
	// then zero further cost — the detected stacks' curated path lists just
	// merge into the wordlist the main fuzz loop will use.
	var detectedTechs []discover.Tech
	if scanCtx.Err() == nil && !*noTechMine {
		detectedTechs = discover.DetectTech(scanCtx, eng, baseURL)
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
	if state != nil {
		crawlResults = state.Crawl
	}
	if scanCtx.Err() == nil && *crawl {
		crawlResults = runCrawl(scanCtx, eng, baseURL, *crawlDepth, *crawlMax, *crawlSimilar, *showAssets, renderer)
		if cw := discover.WordsFromCrawl(crawlResults); len(cw) > 0 {
			before := len(words)
			prev := words
			words = wordlist.Merge(words, cw)
			markExpected(prev, words)
			if added := len(words) - before; added > 0 {
				fmt.Fprintf(os.Stderr, "hellhound: crawl contributed %d new fuzz word(s)\n", added)
			}
		}
	}

	for _, c := range crawlResults {
		known[knownKey(c.URL)] = true
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
	if state != nil {
		exts = state.Extensions
	}

	// The root sensitive-file probes run before fuzzing: they are the most
	// valuable checks, cost about sixty requests, and must not be lost if
	// the long fuzzing phase is interrupted.
	var rootSens []discover.SecurityFinding
	if !*noSecurity && scanCtx.Err() == nil {
		rootSens = discover.ScanSensitive(scanCtx, eng, baseURL)
	}

	opts := discover.Options{
		BaseURL:      baseURL,
		Wordlist:     words,
		CalibrationN: *calibN,
		MaxDepth:     *depth,
		Extensions:   exts,
		MatchCodes:   mcSet,
		FilterCodes:  fcSet,
		FilterSizes:  fsSet,
		Expected:     expected,
		Home:         discover.SnapshotHome(pre[0]),
		OnProgress:   prog.Update,
		OnWarning: func(dir string, err error) {
			prog.Println("hellhound: warning: scanning %s: %s (continuing)", report.Clean(dir), report.Clean(err.Error()))
		},
	}
	stateFailed := false
	opts.OnCheckpoint = func(cp discover.Checkpoint) {
		prog.DirDone(len(cp.Results))
		if *resumeFile == "" || stateFailed {
			return
		}
		st := &scanState{Target: baseURL, Words: words, Extensions: exts, MaxDepth: *depth, CalibN: *calibN, Crawl: crawlResults, Checkpoint: cp}
		if err := saveState(*resumeFile, st); err != nil {
			stateFailed = true
			prog.Println("hellhound: warning: could not save resume state to %s: %v (the scan continues, but cannot be resumed)", *resumeFile, err)
		}
	}
	if state != nil {
		opts.Resume = &state.Checkpoint
	}
	d := discover.New(eng, opts)

	fmt.Fprintf(os.Stderr, "hellhound: calibrating + scanning %s with %d words x %d extensions (depth=%d, concurrency=%d)\n",
		*target, len(words), len(exts), *depth, *concurrency)

	start := time.Now()
	results, err := d.Run(scanCtx, "/")
	prog.Clear()
	if err != nil {
		fmt.Fprintf(os.Stderr, "hellhound: error: %v\n", err)
		os.Exit(1)
	}
	interrupted := ctx.Err() != nil
	timedOut := !interrupted && scanCtx.Err() != nil
	if interrupted || timedOut {
		why := "interrupted"
		if timedOut {
			why = fmt.Sprintf("reached -max-time %s", *maxTime)
		}
		fmt.Fprintf(os.Stderr, "hellhound: %s after %s, sent %d requests — showing partial results below\n",
			why, time.Since(start).Round(time.Millisecond), eng.Sent.Load())
		if *resumeFile != "" && !stateFailed {
			fmt.Fprintf(os.Stderr, "hellhound: progress is saved in %s — run the same command again to continue from the last completed directory\n", *resumeFile)
		} else if *resumeFile == "" {
			fmt.Fprintln(os.Stderr, "hellhound: tip: add -resume <file> to be able to continue an interrupted scan")
		}
		fmt.Fprintln(os.Stderr)
	} else {
		if *resumeFile != "" {
			os.Remove(*resumeFile) // finished: nothing left to resume
		}
		fmt.Fprintf(os.Stderr, "hellhound: done in %s, sent %d requests (%d backoff pauses)\n\n",
			time.Since(start).Round(time.Millisecond), eng.Sent.Load(), eng.Backoffs.Load())
	}
	if n := eng.Throttles.Load(); n > 0 {
		fmt.Fprintf(os.Stderr, "hellhound: slowed down %d time(s) because the target was timing out; finished at %d request(s)/sec\n", n, eng.RatePerSec())
	}

	if d.Blocked() {
		fmt.Fprintln(os.Stderr, "hellhound: warning: the target's firewall blocked part of this scan, so the results below are INCOMPLETE — wait a while and re-run with a lower -rate (e.g. -rate 3 -c 2) to cover the rest")
	}

	listed := results
	if !*showKnown {
		listed = results[:0:0]
		hidden := 0
		for _, r := range results {
			if isKnown(known, expected, baseURL, r) {
				hidden++
				continue
			}
			listed = append(listed, r)
		}
		if hidden > 0 {
			fmt.Fprintf(os.Stderr, "hellhound: %d hit(s) are pages or assets the site already links to (sitemap, crawl, homepage) — not listed as findings; add -show-known to include them\n", hidden)
		}
	}
	rep := report.Build(*target, listed)

	// Tier-A security phases. Each one is independent and skippable; the
	// combined findings land in the same report so stdout/CSV/SARIF all
	// surface them uniformly. These phases DO issue extra requests (sensitive
	// probes + per-discovered-endpoint OPTIONS + per-redirect-param probe), so
	// -no-security turns the whole thing off for a pure discovery run.
	// Both fuzz-discovered AND crawl-discovered URLs are classified — a page
	// reached only by following a link still deserves open-redirect/method
	// checks and still leaks headers worth capturing.
	if !*noSecurity {
		allResults := append([]discover.Result{}, results...)
		allResults = append(allResults, discover.AsResults(crawlResults)...)
		rep.SecurityFindings = report.CleanFindings(runSecurityScans(ctx, eng, baseURL, allResults, rootSens, interrupted))
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

	if n := eng.Blocked.Load(); n > 0 {
		fmt.Fprintf(os.Stderr, "hellhound: %d request(s) were not sent because they fell outside the allowed scope\n", n)
	}
	if interrupted {
		// Partial results were printed and written, but the scan did not
		// finish: exit like any interrupted program so scripts and CI do
		// not mistake it for a completed run.
		os.Exit(130)
	}
}

// runSecurityScans runs every Tier-A detector concurrently and merges the
// findings. Order of lines in stderr is not critical; findings land in the
// returned slice with their severities intact so the reporter can sort.
//
// rootSens are the sensitive-file findings at the root, probed before
// fuzzing. When passiveOnly is set (the user interrupted the scan), no new
// requests are sent: only the checks that work on what was already
// captured run, so Ctrl+C still yields a security section without the tool
// continuing to touch a target the user asked it to stop on.
func runSecurityScans(ctx context.Context, eng *engine.Engine, baseURL string, results []discover.Result, rootSens []discover.SecurityFinding, passiveOnly bool) []discover.SecurityFinding {
	start := time.Now()
	if passiveOnly {
		fmt.Fprintf(os.Stderr, "\nhellhound: interrupted — running only the security checks that need no further requests (dir listings, info-disclosure headers); sensitive files were checked at the root before fuzzing\n")
	} else {
		fmt.Fprintf(os.Stderr, "\nhellhound: running Tier-A security checks (sensitive files, dir listings, dangerous methods, open-redirect, info-disclosure)...\n")
	}

	findings := append([]discover.SecurityFinding{}, rootSens...)

	// Dir-listing and info-disclosure use already-captured bodies/headers.
	findings = append(findings, discover.ClassifyDirListings(results)...)
	findings = append(findings, discover.CaptureInfoDisclosure(results)...)
	if passiveOnly {
		fmt.Fprintf(os.Stderr, "hellhound: security checks done in %s — %d finding(s)\n", time.Since(start).Round(time.Millisecond), len(findings))
		return findings
	}

	// Sensitive-file probes in the discovered directories (the root was
	// probed before fuzzing).
	fmt.Fprintf(os.Stderr, "hellhound: security: probing sensitive files in discovered directories...\n")
	sens, skipped := discover.ScanSensitiveIn(ctx, eng, baseURL, results, false)
	findings = append(findings, sens...)
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "hellhound: sensitive-file probes ran at the root and the first 10 discovered directories; %d more directories were not probed\n", skipped)
	}

	// 4) Dangerous HTTP methods (one OPTIONS per unique discovered URL).
	urls := make([]string, 0, len(results))
	for _, r := range results {
		if r.Status >= 200 && r.Status < 400 {
			urls = append(urls, r.URL)
		}
	}
	if ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "hellhound: security: checking HTTP methods on %d URL(s)...\n", len(urls))
	}
	findings = append(findings, discover.ScanDangerousMethods(ctx, eng, urls)...)

	// 5) Open-redirect classification (probes any discovered URL carrying a
	// redirect-shaped parameter — most discovered URLs have no query string,
	// so the extra request volume is small).
	findings = append(findings, discover.ScanOpenRedirects(ctx, eng, urls)...)

	// 6) Test/staging/backup copies of the site (/test/, /staging/, /old/).
	findings = append(findings, discover.ScanExposedCopies(ctx, eng, baseURL, results)...)

	fmt.Fprintf(os.Stderr, "hellhound: security checks done in %s — %d finding(s)\n", time.Since(start).Round(time.Millisecond), len(findings))
	return findings
}

// knownKey normalizes a URL for the known-pages set: no trailing slash,
// no query or fragment.
func knownKey(rawURL string) string {
	if i := strings.IndexAny(rawURL, "?#"); i >= 0 {
		rawURL = rawURL[:i]
	}
	return strings.TrimRight(rawURL, "/")
}

// isKnown reports whether a fuzzing hit is a page the site already
// publishes (its sitemap or a crawled link), or a static asset whose name
// was mined from the site's own pages: confirmed, but not a discovery.
func isKnown(known, expected map[string]bool, baseURL string, r discover.Result) bool {
	if known[knownKey(r.URL)] {
		return true
	}
	p := strings.TrimPrefix(knownKey(r.URL), baseURL)
	if r.Status < 200 || r.Status >= 300 {
		return false
	}
	return standardPublicFiles[p] || (discover.IsStaticAsset(p) && expected[strings.TrimPrefix(p, "/")])
}

// standardPublicFiles exist on most sites by convention and are meant to be
// public; finding them is not a discovery.
var standardPublicFiles = map[string]bool{
	"/robots.txt": true, "/sitemap.xml": true, "/favicon.ico": true,
	"/site.webmanifest": true, "/manifest.json": true, "/apple-touch-icon.png": true,
}

// errUnwrapPath returns the error from stat-ing path (nil if it exists).
func errUnwrapPath(path string) error {
	_, err := os.Stat(path)
	return err
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
			// Many servers never answer a POST to a path they do not have.
			// Waiting the full timeout for each of those wastes the run's
			// last half minute and trips auto-throttle for no reason.
			Timeout: 3 * time.Second,
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
func runCrawl(ctx context.Context, eng *engine.Engine, baseURL string, depth, maxPages, maxSimilar int, showAssets bool, render discover.Renderer) []discover.CrawlResult {
	start := time.Now()
	fmt.Fprintf(os.Stderr, "\nhellhound: crawling %s for linked pages (max depth %d, max %d pages)...\n", baseURL, depth, maxPages)
	renderErrs := 0
	results, stats := discover.CrawlOpts(ctx, eng, baseURL, discover.CrawlConfig{
		MaxDepth: depth, MaxPages: maxPages, Render: render, MaxSimilar: maxSimilar,
		OnRenderError: func(pageURL string, err error) {
			if renderErrs++; renderErrs <= 3 {
				fmt.Fprintf(os.Stderr, "hellhound: warning: could not render %s: %s\n", report.Clean(pageURL), report.Clean(err.Error()))
			}
		},
	})
	if renderErrs > 3 {
		fmt.Fprintf(os.Stderr, "hellhound: warning: %d more page(s) could not be rendered\n", renderErrs-3)
	}
	if len(results) == 0 {
		fmt.Println("\n[crawl] no additional linked pages found")
	} else {
		var pages []discover.CrawlResult
		assets := map[string]int{}
		nAssets := 0
		for _, r := range results {
			if kind := assetKind(r.URL); kind != "" && !showAssets {
				assets[kind]++
				nAssets++
				continue
			}
			pages = append(pages, r)
		}
		fmt.Printf("\n[crawl] %d linked page(s) found by following links:\n", len(pages))
		for _, r := range pages {
			fmt.Printf("    [%d] (depth %d) %s\n", r.Status, r.Depth, report.Clean(r.URL))
		}
		if nAssets > 0 {
			kinds := make([]string, 0, len(assets))
			for k := range assets {
				kinds = append(kinds, k)
			}
			sort.Strings(kinds)
			parts := make([]string, len(kinds))
			for i, k := range kinds {
				parts[i] = fmt.Sprintf("%s %d", k, assets[k])
			}
			fmt.Printf("    + %d static asset(s) not listed (%s) — add -show-assets to list them\n", nAssets, strings.Join(parts, ", "))
		}
		if len(stats.Capped) > 0 {
			pats := make([]string, 0, len(stats.Capped))
			for p := range stats.Capped {
				pats = append(pats, p)
			}
			sort.Strings(pats)
			for _, p := range pats {
				fmt.Printf("    + %d more link(s) like %s not followed (limit %d per pattern; raise -crawl-similar to follow them)\n", stats.Capped[p], report.Clean(p), maxSimilar)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "hellhound: crawl done in %s\n", time.Since(start).Round(time.Millisecond))
	return results
}

// assetKind classifies a static asset URL by extension ("" for pages).
func assetKind(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	ext := strings.ToLower(path.Ext(u.Path))
	switch ext {
	case ".js", ".mjs", ".map":
		return "js"
	case ".css":
		return "css"
	case ".woff", ".woff2", ".ttf", ".otf", ".eot":
		return "font"
	case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif", ".bmp":
		return "image"
	case ".webmanifest", ".mp4", ".webm", ".mp3", ".wav":
		return "media/other"
	}
	return ""
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

// hostOf returns the lowercase host:port of a URL ("" if it has none).
func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}

// loadScope reads a scope file and checks that the target itself is in it —
// a scope that excludes the target would otherwise "scan" by sending nothing.
func loadScope(path, baseURL string) (*scope.Scope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read -scope file: %v", err)
	}
	defer f.Close()
	sc, err := scope.Parse(f)
	if err != nil {
		return nil, fmt.Errorf("-scope %s: %v", path, err)
	}
	if !sc.Allows(baseURL + "/") {
		if why := sc.Blocker(baseURL + "/"); why != "" {
			return nil, fmt.Errorf("the target %s is excluded by scope rule %q in %s", baseURL, why, path)
		}
		return nil, fmt.Errorf("the target %s is not covered by any rule in %s", baseURL, path)
	}
	return sc, nil
}

// newRenderer prepares page rendering through a local headless browser.
func newRenderer(browser, proxy string, insecure bool, timeout time.Duration, hasHeaders bool) (discover.Renderer, error) {
	if os.Geteuid() == 0 {
		return nil, fmt.Errorf("-render cannot be used as root: Chrome's sandbox does not run as root, and rendering untrusted pages without it is unsafe — run hellhound as a normal user")
	}
	path, err := render.Find(browser)
	if err != nil {
		return nil, fmt.Errorf("-render: %v", err)
	}
	fmt.Fprintf(os.Stderr, "hellhound: rendering pages with %s (confined to the target host)\n", path)
	if hasHeaders {
		fmt.Fprintln(os.Stderr, "hellhound: note: the browser does not send -H headers, so pages are rendered as an anonymous visitor; the crawler's own requests still carry them")
	}
	c := &render.Chrome{Path: path, Timeout: timeout + 20*time.Second, Proxy: proxy, Insecure: insecure, UserAgent: "hellhound/" + banner.Version + " (+authorized-testing; headless)"}
	return c.DOM, nil
}
