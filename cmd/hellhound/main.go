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
	"context"
	"flag"
	"fmt"
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
	h[strings.TrimSpace(k)] = strings.TrimSpace(val)
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
		jsonOut      = flag.String("json", "", "write full JSON report to this path")
		timeout      = flag.Duration("timeout", 10*time.Second, "per-request timeout")
		insecure     = flag.Bool("k", false, "skip TLS certificate verification (only for authorized testing of a target with a self-signed/dev cert)")
		noMine       = flag.Bool("no-mine", false, "skip mining robots.txt/homepage/JS for target-derived wordlist words")
		maxBodyKB    = flag.Int("maxbody", 512, "max response body size to read, in KB (raise this if a large OpenAPI/GraphQL spec is being truncated)")
		vhostFile    = flag.String("vhosts", "", "candidate-hostnames file for virtual-host discovery against -u (one hostname per line); runs in addition to content discovery")
		noBanner     = flag.Bool("no-banner", false, "suppress the startup banner")
	)
	flag.Var(headers, "H", `custom header, repeatable, format "Name: value" (e.g. -H "Authorization: Bearer xyz")`)
	flag.Parse()

	banner.Print(*noBanner)

	if *target == "" {
		fmt.Fprintln(os.Stderr, "usage: hellhound -u http://target [-w wordlist.txt] [-H \"Name: value\"] [-k] [-depth 2] [-ext .bak,.old] [-json out.json]")
		fmt.Fprintln(os.Stderr, "\nFor authorized security testing only — only point this at targets you are authorized to test.")
		os.Exit(2)
	}
	baseURL := strings.TrimRight(*target, "/")

	cfg := engine.DefaultConfig()
	cfg.Concurrency = *concurrency
	cfg.Timeout = *timeout
	cfg.InsecureSkipVerify = *insecure
	cfg.DefaultHeaders = headers
	cfg.MaxBodyBytes = int64(*maxBodyKB) * 1024
	eng := engine.New(cfg)
	defer eng.Close() // not load-bearing for a one-shot process (the OS reclaims everything on exit), but correct practice and free

	// A plain context.Background() here would mean Ctrl+C just kills the
	// process outright — no partial results, no cleanup, matching neither
	// ffuf's nor katana's behavior (both print what they have so far on
	// interrupt). signal.NotifyContext cancels ctx on SIGINT/SIGTERM instead;
	// Engine and Discoverer already check ctx.Done() throughout, so an
	// in-progress scan winds down and whatever was found before the
	// interrupt still gets reported below.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	seed := wordlist.Merge(wordlist.Seed, loadWordlistFile(*wordlistPath))
	words := seed
	if !*noMine {
		fmt.Fprintf(os.Stderr, "hellhound: mining robots.txt + homepage + linked JS for target-derived words...\n")
		words = discover.BuildWordlist(ctx, eng, baseURL, seed)
		if extra := len(words) - len(seed); extra > 0 {
			fmt.Fprintf(os.Stderr, "hellhound: mined %d additional word(s) from the target itself\n", extra)
		}
	}

	exts := []string{""}
	if *extStr != "" {
		for _, e := range strings.Split(*extStr, ",") {
			e = strings.TrimSpace(e)
			if e != "" {
				exts = append(exts, e)
			}
		}
	}

	d := discover.New(eng, discover.Options{
		BaseURL:      baseURL,
		Wordlist:     words,
		CalibrationN: *calibN,
		MaxDepth:     *depth,
		Extensions:   exts,
		OnWarning: func(dir string, err error) {
			fmt.Fprintf(os.Stderr, "hellhound: warning: scanning %s: %v (continuing)\n", dir, err)
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
	report.WriteSummary(os.Stdout, rep)

	if ctx.Err() == nil {
		runAPIDiscovery(ctx, eng, baseURL)
	}

	if ctx.Err() == nil && *vhostFile != "" {
		runVHostScan(ctx, eng, baseURL, *vhostFile, *calibN)
	}

	if *jsonOut != "" {
		f, err := os.Create(*jsonOut)
		if err != nil {
			fmt.Fprintf(os.Stderr, "hellhound: could not write JSON report: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		if err := report.WriteJSON(f, rep); err != nil {
			fmt.Fprintf(os.Stderr, "hellhound: error encoding JSON report: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "\nhellhound: wrote full JSON report to %s\n", *jsonOut)
	}
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
				fmt.Printf("    %-7s %s\n", r.Method, r.Path)
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
				fmt.Printf("    %s.%s\n", f.ParentType, f.Field)
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
		fmt.Printf("    %-40s [%d] len=%d  %s\n", r.Host, r.Status, r.Length, r.Reason)
	}
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
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}
