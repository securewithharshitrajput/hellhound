// Virtual-host discovery: hit one IP/port with many candidate Host
// headers to find vhosts that aren't in DNS — internal admin panels,
// staging environments, or anything else reachable on the same box but
// only exposed to a name nobody outside would know to try. ffuf supports
// this via -H "Host: FUZZ", but the operator has to notice and filter the
// default-vhost noise themselves; this reuses the same calibrated-baseline
// machinery as path discovery, automatically.
package discover

import (
	"context"

	"github.com/securewithharshitrajput/hellhound/internal/analyze"
	"github.com/securewithharshitrajput/hellhound/internal/engine"
)

// VHostResult is one candidate hostname whose response differed from the
// calibrated "unrecognized Host header" baseline.
type VHostResult struct {
	Host   string
	Status int
	Length int
	Reason string
}

// VHostScan probes targetURL (an IP or base URL whose DNS name you already
// know) once per candidate, overriding the Host header each time. It first
// calibrates against calibrationN random, almost-certainly-unregistered
// hostnames — exactly the same soft-404 idea as path discovery, applied to
// Host headers: a server that returns its default vhost for anything
// unrecognized shouldn't flood the result with one line per candidate.
func VHostScan(ctx context.Context, eng *engine.Engine, targetURL string, candidates []string, calibrationN int) []VHostResult {
	cal := analyze.NewCalibrator()

	probeReqs := make([]engine.Request, calibrationN)
	tokens := make([]string, calibrationN)
	for i := range probeReqs {
		tok := analyze.RandomToken() + ".invalid"
		tokens[i] = tok
		probeReqs[i] = engine.Request{Method: "GET", URL: targetURL, HostOverride: tok}
	}
	probeResps := eng.DoAll(ctx, probeReqs)
	probes := make([]analyze.Probe, len(probeResps))
	for i, r := range probeResps {
		probes[i] = analyze.Probe{Token: tokens[i], Resp: r}
	}
	const vhostBaselineKey = "vhost"
	cal.Learn(vhostBaselineKey, probes)

	reqs := make([]engine.Request, len(candidates))
	for i, host := range candidates {
		reqs[i] = engine.Request{Method: "GET", URL: targetURL, HostOverride: host}
	}
	resps := eng.DoAll(ctx, reqs)

	var out []VHostResult
	for i, resp := range resps {
		host := candidates[i]
		v := cal.Classify(vhostBaselineKey, host, resp)
		if !v.Interesting {
			continue
		}
		out = append(out, VHostResult{Host: host, Status: resp.Status, Length: resp.Length, Reason: v.Reason})
	}
	return out
}
