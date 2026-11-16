package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// profiles are named presets for the flags people otherwise retype on
// every engagement. A profile only supplies defaults: a config file
// overrides it, and anything given on the command line overrides both.
var profiles = map[string]map[string]string{
	// Root directory only, no recursion — a first look.
	"quick": {"depth": "0", "c": "60"},
	// Everything on: deeper recursion, crawling, a larger calibration sample.
	"deep": {"depth": "4", "crawl": "true", "crawl-depth": "5", "crawl-max": "2000", "calibrate": "8"},
	// Low and slow, for fragile or production targets where load matters.
	"gentle": {"c": "4", "rate": "8", "depth": "1", "timeout": "20s"},
}

func profileNames() string {
	names := make([]string, 0, len(profiles))
	for n := range profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// expandArgs resolves -profile and -config into ordinary arguments placed
// BEFORE the real command line, so one flag.Parse gives the right
// precedence for free: profile < config file < command line (a later
// occurrence of a flag wins, and for -H a later value replaces an earlier
// one for the same header name).
func expandArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	profile, config := scanFor(args, "profile"), scanFor(args, "config")
	var pre []string
	if profile != "" {
		vals, ok := profiles[profile]
		if !ok {
			return nil, fmt.Errorf("unknown -profile %q (available: %s)", profile, profileNames())
		}
		keys := make([]string, 0, len(vals))
		for k := range vals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			pre = append(pre, "-"+k+"="+vals[k])
		}
	}
	if config != "" {
		entries, err := readConfig(config)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if fs.Lookup(e.key) == nil {
				return nil, fmt.Errorf("%s: unknown option %q", config, e.key)
			}
			pre = append(pre, "-"+e.key+"="+e.val)
		}
	}
	return append(pre, args...), nil
}

// scanFor finds the value of a string flag in raw arguments, accepting
// -name value, -name=value and the double-dash forms, wherever it appears
// (hellhound takes no positional arguments). It stops at "--".
func scanFor(args []string, name string) string {
	val := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if !strings.HasPrefix(a, "-") {
			continue // the value of some other flag
		}
		a = strings.TrimLeft(a, "-")
		if k, v, ok := strings.Cut(a, "="); ok {
			if k == name {
				val = v
			}
			continue
		}
		if a == name && i+1 < len(args) {
			val = args[i+1]
			i++
		}
	}
	return val
}

type kv struct{ key, val string }

// readConfig parses a config file: one "name = value" per line, where name
// is a flag name with or without its leading dash. Blank lines and
// #-comments are ignored; a bare name means "true". -H may appear several
// times. "config" and "profile" cannot be set from inside a config file.
func readConfig(path string) ([]kv, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read -config file: %v", err)
	}
	defer f.Close()
	var out []kv
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\xef\xbb\xbf"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, hasVal := strings.Cut(line, "=")
		key = strings.TrimLeft(strings.TrimSpace(key), "-")
		val = strings.TrimSpace(val)
		if len(val) >= 2 && (val[0] == '"' && val[len(val)-1] == '"' || val[0] == '\'' && val[len(val)-1] == '\'') {
			val = val[1 : len(val)-1]
		}
		if key == "" || strings.ContainsAny(key, " \t") {
			return nil, fmt.Errorf("%s line %d: expected \"name = value\"", path, n)
		}
		if key == "config" || key == "profile" {
			return nil, fmt.Errorf("%s line %d: %q cannot be set in a config file", path, n, key)
		}
		if !hasVal {
			val = "true"
		}
		out = append(out, kv{key: key, val: val})
	}
	return out, sc.Err()
}

// parseIntSet parses a list such as "200,301-302,403" into a set. lo/hi
// bound the accepted values.
func parseIntSet(flagName, s string, lo, hi int) (map[int]bool, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	out := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		a, b, isRange := strings.Cut(part, "-")
		from, err := strconv.Atoi(strings.TrimSpace(a))
		to := from
		if err == nil && isRange {
			to, err = strconv.Atoi(strings.TrimSpace(b))
		}
		if err != nil || from < lo || to > hi || from > to {
			return nil, fmt.Errorf("%s: %q is not a value or range between %d and %d", flagName, part, lo, hi)
		}
		if to-from > 100000 {
			return nil, fmt.Errorf("%s: range %q is too large", flagName, part)
		}
		for v := from; v <= to; v++ {
			out[v] = true
		}
	}
	return out, nil
}
