package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/securewithharshitrajput/hellhound/internal/discover"
)

// stateVersion is bumped whenever the saved format changes incompatibly.
const stateVersion = 1

// scanState is what -resume saves after every completed directory and
// loads to continue a scan: the exact inputs the scan was started with
// (so the continuation tests the same candidates), the crawl results that
// feed the later phases, and the discovery checkpoint.
type scanState struct {
	Version    int                    `json:"version"`
	Tool       string                 `json:"tool"`
	Target     string                 `json:"target"`
	Words      []string               `json:"words"`
	Extensions []string               `json:"extensions"`
	MaxDepth   int                    `json:"max_depth"`
	CalibN     int                    `json:"calibrate"`
	Crawl      []discover.CrawlResult `json:"crawl,omitempty"`
	Checkpoint discover.Checkpoint    `json:"checkpoint"`
}

// loadState reads a state file. A missing file is not an error: it returns
// (nil, nil) and the scan starts fresh, creating the file as it goes.
func loadState(path, target string) (*scanState, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read -resume file: %v", err)
	}
	var st scanState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("-resume file %s is not a hellhound state file: %v", path, err)
	}
	switch {
	case st.Tool != "hellhound" || st.Version != stateVersion:
		return nil, fmt.Errorf("-resume file %s was written by an incompatible version; delete it to start over", path)
	case st.Target != target:
		return nil, fmt.Errorf("-resume file %s belongs to a scan of %s, not %s", path, st.Target, target)
	case len(st.Words) == 0:
		return nil, fmt.Errorf("-resume file %s has no wordlist; delete it to start over", path)
	}
	return &st, nil
}

// saveState writes the state atomically (temp file + rename), so an
// interrupt or crash mid-write can never leave a truncated state file.
func saveState(path string, st *scanState) error {
	st.Version, st.Tool = stateVersion, "hellhound"
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".hellhound-state-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}
