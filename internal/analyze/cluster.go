package analyze

import "sort"

// Finding is one interesting (post-calibration) result, enriched with the
// verdict that produced it.
type Finding struct {
	URL     string
	Status  int
	Length  int
	Words   int
	Lines   int
	Verdict Verdict
}

// Cluster groups findings whose bodies are near-identical (same ClusterKey
// family within simThreshold). This is what prevents a paginated or
// templated section of a site from flooding the report with duplicates:
// e.g. 200 blog posts sharing a template become one cluster with 200
// members instead of 200 separate "look at this" lines.
type Cluster struct {
	Representative Finding
	Members        []Finding
}

// ClusterFindings groups findings by approximate body shape. Greedy
// clustering: for each finding, join the first existing cluster with a
// matching Status AND within simThreshold Hamming distance of its key, else
// start a new cluster. O(n*k) where k is the number of clusters so far,
// fine at content-discovery scale.
//
// Status equality is required, not just a similar body: a 500 error page
// and a 200 response can share nearly identical HTML chrome (same
// nav/footer template) while meaning something completely different. An
// earlier version clustered on body shape alone, which could silently bury
// a real error as "+1 similar" under an unrelated 200 representative —
// exactly the kind of signal a security review can't afford to lose.
func ClusterFindings(findings []Finding) []Cluster {
	var clusters []Cluster
	for _, f := range findings {
		placed := false
		for i := range clusters {
			if clusters[i].Representative.Status != f.Status {
				continue
			}
			if Hamming(clusters[i].Representative.Verdict.ClusterKey, f.Verdict.ClusterKey) <= simThreshold {
				clusters[i].Members = append(clusters[i].Members, f)
				placed = true
				break
			}
		}
		if !placed {
			clusters = append(clusters, Cluster{Representative: f, Members: []Finding{f}})
		}
	}
	sort.SliceStable(clusters, func(i, j int) bool {
		return len(clusters[i].Members) > len(clusters[j].Members)
	})
	return clusters
}
