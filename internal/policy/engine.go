package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// Snapshot is an immutable, validated policy set ready for evaluation.
// It is safe for concurrent reads. A hot-reload design (not built in this
// take-home) would construct a new Snapshot and swap the pointer atomically, so
// an in-flight request always sees one coherent version.
type Snapshot struct {
	defaults Defaults
	rules    []Rule
	// ancestors maps each defined group to its transitive set of parent groups
	// (excluding itself), sorted. Empty when no hierarchy is configured.
	ancestors map[string][]string
	// index is the inverted (bitset) index the evaluator runs on. It is built by
	// the loader for every Snapshot returned from Load/Parse.
	index  *ruleIndex
	digest string
}

// Digest returns the SHA-256 digest of the canonical policy. It is recorded on
// every decision so a reviewer can retrieve the exact rule set later and
// reproduce the result.
func (s *Snapshot) Digest() string { return s.digest }

// Rules returns a copy of the compiled rules, for tooling such as the linter.
func (s *Snapshot) Rules() []Rule {
	out := make([]Rule, len(s.rules))
	copy(out, s.rules)
	return out
}

// DefaultEffect returns the configured default effect.
func (s *Snapshot) DefaultEffect() Effect { return s.defaults.Effect }

// effectiveGroups expands the caller's groups with everything they inherit
// through the hierarchy. The result is a set (deduplicated). With no hierarchy
// configured it is simply the caller's own groups.
func (s *Snapshot) effectiveGroups(callerGroups []string) map[string]bool {
	eff := make(map[string]bool, len(callerGroups))
	for _, g := range callerGroups {
		if eff[g] {
			continue
		}
		eff[g] = true
		for _, a := range s.ancestors[g] {
			eff[a] = true
		}
	}
	return eff
}

// EffectiveGroups returns the caller's effective groups (own + inherited) as a
// sorted slice. Exposed for tooling and audit/debugging.
func (s *Snapshot) EffectiveGroups(callerGroups []string) []string {
	set := s.effectiveGroups(callerGroups)
	out := make([]string, 0, len(set))
	for g := range set {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// computeDigest hashes a canonical form of the policy so that semantically
// identical policies (differing only in ordering) produce the same digest.
func computeDigest(defaults Defaults, groups []GroupDef, rules []Rule) string {
	canon := make([]Rule, len(rules))
	copy(canon, rules)
	for i := range canon {
		g := append([]string(nil), canon[i].Groups...)
		t := append([]string(nil), canon[i].Tools...)
		sort.Strings(g)
		sort.Strings(t)
		canon[i].Groups = g
		canon[i].Tools = t
	}
	sort.Slice(canon, func(i, j int) bool { return canon[i].ID < canon[j].ID })

	canonGroups := make([]GroupDef, len(groups))
	copy(canonGroups, groups)
	for i := range canonGroups {
		p := append([]string(nil), canonGroups[i].Parents...)
		sort.Strings(p)
		canonGroups[i].Parents = p
	}
	sort.Slice(canonGroups, func(i, j int) bool { return canonGroups[i].Name < canonGroups[j].Name })

	payload := struct {
		Defaults Defaults   `json:"defaults"`
		Groups   []GroupDef `json:"groups"`
		Rules    []Rule     `json:"rules"`
	}{defaults, canonGroups, canon}
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
