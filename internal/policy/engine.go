package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
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
	digest    string
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

// Evaluate applies default-deny with deny-overrides semantics. It is pure: no
// I/O, no clock, no mutation. The result is independent of rule order.
//
//   - No rule matches            -> deny (reason: no_matching_policy)
//   - Any matching deny          -> deny (reason: explicit_deny or deny_overrides)
//   - One or more allows, no deny -> allow (reason: explicit_allow)
func (s *Snapshot) Evaluate(req Request) Decision {
	effective := s.effectiveGroups(req.Groups)

	var allows, denies []string
	for i := range s.rules {
		r := &s.rules[i]
		if !groupsMatch(r.Groups, effective) || !toolMatch(r.Tools, req.Tool) {
			continue
		}
		if r.Effect == Deny {
			denies = append(denies, r.ID)
		} else {
			allows = append(allows, r.ID)
		}
	}

	switch {
	case len(denies) > 0:
		reason := ReasonExplicitDeny
		if len(allows) > 0 {
			reason = ReasonDenyOverrides
		}
		return Decision{
			Effect:        Deny,
			Allowed:       false,
			Reason:        reason,
			MatchedAllows: allows,
			MatchedDenies: denies,
			PolicyDigest:  s.digest,
		}
	case len(allows) > 0:
		return Decision{
			Effect:        Allow,
			Allowed:       true,
			Reason:        ReasonExplicitAllow,
			MatchedAllows: allows,
			PolicyDigest:  s.digest,
		}
	default:
		return Decision{
			Effect:       s.defaults.Effect,
			Allowed:      s.defaults.Effect == Allow,
			Reason:       ReasonNoMatchingPolicy,
			PolicyDigest: s.digest,
		}
	}
}

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

// groupsMatch reports whether any rule group is present in the caller's
// effective group set.
func groupsMatch(ruleGroups []string, effective map[string]bool) bool {
	for _, rg := range ruleGroups {
		if effective[rg] {
			return true
		}
	}
	return false
}

// toolMatch supports exact names, a namespace wildcard ("github.*"), and the
// full wildcard ("*"). No regex or general globbing, keeping matching boring
// and reviewable.
func toolMatch(ruleTools []string, tool string) bool {
	for _, rt := range ruleTools {
		switch {
		case rt == "*" || rt == tool:
			return true
		case strings.HasSuffix(rt, ".*"):
			ns := strings.TrimSuffix(rt, ".*")
			if strings.HasPrefix(tool, ns+".") {
				return true
			}
		}
	}
	return false
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
