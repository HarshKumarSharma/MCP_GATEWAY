package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// Snapshot is an immutable, validated policy set ready for evaluation.
// It is safe for concurrent reads; reloads construct a new Snapshot and swap
// the pointer atomically (see the gateway wiring), so an in-flight request
// always sees one coherent version.
type Snapshot struct {
	defaults Defaults
	rules    []Rule
	digest   string
}

// Digest returns the SHA-256 digest of the canonical policy. It is recorded on
// every decision so a reviewer can retrieve the exact rule set later and
// reproduce the result.
func (s *Snapshot) Digest() string { return s.digest }

// Evaluate applies default-deny with deny-overrides semantics. It is pure: no
// I/O, no clock, no mutation. The result is independent of rule order.
//
//   - No rule matches            -> deny (reason: no_matching_policy)
//   - Any matching deny          -> deny (reason: explicit_deny or deny_overrides)
//   - One or more allows, no deny -> allow (reason: explicit_allow)
func (s *Snapshot) Evaluate(req Request) Decision {
	var allows, denies []string
	for i := range s.rules {
		r := &s.rules[i]
		if !groupsMatch(r.Groups, req.Groups) || !toolMatch(r.Tools, req.Tool) {
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

// groupsMatch reports whether any rule group is one of the caller's groups.
func groupsMatch(ruleGroups, callerGroups []string) bool {
	for _, rg := range ruleGroups {
		for _, g := range callerGroups {
			if rg == g {
				return true
			}
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
func computeDigest(defaults Defaults, rules []Rule) string {
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

	payload := struct {
		Defaults Defaults `json:"defaults"`
		Rules    []Rule   `json:"rules"`
	}{defaults, canon}
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
