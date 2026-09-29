package policy

import "strings"

// ruleIndex is an inverted index over the rule set: each attribute value maps to
// the bitset of rules that mention it. It is built once per immutable Snapshot
// and read concurrently without locking.
//
// Evaluation becomes:
//
//	candidates = (⋃ groupRules[g] for effective groups g)   // OR
//	           ∩ (toolExact[t] ∪ ⋃ nsRules[prefix] ∪ star)  // OR, then AND
//	deny  = candidates ∩ denyMask
//	allow = candidates ∩ allowMask
//
// which mirrors the "bit vector" packet-classification technique used by
// software firewalls, applied to (group × tool).
type ruleIndex struct {
	numRules   int
	groupRules map[string]bitset // group name  -> rules naming it
	toolExact  map[string]bitset // exact tool  -> rules naming it
	nsRules    map[string]bitset // "github" (from "github.*") -> rules
	starRules  bitset            // rules with the "*" tool
	allowMask  bitset            // all allow rules
	denyMask   bitset            // all deny rules
}

func buildIndex(rules []Rule) *ruleIndex {
	n := len(rules)
	idx := &ruleIndex{
		numRules:   n,
		groupRules: make(map[string]bitset),
		toolExact:  make(map[string]bitset),
		nsRules:    make(map[string]bitset),
		starRules:  newBitset(n),
		allowMask:  newBitset(n),
		denyMask:   newBitset(n),
	}
	for i := range rules {
		r := &rules[i]
		for _, g := range r.Groups {
			idx.bucket(idx.groupRules, g).set(i)
		}
		for _, t := range r.Tools {
			switch {
			case t == "*":
				idx.starRules.set(i)
			case strings.HasSuffix(t, ".*"):
				idx.bucket(idx.nsRules, strings.TrimSuffix(t, ".*")).set(i)
			default:
				idx.bucket(idx.toolExact, t).set(i)
			}
		}
		if r.Effect == Deny {
			idx.denyMask.set(i)
		} else {
			idx.allowMask.set(i)
		}
	}
	return idx
}

func (idx *ruleIndex) bucket(m map[string]bitset, key string) bitset {
	b, ok := m[key]
	if !ok {
		b = newBitset(idx.numRules)
		m[key] = b
	}
	return b
}

// toolPrefixes returns the segment prefixes of a tool name that a namespace
// wildcard could match. For "a.b.c" it returns ["a", "a.b"] — the keys under
// which rules "a.*" and "a.b.*" are indexed. A name with no dot matches no
// namespace wildcard (a "github.*" rule only matches "github.<something>").
func toolPrefixes(tool string) []string {
	var out []string
	for i := 0; i < len(tool); i++ {
		if tool[i] == '.' {
			out = append(out, tool[:i])
		}
	}
	return out
}

// Evaluate applies default-deny with deny-overrides semantics using the bitset
// index. It is pure: no I/O, no clock, no mutation, and independent of rule
// order.
//
//   - No rule matches             -> deny (reason: no_matching_policy)
//   - Any matching deny            -> deny (reason: explicit_deny or deny_overrides)
//   - One or more allows, no deny  -> allow (reason: explicit_allow)
//
// MatchedAllows / MatchedDenies are reported in ascending (file) order. A
// differential property test cross-checks this against an independent linear
// reference implementation.
func (s *Snapshot) Evaluate(req Request) Decision {
	idx := s.index
	eff := s.effectiveGroups(req.Groups)

	groupCand := newBitset(idx.numRules)
	for g := range eff {
		if bs, ok := idx.groupRules[g]; ok {
			groupCand.orWith(bs)
		}
	}

	toolCand := newBitset(idx.numRules)
	if bs, ok := idx.toolExact[req.Tool]; ok {
		toolCand.orWith(bs)
	}
	for _, p := range toolPrefixes(req.Tool) {
		if bs, ok := idx.nsRules[p]; ok {
			toolCand.orWith(bs)
		}
	}
	toolCand.orWith(idx.starRules)

	groupCand.andWith(toolCand) // groupCand is now the candidate set

	allows := groupCand.andClone(idx.allowMask).ids(s.rules)
	denies := groupCand.andClone(idx.denyMask).ids(s.rules)

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
