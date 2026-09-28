package policy

import "strings"

// Finding is a single issue reported by the linter.
type Finding struct {
	Kind    string // "redundant", "shadowed_allow", "redundant_deny"
	Rule    string // primary rule ID the finding is about
	Related string // other rule ID involved, if any
	Message string
}

// Lint performs static analysis on a policy set, surfacing rules that are
// redundant or unreachable. This is analogous to firewall rule-base hygiene
// checks: a shadowed allow can silently break access, and redundant rules add
// review burden and drift risk. Lint never changes evaluation behavior.
func Lint(s *Snapshot) []Finding {
	rules := s.rules
	var out []Finding

	for i := range rules {
		a := &rules[i]

		// Redundant: fully covered by another rule of the SAME effect.
		for j := range rules {
			if i == j {
				continue
			}
			b := &rules[j]
			if a.Effect != b.Effect {
				continue
			}
			if !groupSubset(a.Groups, b.Groups) || !toolSubset(a.Tools, b.Tools) {
				continue
			}
			// If mutually covered (identical scope), report only the later one
			// to avoid duplicate findings.
			mutual := groupSubset(b.Groups, a.Groups) && toolSubset(b.Tools, a.Tools)
			if mutual && i < j {
				continue
			}
			out = append(out, Finding{
				Kind: "redundant", Rule: a.ID, Related: b.ID,
				Message: "rule is fully covered by another rule with the same effect; it can be removed",
			})
			break
		}

		// Shadowed allow: an allow rule fully covered by a deny rule can never
		// take effect under deny-overrides.
		if a.Effect == Allow {
			for j := range rules {
				b := &rules[j]
				if b.Effect != Deny {
					continue
				}
				if groupSubset(a.Groups, b.Groups) && toolSubset(a.Tools, b.Tools) {
					out = append(out, Finding{
						Kind: "shadowed_allow", Rule: a.ID, Related: b.ID,
						Message: "allow rule is fully shadowed by a deny rule (deny-overrides); it grants nothing",
					})
					break
				}
			}
		}

		// Redundant deny: when the default is deny, a deny rule that overlaps no
		// allow rule (on tools) never changes an outcome. Group membership is
		// deliberately ignored here: a caller may belong to both the deny's group
		// and an allow's group, so a tool-only overlap with any allow makes the
		// deny meaningful under deny-overrides.
		if a.Effect == Deny && s.defaults.Effect == Deny {
			overlapsAllow := false
			for j := range rules {
				b := &rules[j]
				if b.Effect != Allow {
					continue
				}
				if toolsOverlap(a.Tools, b.Tools) {
					overlapsAllow = true
					break
				}
			}
			if !overlapsAllow {
				out = append(out, Finding{
					Kind: "redundant_deny", Rule: a.ID,
					Message: "deny rule overlaps no allow rule and the default is deny; it never changes a decision",
				})
			}
		}
	}
	return out
}

func groupSubset(a, b []string) bool {
	set := make(map[string]bool, len(b))
	for _, g := range b {
		set[g] = true
	}
	for _, g := range a {
		if !set[g] {
			return false
		}
	}
	return true
}

func toolSubset(a, b []string) bool {
	for _, ta := range a {
		covered := false
		for _, tb := range b {
			if toolCovers(tb, ta) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func toolsOverlap(a, b []string) bool {
	for _, ta := range a {
		for _, tb := range b {
			if patternsOverlap(ta, tb) {
				return true
			}
		}
	}
	return false
}

// toolCovers reports whether pattern b matches every tool that pattern a matches.
func toolCovers(b, a string) bool {
	if b == "*" {
		return true
	}
	nb, wb := splitWild(b)
	na, wa := splitWild(a)
	if !wb {
		return !wa && a == b // exact covers only the identical exact name
	}
	if wa {
		return na == nb // "ns.*" covers "ns.*" only for the same namespace
	}
	return strings.HasPrefix(a, nb+".")
}

// patternsOverlap reports whether two tool patterns can match a common tool.
func patternsOverlap(x, y string) bool {
	if x == "*" || y == "*" || x == y {
		return true
	}
	nx, wx := splitWild(x)
	ny, wy := splitWild(y)
	switch {
	case wx && wy:
		return nx == ny
	case wx:
		return strings.HasPrefix(y, nx+".")
	case wy:
		return strings.HasPrefix(x, ny+".")
	default:
		return x == y
	}
}

func splitWild(p string) (string, bool) {
	if strings.HasSuffix(p, ".*") {
		return strings.TrimSuffix(p, ".*"), true
	}
	return p, false
}
