package policy

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func TestToolPrefixes(t *testing.T) {
	cases := map[string][]string{
		"github":        nil,
		"github.create": {"github"},
		"a.b.c":         {"a", "a.b"},
		"payroll.get":   {"payroll"},
		"x.y.z.w":       {"x", "x.y", "x.y.z"},
		"":              nil,
	}
	for in, want := range cases {
		if got := toolPrefixes(in); !reflect.DeepEqual(got, want) {
			t.Errorf("toolPrefixes(%q) = %v, want %v", in, got, want)
		}
	}
}

// diffYAML exercises every tool form (exact, namespace wildcard, full wildcard),
// multi-tool rules, allow/deny conflicts, and a group hierarchy.
const diffYAML = `
version: 1
defaults:
  effect: deny
  conflict_resolution: deny_overrides
groups:
  - name: senior-engineering
    parents: [engineering]
  - name: engineering
    parents: [staff]
  - name: hr
    parents: [staff]
policies:
  - id: staff-read
    groups: [staff]
    tools: [github.list_repositories]
    effect: allow
  - id: eng-github-wild
    groups: [engineering]
    tools: [github.*]
    effect: allow
  - id: eng-deny-delete
    groups: [engineering]
    tools: [github.delete_repository]
    effect: deny
  - id: admin-star
    groups: [repository-admin]
    tools: ["*"]
    effect: allow
  - id: hr-multi
    groups: [hr]
    tools: [payroll.get_employee, payroll.list]
    effect: allow
  - id: contractor-deny-payroll
    groups: [contractor]
    tools: [payroll.*]
    effect: deny
`

// TestIndexedMatchesReference is a differential/property test: for many random
// requests, the production bitset engine must return exactly the same Decision
// as an independent, deliberately naive linear reference (defined below in the
// test package only) — including the order of matched rule IDs. The reference
// is trivial to eyeball as correct, so parity with it is strong evidence the
// bitset index has no edge-case bugs.
func TestIndexedMatchesReference(t *testing.T) {
	s := mustSnapshot(t, diffYAML)
	if s.index == nil {
		t.Fatal("expected an index to be built by the loader")
	}

	groupPool := []string{
		"staff", "engineering", "senior-engineering", "hr",
		"repository-admin", "contractor", "unknown-group",
	}
	toolPool := []string{
		"github.list_repositories", "github.create_issue", "github.delete_repository",
		"payroll.get_employee", "payroll.list", "payroll.secret",
		"slack.post_message", "github", "a.b.c", "unknown.tool",
	}

	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 5000; iter++ {
		// Random subset of groups (possibly empty), random tool.
		var groups []string
		for _, g := range groupPool {
			if rng.Intn(2) == 0 {
				groups = append(groups, g)
			}
		}
		tool := toolPool[rng.Intn(len(toolPool))]
		req := Request{Subject: "u", Groups: groups, Tool: tool}

		got := s.Evaluate(req)
		want := referenceEvaluate(s, req)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("indexed != reference\n groups=%v tool=%s\n indexed  =%+v\n reference=%+v",
				groups, tool, got, want)
		}
	}
}

// referenceEvaluate is an independent, obviously-correct linear evaluator kept
// in the test package only. It exists purely as the oracle for the differential
// test above; production code ships the single bitset engine.
func referenceEvaluate(s *Snapshot, req Request) Decision {
	eff := s.effectiveGroups(req.Groups)

	var allows, denies []string
	for i := range s.rules {
		r := &s.rules[i]
		if !refGroupsMatch(r.Groups, eff) || !refToolMatch(r.Tools, req.Tool) {
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

func refGroupsMatch(ruleGroups []string, effective map[string]bool) bool {
	for _, rg := range ruleGroups {
		if effective[rg] {
			return true
		}
	}
	return false
}

func refToolMatch(ruleTools []string, tool string) bool {
	for _, rt := range ruleTools {
		switch {
		case rt == "*" || rt == tool:
			return true
		case strings.HasSuffix(rt, ".*"):
			if strings.HasPrefix(tool, strings.TrimSuffix(rt, ".*")+".") {
				return true
			}
		}
	}
	return false
}

// Spot-check specific wildcard behaviors on the fast path.
func TestIndexedWildcards(t *testing.T) {
	s := mustSnapshot(t, diffYAML)
	tests := []struct {
		groups     []string
		tool       string
		wantAllow  bool
		wantReason string
	}{
		{[]string{"engineering"}, "github.create_issue", true, ReasonExplicitAllow},             // github.* wildcard
		{[]string{"engineering"}, "github.delete_repository", false, ReasonDenyOverrides},       // wildcard allow + explicit deny
		{[]string{"repository-admin"}, "anything.at_all", true, ReasonExplicitAllow},            // "*" tool
		{[]string{"engineering"}, "github", false, ReasonNoMatchingPolicy},                      // "github" has no dot; github.* must NOT match
		{[]string{"contractor"}, "payroll.secret", false, ReasonExplicitDeny},                   // payroll.* deny
		{[]string{"senior-engineering"}, "github.list_repositories", true, ReasonExplicitAllow}, // inherited staff read
	}
	for _, tc := range tests {
		t.Run(strings.Join(tc.groups, "+")+"/"+tc.tool, func(t *testing.T) {
			d := s.Evaluate(Request{Groups: tc.groups, Tool: tc.tool})
			if d.Allowed != tc.wantAllow || d.Reason != tc.wantReason {
				t.Fatalf("got allowed=%v reason=%s; want allowed=%v reason=%s",
					d.Allowed, d.Reason, tc.wantAllow, tc.wantReason)
			}
		})
	}
}
