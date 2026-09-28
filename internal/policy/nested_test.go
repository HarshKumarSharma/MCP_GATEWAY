package policy

import (
	"reflect"
	"strings"
	"testing"
)

// nestedYAML defines a multi-level hierarchy plus a diamond, and a rule set that
// exercises inheritance of allows, inherited deny-overrides, wildcards, and
// sibling isolation.
//
// Hierarchy (child -> parents):
//
//	lead               -> senior-engineering, sre   (diamond: both reach engineering)
//	senior-engineering -> engineering
//	sre                -> engineering
//	engineering        -> staff
//	hr                 -> staff
//	(staff and contractor are used but not declared as nodes -> leaf groups)
const nestedYAML = `
version: 1
defaults:
  effect: deny
  conflict_resolution: deny_overrides
groups:
  - name: engineering
    parents: [staff]
  - name: senior-engineering
    parents: [engineering]
  - name: sre
    parents: [engineering]
  - name: hr
    parents: [staff]
  - name: lead
    parents: [senior-engineering, sre]
policies:
  - id: staff-read
    groups: [staff]
    tools: [repo.read]
    effect: allow
  - id: engineering-build
    groups: [engineering]
    tools: [repo.build]
    effect: allow
  - id: engineering-deny-delete
    groups: [engineering]
    tools: [repo.delete]
    effect: deny
  - id: senior-allow-delete
    groups: [senior-engineering]
    tools: [repo.delete]
    effect: allow
  - id: sre-infra-wildcard
    groups: [sre]
    tools: [infra.*]
    effect: allow
  - id: hr-payroll
    groups: [hr]
    tools: [payroll.read]
    effect: allow
`

func TestEffectiveGroups(t *testing.T) {
	s := mustSnapshot(t, nestedYAML)
	cases := []struct {
		name   string
		caller []string
		want   []string
	}{
		{"leaf only (undefined)", []string{"contractor"}, []string{"contractor"}},
		{"top group", []string{"staff"}, []string{"staff"}},
		{"one level", []string{"engineering"}, []string{"engineering", "staff"}},
		{"two levels", []string{"senior-engineering"}, []string{"engineering", "senior-engineering", "staff"}},
		{"sibling", []string{"sre"}, []string{"engineering", "sre", "staff"}},
		{"hr branch", []string{"hr"}, []string{"hr", "staff"}},
		{"diamond dedups shared ancestor", []string{"lead"},
			[]string{"engineering", "lead", "senior-engineering", "sre", "staff"}},
		{"multiple caller groups union", []string{"hr", "sre"},
			[]string{"engineering", "hr", "sre", "staff"}},
		{"duplicate caller group", []string{"engineering", "engineering"},
			[]string{"engineering", "staff"}},
		{"empty", nil, []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := s.EffectiveGroups(c.caller)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("EffectiveGroups(%v) = %v, want %v", c.caller, got, c.want)
			}
		})
	}
}

// TestNestedCombinations exhaustively checks decisions across group levels,
// tool tiers (exact + wildcard), inherited allows, and inherited denies.
func TestNestedCombinations(t *testing.T) {
	s := mustSnapshot(t, nestedYAML)
	cases := []struct {
		name       string
		groups     []string
		tool       string
		wantAllow  bool
		wantReason string
	}{
		// Inherited allow: engineering inherits staff's read.
		{"engineering inherits staff read", []string{"engineering"}, "repo.read", true, ReasonExplicitAllow},
		// Two-level inheritance.
		{"senior inherits staff read", []string{"senior-engineering"}, "repo.read", true, ReasonExplicitAllow},
		// Own-level allow.
		{"engineering own build", []string{"engineering"}, "repo.build", true, ReasonExplicitAllow},
		// Child inherits parent's build.
		{"sre inherits engineering build", []string{"sre"}, "repo.build", true, ReasonExplicitAllow},
		// Inherited deny with no competing allow.
		{"sre inherits engineering delete-deny", []string{"sre"}, "repo.delete", false, ReasonExplicitDeny},
		// Own allow but inherited deny -> deny-overrides (the key hierarchy case).
		{"senior allow vs inherited deny", []string{"senior-engineering"}, "repo.delete", false, ReasonDenyOverrides},
		// lead (diamond) also inherits engineering deny and senior allow.
		{"lead deny-overrides via diamond", []string{"lead"}, "repo.delete", false, ReasonDenyOverrides},
		// Wildcard tool inherited nowhere-needed: sre own wildcard.
		{"sre infra wildcard", []string{"sre"}, "infra.provision", true, ReasonExplicitAllow},
		// lead inherits sre's wildcard.
		{"lead inherits sre wildcard", []string{"lead"}, "infra.teardown", true, ReasonExplicitAllow},
		// Sibling isolation: hr does NOT get engineering's build.
		{"hr cannot build (sibling isolation)", []string{"hr"}, "repo.build", false, ReasonNoMatchingPolicy},
		// hr inherits staff read though.
		{"hr inherits staff read", []string{"hr"}, "repo.read", true, ReasonExplicitAllow},
		// staff alone cannot build.
		{"staff cannot build", []string{"staff"}, "repo.build", false, ReasonNoMatchingPolicy},
		// Undefined leaf group inherits nothing.
		{"contractor gets nothing", []string{"contractor"}, "repo.read", false, ReasonNoMatchingPolicy},
		// Parent group does NOT inherit child grants (upward isolation):
		// engineering must not get senior's delete allow.
		{"engineering has no delete allow", []string{"engineering"}, "repo.delete", false, ReasonExplicitDeny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := s.Evaluate(Request{Subject: "u", Groups: c.groups, Tool: c.tool})
			if d.Allowed != c.wantAllow || d.Reason != c.wantReason {
				t.Fatalf("groups=%v tool=%s -> allowed=%v reason=%s; want allowed=%v reason=%s (allows=%v denies=%v)",
					c.groups, c.tool, d.Allowed, d.Reason, c.wantAllow, c.wantReason, d.MatchedAllows, d.MatchedDenies)
			}
		})
	}
}

// Inheritance direction is downward only: being a parent group does not grant a
// child group's permissions.
func TestUpwardIsolation(t *testing.T) {
	s := mustSnapshot(t, nestedYAML)
	// senior-engineering has an allow for repo.delete; plain engineering must not
	// inherit it upward.
	d := s.Evaluate(Request{Groups: []string{"engineering"}, Tool: "repo.delete"})
	for _, id := range d.MatchedAllows {
		if id == "senior-allow-delete" {
			t.Fatal("engineering wrongly inherited a child (senior) allow")
		}
	}
}

// A policy with no group section behaves as flat, exact-match groups.
func TestNoHierarchyIsFlat(t *testing.T) {
	s := mustSnapshot(t, `
version: 1
policies:
  - id: r
    groups: [engineering]
    tools: [repo.read]
    effect: allow
`)
	if d := s.Evaluate(Request{Groups: []string{"engineering"}, Tool: "repo.read"}); !d.Allowed {
		t.Fatal("flat exact match should allow")
	}
	// "staff" is not a parent of anything here, so it grants nothing.
	if d := s.Evaluate(Request{Groups: []string{"staff"}, Tool: "repo.read"}); d.Allowed {
		t.Fatal("flat model must not infer inheritance")
	}
}

// Changing the hierarchy must change the digest (reproducibility of decisions).
func TestHierarchyAffectsDigest(t *testing.T) {
	base := mustSnapshot(t, nestedYAML)
	altered := mustSnapshot(t, strings.Replace(nestedYAML,
		"  - name: hr\n    parents: [staff]",
		"  - name: hr\n    parents: [staff, engineering]", 1))
	if base.Digest() == altered.Digest() {
		t.Fatal("digest must change when the group hierarchy changes")
	}
}

// The digest is independent of the order of group definitions and parents.
func TestHierarchyDigestCanonical(t *testing.T) {
	a := mustSnapshot(t, `
version: 1
groups:
  - name: engineering
    parents: [staff, org]
  - name: hr
    parents: [staff]
policies:
  - id: r
    groups: [engineering]
    tools: [x]
    effect: allow
`)
	b := mustSnapshot(t, `
version: 1
groups:
  - name: hr
    parents: [staff]
  - name: engineering
    parents: [org, staff]
policies:
  - id: r
    groups: [engineering]
    tools: [x]
    effect: allow
`)
	if a.Digest() != b.Digest() {
		t.Fatalf("digest should ignore ordering of groups/parents:\n a=%s\n b=%s", a.Digest(), b.Digest())
	}
}
