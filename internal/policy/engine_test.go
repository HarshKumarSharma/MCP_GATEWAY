package policy

import (
	"strings"
	"testing"
)

const sampleYAML = `
version: 1
defaults:
  effect: deny
  conflict_resolution: deny_overrides
policies:
  - id: eng-read-create
    groups: [engineering]
    tools: [github.list_repositories, github.create_issue]
    effect: allow
  - id: eng-deny-delete
    groups: [engineering]
    tools: [github.delete_repository]
    effect: deny
  - id: repo-admin-delete
    groups: [repository-admin]
    tools: [github.delete_repository]
    effect: allow
  - id: hr-payroll-read
    groups: [hr]
    tools: [payroll.get_employee]
    effect: allow
  - id: eng-github-wildcard-read
    groups: [engineering]
    tools: [github.*]
    effect: allow
`

func mustSnapshot(t *testing.T, y string) *Snapshot {
	t.Helper()
	s, err := Parse(strings.NewReader(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return s
}

func TestEvaluate(t *testing.T) {
	s := mustSnapshot(t, sampleYAML)

	tests := []struct {
		name       string
		groups     []string
		tool       string
		wantAllow  bool
		wantReason string
	}{
		{"exact + wildcard allow", []string{"engineering"}, "github.list_repositories", true, ReasonExplicitAllow},
		{"create issue allow", []string{"engineering"}, "github.create_issue", true, ReasonExplicitAllow},
		{"deny wins over wildcard allow", []string{"engineering"}, "github.delete_repository", false, ReasonDenyOverrides},
		{"admin may delete", []string{"repository-admin"}, "github.delete_repository", true, ReasonExplicitAllow},
		{"multi-group: deny overrides allow", []string{"engineering", "repository-admin"}, "github.delete_repository", false, ReasonDenyOverrides},
		{"hr payroll allow", []string{"hr"}, "payroll.get_employee", true, ReasonExplicitAllow},
		{"no matching rule (wrong group)", []string{"hr"}, "github.list_repositories", false, ReasonNoMatchingPolicy},
		{"no matching rule (finance)", []string{"finance"}, "payroll.get_employee", false, ReasonNoMatchingPolicy},
		{"wildcard namespace match", []string{"engineering"}, "github.get_repository", true, ReasonExplicitAllow},
		{"wildcard does not cross namespace", []string{"engineering"}, "payroll.get_employee", false, ReasonNoMatchingPolicy},
		{"no groups -> default deny", nil, "github.list_repositories", false, ReasonNoMatchingPolicy},
		{"unlisted tool -> default deny", []string{"hr"}, "slack.post_message", false, ReasonNoMatchingPolicy},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := s.Evaluate(Request{Subject: "u", Groups: tc.groups, Tool: tc.tool})
			if d.Allowed != tc.wantAllow {
				t.Errorf("Allowed = %v, want %v (reason=%s allows=%v denies=%v)",
					d.Allowed, tc.wantAllow, d.Reason, d.MatchedAllows, d.MatchedDenies)
			}
			if d.Reason != tc.wantReason {
				t.Errorf("Reason = %q, want %q", d.Reason, tc.wantReason)
			}
			if d.PolicyDigest == "" {
				t.Error("PolicyDigest must be set on every decision")
			}
		})
	}
}

// A deny that matches with no competing allow reports explicit_deny.
func TestExplicitDenyWithoutAllow(t *testing.T) {
	s := mustSnapshot(t, `
version: 1
policies:
  - id: block-hr-delete
    groups: [hr]
    tools: [github.delete_repository]
    effect: deny
`)
	d := s.Evaluate(Request{Groups: []string{"hr"}, Tool: "github.delete_repository"})
	if d.Allowed || d.Reason != ReasonExplicitDeny {
		t.Fatalf("got allowed=%v reason=%q; want deny/explicit_deny", d.Allowed, d.Reason)
	}
	if len(d.MatchedDenies) != 1 || d.MatchedDenies[0] != "block-hr-delete" {
		t.Fatalf("MatchedDenies = %v; want [block-hr-delete]", d.MatchedDenies)
	}
}

// Duplicate groups in a request must not change the outcome.
func TestDuplicateGroupsNoEffect(t *testing.T) {
	s := mustSnapshot(t, sampleYAML)
	one := s.Evaluate(Request{Groups: []string{"engineering"}, Tool: "github.create_issue"})
	dup := s.Evaluate(Request{Groups: []string{"engineering", "engineering"}, Tool: "github.create_issue"})
	if one.Allowed != dup.Allowed || one.Reason != dup.Reason {
		t.Fatalf("duplicate groups changed decision: %+v vs %+v", one, dup)
	}
}

// Decisions must be independent of the order rules appear in the file.
func TestOrderIndependence(t *testing.T) {
	reversed := `
version: 1
policies:
  - id: eng-github-wildcard-read
    groups: [engineering]
    tools: [github.*]
    effect: allow
  - id: hr-payroll-read
    groups: [hr]
    tools: [payroll.get_employee]
    effect: allow
  - id: repo-admin-delete
    groups: [repository-admin]
    tools: [github.delete_repository]
    effect: allow
  - id: eng-deny-delete
    groups: [engineering]
    tools: [github.delete_repository]
    effect: deny
  - id: eng-read-create
    groups: [engineering]
    tools: [github.list_repositories, github.create_issue]
    effect: allow
`
	a := mustSnapshot(t, sampleYAML)
	b := mustSnapshot(t, reversed)

	req := Request{Groups: []string{"engineering", "repository-admin"}, Tool: "github.delete_repository"}
	da, db := a.Evaluate(req), b.Evaluate(req)
	if da.Allowed != db.Allowed || da.Reason != db.Reason {
		t.Fatalf("order changed decision: %+v vs %+v", da, db)
	}
	if a.Digest() != b.Digest() {
		t.Fatalf("digest must be order-independent:\n a=%s\n b=%s", a.Digest(), b.Digest())
	}
}

// The digest must ignore ordering of groups/tools within a rule.
func TestDigestCanonical(t *testing.T) {
	y1 := "version: 1\npolicies:\n  - id: r1\n    groups: [a, b]\n    tools: [x, y]\n    effect: allow\n"
	y2 := "version: 1\npolicies:\n  - id: r1\n    groups: [b, a]\n    tools: [y, x]\n    effect: allow\n"
	if mustSnapshot(t, y1).Digest() != mustSnapshot(t, y2).Digest() {
		t.Fatal("digest should be independent of group/tool ordering")
	}
}
