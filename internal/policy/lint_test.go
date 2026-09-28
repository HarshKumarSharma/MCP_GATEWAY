package policy

import "testing"

func snap(def Effect, rules ...Rule) *Snapshot {
	return &Snapshot{defaults: Defaults{Effect: def, ConflictResolution: "deny_overrides"}, rules: rules}
}

func hasFinding(fs []Finding, kind, rule string) bool {
	for _, f := range fs {
		if f.Kind == kind && f.Rule == rule {
			return true
		}
	}
	return false
}

func TestLintRedundantSameEffect(t *testing.T) {
	s := snap(Deny,
		Rule{ID: "a", Groups: []string{"eng"}, Tools: []string{"github.create_issue"}, Effect: Allow},
		Rule{ID: "b", Groups: []string{"eng"}, Tools: []string{"github.*"}, Effect: Allow},
	)
	fs := Lint(s)
	// "a" is fully covered by wildcard rule "b".
	if !hasFinding(fs, "redundant", "a") {
		t.Fatalf("expected 'a' redundant, got %+v", fs)
	}
	if hasFinding(fs, "redundant", "b") {
		t.Fatalf("'b' should not be redundant, got %+v", fs)
	}
}

func TestLintShadowedAllow(t *testing.T) {
	s := snap(Deny,
		Rule{ID: "allow-delete", Groups: []string{"eng"}, Tools: []string{"github.delete_repository"}, Effect: Allow},
		Rule{ID: "deny-delete", Groups: []string{"eng"}, Tools: []string{"github.delete_repository"}, Effect: Deny},
	)
	fs := Lint(s)
	if !hasFinding(fs, "shadowed_allow", "allow-delete") {
		t.Fatalf("expected shadowed allow, got %+v", fs)
	}
}

func TestLintRedundantDeny(t *testing.T) {
	s := snap(Deny,
		Rule{ID: "deny-hr-payroll", Groups: []string{"hr"}, Tools: []string{"payroll.get_employee"}, Effect: Deny},
	)
	fs := Lint(s)
	// Default is deny and nothing grants hr->payroll, so this deny is redundant.
	if !hasFinding(fs, "redundant_deny", "deny-hr-payroll") {
		t.Fatalf("expected redundant deny, got %+v", fs)
	}
}

func TestLintClean(t *testing.T) {
	// A deny that overlaps an allow is meaningful, not redundant.
	s := snap(Deny,
		Rule{ID: "allow-eng", Groups: []string{"eng"}, Tools: []string{"github.*"}, Effect: Allow},
		Rule{ID: "deny-delete", Groups: []string{"eng"}, Tools: []string{"github.delete_repository"}, Effect: Deny},
		Rule{ID: "allow-hr", Groups: []string{"hr"}, Tools: []string{"payroll.get_employee"}, Effect: Allow},
	)
	fs := Lint(s)
	if len(fs) != 0 {
		t.Fatalf("expected no findings, got %+v", fs)
	}
}

func TestToolCovers(t *testing.T) {
	cases := []struct {
		b, a string
		want bool
	}{
		{"*", "github.x", true},
		{"github.*", "github.x", true},
		{"github.*", "github.*", true},
		{"github.*", "payroll.x", false},
		{"github.x", "github.x", true},
		{"github.x", "github.y", false},
		{"github.x", "github.*", false}, // exact cannot cover a wildcard
	}
	for _, c := range cases {
		if got := toolCovers(c.b, c.a); got != c.want {
			t.Errorf("toolCovers(%q,%q)=%t want %t", c.b, c.a, got, c.want)
		}
	}
}
