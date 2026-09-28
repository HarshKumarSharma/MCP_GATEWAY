package policy

import (
	"strings"
	"testing"
)

// Invalid configuration must fail closed (return an error), never load a
// partial or permissive policy.
func TestLoadInvalid(t *testing.T) {
	cases := map[string]string{
		"unsupported version":     "version: 2\npolicies: []\n",
		"unknown top-level field": "version: 1\nnope: true\npolicies: []\n",
		"unknown rule field":      "version: 1\npolicies:\n  - id: r1\n    groups: [a]\n    tools: [x]\n    effect: allow\n    extra: nope\n",
		"duplicate id":            "version: 1\npolicies:\n  - id: dup\n    groups: [a]\n    tools: [x]\n    effect: allow\n  - id: dup\n    groups: [b]\n    tools: [y]\n    effect: deny\n",
		"invalid effect":          "version: 1\npolicies:\n  - id: r1\n    groups: [a]\n    tools: [x]\n    effect: maybe\n",
		"no groups":               "version: 1\npolicies:\n  - id: r1\n    groups: []\n    tools: [x]\n    effect: allow\n",
		"no tools":                "version: 1\npolicies:\n  - id: r1\n    groups: [a]\n    tools: []\n    effect: allow\n",
		"missing id":              "version: 1\npolicies:\n  - groups: [a]\n    tools: [x]\n    effect: allow\n",
		"empty group":             "version: 1\npolicies:\n  - id: r1\n    groups: [\"\"]\n    tools: [x]\n    effect: allow\n",
		"bad conflict resolution": "version: 1\ndefaults:\n  conflict_resolution: first_match\npolicies: []\n",
	}

	for name, y := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(y)); err == nil {
				t.Fatalf("expected error for %q, got nil", name)
			}
		})
	}
}

// Defaults are optional and fall back to deny / deny_overrides.
func TestDefaultsOptional(t *testing.T) {
	s, err := Parse(strings.NewReader("version: 1\npolicies:\n  - id: r1\n    groups: [a]\n    tools: [x]\n    effect: allow\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if d := s.Evaluate(Request{Groups: []string{"z"}, Tool: "q"}); d.Allowed {
		t.Fatal("missing defaults should still default-deny")
	}
}

// The shipped sample policy must load cleanly.
func TestLoadSampleFile(t *testing.T) {
	s, err := Load("../../config/policies.yaml")
	if err != nil {
		t.Fatalf("Load sample policy: %v", err)
	}
	if s.Digest() == "" {
		t.Fatal("sample policy produced empty digest")
	}
}
