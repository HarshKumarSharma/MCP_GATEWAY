package policy

import (
	"fmt"
	"testing"
)

// buildSnapshot creates a snapshot with nRules rules spread across 64 groups and
// 16 tool namespaces, ~20% of them deny. It is representative of a large,
// realistic rule base.
func buildSnapshot(nRules int) *Snapshot {
	rules := make([]Rule, 0, nRules)
	for i := 0; i < nRules; i++ {
		eff := Allow
		if i%5 == 0 {
			eff = Deny
		}
		rules = append(rules, Rule{
			ID:     fmt.Sprintf("rule-%d", i),
			Groups: []string{fmt.Sprintf("group-%d", i%64)},
			Tools:  []string{fmt.Sprintf("svc%d.tool_%d", i%16, i)},
			Effect: eff,
		})
	}
	s := &Snapshot{
		defaults: Defaults{Effect: Deny, ConflictResolution: "deny_overrides"},
		rules:    rules,
	}
	s.index = buildIndex(s.rules)
	return s
}

// BenchmarkEvaluate measures the indexed (bitset) engine — the production path.
func BenchmarkEvaluate(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		s := buildSnapshot(n)
		req := Request{Subject: "u", Groups: []string{"group-7"}, Tool: "svc3.tool_500"}
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = s.Evaluate(req)
			}
		})
	}
}

// BenchmarkEvaluateReference measures the naive linear reference (test-only
// oracle) so the indexed engine's speedup over a full scan stays visible.
func BenchmarkEvaluateReference(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		s := buildSnapshot(n)
		req := Request{Subject: "u", Groups: []string{"group-7"}, Tool: "svc3.tool_500"}
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = referenceEvaluate(s, req)
			}
		})
	}
}
