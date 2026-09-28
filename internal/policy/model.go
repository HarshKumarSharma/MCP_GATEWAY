// Package policy is the pure decision core (PDP) of the gateway.
//
// It deliberately has no dependencies on HTTP, JWT, MCP, or logging so that
// the authorization decision is easy to reason about and exhaustive to
// unit-test. Everything else in the gateway is plumbing around this package.
package policy

// Effect is the outcome a rule asserts.
type Effect string

const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
)

// Reason codes are recorded in the audit trail and returned on every Decision.
const (
	ReasonExplicitAllow    = "explicit_allow"
	ReasonExplicitDeny     = "explicit_deny"
	ReasonDenyOverrides    = "deny_overrides"
	ReasonNoMatchingPolicy = "no_matching_policy"
)

// Rule is a single allow/deny statement over groups and tools.
//
// A rule matches a request iff (any of its groups is one of the caller's
// EFFECTIVE groups) AND (one of its tools matches the requested tool). Effective
// groups include the caller's groups plus every group they inherit through the
// group hierarchy (see GroupDef). Tools support an exact name, a namespace
// wildcard ("github.*"), or the full wildcard ("*").
type Rule struct {
	ID     string   `yaml:"id"`
	Groups []string `yaml:"groups"`
	Tools  []string `yaml:"tools"`
	Effect Effect   `yaml:"effect"`
}

// GroupDef declares one node in the group hierarchy. Parents are the broader
// groups this group is nested within: membership in this group implies
// membership in each parent (transitively). This lets a grant made to a broad
// group be inherited by nested teams, without repeating rules.
//
// Example: senior-engineering -> engineering -> staff. A caller whose token
// carries only "senior-engineering" is treated as also belonging to
// "engineering" and "staff" during evaluation.
//
// The hierarchy is optional; with no GroupDefs, groups are flat (exact match).
type GroupDef struct {
	Name    string   `yaml:"name"`
	Parents []string `yaml:"parents"`
}

// Defaults configure fallback behavior when no rule matches and how
// conflicting rules are resolved.
type Defaults struct {
	Effect             Effect `yaml:"effect"`
	ConflictResolution string `yaml:"conflict_resolution"`
}

// Request is the pure input to Evaluate: a verified caller and the tool it
// wants to invoke. Subject is carried for audit/ABAC use; the core semantics
// depend only on Groups and Tool.
type Request struct {
	Subject string
	Groups  []string
	Tool    string
}

// Decision is the pure output of Evaluate.
type Decision struct {
	Effect        Effect
	Allowed       bool
	Reason        string
	MatchedAllows []string
	MatchedDenies []string
	PolicyDigest  string
}
