package policy

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// file is the on-disk policy schema.
type file struct {
	Version  int        `yaml:"version"`
	Defaults Defaults   `yaml:"defaults"`
	Groups   []GroupDef `yaml:"groups"`
	Policies []Rule     `yaml:"policies"`
}

// Load reads, strictly parses, and validates a policy file, returning an
// immutable Snapshot. Any error means the caller must fail closed (refuse to
// start, or keep the last known-good snapshot on reload).
func Load(path string) (*Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open policy: %w", err)
	}
	defer f.Close()
	return Parse(f)
}

// Parse is Load for an arbitrary reader (used in tests).
func Parse(r io.Reader) (*Snapshot, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true) // reject unknown fields so typos cannot silently weaken policy
	var fl file
	if err := dec.Decode(&fl); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	return compile(fl)
}

func compile(fl file) (*Snapshot, error) {
	if fl.Version != 1 {
		return nil, fmt.Errorf("unsupported policy version %d (want 1)", fl.Version)
	}

	if fl.Defaults.Effect == "" {
		fl.Defaults.Effect = Deny
	}
	if fl.Defaults.Effect != Allow && fl.Defaults.Effect != Deny {
		return nil, fmt.Errorf("invalid defaults.effect %q", fl.Defaults.Effect)
	}
	if fl.Defaults.ConflictResolution == "" {
		fl.Defaults.ConflictResolution = "deny_overrides"
	}
	if fl.Defaults.ConflictResolution != "deny_overrides" {
		return nil, fmt.Errorf("unsupported conflict_resolution %q (want deny_overrides)", fl.Defaults.ConflictResolution)
	}

	ancestors, err := resolveGroups(fl.Groups)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool, len(fl.Policies))
	for i, r := range fl.Policies {
		if strings.TrimSpace(r.ID) == "" {
			return nil, fmt.Errorf("policy #%d: missing id", i)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("duplicate policy id %q", r.ID)
		}
		seen[r.ID] = true

		if r.Effect != Allow && r.Effect != Deny {
			return nil, fmt.Errorf("policy %q: invalid effect %q (want allow|deny)", r.ID, r.Effect)
		}
		if len(r.Groups) == 0 {
			return nil, fmt.Errorf("policy %q: at least one group required", r.ID)
		}
		if len(r.Tools) == 0 {
			return nil, fmt.Errorf("policy %q: at least one tool required", r.ID)
		}
		for _, g := range r.Groups {
			if strings.TrimSpace(g) == "" {
				return nil, fmt.Errorf("policy %q: empty group name", r.ID)
			}
		}
		for _, t := range r.Tools {
			if strings.TrimSpace(t) == "" {
				return nil, fmt.Errorf("policy %q: empty tool name", r.ID)
			}
		}
	}

	return &Snapshot{
		defaults:  fl.Defaults,
		rules:     fl.Policies,
		ancestors: ancestors,
		digest:    computeDigest(fl.Defaults, fl.Groups, fl.Policies),
	}, nil
}

// resolveGroups validates the group hierarchy and returns, for each defined
// group, the transitive set of its ancestor groups (excluding itself). It
// rejects duplicate/empty names, empty parent names, and cycles. Parents that
// are not themselves defined are treated as leaf groups (a top-level group need
// not have its own entry), so typos surface as ineffective inheritance rather
// than load failures — the linter and `explain` help catch those.
func resolveGroups(defs []GroupDef) (map[string][]string, error) {
	if len(defs) == 0 {
		return nil, nil
	}

	parents := make(map[string][]string, len(defs))
	seen := make(map[string]bool, len(defs))
	for i, d := range defs {
		if strings.TrimSpace(d.Name) == "" {
			return nil, fmt.Errorf("group #%d: missing name", i)
		}
		if seen[d.Name] {
			return nil, fmt.Errorf("duplicate group definition %q", d.Name)
		}
		seen[d.Name] = true
		for _, p := range d.Parents {
			if strings.TrimSpace(p) == "" {
				return nil, fmt.Errorf("group %q: empty parent name", d.Name)
			}
			if p == d.Name {
				return nil, fmt.Errorf("group %q: cannot be its own parent", d.Name)
			}
		}
		parents[d.Name] = d.Parents
	}

	// Detect cycles via DFS coloring over the parent edges.
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make(map[string]int, len(parents))
	var check func(n string) error
	check = func(n string) error {
		color[n] = gray
		for _, p := range parents[n] {
			switch color[p] {
			case gray:
				return fmt.Errorf("group hierarchy cycle detected at %q -> %q", n, p)
			case white:
				if err := check(p); err != nil {
					return err
				}
			}
		}
		color[n] = black
		return nil
	}
	for n := range parents {
		if color[n] == white {
			if err := check(n); err != nil {
				return nil, err
			}
		}
	}

	// Compute transitive ancestors with memoization (graph is acyclic here).
	memo := make(map[string][]string, len(parents))
	var ancestorsOf func(n string) []string
	ancestorsOf = func(n string) []string {
		if v, ok := memo[n]; ok {
			return v
		}
		set := make(map[string]bool)
		for _, p := range parents[n] {
			set[p] = true
			for _, a := range ancestorsOf(p) {
				set[a] = true
			}
		}
		list := make([]string, 0, len(set))
		for a := range set {
			list = append(list, a)
		}
		sort.Strings(list)
		memo[n] = list
		return list
	}

	out := make(map[string][]string, len(parents))
	for n := range parents {
		out[n] = ancestorsOf(n)
	}
	return out, nil
}
