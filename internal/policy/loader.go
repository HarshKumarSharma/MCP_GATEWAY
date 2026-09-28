package policy

import (
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// file is the on-disk policy schema.
type file struct {
	Version  int      `yaml:"version"`
	Defaults Defaults `yaml:"defaults"`
	Policies []Rule   `yaml:"policies"`
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
		defaults: fl.Defaults,
		rules:    fl.Policies,
		digest:   computeDigest(fl.Defaults, fl.Policies),
	}, nil
}
