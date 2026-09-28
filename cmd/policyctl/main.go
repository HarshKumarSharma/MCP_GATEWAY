// Command policyctl is an operator tool for the policy file. It can explain a
// single decision (why a given group/tool is allowed or denied) and lint the
// rule base for redundant or unreachable rules.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/harshsharma/mcp-policy-gateway/internal/policy"
)

func newFlagSet(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ExitOnError)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "explain":
		os.Exit(runExplain(os.Args[2:]))
	case "lint":
		os.Exit(runLint(os.Args[2:]))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `policyctl: policy inspection tool

usage:
  policyctl explain -policy config/policies.yaml -groups engineering,hr -tool github.create_issue
  policyctl lint    -policy config/policies.yaml
`)
}

func runExplain(args []string) int {
	fs := newFlagSet("explain")
	policyPath := fs.String("policy", "config/policies.yaml", "policy file")
	groupsCSV := fs.String("groups", "", "comma-separated caller groups")
	tool := fs.String("tool", "", "tool name to evaluate")
	subject := fs.String("subject", "cli-user", "caller subject (for display only)")
	_ = fs.Parse(args)

	if *tool == "" {
		fmt.Fprintln(os.Stderr, "policyctl: -tool is required")
		return 2
	}

	snap, err := policy.Load(*policyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "policyctl:", err)
		return 1
	}

	dec := snap.Evaluate(policy.Request{
		Subject: *subject,
		Groups:  splitCSV(*groupsCSV),
		Tool:    *tool,
	})

	fmt.Printf("tool:           %s\n", *tool)
	fmt.Printf("groups:         %s\n", orNone(splitCSV(*groupsCSV)))
	fmt.Printf("effect:         %s\n", dec.Effect)
	fmt.Printf("allowed:        %t\n", dec.Allowed)
	fmt.Printf("reason:         %s\n", dec.Reason)
	fmt.Printf("matched allows: %s\n", orNone(dec.MatchedAllows))
	fmt.Printf("matched denies: %s\n", orNone(dec.MatchedDenies))
	fmt.Printf("policy digest:  %s\n", dec.PolicyDigest)
	return 0
}

func runLint(args []string) int {
	fs := newFlagSet("lint")
	policyPath := fs.String("policy", "config/policies.yaml", "policy file")
	_ = fs.Parse(args)

	snap, err := policy.Load(*policyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "policyctl:", err)
		return 1
	}

	findings := policy.Lint(snap)
	if len(findings) == 0 {
		fmt.Printf("ok: no issues found (digest %s)\n", snap.Digest())
		return 0
	}
	for _, f := range findings {
		if f.Related != "" {
			fmt.Printf("[%s] %s (vs %s): %s\n", f.Kind, f.Rule, f.Related, f.Message)
		} else {
			fmt.Printf("[%s] %s: %s\n", f.Kind, f.Rule, f.Message)
		}
	}
	return 1
}

func splitCSV(csv string) []string {
	if strings.TrimSpace(csv) == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func orNone(ss []string) string {
	if len(ss) == 0 {
		return "(none)"
	}
	return strings.Join(ss, ", ")
}
