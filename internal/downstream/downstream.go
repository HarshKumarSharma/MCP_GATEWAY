// Package downstream models the MCP servers that sit behind the gateway.
//
// In production these would be separate processes reached over an MCP
// transport. Here they are in-process mocks behind the Downstream interface,
// so the gateway's authentication, policy, and audit paths can be exercised
// without external dependencies. Swapping in a real transport is a matter of
// providing another Downstream implementation.
package downstream

import (
	"context"
	"fmt"
	"sort"
)

// Tool describes a callable tool exposed by a downstream server.
type Tool struct {
	Name        string
	Description string
	// InputSchema is a minimal JSON Schema object advertised to clients.
	InputSchema map[string]any
}

// Downstream is the interface the gateway forwards allowed calls to.
type Downstream interface {
	// Tools returns the catalog of tools this downstream exposes.
	Tools() []Tool
	// Call invokes a tool by name with decoded arguments.
	Call(ctx context.Context, tool string, args map[string]any) (any, error)
}

// ErrUnknownTool is returned when a tool name is not served here.
type ErrUnknownTool struct{ Tool string }

func (e *ErrUnknownTool) Error() string { return fmt.Sprintf("unknown tool %q", e.Tool) }

type handler func(ctx context.Context, args map[string]any) (any, error)

// Mock is an in-process Downstream with a fixed set of deterministic tools.
type Mock struct {
	tools    []Tool
	handlers map[string]handler
}

// NewMock builds the demo downstream with four tools spanning two services
// (github.*, payroll.*), matching config/policies.yaml.
func NewMock() *Mock {
	m := &Mock{handlers: map[string]handler{}}

	m.register(Tool{
		Name:        "github.list_repositories",
		Description: "List repositories visible to the caller.",
		InputSchema: objSchema(map[string]any{
			"owner": strProp("Repository owner/org to scope the listing."),
		}, nil),
	}, func(_ context.Context, args map[string]any) (any, error) {
		owner, _ := args["owner"].(string)
		if owner == "" {
			owner = "acme"
		}
		return map[string]any{
			"repositories": []map[string]any{
				{"full_name": owner + "/service-gateway", "private": true},
				{"full_name": owner + "/docs", "private": false},
			},
		}, nil
	})

	m.register(Tool{
		Name:        "github.create_issue",
		Description: "Open an issue in a repository.",
		InputSchema: objSchema(map[string]any{
			"repo":  strProp("Target repository, e.g. acme/docs."),
			"title": strProp("Issue title."),
		}, []string{"repo", "title"}),
	}, func(_ context.Context, args map[string]any) (any, error) {
		repo, _ := args["repo"].(string)
		title, _ := args["title"].(string)
		if repo == "" || title == "" {
			return nil, fmt.Errorf("repo and title are required")
		}
		return map[string]any{"repo": repo, "number": 4242, "title": title, "state": "open"}, nil
	})

	m.register(Tool{
		Name:        "github.delete_repository",
		Description: "Permanently delete a repository (destructive).",
		InputSchema: objSchema(map[string]any{
			"repo": strProp("Repository to delete, e.g. acme/docs."),
		}, []string{"repo"}),
	}, func(_ context.Context, args map[string]any) (any, error) {
		repo, _ := args["repo"].(string)
		if repo == "" {
			return nil, fmt.Errorf("repo is required")
		}
		return map[string]any{"repo": repo, "deleted": true}, nil
	})

	m.register(Tool{
		Name:        "payroll.get_employee",
		Description: "Fetch a payroll record for an employee.",
		InputSchema: objSchema(map[string]any{
			"employee_id": strProp("Employee identifier."),
		}, []string{"employee_id"}),
	}, func(_ context.Context, args map[string]any) (any, error) {
		id, _ := args["employee_id"].(string)
		if id == "" {
			return nil, fmt.Errorf("employee_id is required")
		}
		return map[string]any{
			"employee_id": id,
			"name":        "Jordan Rivera",
			"currency":    "USD",
			"base_salary": 145000,
		}, nil
	})

	return m
}

func (m *Mock) register(t Tool, h handler) {
	m.tools = append(m.tools, t)
	m.handlers[t.Name] = h
}

// Tools returns the tool catalog sorted by name for deterministic output.
func (m *Mock) Tools() []Tool {
	out := make([]Tool, len(m.tools))
	copy(out, m.tools)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Call dispatches to the named tool handler.
func (m *Mock) Call(ctx context.Context, tool string, args map[string]any) (any, error) {
	h, ok := m.handlers[tool]
	if !ok {
		return nil, &ErrUnknownTool{Tool: tool}
	}
	return h(ctx, args)
}

func objSchema(props map[string]any, required []string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}
