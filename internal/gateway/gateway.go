// Package gateway is the policy enforcement point (PEP). It receives MCP tool
// calls, requires a verified caller identity, asks the policy engine (PDP) for
// a decision, forwards allowed calls to the downstream, and records both an
// authorization decision and a tool outcome to the audit trail.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/harshsharma/mcp-policy-gateway/internal/audit"
	"github.com/harshsharma/mcp-policy-gateway/internal/authn"
	"github.com/harshsharma/mcp-policy-gateway/internal/downstream"
	"github.com/harshsharma/mcp-policy-gateway/internal/policy"
)

// JSON-RPC 2.0 error codes used by the gateway.
const (
	CodeInvalidParams = -32602
	CodeInternal      = -32603
	CodeAccessDenied  = -32001 // application-defined: policy denied the call
)

// RPCError is a JSON-RPC error returned to the client. Messages are kept
// generic; detailed reasons live only in the audit trail.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *RPCError) Error() string { return e.Message }

// Content is a single MCP content block.
type Content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// CallResult is the MCP tools/call result payload.
type CallResult struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

// ToolInfo is one entry in a tools/list response.
type ToolInfo struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema,omitempty"`
}

// Gateway wires the enforcement pipeline together.
type Gateway struct {
	Policy *policy.Snapshot
	Down   downstream.Downstream
	Audit  audit.Logger
	Now    func() time.Time
}

// New constructs a Gateway with sensible defaults.
func New(pol *policy.Snapshot, down downstream.Downstream, aud audit.Logger) *Gateway {
	return &Gateway{Policy: pol, Down: down, Audit: aud, Now: time.Now}
}

func (g *Gateway) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

// ListTools returns the tools the identity is allowed to see. tools/list is
// filtered by policy so callers never learn about tools they cannot use.
func (g *Gateway) ListTools(id authn.AgentIdentity) []ToolInfo {
	out := make([]ToolInfo, 0)
	for _, t := range g.Down.Tools() {
		dec := g.Policy.Evaluate(policy.Request{Subject: id.Subject, Groups: id.Groups, Tool: t.Name})
		if !dec.Allowed {
			continue
		}
		out = append(out, ToolInfo{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema})
	}
	return out
}

// CallTool runs the full enforcement pipeline for a single tool call.
func (g *Gateway) CallTool(ctx context.Context, id authn.AgentIdentity, requestID, sourceIP, tool string, args map[string]any) (*CallResult, *RPCError) {
	dec := g.Policy.Evaluate(policy.Request{Subject: id.Subject, Groups: id.Groups, Tool: tool})

	// Event 1: the authorization decision, always recorded before dispatch.
	g.Audit.LogDecision(audit.Decision{
		RequestID:     requestID,
		SourceIP:      sourceIP,
		Subject:       id.Subject,
		Issuer:        id.Issuer,
		Groups:        id.Groups,
		Tool:          tool,
		Allowed:       dec.Allowed,
		Effect:        string(dec.Effect),
		Reason:        dec.Reason,
		MatchedAllows: dec.MatchedAllows,
		MatchedDenies: dec.MatchedDenies,
		PolicyDigest:  dec.PolicyDigest,
	})

	if !dec.Allowed {
		// The client gets a generic message; the reason is only in the audit log.
		return nil, &RPCError{Code: CodeAccessDenied, Message: "access denied by policy"}
	}

	start := g.now()
	result, err := g.Down.Call(ctx, tool, args)
	elapsed := g.now().Sub(start)

	if err != nil {
		var unknown *downstream.ErrUnknownTool
		if errors.As(err, &unknown) {
			g.Audit.LogOutcome(audit.Outcome{
				RequestID: requestID, Subject: id.Subject, Tool: tool,
				Status: "error", Error: "unknown_tool",
			}.WithDuration(elapsed))
			return nil, &RPCError{Code: CodeInvalidParams, Message: "unknown tool: " + tool}
		}
		// Downstream execution error: report generically, log detail.
		g.Audit.LogOutcome(audit.Outcome{
			RequestID: requestID, Subject: id.Subject, Tool: tool,
			Status: "error", Error: err.Error(),
		}.WithDuration(elapsed))
		return &CallResult{
			Content: []Content{{Type: "text", Text: "tool execution failed"}},
			IsError: true,
		}, nil
	}

	g.Audit.LogOutcome(audit.Outcome{
		RequestID: requestID, Subject: id.Subject, Tool: tool, Status: "ok",
	}.WithDuration(elapsed))

	return &CallResult{Content: []Content{{Type: "text", Text: marshalText(result)}}}, nil
}

func marshalText(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}
