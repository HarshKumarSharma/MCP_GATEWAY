package gateway

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/harshsharma/mcp-policy-gateway/internal/audit"
	"github.com/harshsharma/mcp-policy-gateway/internal/authn"
	"github.com/harshsharma/mcp-policy-gateway/internal/downstream"
	"github.com/harshsharma/mcp-policy-gateway/internal/policy"
	"github.com/harshsharma/mcp-policy-gateway/internal/ratelimit"
)

const (
	testIssuer = "https://issuer.test"
	testAud    = "https://gateway.test/mcp"
)

var fixedNow = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

type harness struct {
	ts    *httptest.Server
	key   *ecdsa.PrivateKey
	audit *bytes.Buffer
}

func setup(t *testing.T, snap *policy.Snapshot) *harness {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	auditLog := audit.NewJSONL(buf, func() time.Time { return fixedNow })
	verifier, err := authn.NewJWTVerifier(authn.Config{
		Issuer: testIssuer, Audience: testAud,
		PublicKey: &key.PublicKey, Now: func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	gw := New(snap, downstream.NewMock(), auditLog)
	gw.Now = func() time.Time { return fixedNow }
	limiter := ratelimit.New(1000, 1000, nil)
	srv := NewServer(gw, verifier, auditLog, limiter)

	mux := http.NewServeMux()
	mux.Handle("/mcp", srv)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return &harness{ts: ts, key: key, audit: buf}
}

func loadSamplePolicy(t *testing.T) *policy.Snapshot {
	t.Helper()
	snap, err := policy.Load("../../config/policies.yaml")
	if err != nil {
		t.Fatalf("load sample policy: %v", err)
	}
	return snap
}

func (h *harness) token(t *testing.T, sub string, groups []string) string {
	t.Helper()
	cl := jwt.MapClaims{
		"iss": testIssuer, "aud": testAud, "sub": sub, "groups": groups,
		"iat": fixedNow.Unix(), "nbf": fixedNow.Unix(), "exp": fixedNow.Add(time.Hour).Unix(),
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodES256, cl).SignedString(h.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   *RPCError       `json:"error"`
}

func (h *harness) rpc(t *testing.T, token, method string, params any) (int, rpcResp) {
	t.Helper()
	body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method}
	if params != nil {
		body["params"] = params
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/mcp", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out rpcResp
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func (h *harness) auditEvents(t *testing.T) []map[string]any {
	t.Helper()
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(h.audit.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad audit line %q: %v", line, err)
		}
		events = append(events, m)
	}
	return events
}

func TestToolsListFilteredByPolicy(t *testing.T) {
	h := setup(t, loadSamplePolicy(t))
	tok := h.token(t, "alice", []string{"engineering"})

	status, resp := h.rpc(t, tok, "tools/list", nil)
	if status != http.StatusOK || resp.Error != nil {
		t.Fatalf("status=%d err=%v", status, resp.Error)
	}
	var res struct {
		Tools []ToolInfo `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, tl := range res.Tools {
		got[tl.Name] = true
	}
	if !got["github.list_repositories"] || !got["github.create_issue"] {
		t.Fatalf("engineering should see read/create tools, got %v", got)
	}
	if got["github.delete_repository"] {
		t.Fatalf("engineering must NOT see denied delete tool")
	}
	if got["payroll.get_employee"] {
		t.Fatalf("engineering must NOT see hr-only payroll tool")
	}
}

func TestCallAllowed(t *testing.T) {
	h := setup(t, loadSamplePolicy(t))
	tok := h.token(t, "alice", []string{"engineering"})

	status, resp := h.rpc(t, tok, "tools/call", map[string]any{
		"name":      "github.create_issue",
		"arguments": map[string]any{"repo": "acme/docs", "title": "hello"},
	})
	if status != http.StatusOK || resp.Error != nil {
		t.Fatalf("status=%d err=%v", status, resp.Error)
	}

	ev := h.auditEvents(t)
	if len(ev) != 2 {
		t.Fatalf("expected 2 audit events (decision+outcome), got %d: %v", len(ev), ev)
	}
	if ev[0]["event"] != audit.EventDecision || ev[0]["allowed"] != true {
		t.Fatalf("first event should be an allow decision: %v", ev[0])
	}
	if ev[1]["event"] != audit.EventOutcome || ev[1]["status"] != "ok" {
		t.Fatalf("second event should be an ok outcome: %v", ev[1])
	}
}

func TestCallDeniedByPolicy(t *testing.T) {
	h := setup(t, loadSamplePolicy(t))
	tok := h.token(t, "alice", []string{"engineering"})

	status, resp := h.rpc(t, tok, "tools/call", map[string]any{
		"name": "github.delete_repository", "arguments": map[string]any{"repo": "acme/docs"},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	if resp.Error == nil || resp.Error.Code != CodeAccessDenied {
		t.Fatalf("expected access-denied error, got %+v", resp.Error)
	}
	// Client message must be generic; the detailed reason lives in the audit log.
	if strings.Contains(strings.ToLower(resp.Error.Message), "deny_overrides") {
		t.Fatalf("client message leaked internal reason: %q", resp.Error.Message)
	}
	ev := h.auditEvents(t)
	if len(ev) != 1 || ev[0]["allowed"] != false {
		t.Fatalf("expected a single deny decision, got %v", ev)
	}
	if ev[0]["reason"] == "" {
		t.Fatalf("audit decision must record a reason")
	}
}

func TestRepositoryAdminCanDelete(t *testing.T) {
	h := setup(t, loadSamplePolicy(t))
	tok := h.token(t, "root", []string{"repository-admin"})

	status, resp := h.rpc(t, tok, "tools/call", map[string]any{
		"name": "github.delete_repository", "arguments": map[string]any{"repo": "acme/docs"},
	})
	if status != http.StatusOK || resp.Error != nil {
		t.Fatalf("repository-admin should delete: status=%d err=%v", status, resp.Error)
	}
}

func TestUnauthenticated(t *testing.T) {
	h := setup(t, loadSamplePolicy(t))

	status, resp := h.rpc(t, "", "tools/call", map[string]any{"name": "github.list_repositories"})
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", status)
	}
	if resp.Error == nil || resp.Error.Message != "unauthorized" {
		t.Fatalf("expected generic unauthorized, got %+v", resp.Error)
	}
	ev := h.auditEvents(t)
	if len(ev) != 1 || ev[0]["allowed"] != false {
		t.Fatalf("auth failure should be audited as denied: %v", ev)
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	h := setup(t, loadSamplePolicy(t))
	cl := jwt.MapClaims{
		"iss": testIssuer, "aud": testAud, "sub": "alice", "groups": []string{"engineering"},
		"iat": fixedNow.Add(-2 * time.Hour).Unix(), "nbf": fixedNow.Add(-2 * time.Hour).Unix(),
		"exp": fixedNow.Add(-time.Hour).Unix(),
	}
	tok, _ := jwt.NewWithClaims(jwt.SigningMethodES256, cl).SignedString(h.key)

	status, _ := h.rpc(t, tok, "tools/list", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired token, got %d", status)
	}
	ev := h.auditEvents(t)
	if len(ev) != 1 || ev[0]["reason"] != authn.ReasonExpired {
		t.Fatalf("expected token_expired reason in audit, got %v", ev)
	}
}

func TestUnknownToolWhenAllowed(t *testing.T) {
	// A policy that allows everything for group "admin" lets us reach the
	// downstream with a tool it does not serve, exercising the unknown-tool path.
	snap, err := policy.Parse(strings.NewReader(`
version: 1
defaults: {effect: deny, conflict_resolution: deny_overrides}
policies:
  - id: admin-all
    groups: [admin]
    tools: ["*"]
    effect: allow
`))
	if err != nil {
		t.Fatal(err)
	}
	h := setup(t, snap)
	tok := h.token(t, "root", []string{"admin"})

	status, resp := h.rpc(t, tok, "tools/call", map[string]any{"name": "github.does_not_exist"})
	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	if resp.Error == nil || resp.Error.Code != CodeInvalidParams {
		t.Fatalf("expected invalid-params for unknown tool, got %+v", resp.Error)
	}
}

// Guard against accidentally shipping a broken sample policy file.
func TestSamplePolicyLoads(t *testing.T) {
	if _, err := os.Stat("../../config/policies.yaml"); err != nil {
		t.Fatalf("sample policy missing: %v", err)
	}
	loadSamplePolicy(t)
}
