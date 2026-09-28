package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/harshsharma/mcp-policy-gateway/internal/audit"
	"github.com/harshsharma/mcp-policy-gateway/internal/authn"
	"github.com/harshsharma/mcp-policy-gateway/internal/ratelimit"
)

// jsonrpcVersion is the only supported JSON-RPC version.
const jsonrpcVersion = "2.0"

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

type callParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// Server adapts the Gateway to an HTTP + JSON-RPC 2.0 transport.
type Server struct {
	gw       *Gateway
	verifier authn.TokenVerifier
	audit    audit.Logger
	limiter  *ratelimit.Limiter
	now      func() time.Time
	newID    func() string
}

// NewServer builds an HTTP transport for the gateway.
func NewServer(gw *Gateway, verifier authn.TokenVerifier, aud audit.Logger, limiter *ratelimit.Limiter) *Server {
	return &Server{
		gw:       gw,
		verifier: verifier,
		audit:    aud,
		limiter:  limiter,
		now:      time.Now,
		newID:    newRequestID,
	}
}

// ServeHTTP handles a single JSON-RPC request over HTTP POST.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := clientIP(r)

	// Edge rate limit: applied before authentication so unauthenticated floods
	// are shed cheaply.
	if s.limiter != nil && !s.limiter.Allow(ip) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	var req rpcRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.JSONRPC != jsonrpcVersion {
		writeRPC(w, http.StatusBadRequest, rpcResponse{
			JSONRPC: jsonrpcVersion,
			Error:   &RPCError{Code: -32700, Message: "parse error"},
		})
		return
	}

	requestID := s.newID()

	switch req.Method {
	case "initialize":
		writeRPC(w, http.StatusOK, rpcResponse{
			JSONRPC: jsonrpcVersion, ID: req.ID,
			Result: map[string]any{
				"protocolVersion": "2025-06-18",
				"serverInfo":      map[string]any{"name": "mcp-policy-gateway", "version": "0.1.0"},
				"capabilities":    map[string]any{"tools": map[string]any{}},
			},
		})
		return

	case "tools/list", "tools/call":
		// Both require an authenticated caller.
		id, ok := s.authenticate(w, r, requestID, ip, methodTool(req.Method))
		if !ok {
			return
		}
		if req.Method == "tools/list" {
			writeRPC(w, http.StatusOK, rpcResponse{
				JSONRPC: jsonrpcVersion, ID: req.ID,
				Result: map[string]any{"tools": s.gw.ListTools(id)},
			})
			return
		}
		s.handleCall(w, r, req, requestID, ip, id)
		return

	default:
		writeRPC(w, http.StatusOK, rpcResponse{
			JSONRPC: jsonrpcVersion, ID: req.ID,
			Error: &RPCError{Code: -32601, Message: "method not found"},
		})
	}
}

func (s *Server) handleCall(w http.ResponseWriter, r *http.Request, req rpcRequest, requestID, ip string, id authn.AgentIdentity) {
	var p callParams
	if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
		writeRPC(w, http.StatusOK, rpcResponse{
			JSONRPC: jsonrpcVersion, ID: req.ID,
			Error: &RPCError{Code: CodeInvalidParams, Message: "invalid params: name is required"},
		})
		return
	}

	result, rpcErr := s.gw.CallTool(r.Context(), id, requestID, ip, p.Name, p.Arguments)
	if rpcErr != nil {
		writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: rpcErr})
		return
	}
	writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Result: result})
}

// authenticate extracts and verifies the bearer token. On failure it records an
// authorization_decision (denied) and writes HTTP 401, returning ok=false.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, requestID, ip, tool string) (authn.AgentIdentity, bool) {
	raw := bearerToken(r)
	id, err := s.verifier.Verify(r.Context(), raw)
	if err != nil {
		reason := "unauthorized"
		var ve *authn.VerifyError
		if errors.As(err, &ve) {
			reason = ve.Reason
		}
		s.audit.LogDecision(audit.Decision{
			RequestID: requestID, SourceIP: ip, Tool: tool,
			Allowed: false, Effect: "deny", Reason: reason,
		})
		// Generic message to the client; specific reason only in the audit log.
		w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-policy-gateway"`)
		writeRPC(w, http.StatusUnauthorized, rpcResponse{
			JSONRPC: jsonrpcVersion,
			Error:   &RPCError{Code: CodeAccessDenied, Message: "unauthorized"},
		})
		return authn.AgentIdentity{}, false
	}
	return id, true
}

func methodTool(method string) string {
	if method == "tools/list" {
		return "tools/list"
	}
	return ""
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// clientIP returns the peer address (host only). X-Forwarded-For is intentionally
// NOT trusted here because it is client-controlled; a real deployment would honor
// it only from a trusted proxy.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func writeRPC(w http.ResponseWriter, status int, resp rpcResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}
