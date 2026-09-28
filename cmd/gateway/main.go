// Command gateway runs the MCP Policy Gateway: an HTTP + JSON-RPC 2.0 endpoint
// that authenticates callers, enforces allow/deny policy on MCP tool calls,
// forwards allowed calls to downstream tools, and audits every invocation.
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/harshsharma/mcp-policy-gateway/internal/audit"
	"github.com/harshsharma/mcp-policy-gateway/internal/authn"
	"github.com/harshsharma/mcp-policy-gateway/internal/downstream"
	"github.com/harshsharma/mcp-policy-gateway/internal/gateway"
	"github.com/harshsharma/mcp-policy-gateway/internal/policy"
	"github.com/harshsharma/mcp-policy-gateway/internal/ratelimit"
)

func main() {
	var (
		addr       = flag.String("addr", "127.0.0.1:8080", "listen address")
		policyPath = flag.String("policy", "config/policies.yaml", "path to policy file")
		pubKeyPath = flag.String("pubkey", "testdata/keys/demo-ec-public.pem", "PEM ES256 public key of the token issuer")
		issuer     = flag.String("issuer", "https://issuer.demo", "expected token issuer")
		audience   = flag.String("audience", "https://gateway.demo/mcp", "expected token audience")
		leeway     = flag.Duration("leeway", 60*time.Second, "clock-skew tolerance for token validation")
		rps        = flag.Float64("rate", 20, "edge rate limit: requests per second per client IP")
		burst      = flag.Float64("burst", 40, "edge rate limit: burst size per client IP")
		tlsCert    = flag.String("tls-cert", "", "TLS certificate file (enables HTTPS, TLS 1.3+)")
		tlsKey     = flag.String("tls-key", "", "TLS private key file")
	)
	flag.Parse()

	logger := log.New(os.Stderr, "", log.LstdFlags|log.LUTC)

	snap, err := policy.Load(*policyPath)
	if err != nil {
		logger.Fatalf("load policy: %v", err)
	}

	pub, err := authn.LoadECDSAPublicKeyFile(*pubKeyPath)
	if err != nil {
		logger.Fatalf("load public key: %v", err)
	}

	verifier, err := authn.NewJWTVerifier(authn.Config{
		Issuer:    *issuer,
		Audience:  *audience,
		PublicKey: pub,
		Leeway:    *leeway,
	})
	if err != nil {
		logger.Fatalf("build verifier: %v", err)
	}

	auditLog := audit.NewJSONL(os.Stdout, nil)
	gw := gateway.New(snap, downstream.NewMock(), auditLog)
	limiter := ratelimit.New(*rps, *burst, nil)
	srv := gateway.NewServer(gw, verifier, auditLog, limiter)

	mux := http.NewServeMux()
	mux.Handle("/mcp", srv)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	logger.Printf("policy loaded: digest=%s", snap.Digest())

	if *tlsCert != "" && *tlsKey != "" {
		httpSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		logger.Printf("listening on https://%s/mcp (TLS 1.3+)", *addr)
		if err := httpSrv.ListenAndServeTLS(*tlsCert, *tlsKey); err != nil {
			logger.Fatalf("serve: %v", err)
		}
		return
	}

	logger.Printf("listening on http://%s/mcp (plaintext; enable -tls-cert/-tls-key for TLS 1.3 in production)", *addr)
	if err := httpSrv.ListenAndServe(); err != nil {
		logger.Fatalf("serve: %v", err)
	}
}
