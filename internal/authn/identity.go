// Package authn verifies the caller's credential (a JWT) and produces a
// verified AgentIdentity. It is the only place raw credentials are handled;
// every other component consumes the verified identity.
//
// Verification is exposed behind the TokenVerifier interface so the identity
// source can later become an X.509 / SPIFFE SVID or verifiable credential
// without touching the policy layer.
package authn

// AgentIdentity is the verified caller. It is the only identity value that
// crosses the authentication boundary.
type AgentIdentity struct {
	Subject string
	Issuer  string
	Groups  []string
}
