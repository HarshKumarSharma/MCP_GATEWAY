package authn

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Reason codes are recorded in the audit trail. They are intentionally NOT
// returned to the client, which sees only a generic "unauthorized".
const (
	ReasonMalformed         = "token_malformed"
	ReasonSignatureInvalid  = "signature_invalid"
	ReasonExpired           = "token_expired"
	ReasonNotYetValid       = "token_not_yet_valid"
	ReasonIssuerMismatch    = "issuer_mismatch"
	ReasonAudienceMismatch  = "audience_mismatch"
	ReasonAlgorithmRejected = "algorithm_rejected"
	ReasonClaimsInvalid     = "claims_invalid"
)

// VerifyError carries an audit-friendly reason code alongside the underlying
// error. The gateway logs Reason and returns a generic error to the client.
type VerifyError struct {
	Reason string
	Err    error
}

func (e *VerifyError) Error() string {
	if e.Err == nil {
		return e.Reason
	}
	return e.Reason + ": " + e.Err.Error()
}

func (e *VerifyError) Unwrap() error { return e.Err }

// TokenVerifier turns a raw credential into a verified AgentIdentity.
type TokenVerifier interface {
	Verify(ctx context.Context, raw string) (AgentIdentity, error)
}

// Config configures the JWT verifier. Secrets/keys are supplied by the caller
// (loaded from files/env), never hardcoded.
type Config struct {
	Issuer      string
	Audience    string
	Algorithms  []string // allowlist; defaults to ["ES256"]
	PublicKey   *ecdsa.PublicKey
	Leeway      time.Duration    // clock-skew tolerance
	MaxGroups   int              // defaults to 64
	MaxGroupLen int              // defaults to 256
	Now         func() time.Time // injectable clock; defaults to time.Now
}

type jwtVerifier struct {
	cfg Config
}

type claims struct {
	Groups []string `json:"groups"`
	jwt.RegisteredClaims
}

// NewJWTVerifier validates configuration and returns a TokenVerifier.
func NewJWTVerifier(cfg Config) (TokenVerifier, error) {
	if cfg.PublicKey == nil {
		return nil, errors.New("authn: public key required")
	}
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("authn: issuer and audience are required")
	}
	if len(cfg.Algorithms) == 0 {
		cfg.Algorithms = []string{"ES256"}
	}
	if cfg.MaxGroups == 0 {
		cfg.MaxGroups = 64
	}
	if cfg.MaxGroupLen == 0 {
		cfg.MaxGroupLen = 256
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &jwtVerifier{cfg: cfg}, nil
}

func (v *jwtVerifier) Verify(_ context.Context, raw string) (AgentIdentity, error) {
	if raw == "" {
		return AgentIdentity{}, &VerifyError{Reason: ReasonMalformed, Err: errors.New("empty token")}
	}

	var cl claims
	opts := []jwt.ParserOption{
		jwt.WithValidMethods(v.cfg.Algorithms), // rejects alg=none and any non-allowlisted alg
		jwt.WithIssuer(v.cfg.Issuer),
		jwt.WithAudience(v.cfg.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(v.cfg.Leeway),
		jwt.WithTimeFunc(v.cfg.Now),
	}
	keyFunc := func(t *jwt.Token) (any, error) {
		// Defense in depth: only ECDSA keys, guarding against alg/key confusion.
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, &VerifyError{Reason: ReasonAlgorithmRejected,
				Err: fmt.Errorf("unexpected signing method %q", t.Method.Alg())}
		}
		return v.cfg.PublicKey, nil
	}

	if _, err := jwt.ParseWithClaims(raw, &cl, keyFunc, opts...); err != nil {
		return AgentIdentity{}, mapErr(err)
	}

	if cl.Subject == "" {
		return AgentIdentity{}, &VerifyError{Reason: ReasonClaimsInvalid, Err: errors.New("missing sub")}
	}
	if len(cl.Groups) > v.cfg.MaxGroups {
		return AgentIdentity{}, &VerifyError{Reason: ReasonClaimsInvalid,
			Err: fmt.Errorf("too many groups (%d > %d)", len(cl.Groups), v.cfg.MaxGroups)}
	}
	groups, err := normalizeGroups(cl.Groups, v.cfg.MaxGroupLen)
	if err != nil {
		return AgentIdentity{}, &VerifyError{Reason: ReasonClaimsInvalid, Err: err}
	}

	return AgentIdentity{Subject: cl.Subject, Issuer: cl.Issuer, Groups: groups}, nil
}

// normalizeGroups deduplicates and sorts groups, rejecting empty or oversized
// entries. A missing groups claim yields an empty set (which default-denies).
func normalizeGroups(in []string, maxLen int) ([]string, error) {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, g := range in {
		if g == "" {
			return nil, errors.New("empty group name")
		}
		if len(g) > maxLen {
			return nil, fmt.Errorf("group name exceeds %d bytes", maxLen)
		}
		if seen[g] {
			continue
		}
		seen[g] = true
		out = append(out, g)
	}
	sort.Strings(out)
	return out, nil
}

func mapErr(err error) error {
	var ve *VerifyError
	if errors.As(err, &ve) {
		return ve
	}
	switch {
	case errors.Is(err, jwt.ErrTokenMalformed):
		return &VerifyError{Reason: ReasonMalformed, Err: err}
	case errors.Is(err, jwt.ErrTokenExpired):
		return &VerifyError{Reason: ReasonExpired, Err: err}
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return &VerifyError{Reason: ReasonNotYetValid, Err: err}
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return &VerifyError{Reason: ReasonIssuerMismatch, Err: err}
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return &VerifyError{Reason: ReasonAudienceMismatch, Err: err}
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return &VerifyError{Reason: ReasonSignatureInvalid, Err: err}
	default:
		return &VerifyError{Reason: ReasonSignatureInvalid, Err: err}
	}
}
