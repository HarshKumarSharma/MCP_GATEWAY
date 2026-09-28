package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testIssuer = "https://issuer.test"
	testAud    = "https://gateway.test/mcp"
)

var fixedNow = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newVerifier(t *testing.T, pub *ecdsa.PublicKey) TokenVerifier {
	t.Helper()
	v, err := NewJWTVerifier(Config{
		Issuer:    testIssuer,
		Audience:  testAud,
		PublicKey: pub,
		Now:       func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

type mintOpts struct {
	iss, aud, sub string
	groups        []string
	nbf, exp      time.Time
	method        jwt.SigningMethod
	none          bool
}

func mint(t *testing.T, key any, o mintOpts) string {
	t.Helper()
	if o.method == nil {
		o.method = jwt.SigningMethodES256
	}
	if o.nbf.IsZero() {
		o.nbf = fixedNow
	}
	if o.exp.IsZero() {
		o.exp = fixedNow.Add(time.Hour)
	}
	var aud jwt.ClaimStrings
	if o.aud != "" {
		aud = jwt.ClaimStrings{o.aud}
	}
	cl := claims{
		Groups: o.groups,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    o.iss,
			Subject:   o.sub,
			Audience:  aud,
			IssuedAt:  jwt.NewNumericDate(fixedNow),
			NotBefore: jwt.NewNumericDate(o.nbf),
			ExpiresAt: jwt.NewNumericDate(o.exp),
		},
	}
	tok := jwt.NewWithClaims(o.method, cl)
	signKey := key
	if o.none {
		signKey = jwt.UnsafeAllowNoneSignatureType
	}
	s, err := tok.SignedString(signKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func wantReason(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with reason %q, got nil", reason)
	}
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *VerifyError, got %T: %v", err, err)
	}
	if ve.Reason != reason {
		t.Fatalf("reason = %q, want %q", ve.Reason, reason)
	}
}

func TestVerifyValid(t *testing.T) {
	key := newKey(t)
	v := newVerifier(t, &key.PublicKey)

	raw := mint(t, key, mintOpts{
		iss: testIssuer, aud: testAud, sub: "alice",
		groups: []string{"engineering", "hr", "engineering"}, // duplicate on purpose
	})
	id, err := v.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.Subject != "alice" || id.Issuer != testIssuer {
		t.Fatalf("identity = %+v", id)
	}
	if want := []string{"engineering", "hr"}; !reflect.DeepEqual(id.Groups, want) {
		t.Fatalf("groups = %v, want %v (deduped + sorted)", id.Groups, want)
	}
}

func TestVerifyFailures(t *testing.T) {
	key := newKey(t)
	other := newKey(t)
	v := newVerifier(t, &key.PublicKey)
	ctx := context.Background()

	t.Run("expired", func(t *testing.T) {
		raw := mint(t, key, mintOpts{iss: testIssuer, aud: testAud, sub: "a", exp: fixedNow.Add(-time.Minute)})
		_, err := v.Verify(ctx, raw)
		wantReason(t, err, ReasonExpired)
	})
	t.Run("not yet valid", func(t *testing.T) {
		raw := mint(t, key, mintOpts{iss: testIssuer, aud: testAud, sub: "a", nbf: fixedNow.Add(time.Hour), exp: fixedNow.Add(2 * time.Hour)})
		_, err := v.Verify(ctx, raw)
		wantReason(t, err, ReasonNotYetValid)
	})
	t.Run("wrong issuer", func(t *testing.T) {
		raw := mint(t, key, mintOpts{iss: "https://evil", aud: testAud, sub: "a"})
		_, err := v.Verify(ctx, raw)
		wantReason(t, err, ReasonIssuerMismatch)
	})
	t.Run("wrong audience", func(t *testing.T) {
		raw := mint(t, key, mintOpts{iss: testIssuer, aud: "https://other/mcp", sub: "a"})
		_, err := v.Verify(ctx, raw)
		wantReason(t, err, ReasonAudienceMismatch)
	})
	t.Run("missing sub", func(t *testing.T) {
		raw := mint(t, key, mintOpts{iss: testIssuer, aud: testAud, sub: ""})
		_, err := v.Verify(ctx, raw)
		wantReason(t, err, ReasonClaimsInvalid)
	})
	t.Run("bad signature", func(t *testing.T) {
		raw := mint(t, other, mintOpts{iss: testIssuer, aud: testAud, sub: "a"})
		_, err := v.Verify(ctx, raw)
		wantReason(t, err, ReasonSignatureInvalid)
	})
	t.Run("alg none rejected", func(t *testing.T) {
		raw := mint(t, nil, mintOpts{iss: testIssuer, aud: testAud, sub: "a", method: jwt.SigningMethodNone, none: true})
		if _, err := v.Verify(ctx, raw); err == nil {
			t.Fatal("expected alg=none to be rejected")
		}
	})
	t.Run("malformed", func(t *testing.T) {
		_, err := v.Verify(ctx, "not.a.jwt")
		wantReason(t, err, ReasonMalformed)
	})
	t.Run("empty", func(t *testing.T) {
		_, err := v.Verify(ctx, "")
		wantReason(t, err, ReasonMalformed)
	})
}

// A token expired within the leeway window is still accepted.
func TestVerifyLeeway(t *testing.T) {
	key := newKey(t)
	v, err := NewJWTVerifier(Config{
		Issuer: testIssuer, Audience: testAud, PublicKey: &key.PublicKey,
		Leeway: 30 * time.Second, Now: func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := mint(t, key, mintOpts{iss: testIssuer, aud: testAud, sub: "a", exp: fixedNow.Add(-10 * time.Second)})
	if _, err := v.Verify(context.Background(), raw); err != nil {
		t.Fatalf("token within leeway should verify: %v", err)
	}
}
