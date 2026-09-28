package authn

import (
	"crypto/ecdsa"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

// LoadECDSAPublicKeyFile reads a PEM-encoded ECDSA public key from disk.
// The gateway only ever loads the PUBLIC key; the private signing key belongs
// to the issuer and must never be present in the gateway's environment.
func LoadECDSAPublicKeyFile(path string) (*ecdsa.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	pub, err := jwt.ParseECPublicKeyFromPEM(b)
	if err != nil {
		return nil, fmt.Errorf("parse EC public key: %w", err)
	}
	return pub, nil
}
