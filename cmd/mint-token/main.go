// Command mint-token is a DEMO utility. It generates a demo ES256 key pair and
// mints short-lived JWTs so the gateway can be exercised locally.
//
// This tool stands in for a real credential issuer (an OAuth authorization
// server / internal CA). In production the gateway never sees a private key:
// it loads only the issuer's public key and verifies tokens it receives.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "genkey":
		runGenKey(os.Args[2:])
	case "mint":
		runMint(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `mint-token: demo credential issuer

usage:
  mint-token genkey [-dir testdata/keys]
  mint-token mint   -key testdata/keys/demo-ec-private.pem -sub alice -groups engineering,hr [flags]

mint flags:
  -iss   issuer   (default https://issuer.demo)
  -aud   audience (default https://gateway.demo/mcp)
  -ttl   lifetime (default 15m)
`)
}

func runGenKey(args []string) {
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	dir := fs.String("dir", "testdata/keys", "output directory for the demo key pair")
	_ = fs.Parse(args)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)

	if err := os.MkdirAll(*dir, 0o755); err != nil {
		fatal(err)
	}
	privPath := filepath.Join(*dir, "demo-ec-private.pem")
	pubPath := filepath.Join(*dir, "demo-ec-public.pem")

	writePEM(privPath, "EC PRIVATE KEY", mustBytes(x509.MarshalECPrivateKey(key)), 0o600)
	writePEM(pubPath, "PUBLIC KEY", mustBytes(x509.MarshalPKIXPublicKey(&key.PublicKey)), 0o644)

	fmt.Printf("wrote %s (private, demo only) and %s (public)\n", privPath, pubPath)
}

func runMint(args []string) {
	fs := flag.NewFlagSet("mint", flag.ExitOnError)
	keyPath := fs.String("key", "testdata/keys/demo-ec-private.pem", "PEM ES256 private key")
	iss := fs.String("iss", "https://issuer.demo", "issuer")
	aud := fs.String("aud", "https://gateway.demo/mcp", "audience")
	sub := fs.String("sub", "", "subject (required)")
	groupsCSV := fs.String("groups", "", "comma-separated groups")
	ttl := fs.Duration("ttl", 15*time.Minute, "token lifetime")
	_ = fs.Parse(args)

	if *sub == "" {
		fatal(fmt.Errorf("-sub is required"))
	}

	key := loadPrivateKey(*keyPath)
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":    *iss,
		"aud":    *aud,
		"sub":    *sub,
		"groups": splitGroups(*groupsCSV),
		"iat":    now.Unix(),
		"nbf":    now.Unix(),
		"exp":    now.Add(*ttl).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signed, err := tok.SignedString(key)
	must(err)
	fmt.Println(signed)
}

func loadPrivateKey(path string) *ecdsa.PrivateKey {
	b, err := os.ReadFile(path)
	must(err)
	key, err := jwt.ParseECPrivateKeyFromPEM(b)
	must(err)
	return key
}

func splitGroups(csv string) []string {
	if strings.TrimSpace(csv) == "" {
		return []string{}
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

func writePEM(path, typ string, der []byte, perm os.FileMode) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	must(err)
	defer f.Close()
	must(pem.Encode(f, &pem.Block{Type: typ, Bytes: der}))
}

func mustBytes(b []byte, err error) []byte { must(err); return b }

func must(err error) {
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "mint-token:", err)
	os.Exit(1)
}
