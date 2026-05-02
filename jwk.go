package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

type JWK struct {
	Kty    string   `json:"kty"`
	Crv    string   `json:"crv,omitempty"`
	X      string   `json:"x,omitempty"`
	Y      string   `json:"y,omitempty"`
	D      string   `json:"d,omitempty"`
	Alg    string   `json:"alg,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`
}

func b64dec(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
func b64enc(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }

func curveByName(n string) elliptic.Curve {
	switch n {
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	}
	return nil
}

func defaultAlg(crv string) string {
	switch crv {
	case "P-256":
		return "ES256"
	case "P-384":
		return "ES384"
	case "P-521":
		return "ES512"
	}
	return ""
}

func (j *JWK) PublicKey() (*ecdsa.PublicKey, error) {
	c := curveByName(j.Crv)
	if c == nil {
		return nil, errors.New("unsupported curve: " + j.Crv)
	}
	xb, err := b64dec(j.X)
	if err != nil {
		return nil, err
	}
	yb, err := b64dec(j.Y)
	if err != nil {
		return nil, err
	}
	x, y := new(big.Int).SetBytes(xb), new(big.Int).SetBytes(yb)
	if !c.IsOnCurve(x, y) {
		return nil, errors.New("point not on curve")
	}
	return &ecdsa.PublicKey{Curve: c, X: x, Y: y}, nil
}

func (j *JWK) PrivateScalar() (*big.Int, error) {
	if j.D == "" {
		return nil, errors.New("no private scalar")
	}
	db, err := b64dec(j.D)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(db), nil
}

// RFC 7638 thumbprint for EC keys (SHA-256, base64url, no padding).
// Manual JSON build to avoid relying on map-key ordering in TinyGo's encoder.
func (j *JWK) Thumbprint() string {
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, j.Crv, j.Kty, j.X, j.Y)
	h := sha256.Sum256([]byte(canonical))
	return b64enc(h[:])
}

// Public returns a copy with the private scalar stripped.
func (j *JWK) Public() *JWK {
	c := *j
	c.D = ""
	return &c
}

func (j *JWK) HasOp(op string) bool {
	for _, o := range j.KeyOps {
		if o == op {
			return true
		}
	}
	return false
}

func padLeft(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}
