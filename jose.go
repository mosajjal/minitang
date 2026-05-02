package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
)

// signJWS produces a flattened JWS over payload using the given EC private JWK.
// Returns the serialized JSON object.
func signJWS(payload []byte, signer *JWK) ([]byte, error) {
	alg := signer.Alg
	if alg == "" {
		alg = defaultAlg(signer.Crv)
	}
	if alg == "" {
		return nil, errors.New("cannot determine signing alg")
	}

	// Manual header JSON for stable byte representation.
	protected := fmt.Sprintf(`{"alg":%q,"cty":"jwk-set+json"}`, alg)
	h64 := b64enc([]byte(protected))
	p64 := b64enc(payload)
	signing := h64 + "." + p64

	pub, err := signer.PublicKey()
	if err != nil {
		return nil, err
	}
	d, err := signer.PrivateScalar()
	if err != nil {
		return nil, err
	}
	priv := &ecdsa.PrivateKey{PublicKey: *pub, D: d}

	var hash []byte
	switch alg {
	case "ES256":
		s := sha256.Sum256([]byte(signing))
		hash = s[:]
	case "ES384":
		s := sha512.Sum384([]byte(signing))
		hash = s[:]
	case "ES512":
		s := sha512.Sum512([]byte(signing))
		hash = s[:]
	default:
		return nil, errors.New("unsupported alg: " + alg)
	}

	r, s, err := ecdsa.Sign(rand.Reader, priv, hash)
	if err != nil {
		return nil, err
	}

	byteLen := (priv.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*byteLen)
	copy(sig[:byteLen], padLeft(r.Bytes(), byteLen))
	copy(sig[byteLen:], padLeft(s.Bytes(), byteLen))

	out := map[string]string{
		"payload":   p64,
		"protected": h64,
		"signature": b64enc(sig),
	}
	return json.Marshal(out)
}

// recoverKey performs the McCallum-Relyea exchange step on the server side:
// multiply the client-supplied point by the server's private scalar and
// return the resulting EC public point as a JWK.
func recoverKey(priv *JWK, req *JWK) (*JWK, error) {
	if priv.Crv != req.Crv {
		return nil, errors.New("curve mismatch")
	}
	c := curveByName(priv.Crv)
	if c == nil {
		return nil, errors.New("unsupported curve")
	}
	pub, err := req.PublicKey() // also checks IsOnCurve
	if err != nil {
		return nil, err
	}
	d, err := priv.PrivateScalar()
	if err != nil {
		return nil, err
	}

	// ScalarMult is deprecated in modern Go but is the only stdlib way to
	// recover both coordinates of the resulting point. crypto/ecdh hides Y.
	rx, ry := c.ScalarMult(pub.X, pub.Y, d.Bytes())

	byteLen := (c.Params().BitSize + 7) / 8
	return &JWK{
		Kty:    "EC",
		Crv:    priv.Crv,
		X:      b64enc(padLeft(rx.Bytes(), byteLen)),
		Y:      b64enc(padLeft(ry.Bytes(), byteLen)),
		Alg:    "ECMR",
		KeyOps: []string{"deriveKey"},
	}, nil
}
