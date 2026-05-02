package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Keyset struct {
	// Sign: private signing keys whose public half is advertised.
	Sign []*JWK
	// Exchange: private deriveKey keys (used in /rec). Hidden ones are
	// still usable for recovery but are not advertised.
	Exchange []*JWK
	// AdvPub: public JWKs to include in the advertisement payload.
	AdvPub []*JWK
}

func loadKeys(dir string) (*Keyset, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	ks := &Keyset{}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".jwk") {
			continue
		}
		hidden := strings.HasPrefix(name, ".")

		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", path, err)
			continue
		}
		jwk := &JWK{}
		if err := json.Unmarshal(data, jwk); err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", path, err)
			continue
		}
		if jwk.Kty != "EC" || jwk.D == "" {
			continue
		}

		sign, deriv := classify(jwk)

		if sign && !hidden {
			ks.Sign = append(ks.Sign, jwk)
			ks.AdvPub = append(ks.AdvPub, jwk.Public())
		}
		if deriv {
			ks.Exchange = append(ks.Exchange, jwk)
			if !hidden {
				ks.AdvPub = append(ks.AdvPub, jwk.Public())
			}
		}
	}
	return ks, nil
}

func classify(j *JWK) (sign, deriv bool) {
	if len(j.KeyOps) > 0 {
		return j.HasOp("sign"), j.HasOp("deriveKey")
	}
	switch j.Alg {
	case "ES256", "ES384", "ES512":
		return true, false
	case "ECMR":
		return false, true
	}
	// no hints: be permissive
	return true, true
}

func (ks *Keyset) FindExchange(thumbprint string) *JWK {
	for _, k := range ks.Exchange {
		if k.Thumbprint() == thumbprint {
			return k
		}
	}
	return nil
}

func (ks *Keyset) FindSigner(thumbprint string) *JWK {
	if thumbprint == "" {
		if len(ks.Sign) > 0 {
			return ks.Sign[0]
		}
		return nil
	}
	for _, k := range ks.Sign {
		if k.Thumbprint() == thumbprint {
			return k
		}
	}
	return nil
}
