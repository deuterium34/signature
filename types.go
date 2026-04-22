package signature

import (
	"crypto/ecdsa"
)

// Цифровая подпись
type Signature []byte

type PublicKey struct {
	key *ecdsa.PublicKey
}

type PrivateKey struct {
	key *ecdsa.PrivateKey
}
