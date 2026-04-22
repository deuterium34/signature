package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// Cоздает подпись данных
func Sign(data []byte, key PrivateKey) (Signature, error) {
	hash := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, key.key, hash[:])
}

// Проверяет подлинность подписи
func Verify(data []byte, key PublicKey, sig Signature) bool {
	hash := sha256.Sum256(data)
	return ecdsa.VerifyASN1(key.key, hash[:], sig)
}

// Создает публичный и приватный ключи
func GenerateKeys() (PublicKey, PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return PublicKey{}, PrivateKey{}, fmt.Errorf("gen key: %w", err)
	}
	return PublicKey{&priv.PublicKey}, PrivateKey{priv}, nil
}
