package signature

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

// --- Методы для PrivateKey ---

func (k *PrivateKey) Encode(w io.Writer) error {
	der, err := x509.MarshalECPrivateKey(k.key)
	if err != nil {
		return fmt.Errorf("marshal ec private key: %w", err)
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}
	return pem.Encode(w, block)
}

func (k *PrivateKey) Decode(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return errors.New("invalid private key PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	k.key = key
	return nil
}

// --- Методы для PublicKey ---

func (k *PublicKey) Encode(w io.Writer) error {
	der, err := x509.MarshalPKIXPublicKey(k.key)
	if err != nil {
		return fmt.Errorf("marshal pkix public key: %w", err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return pem.Encode(w, block)
}

func (k *PublicKey) Decode(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New("invalid public key PEM")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("not an ECDSA public key")
	}
	k.key = pub
	return nil
}

// --- Методы для Signature ---

func (s *Signature) Encode(w io.Writer) error {
	block := &pem.Block{
		Type:  "ECDSA SIGNATURE",
		Bytes: *s,
	}
	return pem.Encode(w, block)
}

func (s *Signature) Decode(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "ECDSA SIGNATURE" {
		return errors.New("invalid signature PEM")
	}

	*s = block.Bytes
	return nil
}
