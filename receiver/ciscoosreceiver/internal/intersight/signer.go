// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package intersight

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

type signer interface {
	algorithm() string
	sign(payload []byte) ([]byte, error)
}

type rsaSigner struct {
	key *rsa.PrivateKey
}

func (s rsaSigner) algorithm() string {
	return "rsa-sha256"
}

func (s rsaSigner) sign(payload []byte) ([]byte, error) {
	digest := sha256.Sum256(payload)
	return rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
}

type ecdsaSigner struct {
	key *ecdsa.PrivateKey
}

func (s ecdsaSigner) algorithm() string {
	return "hs2019"
}

func (s ecdsaSigner) sign(payload []byte) ([]byte, error) {
	digest := sha256.Sum256(payload)
	return ecdsa.SignASN1(rand.Reader, s.key, digest[:])
}

type ed25519Signer struct {
	key ed25519.PrivateKey
}

func (s ed25519Signer) algorithm() string {
	return "ed25519"
}

func (s ed25519Signer) sign(payload []byte) ([]byte, error) {
	return ed25519.Sign(s.key, payload), nil
}

func newSigner(keyPEM, keyFile string) (signer, error) {
	if keyPEM == "" && keyFile == "" {
		return nil, errors.New("intersight private key is required")
	}
	if keyPEM == "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("read intersight key file: %w", err)
		}
		keyPEM = string(data)
	}

	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New("decode intersight PEM private key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return rsaSigner{key: key}, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return ecdsaSigner{key: key}, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse intersight private key: %w", err)
	}
	switch typed := key.(type) {
	case *rsa.PrivateKey:
		return rsaSigner{key: typed}, nil
	case *ecdsa.PrivateKey:
		return ecdsaSigner{key: typed}, nil
	case ed25519.PrivateKey:
		return ed25519Signer{key: typed}, nil
	default:
		return nil, fmt.Errorf("unsupported intersight private key type %T", key)
	}
}
