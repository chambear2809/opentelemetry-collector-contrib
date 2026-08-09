// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/ise"

import (
	"crypto/cipher"
	"crypto/des"  // #nosec G502 -- RFC 7292 and Cisco ISE fix this legacy key-file PBE to three-key Triple DES.
	"crypto/sha1" // #nosec G505 -- RFC 7292 requires SHA-1 for this legacy Cisco ISE key format.
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/youmark/pkcs8"
)

const (
	maxEncryptedPKCS8Bytes  = 64 * 1024
	maxPKCS8ParametersBytes = 256
	maxPKCS12PasswordBytes  = 1024
	maxPKCS12SaltBytes      = 64
	maxPKCS12Iterations     = 1_000_000
	pkcs12SHA1BlockSize     = 64
)

var (
	oidPBES2                       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2                      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidPBEWithSHA1And3KeyTripleDES = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
	oidAES128CBC                   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC                   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC                   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	errInvalidEncryptedPKCS8       = errors.New("invalid encrypted PKCS#8 private key")
	errUnsupportedPKCS8Encryption  = errors.New("unsupported encrypted PKCS#8 algorithm")
)

type encryptedPrivateKeyInfo struct {
	EncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

type pkcs12PBEParameters struct {
	Salt       []byte
	Iterations int
}

type pbes2Parameters struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}

type pbkdf2Parameters struct {
	Salt       []byte
	Iterations int
	KeyLength  int                      `asn1:"optional"`
	PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
}

// parseEncryptedPKCS8PrivateKey accepts modern PBES2 keys and the legacy
// PKCS#12 PBE emitted by Cisco ISE 3.4. The latter is defined by RFC 7292 and
// uses SHA-1 and three-key Triple DES; it is supported for key-file
// interoperability only, not for creating new encrypted material.
func parseEncryptedPKCS8PrivateKey(der, password []byte) (any, error) {
	if len(der) == 0 || len(der) > maxEncryptedPKCS8Bytes || len(password) > maxPKCS12PasswordBytes {
		return nil, errInvalidEncryptedPKCS8
	}

	var info encryptedPrivateKeyInfo
	remainder, err := asn1.Unmarshal(der, &info)
	if err != nil || len(remainder) != 0 || len(info.EncryptedData) == 0 {
		return nil, errInvalidEncryptedPKCS8
	}
	if len(info.EncryptionAlgorithm.Parameters.FullBytes) > maxPKCS8ParametersBytes {
		return nil, errInvalidEncryptedPKCS8
	}

	switch {
	case info.EncryptionAlgorithm.Algorithm.Equal(oidPBES2):
		if validatePBES2Parameters(info.EncryptionAlgorithm.Parameters.FullBytes, info.EncryptedData) != nil {
			return nil, errInvalidEncryptedPKCS8
		}
		privateKey, parseErr := pkcs8.ParsePKCS8PrivateKey(der, password)
		if parseErr != nil {
			return nil, errInvalidEncryptedPKCS8
		}
		return privateKey, nil
	case info.EncryptionAlgorithm.Algorithm.Equal(oidPBEWithSHA1And3KeyTripleDES):
		decrypted, decryptErr := decryptPKCS12TripleDES(info, password)
		if decryptErr != nil {
			return nil, errInvalidEncryptedPKCS8
		}
		decryptedLen := len(decrypted)
		decryptedCap := cap(decrypted)
		decryptedBase := decrypted[:decryptedCap]
		defer clear(decryptedBase)

		privateKey, parseErr := x509.ParsePKCS8PrivateKey(decrypted[:decryptedLen])
		if parseErr != nil {
			return nil, errInvalidEncryptedPKCS8
		}
		return privateKey, nil
	default:
		return nil, errUnsupportedPKCS8Encryption
	}
}

// validatePBES2Parameters prevents attacker-controlled local key material from
// requesting unbounded KDF work inside the third-party parser. PBKDF2 is the
// PBES2 KDF emitted by OpenSSL and supported here; other KDFs are rejected
// rather than delegated without comparable resource bounds.
func validatePBES2Parameters(parametersDER, encryptedData []byte) error {
	if len(parametersDER) == 0 || len(parametersDER) > maxPKCS8ParametersBytes {
		return errInvalidEncryptedPKCS8
	}

	var parameters pbes2Parameters
	remainder, err := asn1.Unmarshal(parametersDER, &parameters)
	if err != nil || len(remainder) != 0 || !parameters.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) {
		return errInvalidEncryptedPKCS8
	}
	if !supportedPBES2Cipher(parameters.EncryptionScheme.Algorithm) || len(encryptedData) == 0 ||
		len(encryptedData) > maxEncryptedPKCS8Bytes || len(encryptedData)%16 != 0 {
		return errInvalidEncryptedPKCS8
	}
	var iv []byte
	remainder, err = asn1.Unmarshal(parameters.EncryptionScheme.Parameters.FullBytes, &iv)
	if err != nil || len(remainder) != 0 || len(iv) != 16 {
		return errInvalidEncryptedPKCS8
	}

	kdfDER := parameters.KeyDerivationFunc.Parameters.FullBytes
	if len(kdfDER) == 0 || len(kdfDER) > maxPKCS8ParametersBytes {
		return errInvalidEncryptedPKCS8
	}
	var kdf pbkdf2Parameters
	remainder, err = asn1.Unmarshal(kdfDER, &kdf)
	if err != nil || len(remainder) != 0 || len(kdf.Salt) < 8 || len(kdf.Salt) > maxPKCS12SaltBytes ||
		kdf.Iterations < 1 || kdf.Iterations > maxPKCS12Iterations || kdf.KeyLength != 0 {
		return errInvalidEncryptedPKCS8
	}
	return nil
}

func supportedPBES2Cipher(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidAES128CBC) || oid.Equal(oidAES192CBC) || oid.Equal(oidAES256CBC)
}

func decryptPKCS12TripleDES(info encryptedPrivateKeyInfo, password []byte) ([]byte, error) {
	parametersDER := info.EncryptionAlgorithm.Parameters.FullBytes
	if len(parametersDER) == 0 || len(parametersDER) > maxPKCS8ParametersBytes {
		return nil, errInvalidEncryptedPKCS8
	}

	var parameters pkcs12PBEParameters
	remainder, err := asn1.Unmarshal(parametersDER, &parameters)
	if err != nil || len(remainder) != 0 || len(parameters.Salt) < 8 || len(parameters.Salt) > maxPKCS12SaltBytes ||
		parameters.Iterations < 1 || parameters.Iterations > maxPKCS12Iterations {
		return nil, errInvalidEncryptedPKCS8
	}
	if len(info.EncryptedData) == 0 || len(info.EncryptedData) > maxEncryptedPKCS8Bytes || len(info.EncryptedData)%des.BlockSize != 0 {
		return nil, errInvalidEncryptedPKCS8
	}

	bmpPassword, err := encodePKCS12Password(password)
	if err != nil {
		return nil, errInvalidEncryptedPKCS8
	}
	defer clear(bmpPassword)

	key := derivePKCS12SHA1(bmpPassword, parameters.Salt, 1, parameters.Iterations, 24)
	defer clear(key)
	iv := derivePKCS12SHA1(bmpPassword, parameters.Salt, 2, parameters.Iterations, des.BlockSize)
	defer clear(iv)

	block, err := des.NewTripleDESCipher(key) // #nosec G405 -- Required to decrypt Cisco ISE's legacy key-file PBE.
	if err != nil {
		return nil, errInvalidEncryptedPKCS8
	}
	plaintext := make([]byte, len(info.EncryptedData))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, info.EncryptedData)

	unpadded, err := unpadPKCS7(plaintext, des.BlockSize)
	if err != nil {
		clear(plaintext)
		return nil, errInvalidEncryptedPKCS8
	}
	result := append([]byte(nil), unpadded...)
	clear(plaintext)
	return result, nil
}

func encodePKCS12Password(password []byte) ([]byte, error) {
	if len(password) > maxPKCS12PasswordBytes || !utf8.Valid(password) {
		return nil, errInvalidEncryptedPKCS8
	}

	// Decode directly from the caller-owned byte slice so the password is not
	// copied into an immutable Go string that cannot be cleared.
	encoded := make([]byte, 0, 2*(len(password)+1))
	for len(password) > 0 {
		value, size := utf8.DecodeRune(password)
		password = password[size:]
		if value <= 0xffff {
			encoded = binary.BigEndian.AppendUint16(encoded, uint16(value))
			continue
		}
		high, low := utf16.EncodeRune(value)
		encoded = binary.BigEndian.AppendUint16(encoded, uint16(high))
		encoded = binary.BigEndian.AppendUint16(encoded, uint16(low))
	}
	// PKCS#12 passwords include a terminating two-byte NUL.
	encoded = append(encoded, 0, 0)
	return encoded, nil
}

// derivePKCS12SHA1 implements the RFC 7292 Appendix B diversifier. All inputs
// have already been bounded by the encrypted-key parser.
func derivePKCS12SHA1(password, salt []byte, diversifier byte, iterations, outputLen int) []byte {
	diversifierBlock := make([]byte, pkcs12SHA1BlockSize)
	defer clear(diversifierBlock)
	for i := range diversifierBlock {
		diversifierBlock[i] = diversifier
	}

	expandedSalt := repeatToBlockMultiple(salt, pkcs12SHA1BlockSize)
	defer clear(expandedSalt)
	expandedPassword := repeatToBlockMultiple(password, pkcs12SHA1BlockSize)
	defer clear(expandedPassword)
	input := make([]byte, 0, len(expandedSalt)+len(expandedPassword))
	input = append(input, expandedSalt...)
	input = append(input, expandedPassword...)
	defer clear(input)

	result := make([]byte, 0, outputLen)
	hasher := sha1.New() // #nosec G401 -- RFC 7292 fixes this legacy KDF to SHA-1.
	for len(result) < outputLen {
		hasher.Reset()
		_, _ = hasher.Write(diversifierBlock)
		_, _ = hasher.Write(input)
		digest := hasher.Sum(nil)
		for i := 1; i < iterations; i++ {
			next := sha1.Sum(digest) // #nosec G401 -- RFC 7292 fixes this legacy KDF to SHA-1.
			copy(digest, next[:])
			clear(next[:])
		}

		remaining := min(outputLen-len(result), len(digest))
		result = append(result, digest[:remaining]...)

		adjustment := make([]byte, pkcs12SHA1BlockSize)
		for i := range adjustment {
			adjustment[i] = digest[i%len(digest)]
		}
		for offset := 0; offset < len(input); offset += pkcs12SHA1BlockSize {
			addPKCS12Adjustment(input[offset:offset+pkcs12SHA1BlockSize], adjustment)
		}
		clear(adjustment)
		clear(digest)
	}
	return result
}

func repeatToBlockMultiple(input []byte, blockSize int) []byte {
	if len(input) == 0 {
		return nil
	}
	length := blockSize * ((len(input) + blockSize - 1) / blockSize)
	result := make([]byte, length)
	for i := range result {
		result[i] = input[i%len(input)]
	}
	return result
}

func addPKCS12Adjustment(block, adjustment []byte) {
	carry := 1
	for i := len(block) - 1; i >= 0; i-- {
		sum := int(block[i]) + int(adjustment[i]) + carry
		block[i] = byte(sum)
		carry = sum >> 8
	}
}

func unpadPKCS7(plaintext []byte, blockSize int) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext)%blockSize != 0 {
		return nil, errInvalidEncryptedPKCS8
	}
	paddingLen := int(plaintext[len(plaintext)-1])
	if paddingLen < 1 || paddingLen > blockSize || paddingLen > len(plaintext) {
		return nil, errInvalidEncryptedPKCS8
	}
	for _, value := range plaintext[len(plaintext)-paddingLen:] {
		if int(value) != paddingLen {
			return nil, errInvalidEncryptedPKCS8
		}
	}
	return plaintext[:len(plaintext)-paddingLen], nil
}
