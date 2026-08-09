// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/youmark/pkcs8"
)

const (
	legacyPKCS12EncryptedPKCS8Fixture = "MIG9MCgGCiqGSIb3DQEMAQMwGgQUAQIDBAUGBwgJCgsMDQ4PEBESExQCAggABIGQGVrWC2nkSKlaeB7eox1EkSwtue17L2fm+Gwex1cku4higqClRYU5EqHTvLIA3prr+YtW7de3V4YD/jblnI7ltN2jAHFIPOI9uNvJWkkTa8Hgjgq5IDxIb0MjsTKIoEkPqBT1h9l6pHxM6kun4LIN3lFLhO0+FRe9prFxEQH1jb3Qd/3TroqWUVB9H0AMA//x"
	legacyPKCS12PlainPKCS8Fixture     = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgco6S9/aIdNvxu+tPT2n3RbwICUW3pkiO4hpML+I3UAehRANCAASNJ2xM9M+OICQVzdhutYutr4k3k23B3z+7anGhfLbJQsf58la67z4CcAVZmLsw1YIVev2pF8PQiOFADhSukefv"
	legacyPKCS12FixturePassword       = "test-fixture-password"
)

// The fixture is a non-secret P-256 test key encrypted with the Cisco ISE 3.4
// algorithm, a 20-byte salt, and 2,048 iterations. It was generated outside
// this package and independently verified with `openssl pkcs8`.
func TestParseEncryptedPKCS8PrivateKeySupportsCiscoISELegacyPBE(t *testing.T) {
	encryptedDER := decodeTestBase64(t, legacyPKCS12EncryptedPKCS8Fixture)
	expectedDER := decodeTestBase64(t, legacyPKCS12PlainPKCS8Fixture)
	expected, err := x509.ParsePKCS8PrivateKey(expectedDER)
	require.NoError(t, err)

	actual, err := parseEncryptedPKCS8PrivateKey(encryptedDER, []byte(legacyPKCS12FixturePassword))
	require.NoError(t, err)

	expectedECDSA, ok := expected.(*ecdsa.PrivateKey)
	require.True(t, ok)
	actualECDSA, ok := actual.(*ecdsa.PrivateKey)
	require.True(t, ok)
	assert.Zero(t, expectedECDSA.D.Cmp(actualECDSA.D))
	assert.True(t, expectedECDSA.PublicKey.Equal(&actualECDSA.PublicKey))
}

func TestLoadPxGridKeyPairSupportsCiscoISELegacyPBE(t *testing.T) {
	encryptedDER := decodeTestBase64(t, legacyPKCS12EncryptedPKCS8Fixture)
	plainDER := decodeTestBase64(t, legacyPKCS12PlainPKCS8Fixture)
	privateKey, err := x509.ParsePKCS8PrivateKey(plainDER)
	require.NoError(t, err)
	ecdsaPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	require.True(t, ok)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(4_102_444_800, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &ecdsaPrivateKey.PublicKey, ecdsaPrivateKey)
	require.NoError(t, err)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "pxgrid-client.crt")
	keyFile := filepath.Join(dir, "pxgrid-client.key")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encryptedDER}), 0o600))

	certificate, err := loadPxGridKeyPair(certFile, keyFile, legacyPKCS12FixturePassword)
	require.NoError(t, err)
	assert.NotNil(t, certificate.PrivateKey)
}

func TestParseEncryptedPKCS8PrivateKeyRejectsWrongLegacyPasswordWithoutLeakingIt(t *testing.T) {
	const wrongPassword = "wrong-fixture-password-must-not-leak"
	encryptedDER := decodeTestBase64(t, legacyPKCS12EncryptedPKCS8Fixture)

	_, err := parseEncryptedPKCS8PrivateKey(encryptedDER, []byte(wrongPassword))
	require.ErrorIs(t, err, errInvalidEncryptedPKCS8)
	assert.NotContains(t, err.Error(), legacyPKCS12FixturePassword)
	assert.NotContains(t, err.Error(), wrongPassword)
}

func TestParseEncryptedPKCS8PrivateKeyRejectsUnsupportedAlgorithmWithoutExposingOID(t *testing.T) {
	encryptedDER := decodeTestBase64(t, legacyPKCS12EncryptedPKCS8Fixture)
	var info encryptedPrivateKeyInfo
	remainder, err := asn1.Unmarshal(encryptedDER, &info)
	require.NoError(t, err)
	require.Empty(t, remainder)
	info.EncryptionAlgorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}
	unsupportedDER, err := asn1.Marshal(info)
	require.NoError(t, err)

	_, err = parseEncryptedPKCS8PrivateKey(unsupportedDER, []byte(legacyPKCS12FixturePassword))
	require.ErrorIs(t, err, errUnsupportedPKCS8Encryption)
	assert.NotContains(t, err.Error(), "1.2.3.4.5.6.7")
}

func TestParseEncryptedPKCS8PrivateKeyBoundsLegacyParameters(t *testing.T) {
	encryptedDER := decodeTestBase64(t, legacyPKCS12EncryptedPKCS8Fixture)
	var info encryptedPrivateKeyInfo
	remainder, err := asn1.Unmarshal(encryptedDER, &info)
	require.NoError(t, err)
	require.Empty(t, remainder)

	for name, iterations := range map[string]int{
		"zero":      0,
		"excessive": maxPKCS12Iterations + 1,
	} {
		t.Run(name, func(t *testing.T) {
			parameters, marshalErr := asn1.Marshal(pkcs12PBEParameters{
				Salt:       []byte("bounded-test-salt"),
				Iterations: iterations,
			})
			require.NoError(t, marshalErr)
			mutated := info
			mutated.EncryptionAlgorithm.Parameters = asn1.RawValue{FullBytes: parameters}
			mutatedDER, marshalErr := asn1.Marshal(mutated)
			require.NoError(t, marshalErr)

			_, parseErr := parseEncryptedPKCS8PrivateKey(mutatedDER, []byte(legacyPKCS12FixturePassword))
			require.ErrorIs(t, parseErr, errInvalidEncryptedPKCS8)
		})
	}
}

func TestParseEncryptedPKCS8PrivateKeyBoundsPBKDF2Parameters(t *testing.T) {
	plainDER := decodeTestBase64(t, legacyPKCS12PlainPKCS8Fixture)
	privateKey, err := x509.ParsePKCS8PrivateKey(plainDER)
	require.NoError(t, err)
	encryptedDER, err := pkcs8.MarshalPrivateKey(privateKey, []byte(legacyPKCS12FixturePassword), &pkcs8.Opts{
		Cipher: pkcs8.AES256CBC,
		KDFOpts: pkcs8.PBKDF2Opts{
			SaltSize:       20,
			IterationCount: 2048,
			HMACHash:       crypto.SHA256,
		},
	})
	require.NoError(t, err)

	parsed, err := parseEncryptedPKCS8PrivateKey(encryptedDER, []byte(legacyPKCS12FixturePassword))
	require.NoError(t, err)
	assert.IsType(t, &ecdsa.PrivateKey{}, parsed)

	var info encryptedPrivateKeyInfo
	remainder, err := asn1.Unmarshal(encryptedDER, &info)
	require.NoError(t, err)
	require.Empty(t, remainder)
	var parameters pbes2Parameters
	remainder, err = asn1.Unmarshal(info.EncryptionAlgorithm.Parameters.FullBytes, &parameters)
	require.NoError(t, err)
	require.Empty(t, remainder)
	var kdf pbkdf2Parameters
	remainder, err = asn1.Unmarshal(parameters.KeyDerivationFunc.Parameters.FullBytes, &kdf)
	require.NoError(t, err)
	require.Empty(t, remainder)

	for name, mutate := range map[string]func(*pbkdf2Parameters){
		"short salt":           func(value *pbkdf2Parameters) { value.Salt = []byte("short") },
		"zero iterations":      func(value *pbkdf2Parameters) { value.Iterations = 0 },
		"excessive iterations": func(value *pbkdf2Parameters) { value.Iterations = maxPKCS12Iterations + 1 },
		"explicit key length":  func(value *pbkdf2Parameters) { value.KeyLength = 32 },
	} {
		t.Run(name, func(t *testing.T) {
			mutatedKDF := kdf
			mutate(&mutatedKDF)
			mutatedKDFDER, marshalErr := asn1.Marshal(mutatedKDF)
			require.NoError(t, marshalErr)
			mutatedParameters := parameters
			mutatedParameters.KeyDerivationFunc.Parameters = asn1.RawValue{FullBytes: mutatedKDFDER}
			mutatedParametersDER, marshalErr := asn1.Marshal(mutatedParameters)
			require.NoError(t, marshalErr)
			mutatedInfo := info
			mutatedInfo.EncryptionAlgorithm.Parameters = asn1.RawValue{FullBytes: mutatedParametersDER}
			mutatedDER, marshalErr := asn1.Marshal(mutatedInfo)
			require.NoError(t, marshalErr)

			_, parseErr := parseEncryptedPKCS8PrivateKey(mutatedDER, []byte(legacyPKCS12FixturePassword))
			require.ErrorIs(t, parseErr, errInvalidEncryptedPKCS8)
		})
	}

	t.Run("invalid CBC inputs do not panic", func(t *testing.T) {
		for name, mutate := range map[string]func(*encryptedPrivateKeyInfo, *pbes2Parameters){
			"short IV": func(_ *encryptedPrivateKeyInfo, value *pbes2Parameters) {
				ivDER, marshalErr := asn1.Marshal([]byte("short"))
				require.NoError(t, marshalErr)
				value.EncryptionScheme.Parameters = asn1.RawValue{FullBytes: ivDER}
			},
			"unaligned ciphertext": func(value *encryptedPrivateKeyInfo, _ *pbes2Parameters) {
				value.EncryptedData = append([]byte(nil), value.EncryptedData[:len(value.EncryptedData)-1]...)
			},
		} {
			t.Run(name, func(t *testing.T) {
				mutatedInfo := info
				mutatedParameters := parameters
				mutate(&mutatedInfo, &mutatedParameters)
				mutatedParametersDER, marshalErr := asn1.Marshal(mutatedParameters)
				require.NoError(t, marshalErr)
				mutatedInfo.EncryptionAlgorithm.Parameters = asn1.RawValue{FullBytes: mutatedParametersDER}
				mutatedDER, marshalErr := asn1.Marshal(mutatedInfo)
				require.NoError(t, marshalErr)

				assert.NotPanics(t, func() {
					_, parseErr := parseEncryptedPKCS8PrivateKey(mutatedDER, []byte(legacyPKCS12FixturePassword))
					require.ErrorIs(t, parseErr, errInvalidEncryptedPKCS8)
				})
			})
		}
	})
}

func TestUnpadPKCS7RequiresEveryPaddingByte(t *testing.T) {
	valid := []byte{1, 2, 3, 4, 4, 4, 4, 4}
	unpadded, err := unpadPKCS7(valid, 8)
	require.NoError(t, err)
	assert.Equal(t, []byte{1, 2, 3, 4}, unpadded)

	_, err = unpadPKCS7([]byte{1, 2, 3, 4, 4, 4, 3, 4}, 8)
	require.ErrorIs(t, err, errInvalidEncryptedPKCS8)
}

func TestEncodePKCS12PasswordUsesUTF16BEWithTerminator(t *testing.T) {
	encoded, err := encodePKCS12Password([]byte("Aé😀"))
	require.NoError(t, err)
	assert.Equal(t, []byte{
		0x00, 0x41,
		0x00, 0xe9,
		0xd8, 0x3d, 0xde, 0x00,
		0x00, 0x00,
	}, encoded)
}

func decodeTestBase64(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	require.NoError(t, err)
	return decoded
}
