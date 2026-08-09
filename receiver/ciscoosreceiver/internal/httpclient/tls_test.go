// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package httpclient

import (
	"crypto/x509"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecorateCertificateVerificationError(t *testing.T) {
	cause := x509.UnknownAuthorityError{Cert: &x509.Certificate{}}
	err := fmt.Errorf("request failed: %w", cause)

	decorated := DecorateCertificateVerificationError(err, "ise.ca_file", "ise.insecure_skip_verify")
	require.Error(t, decorated)
	assert.ErrorContains(t, decorated, "TLS certificate verification failed")
	assert.ErrorContains(t, decorated, "configure ise.ca_file with the issuing CA (preferred)")
	assert.ErrorContains(t, decorated, "set ise.insecure_skip_verify: true only for an isolated lab")
	assert.ErrorIs(t, decorated, cause)

	var typed *CertificateVerificationError
	require.ErrorAs(t, decorated, &typed)
	assert.True(t, IsCertificateVerificationError(decorated))
	assert.Equal(t, "ise.ca_file", typed.CAConfigPath)
	assert.Equal(t, "ise.insecure_skip_verify", typed.InsecureSkipVerifyConfigPath)
	assert.Same(t, decorated, DecorateCertificateVerificationError(decorated, "other.ca", "other.insecure_skip_verify"))
}

func TestDecorateCertificateVerificationErrorUsesSystemTrustStoreHint(t *testing.T) {
	err := DecorateCertificateVerificationError(
		x509.UnknownAuthorityError{Cert: &x509.Certificate{}},
		"",
		"aci.insecure_skip_verify",
	)
	require.Error(t, err)
	assert.ErrorContains(t, err, "trust the issuing CA in the Collector host trust store (preferred)")
	assert.ErrorContains(t, err, "set aci.insecure_skip_verify: true")
}

func TestDecorateCertificateVerificationErrorUsesHostnameRepairHint(t *testing.T) {
	err := DecorateCertificateVerificationError(
		x509.HostnameError{Certificate: &x509.Certificate{}, Host: "controller.example.com"},
		"ise.ca_file",
		"ise.insecure_skip_verify",
	)
	require.Error(t, err)
	assert.ErrorContains(t, err, "use an endpoint hostname or server-name setting that matches the certificate SAN (preferred)")
	assert.NotContains(t, err.Error(), "configure ise.ca_file")
}

func TestDecorateCertificateVerificationErrorUsesInvalidCertificateRepairHint(t *testing.T) {
	err := DecorateCertificateVerificationError(
		x509.CertificateInvalidError{Cert: &x509.Certificate{}, Reason: x509.Expired},
		"ise.ca_file",
		"ise.insecure_skip_verify",
	)
	require.Error(t, err)
	assert.ErrorContains(t, err, "renew or reissue the endpoint certificate")
	assert.NotContains(t, err.Error(), "configure ise.ca_file")
}

func TestDecorateCertificateVerificationErrorSupportsInverseLabOptIn(t *testing.T) {
	err := DecorateCertificateVerificationErrorWithValue(
		x509.UnknownAuthorityError{Cert: &x509.Certificate{}},
		"ise.data_connect.wallet_dir",
		"ise.data_connect.ssl_verify",
		"false",
	)
	require.Error(t, err)
	assert.ErrorContains(t, err, "configure ise.data_connect.wallet_dir with the issuing CA (preferred)")
	assert.ErrorContains(t, err, "set ise.data_connect.ssl_verify: false only for an isolated lab")
}

func TestDecorateCertificateVerificationErrorLeavesOtherErrorsUnchanged(t *testing.T) {
	cause := errors.New("connection refused")
	assert.Same(t, cause, DecorateCertificateVerificationError(cause, "ise.ca_file", "ise.insecure_skip_verify"))
	assert.False(t, IsCertificateVerificationError(cause))
	assert.NoError(t, DecorateCertificateVerificationError(nil, "ise.ca_file", "ise.insecure_skip_verify"))
}
