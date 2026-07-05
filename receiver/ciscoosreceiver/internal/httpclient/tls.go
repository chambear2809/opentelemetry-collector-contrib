// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package httpclient // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// CertificateVerificationError adds actionable receiver configuration guidance
// to a certificate-verification failure while preserving the original error.
type CertificateVerificationError struct {
	Err                          error
	CAConfigPath                 string
	InsecureSkipVerifyConfigPath string
	LabOptInValue                string
}

func (e *CertificateVerificationError) Error() string {
	if e == nil {
		return "TLS certificate verification failed"
	}
	hint := fmt.Sprintf(
		"TLS certificate verification failed: %s (preferred), or set %s: %s only for an isolated lab",
		preferredCertificateRepair(e.Err, e.CAConfigPath),
		e.InsecureSkipVerifyConfigPath,
		firstNonEmpty(e.LabOptInValue, "true"),
	)
	if e.Err == nil {
		return hint
	}
	return hint + ": " + e.Err.Error()
}

func preferredCertificateRepair(err error, caConfigPath string) string {
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return "use an endpoint hostname or server-name setting that matches the certificate SAN"
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		return "renew or reissue the endpoint certificate with valid dates, usages, and constraints"
	}
	var unknownAuthority x509.UnknownAuthorityError
	var systemRoots x509.SystemRootsError
	if errors.As(err, &unknownAuthority) || errors.As(err, &systemRoots) {
		if caConfigPath != "" {
			return fmt.Sprintf("configure %s with the issuing CA", caConfigPath)
		}
		return "trust the issuing CA in the Collector host trust store"
	}
	return "repair the endpoint certificate chain, validity, and server name"
}

func (e *CertificateVerificationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// DecorateCertificateVerificationError returns err unchanged unless its chain
// contains a typed TLS/x509 certificate-verification failure. The decorated
// error keeps the original chain available to errors.Is and errors.As.
func DecorateCertificateVerificationError(err error, caConfigPath, insecureSkipVerifyConfigPath string) error {
	return DecorateCertificateVerificationErrorWithValue(err, caConfigPath, insecureSkipVerifyConfigPath, "true")
}

// DecorateCertificateVerificationErrorWithValue supports secure-by-default
// settings whose lab opt-in uses inverse semantics, such as ssl_verify: false.
func DecorateCertificateVerificationErrorWithValue(err error, caConfigPath, labOptInConfigPath, labOptInValue string) error {
	if err == nil {
		return nil
	}
	var alreadyDecorated *CertificateVerificationError
	if errors.As(err, &alreadyDecorated) {
		return err
	}
	if !isCertificateVerificationError(err) {
		return err
	}
	return &CertificateVerificationError{
		Err:                          err,
		CAConfigPath:                 caConfigPath,
		InsecureSkipVerifyConfigPath: labOptInConfigPath,
		LabOptInValue:                labOptInValue,
	}
}

// IsCertificateVerificationError reports whether err has already been
// classified as a deterministic certificate-verification failure. Callers use
// this after decoration to keep transport retry loops for transient failures
// without retrying a certificate that cannot pass the configured trust policy.
func IsCertificateVerificationError(err error) bool {
	var certificateErr *CertificateVerificationError
	return errors.As(err, &certificateErr)
}

func firstNonEmpty(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func isCertificateVerificationError(err error) bool {
	var tlsVerification *tls.CertificateVerificationError
	if errors.As(err, &tlsVerification) {
		return true
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return true
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return true
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		return true
	}
	var roots x509.SystemRootsError
	return errors.As(err, &roots)
}
