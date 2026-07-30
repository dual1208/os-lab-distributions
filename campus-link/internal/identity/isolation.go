package identity

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// ErrKeyIsolation is returned when one asymmetric key could act as more than
// one local identity or is also authorized as a remote identity. The error is
// deliberately generic so a preflight failure cannot disclose which pin was
// involved.
var ErrKeyIsolation = errors.New("asymmetric identity key isolation rejected")

// ValidateAuthorizationIsolation requires every current/next public slot in
// the supplied component-visible roles to be canonical and globally distinct.
// It covers prospective next keys that are not yet loaded locally, complementing
// ValidateKeyIsolation's proof about the private keys loaded by this process.
func ValidateAuthorizationIsolation(requirements ...Requirements) error {
	if len(requirements) < 2 {
		return ErrKeyIsolation
	}
	seen := make(map[[sha256.Size]byte]struct{}, 2*len(requirements))
	for _, requirement := range requirements {
		if ValidateRequirements(requirement) != nil {
			return ErrKeyIsolation
		}
		for _, encoded := range requirement.Pins {
			pin, err := parsePin(encoded)
			if err != nil {
				return ErrKeyIsolation
			}
			if _, duplicate := seen[pin]; duplicate {
				return ErrKeyIsolation
			}
			seen[pin] = struct{}{}
		}
	}
	return nil
}

// ValidateKeyIsolation proves that each local certificate has a distinct SPKI
// and that none of those SPKIs appears in the supplied remote authorization
// pins. LoadKeyPair and VerifyLocalCertificate separately prove possession of
// the matching private key and the exact certificate profile.
func ValidateKeyIsolation(localCertificates []tls.Certificate, authorizedPins ...string) error {
	if len(localCertificates) == 0 {
		return ErrKeyIsolation
	}
	localPins := make(map[[sha256.Size]byte]struct{}, len(localCertificates))
	for _, certificate := range localCertificates {
		if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
			return ErrKeyIsolation
		}
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil || len(leaf.RawSubjectPublicKeyInfo) == 0 {
			return ErrKeyIsolation
		}
		pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		if _, duplicate := localPins[pin]; duplicate {
			return ErrKeyIsolation
		}
		localPins[pin] = struct{}{}
	}
	authorized := make(map[[sha256.Size]byte]struct{}, len(authorizedPins))
	for _, encoded := range authorizedPins {
		pin, err := parsePin(encoded)
		if err != nil {
			return ErrKeyIsolation
		}
		if _, reused := localPins[pin]; reused {
			return ErrKeyIsolation
		}
		if _, duplicate := authorized[pin]; duplicate {
			return ErrKeyIsolation
		}
		authorized[pin] = struct{}{}
	}
	return nil
}
