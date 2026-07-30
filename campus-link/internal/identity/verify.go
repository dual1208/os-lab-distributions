package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

const (
	pinPrefix       = "sha256/"
	maxLeafLifetime = 90 * 24 * time.Hour
)

var ErrPeerIdentity = errors.New("peer asymmetric identity rejected")

type Requirements struct {
	URI    string
	Pins   []string
	Usages []x509.ExtKeyUsage
	Now    time.Time
}

type Verified struct {
	NotAfter time.Time
	PinSlot  int
}

func SPKIPin(cert *x509.Certificate) (string, error) {
	if cert == nil || len(cert.RawSubjectPublicKeyInfo) == 0 {
		return "", ErrPeerIdentity
	}
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return pinPrefix + base64.StdEncoding.EncodeToString(digest[:]), nil
}

// ValidateRequirements rejects an ambiguous or non-canonical authorization
// before it can be installed in a TLS callback.
func ValidateRequirements(requirements Requirements) error {
	if requirements.URI == "" || len(requirements.Pins) == 0 || len(requirements.Pins) > 2 || len(requirements.Usages) == 0 {
		return ErrPeerIdentity
	}
	if _, err := expectedIdentityDNS(requirements.URI); err != nil {
		return ErrPeerIdentity
	}
	seenUsages := make(map[x509.ExtKeyUsage]struct{}, len(requirements.Usages))
	for _, usage := range requirements.Usages {
		if usage == x509.ExtKeyUsageAny {
			return ErrPeerIdentity
		}
		if _, duplicate := seenUsages[usage]; duplicate {
			return ErrPeerIdentity
		}
		seenUsages[usage] = struct{}{}
	}
	seenPins := make(map[[sha256.Size]byte]struct{}, len(requirements.Pins))
	for _, encoded := range requirements.Pins {
		pin, err := parsePin(encoded)
		if err != nil {
			return ErrPeerIdentity
		}
		if _, duplicate := seenPins[pin]; duplicate {
			return ErrPeerIdentity
		}
		seenPins[pin] = struct{}{}
	}
	return nil
}

// VerifyConnection must be called from tls.Config.VerifyConnection after
// native X.509 verification. It deliberately consumes VerifiedChains instead
// of the unverified PeerCertificates input.
func VerifyConnection(state tls.ConnectionState, requirements Requirements) (Verified, error) {
	var verified Verified
	if err := ValidateRequirements(requirements); err != nil || len(state.VerifiedChains) == 0 {
		return verified, ErrPeerIdentity
	}
	var leaf *x509.Certificate
	for _, chain := range state.VerifiedChains {
		if len(chain) == 0 || chain[0] == nil {
			return verified, ErrPeerIdentity
		}
		if leaf == nil {
			leaf = chain[0]
			continue
		}
		if !bytes.Equal(leaf.Raw, chain[0].Raw) {
			return verified, ErrPeerIdentity
		}
	}
	if len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil ||
		len(leaf.Raw) == 0 || len(leaf.RawSubjectPublicKeyInfo) == 0 ||
		!bytes.Equal(leaf.Raw, state.PeerCertificates[0].Raw) {
		return verified, ErrPeerIdentity
	}
	now := requirements.Now
	if now.IsZero() {
		now = time.Now()
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) || !leaf.NotAfter.After(leaf.NotBefore) ||
		leaf.NotAfter.Sub(leaf.NotBefore) > maxLeafLifetime || !leaf.BasicConstraintsValid || leaf.IsCA ||
		leaf.PublicKeyAlgorithm != x509.Ed25519 || leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		return verified, ErrPeerIdentity
	}
	publicKey, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return verified, ErrPeerIdentity
	}
	expectedDNS, err := expectedIdentityDNS(requirements.URI)
	if err != nil || !hasExactSANProfile(leaf, requirements.URI, expectedDNS) ||
		!hasExactUsages(leaf.ExtKeyUsage, leaf.UnknownExtKeyUsage, requirements.Usages) {
		return verified, ErrPeerIdentity
	}
	digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	matchedSlot := -1
	for slot, encoded := range requirements.Pins {
		pin, err := parsePin(encoded)
		if err != nil {
			return verified, ErrPeerIdentity
		}
		if subtle.ConstantTimeCompare(digest[:], pin[:]) == 1 {
			matchedSlot = slot
		}
	}
	if matchedSlot < 0 {
		return verified, ErrPeerIdentity
	}
	return Verified{NotAfter: leaf.NotAfter, PinSlot: matchedSlot}, nil
}

func parsePin(encoded string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if len(encoded) <= len(pinPrefix) || encoded[:len(pinPrefix)] != pinPrefix {
		return result, ErrPeerIdentity
	}
	payload := encoded[len(pinPrefix):]
	pin, err := base64.StdEncoding.Strict().DecodeString(payload)
	if err != nil || len(pin) != sha256.Size || base64.StdEncoding.EncodeToString(pin) != payload {
		return result, fmt.Errorf("%w: malformed SPKI pin", ErrPeerIdentity)
	}
	copy(result[:], pin)
	return result, nil
}

func hasExactUsages(actual []x509.ExtKeyUsage, unknown []asn1.ObjectIdentifier, required []x509.ExtKeyUsage) bool {
	if len(unknown) != 0 || len(actual) != len(required) {
		return false
	}
	want := make(map[x509.ExtKeyUsage]struct{}, len(required))
	for _, usage := range required {
		want[usage] = struct{}{}
	}
	for _, usage := range actual {
		if _, ok := want[usage]; !ok {
			return false
		}
		delete(want, usage)
	}
	return len(want) == 0
}
