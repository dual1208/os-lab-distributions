package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

const pinPrefix = "sha256/"

var ErrPeerIdentity = errors.New("peer asymmetric identity rejected")

type Requirements struct {
	URI   string
	Pins  []string
	Usage x509.ExtKeyUsage
	Now   time.Time
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

func VerifyPeer(certs []*x509.Certificate, requirements Requirements) (Verified, error) {
	var verified Verified
	if len(certs) == 0 || certs[0] == nil || requirements.URI == "" ||
		requirements.Usage == x509.ExtKeyUsageAny || len(requirements.Pins) == 0 || len(requirements.Pins) > 2 {
		return verified, ErrPeerIdentity
	}
	leaf := certs[0]
	now := requirements.Now
	if now.IsZero() {
		now = time.Now()
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) ||
		leaf.PublicKeyAlgorithm != x509.Ed25519 || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return verified, ErrPeerIdentity
	}
	if _, ok := leaf.PublicKey.(ed25519.PublicKey); !ok {
		return verified, ErrPeerIdentity
	}
	uriMatch := false
	for _, uri := range leaf.URIs {
		if uri != nil && uri.String() == requirements.URI {
			uriMatch = true
			break
		}
	}
	if !uriMatch || !hasExactUsage(leaf.ExtKeyUsage, requirements.Usage) {
		return verified, ErrPeerIdentity
	}
	digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	matchedSlot := -1
	seen := make(map[string]struct{}, len(requirements.Pins))
	for slot, encoded := range requirements.Pins {
		pin, err := parsePin(encoded)
		if err != nil {
			return verified, ErrPeerIdentity
		}
		if _, duplicate := seen[encoded]; duplicate {
			return verified, ErrPeerIdentity
		}
		seen[encoded] = struct{}{}
		if subtle.ConstantTimeCompare(digest[:], pin) == 1 {
			matchedSlot = slot
		}
	}
	if matchedSlot < 0 {
		return verified, ErrPeerIdentity
	}
	return Verified{NotAfter: leaf.NotAfter, PinSlot: matchedSlot}, nil
}

func parsePin(encoded string) ([]byte, error) {
	if len(encoded) <= len(pinPrefix) || encoded[:len(pinPrefix)] != pinPrefix {
		return nil, ErrPeerIdentity
	}
	pin, err := base64.StdEncoding.DecodeString(encoded[len(pinPrefix):])
	if err != nil || len(pin) != sha256.Size {
		return nil, fmt.Errorf("%w: malformed SPKI pin", ErrPeerIdentity)
	}
	return pin, nil
}

func hasExactUsage(usages []x509.ExtKeyUsage, required x509.ExtKeyUsage) bool {
	found := false
	for _, usage := range usages {
		if usage == x509.ExtKeyUsageAny {
			return false
		}
		if usage == required {
			found = true
		}
	}
	return found
}
