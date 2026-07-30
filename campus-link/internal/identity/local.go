package identity

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// VerifyLocalCertificate applies the same exact identity profile used for a
// peer to a locally loaded certificate after proving its chain to roots. A
// dnsName must match the DNS profile implied by the canonical identity URI;
// wildcard, missing, or additional identities are not canonical.
// Requirements must carry the explicit public
// current/next authorization slots; deriving a slot from the loaded leaf would
// make every local key appear to be current. The key-pair parser separately
// proves that the private key matches the leaf.
func VerifyLocalCertificate(certificate tls.Certificate, roots *x509.CertPool, requirements Requirements, dnsName string) (Verified, error) {
	if roots == nil || len(certificate.Certificate) == 0 || certificate.PrivateKey == nil ||
		ValidateRequirements(requirements) != nil {
		return Verified{}, ErrPeerIdentity
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return Verified{}, ErrPeerIdentity
	}
	expectedDNS, err := expectedIdentityDNS(requirements.URI)
	if err != nil || dnsName != expectedDNS || !hasExactSANProfile(leaf, requirements.URI, expectedDNS) {
		return Verified{}, ErrPeerIdentity
	}
	intermediates := x509.NewCertPool()
	peerCertificates := make([]*x509.Certificate, 0, len(certificate.Certificate))
	peerCertificates = append(peerCertificates, leaf)
	for _, encoded := range certificate.Certificate[1:] {
		intermediate, parseErr := x509.ParseCertificate(encoded)
		if parseErr != nil {
			return Verified{}, ErrPeerIdentity
		}
		intermediates.AddCert(intermediate)
		peerCertificates = append(peerCertificates, intermediate)
	}
	verifyOptions := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       dnsName,
		KeyUsages:     append([]x509.ExtKeyUsage(nil), requirements.Usages...),
	}
	if !requirements.Now.IsZero() {
		verifyOptions.CurrentTime = requirements.Now
	}
	chains, err := leaf.Verify(verifyOptions)
	if err != nil || len(chains) == 0 {
		return Verified{}, ErrPeerIdentity
	}
	verified, err := VerifyConnection(tls.ConnectionState{
		PeerCertificates: peerCertificates,
		VerifiedChains:   chains,
	}, requirements)
	if err != nil {
		return Verified{}, errors.Join(ErrPeerIdentity, err)
	}
	return verified, nil
}
