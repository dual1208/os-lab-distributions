package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

func makeLeaf(t *testing.T, uriTexts []string, usages []x509.ExtKeyUsage, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uris := make([]*url.URL, 0, len(uriTexts))
	for _, uriText := range uriTexts {
		uri, err := url.Parse(uriText)
		if err != nil {
			t.Fatal(err)
		}
		uris = append(uris, uri)
	}
	var dnsNames []string
	if len(uriTexts) == 1 {
		dnsName, err := expectedIdentityDNS(uriTexts[0])
		if err != nil {
			t.Fatal(err)
		}
		if dnsName != "" {
			dnsNames = []string{dnsName}
		}
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ignored-common-name"},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: usages, URIs: uris, DNSNames: dnsNames, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func connectionState(leaf *x509.Certificate) tls.ConnectionState {
	return tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}
}

func TestVerifyConnectionRequiresVerifiedLeafAndExactProfile(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	uri := "spiffe://campus-link/home-pair-1/site-b/data"
	leaf := makeLeaf(t, []string{uri}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, now.Add(-time.Hour), now.Add(24*time.Hour))
	pin, err := SPKIPin(leaf)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyConnection(connectionState(leaf), Requirements{
		URI: uri, Pins: []string{pin}, Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, Now: now,
	})
	if err != nil || verified.PinSlot != 0 || !verified.NotAfter.Equal(leaf.NotAfter) {
		t.Fatalf("valid peer rejected: %#v %v", verified, err)
	}

	withIntermediate := connectionState(leaf)
	withIntermediate.PeerCertificates = append(withIntermediate.PeerCertificates, leaf)
	withIntermediate.VerifiedChains[0] = append(withIntermediate.VerifiedChains[0], leaf)
	if _, err := VerifyConnection(withIntermediate, Requirements{
		URI: uri, Pins: []string{pin}, Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, Now: now,
	}); err != nil {
		t.Fatalf("verified chain with an intermediate rejected: %v", err)
	}
}

func TestVerifyConnectionRejectsUnverifiedOrMismatchedLeaf(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	uri := "spiffe://campus-link/home-pair-1/site-a/control"
	leaf := makeLeaf(t, []string{uri}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now.Add(-time.Hour), now.Add(time.Hour))
	foreign := makeLeaf(t, []string{uri}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now.Add(-time.Hour), now.Add(time.Hour))
	pin, _ := SPKIPin(leaf)
	requirements := Requirements{URI: uri, Pins: []string{pin}, Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, Now: now}
	tests := []struct {
		name  string
		state tls.ConnectionState
	}{
		{name: "no verified chain", state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}},
		{name: "empty verified chain", state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{}}}},
		{name: "no presented leaf", state: tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}},
		{name: "presented leaf differs", state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{foreign}, VerifiedChains: [][]*x509.Certificate{{leaf}}}},
		{name: "verified chains disagree", state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}, {foreign}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := VerifyConnection(test.state, requirements); err == nil {
				t.Fatal("unverified or inconsistent peer accepted")
			}
		})
	}
}

func TestVerifyConnectionRejectsIdentityConfusion(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	uri := "spiffe://campus-link/home-pair-1/site-a/control"
	valid := makeLeaf(t, []string{uri}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now.Add(-time.Hour), now.Add(time.Hour))
	pin, _ := SPKIPin(valid)
	validRequirements := Requirements{URI: uri, Pins: []string{pin}, Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, Now: now}
	clone := func() *x509.Certificate {
		copy := *valid
		return &copy
	}
	noURI := clone()
	noURI.URIs = nil
	extraURI := clone()
	extra, _ := url.Parse("spiffe://campus-link/home-pair-1/site-b/control")
	extraURI.URIs = append(append([]*url.URL(nil), valid.URIs...), extra)
	extraDNS := clone()
	extraDNS.DNSNames = []string{"other.campus-link"}
	extraIP := clone()
	extraIP.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")}
	extraEmail := clone()
	extraEmail.EmailAddresses = []string{"other@example.invalid"}
	unsupportedGeneralName := clone()
	unsupportedGeneralName.Extensions = append([]pkix.Extension(nil), valid.Extensions...)
	for index := range unsupportedGeneralName.Extensions {
		if !unsupportedGeneralName.Extensions[index].Id.Equal(subjectAltNameOID) {
			continue
		}
		var sequence asn1.RawValue
		if rest, err := asn1.Unmarshal(unsupportedGeneralName.Extensions[index].Value, &sequence); err != nil || len(rest) != 0 {
			t.Fatal("parse test SAN extension")
		}
		sequence.Bytes = append(sequence.Bytes, 0xa0, 0x00)
		sequence.FullBytes = nil
		encoded, err := asn1.Marshal(sequence)
		if err != nil {
			t.Fatal(err)
		}
		unsupportedGeneralName.Extensions[index].Value = encoded
	}
	extraUsage := clone()
	extraUsage.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	unknownUsage := clone()
	unknownUsage.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
	ca := clone()
	ca.IsCA = true
	missingConstraints := clone()
	missingConstraints.BasicConstraintsValid = false
	wrongKeyUsage := clone()
	wrongKeyUsage.KeyUsage |= x509.KeyUsageCertSign
	wrongAlgorithm := clone()
	wrongAlgorithm.PublicKeyAlgorithm = x509.RSA
	missingRawSPKI := clone()
	missingRawSPKI.RawSubjectPublicKeyInfo = nil
	tooLong := clone()
	tooLong.NotAfter = tooLong.NotBefore.Add(90*24*time.Hour + time.Second)
	tests := []struct {
		name         string
		leaf         *x509.Certificate
		requirements Requirements
	}{
		{name: "no URI", leaf: noURI, requirements: validRequirements},
		{name: "more than one URI", leaf: extraURI, requirements: validRequirements},
		{name: "extra DNS SAN", leaf: extraDNS, requirements: validRequirements},
		{name: "IP SAN", leaf: extraIP, requirements: validRequirements},
		{name: "email SAN", leaf: extraEmail, requirements: validRequirements},
		{name: "unsupported GeneralName SAN", leaf: unsupportedGeneralName, requirements: validRequirements},
		{name: "wrong circuit", leaf: valid, requirements: Requirements{URI: "spiffe://campus-link/other/site-a/control", Pins: []string{pin}, Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, Now: now}},
		{name: "extra EKU", leaf: extraUsage, requirements: validRequirements},
		{name: "unknown EKU", leaf: unknownUsage, requirements: validRequirements},
		{name: "wrong required EKU", leaf: valid, requirements: Requirements{URI: uri, Pins: []string{pin}, Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, Now: now}},
		{name: "CA leaf", leaf: ca, requirements: validRequirements},
		{name: "missing basic constraints", leaf: missingConstraints, requirements: validRequirements},
		{name: "extra key usage", leaf: wrongKeyUsage, requirements: validRequirements},
		{name: "wrong key algorithm", leaf: wrongAlgorithm, requirements: validRequirements},
		{name: "missing raw SPKI", leaf: missingRawSPKI, requirements: validRequirements},
		{name: "lifetime exceeds 90 days", leaf: tooLong, requirements: validRequirements},
		{name: "expired", leaf: valid, requirements: Requirements{URI: uri, Pins: []string{pin}, Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, Now: now.Add(2 * time.Hour)}},
		{name: "not yet valid", leaf: valid, requirements: Requirements{URI: uri, Pins: []string{pin}, Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, Now: now.Add(-2 * time.Hour)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := VerifyConnection(connectionState(test.leaf), test.requirements); err == nil {
				t.Fatal("invalid identity accepted")
			}
		})
	}
}

func TestValidateRequirementsRejectsNonCanonicalOrDuplicatePins(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	uri := "spiffe://campus-link/home-pair-1/site-b/control"
	leaf := makeLeaf(t, []string{uri}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now.Add(-time.Hour), now.Add(time.Hour))
	pin, _ := SPKIPin(leaf)
	payload := strings.TrimPrefix(pin, pinPrefix)
	tests := []struct {
		name string
		pins []string
	}{
		{name: "missing current", pins: []string{""}},
		{name: "unpadded base64", pins: []string{pinPrefix + strings.TrimSuffix(payload, "=")}},
		{name: "embedded newline", pins: []string{pinPrefix + payload[:20] + "\n" + payload[20:]}},
		{name: "trailing newline", pins: []string{pin + "\n"}},
		{name: "duplicate decoded pin", pins: []string{pin, pin}},
		{name: "too many slots", pins: []string{pin, pin, pin}},
		{name: "wrong prefix case", pins: []string{"SHA256/" + payload}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateRequirements(Requirements{URI: uri, Pins: test.pins, Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
				t.Fatal("ambiguous authorization accepted")
			}
		})
	}
}

func TestValidateRequirementsRejectsNonCanonicalIdentityURI(t *testing.T) {
	pin := "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	tests := []string{
		"spiffe://CAMPUS-LINK/c/site-a/control",
		"spiffe://campus-link/c/site-a/control?scope=extra",
		"spiffe://campus-link/c/site-a/control#extra",
		"spiffe://campus-link/c/relay/data",
		"spiffe://campus-link/c/site-c/data",
		"spiffe://campus-link/c/site-a/other",
		"spiffe://campus-link/c%2Fother/site-a/control",
	}
	for _, uri := range tests {
		t.Run(uri, func(t *testing.T) {
			if err := ValidateRequirements(Requirements{
				URI: uri, Pins: []string{pin}, Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}); err == nil {
				t.Fatal("non-canonical identity URI accepted")
			}
		})
	}
}

func TestVerifyConnectionRequiresExactDataDNSProfile(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	uri := "spiffe://campus-link/home-pair-1/site-b/data"
	valid := makeLeaf(t, []string{uri}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, now.Add(-time.Hour), now.Add(time.Hour))
	pin, _ := SPKIPin(valid)
	requirements := Requirements{URI: uri, Pins: []string{pin}, Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, Now: now}
	for name, dnsNames := range map[string][]string{
		"missing": nil,
		"wrong":   {"site-a.campus-link"},
		"extra":   {"site-b.campus-link", "other.campus-link"},
	} {
		t.Run(name, func(t *testing.T) {
			leaf := *valid
			leaf.DNSNames = dnsNames
			if _, err := VerifyConnection(connectionState(&leaf), requirements); err == nil {
				t.Fatal("invalid data DNS profile accepted")
			}
		})
	}
}

func TestVerifyConnectionAcceptsCurrentOrNextPin(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	uri := "spiffe://campus-link/home-pair-1/site-b/control"
	current := makeLeaf(t, []string{uri}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now.Add(-time.Hour), now.Add(time.Hour))
	next := makeLeaf(t, []string{uri}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now.Add(-time.Hour), now.Add(24*time.Hour))
	currentPin, _ := SPKIPin(current)
	nextPin, _ := SPKIPin(next)
	requirements := Requirements{URI: uri, Pins: []string{currentPin, nextPin}, Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, Now: now}
	if verified, err := VerifyConnection(connectionState(current), requirements); err != nil || verified.PinSlot != 0 {
		t.Fatal("current slot rejected")
	}
	if verified, err := VerifyConnection(connectionState(next), requirements); err != nil || verified.PinSlot != 1 {
		t.Fatal("next slot rejected")
	}
	if _, err := VerifyConnection(connectionState(current), Requirements{URI: uri, Pins: []string{nextPin}, Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, Now: now}); err == nil {
		t.Fatal("retired current pin remained authorized")
	}
}

func FuzzPinParser(f *testing.F) {
	f.Add("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	f.Add("")
	f.Fuzz(func(t *testing.T, value string) {
		_, _ = parsePin(value)
	})
}
