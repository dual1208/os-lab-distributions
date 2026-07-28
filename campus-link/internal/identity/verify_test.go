package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func makeLeaf(t *testing.T, uriText string, usages []x509.ExtKeyUsage, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var uris []*url.URL
	if uriText != "" {
		uri, err := url.Parse(uriText)
		if err != nil {
			t.Fatal(err)
		}
		uris = []*url.URL{uri}
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ignored-common-name"},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: usages, URIs: uris,
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

func TestVerifyPeerRequiresExactURIUsageAndPin(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	uri := "spiffe://campus-link/home-pair-1/site-b/data"
	leaf := makeLeaf(t, uri, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, now.Add(-time.Hour), now.Add(24*time.Hour))
	pin, err := SPKIPin(leaf)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyPeer([]*x509.Certificate{leaf}, Requirements{
		URI: uri, Pins: []string{pin}, Usage: x509.ExtKeyUsageServerAuth, Now: now,
	})
	if err != nil || verified.PinSlot != 0 || !verified.NotAfter.Equal(leaf.NotAfter) {
		t.Fatalf("valid peer rejected: %#v %v", verified, err)
	}

	foreign := makeLeaf(t, uri, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, now.Add(-time.Hour), now.Add(24*time.Hour))
	if _, err := VerifyPeer([]*x509.Certificate{foreign}, Requirements{URI: uri, Pins: []string{pin}, Usage: x509.ExtKeyUsageServerAuth, Now: now}); err == nil {
		t.Fatal("unlisted key with valid URI and usage accepted")
	}
}

func TestVerifyPeerRejectsIdentityConfusion(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	uri := "spiffe://campus-link/home-pair-1/site-a/control"
	valid := makeLeaf(t, uri, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now.Add(-time.Hour), now.Add(time.Hour))
	pin, _ := SPKIPin(valid)
	tests := []struct {
		name  string
		cert  *x509.Certificate
		uri   string
		usage x509.ExtKeyUsage
		pins  []string
		now   time.Time
	}{
		{"common-name only", makeLeaf(t, "", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now.Add(-time.Hour), now.Add(time.Hour)), uri, x509.ExtKeyUsageClientAuth, []string{pin}, now},
		{"wrong circuit", valid, "spiffe://campus-link/other/site-a/control", x509.ExtKeyUsageClientAuth, []string{pin}, now},
		{"wrong plane usage", valid, uri, x509.ExtKeyUsageServerAuth, []string{pin}, now},
		{"expired", valid, uri, x509.ExtKeyUsageClientAuth, []string{pin}, now.Add(2 * time.Hour)},
		{"not yet valid", valid, uri, x509.ExtKeyUsageClientAuth, []string{pin}, now.Add(-2 * time.Hour)},
		{"malformed pin", valid, uri, x509.ExtKeyUsageClientAuth, []string{"sha256/not-base64"}, now},
		{"duplicate pins", valid, uri, x509.ExtKeyUsageClientAuth, []string{pin, pin}, now},
		{"any usage", valid, uri, x509.ExtKeyUsageAny, []string{pin}, now},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := VerifyPeer([]*x509.Certificate{test.cert}, Requirements{URI: test.uri, Pins: test.pins, Usage: test.usage, Now: test.now}); err == nil {
				t.Fatal("invalid identity accepted")
			}
		})
	}
}

func TestVerifyPeerAcceptsCurrentOrNextPin(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	uri := "spiffe://campus-link/home-pair-1/site-b/control"
	current := makeLeaf(t, uri, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now.Add(-time.Hour), now.Add(time.Hour))
	next := makeLeaf(t, uri, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now.Add(-time.Hour), now.Add(24*time.Hour))
	currentPin, _ := SPKIPin(current)
	nextPin, _ := SPKIPin(next)
	requirements := Requirements{URI: uri, Pins: []string{currentPin, nextPin}, Usage: x509.ExtKeyUsageClientAuth, Now: now}
	if verified, err := VerifyPeer([]*x509.Certificate{current}, requirements); err != nil || verified.PinSlot != 0 {
		t.Fatal("current slot rejected")
	}
	if verified, err := VerifyPeer([]*x509.Certificate{next}, requirements); err != nil || verified.PinSlot != 1 {
		t.Fatal("next slot rejected")
	}
	if _, err := VerifyPeer([]*x509.Certificate{current}, Requirements{URI: uri, Pins: []string{nextPin}, Usage: x509.ExtKeyUsageClientAuth, Now: now}); err == nil {
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
