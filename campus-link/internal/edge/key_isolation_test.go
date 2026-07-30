package edge

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/identity"
)

const oneSPKIPin = "sha256/AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="

func issueEdgeTestLeafWithKey(t *testing.T, ca edgeTestCA, privateKey ed25519.PrivateKey, dnsNames []string, uriText string, usages []x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	uri, err := url.Parse(uriText)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "key-isolation-test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages,
		DNSNames: append([]string(nil), dnsNames...), URIs: []*url.URL{uri}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, privateKey.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey, Leaf: leaf}
}

func newKeyIsolationEdgeRunner(t *testing.T, localControlPin, localDataPin, relayPin, peerDataPin string) *Runner {
	t.Helper()
	runner, err := New(config.Edge{
		Site: "site-b", Role: "server", Generation: "g", Circuit: "c", DeploymentID: edgeTestDeploymentID,
		Prefix: "10.82.0.0/24", RemotePrefix: "10.81.0.0/24",
		RelayAddress: "not-resolved.invalid:443", ControlServerName: "gz.campus-link",
		LocalControlIdentity: config.IdentityAuthorization{
			URI: "spiffe://campus-link/c/site-b/control", CurrentSPKI: localControlPin,
		},
		ControlIdentity: config.IdentityAuthorization{
			URI: "spiffe://campus-link/c/relay/control", CurrentSPKI: relayPin,
		},
		DataServerName: "site-b.campus-link",
		LocalDataIdentity: config.IdentityAuthorization{
			URI: "spiffe://campus-link/c/site-b/data", CurrentSPKI: localDataPin,
		},
		DataIdentity: config.IdentityAuthorization{
			URI: "spiffe://campus-link/c/site-a/data", CurrentSPKI: peerDataPin,
		},
	}, "test")
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

func TestEdgePreflightRejectsSPKIReuseAcrossLocalAndAuthorizedIdentities(t *testing.T) {
	ca := newEdgeTestCA(t)
	controlUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	dataUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	control := issueEdgeTestLeaf(t, ca, "ignored", "", "spiffe://campus-link/c/site-b/control", controlUsages)
	data := issueEdgeTestLeaf(t, ca, "ignored", "site-b.campus-link", "spiffe://campus-link/c/site-b/data", dataUsages)
	remoteControl := issueEdgeTestLeaf(t, ca, "ignored", "gz.campus-link", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	remoteData := issueEdgeTestLeaf(t, ca, "ignored", "site-a.campus-link", "spiffe://campus-link/c/site-a/data", dataUsages)
	controlPin, _ := identity.SPKIPin(control.Leaf)
	dataPin, _ := identity.SPKIPin(data.Leaf)
	remoteControlPin, _ := identity.SPKIPin(remoteControl.Leaf)
	remoteDataPin, _ := identity.SPKIPin(remoteData.Leaf)
	pool := edgeTestPool(t, ca)

	sharedData := issueEdgeTestLeafWithKey(t, ca, control.PrivateKey.(ed25519.PrivateKey), []string{"site-b.campus-link"}, "spiffe://campus-link/c/site-b/data", dataUsages)
	tests := []struct {
		name      string
		localData tls.Certificate
		relayPin  string
		peerPin   string
	}{
		{name: "local control and local data", localData: sharedData, relayPin: remoteControlPin, peerPin: remoteDataPin},
		{name: "local control and relay", localData: data, relayPin: controlPin, peerPin: remoteDataPin},
		{name: "local control and peer data", localData: data, relayPin: remoteControlPin, peerPin: controlPin},
		{name: "local data and relay", localData: data, relayPin: dataPin, peerPin: remoteDataPin},
		{name: "local data and peer data", localData: data, relayPin: remoteControlPin, peerPin: dataPin},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			localDataPin, err := identity.SPKIPin(test.localData.Leaf)
			if err != nil {
				t.Fatal(err)
			}
			runner := newKeyIsolationEdgeRunner(t, controlPin, localDataPin, test.relayPin, test.peerPin)
			if _, _, err := runner.verifyLocalIdentities(control, pool, test.localData, pool, time.Now()); !errors.Is(err, identity.ErrKeyIsolation) {
				t.Fatalf("SPKI/private-key reuse did not fail the isolation gate: %v", err)
			}
		})
	}
}

func TestEdgePreflightAcceptsDistinctLocalAndAuthorizedSPKIs(t *testing.T) {
	ca := newEdgeTestCA(t)
	dataUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	control := issueEdgeTestLeaf(t, ca, "ignored", "", "spiffe://campus-link/c/site-b/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	data := issueEdgeTestLeaf(t, ca, "ignored", "site-b.campus-link", "spiffe://campus-link/c/site-b/data", dataUsages)
	remoteControl := issueEdgeTestLeaf(t, ca, "ignored", "gz.campus-link", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	remoteData := issueEdgeTestLeaf(t, ca, "ignored", "site-a.campus-link", "spiffe://campus-link/c/site-a/data", dataUsages)
	remoteControlPin, _ := identity.SPKIPin(remoteControl.Leaf)
	remoteDataPin, _ := identity.SPKIPin(remoteData.Leaf)
	controlPin, _ := identity.SPKIPin(control.Leaf)
	dataPin, _ := identity.SPKIPin(data.Leaf)
	runner := newKeyIsolationEdgeRunner(t, controlPin, dataPin, remoteControlPin, remoteDataPin)
	pool := edgeTestPool(t, ca)
	if _, _, err := runner.verifyLocalIdentities(control, pool, data, pool, time.Now()); err != nil {
		t.Fatalf("distinct edge identity keys rejected: %v", err)
	}
}

func TestEdgePreflightRejectsLocalSPKIInNextAuthorizationSlot(t *testing.T) {
	ca := newEdgeTestCA(t)
	dataUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	control := issueEdgeTestLeaf(t, ca, "ignored", "", "spiffe://campus-link/c/site-b/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	data := issueEdgeTestLeaf(t, ca, "ignored", "site-b.campus-link", "spiffe://campus-link/c/site-b/data", dataUsages)
	remoteControl := issueEdgeTestLeaf(t, ca, "ignored", "gz.campus-link", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	remoteData := issueEdgeTestLeaf(t, ca, "ignored", "site-a.campus-link", "spiffe://campus-link/c/site-a/data", dataUsages)
	controlPin, _ := identity.SPKIPin(control.Leaf)
	dataPin, _ := identity.SPKIPin(data.Leaf)
	remoteControlPin, _ := identity.SPKIPin(remoteControl.Leaf)
	remoteDataPin, _ := identity.SPKIPin(remoteData.Leaf)
	pool := edgeTestPool(t, ca)

	t.Run("relay next", func(t *testing.T) {
		runner := newKeyIsolationEdgeRunner(t, controlPin, dataPin, remoteControlPin, remoteDataPin)
		runner.controlRequirements.Pins = append(runner.controlRequirements.Pins, controlPin)
		if _, _, err := runner.verifyLocalIdentities(control, pool, data, pool, time.Now()); !errors.Is(err, identity.ErrKeyIsolation) {
			t.Fatalf("relay next-slot reuse did not fail the isolation gate: %v", err)
		}
	})
	t.Run("peer data next", func(t *testing.T) {
		runner := newKeyIsolationEdgeRunner(t, controlPin, dataPin, remoteControlPin, remoteDataPin)
		runner.dataRequirements.Pins = append(runner.dataRequirements.Pins, dataPin)
		if _, _, err := runner.verifyLocalIdentities(control, pool, data, pool, time.Now()); !errors.Is(err, identity.ErrKeyIsolation) {
			t.Fatalf("peer next-slot reuse did not fail the isolation gate: %v", err)
		}
	})
}

func TestEdgePreflightRejectsSPKIReuseAcrossAuthorizedPlanes(t *testing.T) {
	ca := newEdgeTestCA(t)
	dataUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	control := issueEdgeTestLeaf(t, ca, "ignored", "", "spiffe://campus-link/c/site-b/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	data := issueEdgeTestLeaf(t, ca, "ignored", "site-b.campus-link", "spiffe://campus-link/c/site-b/data", dataUsages)
	remote := issueEdgeTestLeaf(t, ca, "ignored", "gz.campus-link", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	remotePin, _ := identity.SPKIPin(remote.Leaf)
	controlPin, _ := identity.SPKIPin(control.Leaf)
	dataPin, _ := identity.SPKIPin(data.Leaf)
	runner := newKeyIsolationEdgeRunner(t, controlPin, dataPin, remotePin, remotePin)
	pool := edgeTestPool(t, ca)
	if _, _, err := runner.verifyLocalIdentities(control, pool, data, pool, time.Now()); !errors.Is(err, identity.ErrKeyIsolation) {
		t.Fatalf("cross-authorized SPKI reuse did not fail the isolation gate: %v", err)
	}
}
