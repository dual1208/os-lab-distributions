package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/identity"
)

type relayTestCA struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
	pem  []byte
}

func newRelayTestCA(t *testing.T) relayTestCA {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "control test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return relayTestCA{cert: cert, key: privateKey, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func issueRelayTestLeaf(t *testing.T, ca relayTestCA, commonName, dnsName, uriText string, usages []x509.ExtKeyUsage) tls.Certificate {
	now := time.Now()
	return issueRelayTestLeafWithValidity(t, ca, commonName, dnsName, uriText, usages, now.Add(-time.Hour), now.Add(24*time.Hour))
}

func issueRelayTestLeafWithValidity(t *testing.T, ca relayTestCA, commonName, dnsName, uriText string, usages []x509.ExtKeyUsage, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(uriText)
	if err != nil {
		t.Fatal(err)
	}
	dnsNames := []string(nil)
	if dnsName != "" {
		dnsNames = []string{dnsName}
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: commonName},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages,
		DNSNames: dnsNames, URIs: []*url.URL{uri}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, publicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey, Leaf: leaf}
}

func writeRelayTestMaterial(t *testing.T, certificate tls.Certificate, ca relayTestCA) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "relay.crt")
	keyPath := filepath.Join(dir, "relay.key")
	caPath := filepath.Join(dir, "control-ca.crt")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	for path, contents := range map[string][]byte{certPath: certPEM, keyPath: keyPEM, caPath: ca.pem} {
		if err := os.WriteFile(path, contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return certPath, keyPath, caPath
}

func relayTestPool(t *testing.T, ca relayTestCA) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.pem) {
		t.Fatal("append control test CA")
	}
	return pool
}

func authorizeRelayLocal(t *testing.T, cfg *config.Relay, certificate tls.Certificate) {
	t.Helper()
	pin, err := identity.SPKIPin(certificate.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	cfg.LocalControlIdentity = config.IdentityAuthorization{
		URI: "spiffe://campus-link/c/relay/control", CurrentSPKI: pin,
	}
}

func runRelayTLSHandshake(clientConfig, serverConfig *tls.Config) (tls.ConnectionState, error) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	deadline := time.Now().Add(5 * time.Second)
	_ = clientRaw.SetDeadline(deadline)
	_ = serverRaw.SetDeadline(deadline)
	client := tls.Client(clientRaw, clientConfig)
	server := tls.Server(serverRaw, serverConfig)
	results := make(chan error, 2)
	go func() { results <- client.Handshake() }()
	go func() { results <- server.Handshake() }()
	first := <-results
	if first != nil {
		_ = clientRaw.Close()
		_ = serverRaw.Close()
	}
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	var second error
	select {
	case second = <-results:
	case <-timer.C:
		_ = clientRaw.Close()
		_ = serverRaw.Close()
		second = <-results
	}
	err := errors.Join(first, second)
	return server.ConnectionState(), err
}

func TestRelayControlTLSRejectsForeignSameProfileSPKIAndDerivesSite(t *testing.T) {
	ca := newRelayTestCA(t)
	relayCertificate := issueRelayTestLeaf(t, ca, "relay", "gz.campus-link", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	// The common names deliberately assert the opposite sites. Authorization
	// must be derived only from the exact URI and SPKI entry.
	siteA := issueRelayTestLeaf(t, ca, "site-b", "", "spiffe://campus-link/c/site-a/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	foreignSiteA := issueRelayTestLeaf(t, ca, "site-b", "", "spiffe://campus-link/c/site-a/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	siteB := issueRelayTestLeaf(t, ca, "site-a", "", "spiffe://campus-link/c/site-b/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	certPath, keyPath, caPath := writeRelayTestMaterial(t, relayCertificate, ca)
	siteAPin, _ := identity.SPKIPin(siteA.Leaf)
	siteBPin, _ := identity.SPKIPin(siteB.Leaf)
	cfg := validRelayConfig(t)
	authorizeRelayLocal(t, &cfg, relayCertificate)
	cfg.ControlCert, cfg.ControlKey, cfg.ControlCA = certPath, keyPath, caPath
	cfg.ControlIdentities = map[string]config.IdentityAuthorization{
		"site-a": {URI: "spiffe://campus-link/c/site-a/control", CurrentSPKI: siteAPin},
		"site-b": {URI: "spiffe://campus-link/c/site-b/control", CurrentSPKI: siteBPin},
	}
	server, err := newTestRelay(cfg, relayTestVersion)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig, err := server.relayTLS()
	if err != nil {
		t.Fatal(err)
	}
	if serverConfig.MinVersion != tls.VersionTLS13 || serverConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("relay TLS versions are not pinned to TLS 1.3: min=%x max=%x", serverConfig.MinVersion, serverConfig.MaxVersion)
	}
	clientBase := &tls.Config{RootCAs: relayTestPool(t, ca), ServerName: "gz.campus-link", MinVersion: tls.VersionTLS13}
	validA := clientBase.Clone()
	validA.Certificates = []tls.Certificate{siteA}
	state, err := runRelayTLSHandshake(validA, serverConfig)
	if err != nil {
		t.Fatalf("authorized site-a control handshake failed: %v", err)
	}
	if site, err := server.authorizedSite(state); err != nil || site != "site-a" {
		t.Fatalf("certificate common name influenced site derivation: site=%q err=%v", site, err)
	}
	validB := clientBase.Clone()
	validB.Certificates = []tls.Certificate{siteB}
	if _, err := runRelayTLSHandshake(validB, serverConfig); err != nil {
		t.Fatalf("authorized site-b control handshake failed: %v", err)
	}
	foreignA := clientBase.Clone()
	foreignA.Certificates = []tls.Certificate{foreignSiteA}
	if _, err := runRelayTLSHandshake(foreignA, serverConfig); err == nil {
		t.Fatal("relay accepted foreign same-root, same-DNS, same-URI, same-EKU SPKI")
	}
}

func TestLocalCredentialPreflightRequiresExactRelayIdentity(t *testing.T) {
	ca := newRelayTestCA(t)
	valid := issueRelayTestLeaf(t, ca, "ignored", "gz.campus-link", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	cfg := validRelayConfig(t)
	authorizeRelayLocal(t, &cfg, valid)
	server, err := newTestRelay(cfg, relayTestVersion)
	if err != nil {
		t.Fatal(err)
	}
	pool := relayTestPool(t, ca)
	if err := server.validateLocalIdentity(valid, pool); err != nil {
		t.Fatalf("valid local relay identity rejected: %v", err)
	}
	wrongURI := issueRelayTestLeaf(t, ca, "ignored", "gz.campus-link", "spiffe://campus-link/c/site-a/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err := server.validateLocalIdentity(wrongURI, pool); err == nil {
		t.Fatal("wrong local relay URI accepted")
	}
	wrongUsage := issueRelayTestLeaf(t, ca, "ignored", "gz.campus-link", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if err := server.validateLocalIdentity(wrongUsage, pool); err == nil {
		t.Fatal("wrong local relay EKU accepted")
	}
	wrongDNS := issueRelayTestLeaf(t, ca, "ignored", "foreign.campus-link", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err := server.validateLocalIdentity(wrongDNS, pool); err == nil {
		t.Fatal("wrong local relay DNS identity accepted")
	}
	missingDNS := issueRelayTestLeaf(t, ca, "ignored", "", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err := server.validateLocalIdentity(missingDNS, pool); err == nil {
		t.Fatal("missing local relay DNS identity accepted")
	}
	wildcardDNS := issueRelayTestLeaf(t, ca, "ignored", "*.campus-link", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err := server.validateLocalIdentity(wildcardDNS, pool); err == nil {
		t.Fatal("wildcard local relay DNS identity accepted")
	}
	foreignCA := newRelayTestCA(t)
	if err := server.validateLocalIdentity(valid, relayTestPool(t, foreignCA)); err == nil {
		t.Fatal("local relay certificate accepted under the wrong root")
	}
}

func TestValidateConfigUsesSuppliedRelayCredentialPathsWithoutListening(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux production policy requires root-owned credential fixtures")
	}
	ca := newRelayTestCA(t)
	relayCertificate := issueRelayTestLeaf(t, ca, "ignored", "gz.campus-link", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	certPath, keyPath, caPath := writeRelayTestMaterial(t, relayCertificate, ca)
	cfg := validRelayConfig(t)
	authorizeRelayLocal(t, &cfg, relayCertificate)
	cfg.ControlListen = "not a listen address"
	cfg.UDPListen = "also not a listen address"
	cfg.ControlCert, cfg.ControlKey, cfg.ControlCA = certPath, keyPath, caPath
	server, err := newTestRelay(cfg, relayTestVersion)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.ValidateConfig(); err != nil {
		t.Fatalf("offline relay preflight failed: %v", err)
	}
}

func TestLocalRelayPreflightRejectsReconnectMarginAndCapturesExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca := newRelayTestCA(t)
	valid := issueRelayTestLeafWithValidity(t, ca, "ignored", "gz.campus-link", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, now.Add(-time.Hour), now.Add(time.Hour))
	cfg := validRelayConfig(t)
	authorizeRelayLocal(t, &cfg, valid)
	server, err := newTestRelay(cfg, relayTestVersion)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := server.verifyLocalIdentity(valid, relayTestPool(t, ca), now)
	if err != nil {
		t.Fatalf("safe relay identity rejected: %v", err)
	}
	if verified.PinSlot != 0 || !verified.NotAfter.Equal(valid.Leaf.NotAfter) {
		t.Fatalf("local relay verification metadata was not captured: %#v", verified)
	}
	expiring := issueRelayTestLeafWithValidity(t, ca, "ignored", "gz.campus-link", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, now.Add(-time.Hour), now.Add(identity.ReconnectMargin))
	authorizeRelayLocal(t, &server.cfg, expiring)
	if _, err := server.verifyLocalIdentity(expiring, relayTestPool(t, ca), now); !errors.Is(err, identity.ErrReconnectMargin) {
		t.Fatalf("relay leaf inside reconnect margin accepted: %v", err)
	}
}

func TestAuthorizedSiteCapturesNextPinSlotAndExpiry(t *testing.T) {
	now := time.Now()
	ca := newRelayTestCA(t)
	siteA := issueRelayTestLeaf(t, ca, "ignored", "", "spiffe://campus-link/c/site-a/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	currentA := issueRelayTestLeaf(t, ca, "ignored", "", "spiffe://campus-link/c/site-a/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	siteB := issueRelayTestLeaf(t, ca, "ignored", "", "spiffe://campus-link/c/site-b/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	nextPin, _ := identity.SPKIPin(siteA.Leaf)
	currentPin, _ := identity.SPKIPin(currentA.Leaf)
	siteBPin, _ := identity.SPKIPin(siteB.Leaf)
	cfg := validRelayConfig(t)
	cfg.ControlIdentities = map[string]config.IdentityAuthorization{
		"site-a": {URI: "spiffe://campus-link/c/site-a/control", CurrentSPKI: currentPin, NextSPKI: nextPin},
		"site-b": {URI: "spiffe://campus-link/c/site-b/control", CurrentSPKI: siteBPin},
	}
	server, err := newTestRelay(cfg, relayTestVersion)
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{siteA.Leaf},
		VerifiedChains:   [][]*x509.Certificate{{siteA.Leaf, ca.cert}},
	}
	site, verified, err := server.authorizedSiteVerified(state)
	if err != nil {
		t.Fatal(err)
	}
	if site != "site-a" || verified.PinSlot != 1 || !verified.NotAfter.Equal(siteA.Leaf.NotAfter) || verified.NotAfter.Before(now) {
		t.Fatalf("next-slot peer metadata not captured: site=%q verified=%#v", site, verified)
	}
}

func TestRelayStatusContainsOnlySanitizedIdentityLifetime(t *testing.T) {
	expiry := time.Date(2026, 8, 1, 2, 3, 4, 0, time.UTC)
	server, err := newTestRelay(validRelayConfig(t), relayTestVersion)
	if err != nil {
		t.Fatal(err)
	}
	server.cfg.StatusPath = filepath.Join(t.TempDir(), "relay-status.json")
	server.mu.Lock()
	server.localControl = identity.Verified{NotAfter: expiry, PinSlot: 0}
	server.legs["site-a"] = &leg{
		online: true, bound: true,
		verified: identity.Verified{NotAfter: expiry.Add(time.Hour), PinSlot: 1},
		token:    []byte("secret-token"), addr: &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4444},
	}
	server.queueStatusLocked()
	server.mu.Unlock()
	statusSnapshot := <-server.statusQueue
	wire, err := json.Marshal(statusSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-token", "203.0.113.7", relayZeroSPKIPin, relayOneSPKIPin, "BEGIN CERTIFICATE"} {
		if strings.Contains(string(wire), secret) {
			t.Fatalf("relay status exposed sensitive material %q: %s", secret, wire)
		}
	}
	statuses := []*certificateStatus{statusSnapshot.LocalIdentity, statusSnapshot.Sites["site-a"].ControlIdentity}
	for index, identityStatus := range statuses {
		if identityStatus == nil {
			t.Fatalf("identity status %d missing", index)
		}
		if _, err := time.Parse(time.RFC3339, identityStatus.Expires); err != nil {
			t.Fatalf("identity status %d has non-RFC3339 expiry %q", index, identityStatus.Expires)
		}
		if identityStatus.PinSlot != "current" && identityStatus.PinSlot != "next" {
			t.Fatalf("identity status %d exposed invalid slot %q", index, identityStatus.PinSlot)
		}
	}
}

func TestRegisteredWriteFailurePreservesEstablishedOwners(t *testing.T) {
	ca := newRelayTestCA(t)
	relayCertificate := issueRelayTestLeaf(t, ca, "relay", "gz.campus-link", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	siteA := issueRelayTestLeaf(t, ca, "site-a", "", "spiffe://campus-link/c/site-a/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	siteB := issueRelayTestLeaf(t, ca, "site-b", "", "spiffe://campus-link/c/site-b/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	certPath, keyPath, caPath := writeRelayTestMaterial(t, relayCertificate, ca)
	siteAPin, _ := identity.SPKIPin(siteA.Leaf)
	siteBPin, _ := identity.SPKIPin(siteB.Leaf)
	cfg := validRelayConfig(t)
	authorizeRelayLocal(t, &cfg, relayCertificate)
	cfg.ControlCert, cfg.ControlKey, cfg.ControlCA = certPath, keyPath, caPath
	cfg.ControlIdentities = map[string]config.IdentityAuthorization{
		"site-a": {URI: "spiffe://campus-link/c/site-a/control", CurrentSPKI: siteAPin},
		"site-b": {URI: "spiffe://campus-link/c/site-b/control", CurrentSPKI: siteBPin},
	}
	srv, err := newTestRelay(cfg, relayTestVersion)
	if err != nil {
		t.Fatal(err)
	}
	oldAClient, oldAServer := net.Pipe()
	defer oldAClient.Close()
	defer oldAServer.Close()
	oldBClient, oldBServer := net.Pipe()
	defer oldBClient.Close()
	defer oldBServer.Close()
	srv.mu.Lock()
	oldAOwner, err := srv.activateLegLocked("site-a", "old-a", relayBindingToken(0x21), oldAServer)
	if err != nil {
		srv.mu.Unlock()
		t.Fatal(err)
	}
	oldBOwner, err := srv.activateLegLocked("site-b", "old-b", relayBindingToken(0x41), oldBServer)
	if err != nil {
		srv.mu.Unlock()
		t.Fatal(err)
	}
	srv.mu.Unlock()
	serverConfig, err := srv.relayTLS()
	if err != nil {
		t.Fatal(err)
	}
	clientRaw, serverRaw := net.Pipe()
	client := tls.Client(clientRaw, &tls.Config{
		Certificates: []tls.Certificate{siteA}, RootCAs: relayTestPool(t, ca),
		ServerName: "gz.campus-link", MinVersion: tls.VersionTLS13,
	})
	server := tls.Server(serverRaw, serverConfig)
	serverDone := make(chan struct{})
	go func() {
		srv.handleControl(server)
		close(serverDone)
	}()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(client).Encode(control.Register{
		Type: "register", Site: "site-a", Circuit: "c", Prefix: "10.81.0.0/24", Generation: "ga",
		Version: relayTestVersion, DeploymentID: relayTestDeploymentID,
	}); err != nil {
		t.Fatal(err)
	}
	// Close the transport before reading Registered. Token delivery fails, so
	// the prospective owner must never replace the established pair.
	_ = clientRaw.Close()
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not return after Registered write failure")
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if !srv.established || !srv.legs["site-a"].online || !srv.legs["site-b"].online ||
		srv.legs["site-a"].owner != oldAOwner || srv.legs["site-b"].owner != oldBOwner {
		t.Fatal("failed Registered delivery disturbed the established owners")
	}
}
