package edge

import (
	"context"
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
	"github.com/dual1208/os-lab-distributions/campus-link/internal/datapath"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/identity"
)

type edgeTestCA struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
	pem  []byte
}

func newEdgeTestCA(t *testing.T) edgeTestCA {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "test root"},
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
	return edgeTestCA{cert: cert, key: privateKey, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func issueEdgeTestLeaf(t *testing.T, ca edgeTestCA, commonName, dnsName, uriText string, usages []x509.ExtKeyUsage) tls.Certificate {
	dnsNames := []string(nil)
	if dnsName != "" {
		dnsNames = []string{dnsName}
	}
	return issueEdgeTestLeafWithDNSNames(t, ca, commonName, dnsNames, uriText, usages)
}

func issueEdgeTestLeafWithDNSNames(t *testing.T, ca edgeTestCA, commonName string, dnsNames []string, uriText string, usages []x509.ExtKeyUsage) tls.Certificate {
	now := time.Now()
	return issueEdgeTestLeafWithValidity(t, ca, commonName, dnsNames, uriText, usages, now.Add(-time.Hour), now.Add(24*time.Hour))
}

func issueEdgeTestLeafWithValidity(t *testing.T, ca edgeTestCA, commonName string, dnsNames []string, uriText string, usages []x509.ExtKeyUsage, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(uriText)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: commonName},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages,
		DNSNames: append([]string(nil), dnsNames...), URIs: []*url.URL{uri}, BasicConstraintsValid: true,
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

func writeEdgeTestMaterial(t *testing.T, name string, certificate tls.Certificate, ca edgeTestCA) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")
	caPath := filepath.Join(dir, "ca.crt")
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

func edgeTestPool(t *testing.T, ca edgeTestCA) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.pem) {
		t.Fatal("append test CA")
	}
	return pool
}

func authorizeEdgeLocals(t *testing.T, cfg *config.Edge, control, data tls.Certificate) {
	t.Helper()
	controlPin, err := identity.SPKIPin(control.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	dataPin, err := identity.SPKIPin(data.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	baseURI := "spiffe://campus-link/" + cfg.Circuit + "/" + cfg.Site
	cfg.LocalControlIdentity = config.IdentityAuthorization{
		URI: baseURI + "/control", CurrentSPKI: controlPin,
	}
	cfg.LocalDataIdentity = config.IdentityAuthorization{
		URI: baseURI + "/data", CurrentSPKI: dataPin,
	}
}

func runEdgeTLSHandshake(clientConfig, serverConfig *tls.Config) error {
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
	select {
	case second := <-results:
		return errors.Join(first, second)
	case <-timer.C:
		_ = clientRaw.Close()
		_ = serverRaw.Close()
		return errors.Join(first, <-results)
	}
}

func TestControlClientTLSRejectsForeignSameProfileSPKI(t *testing.T) {
	ca := newEdgeTestCA(t)
	clientCertificate := issueEdgeTestLeaf(t, ca, "irrelevant-cn", "", "spiffe://campus-link/c/site-a/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	relayCertificate := issueEdgeTestLeaf(t, ca, "irrelevant-cn", "gz.campus-link", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	foreignRelayCertificate := issueEdgeTestLeaf(t, ca, "same-irrelevant-cn", "gz.campus-link", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	certPath, keyPath, caPath := writeEdgeTestMaterial(t, "site-a-control", clientCertificate, ca)
	relayPin, err := identity.SPKIPin(relayCertificate.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := clientTLS(certPath, keyPath, caPath, "gz.campus-link", identity.Requirements{
		URI: "spiffe://campus-link/c/relay/control", Pins: []string{relayPin}, Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatal(err)
	}
	if clientConfig.MinVersion != tls.VersionTLS13 || clientConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("control client TLS versions are not pinned to TLS 1.3: min=%x max=%x", clientConfig.MinVersion, clientConfig.MaxVersion)
	}
	serverBase := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: edgeTestPool(t, ca), MinVersion: tls.VersionTLS13,
	}
	validServer := serverBase.Clone()
	validServer.Certificates = []tls.Certificate{relayCertificate}
	if err := runEdgeTLSHandshake(clientConfig, validServer); err != nil {
		t.Fatalf("authorized relay handshake failed: %v", err)
	}
	foreignServer := serverBase.Clone()
	foreignServer.Certificates = []tls.Certificate{foreignRelayCertificate}
	if err := runEdgeTLSHandshake(clientConfig, foreignServer); err == nil {
		t.Fatal("foreign same-root, same-DNS, same-URI, same-EKU relay SPKI accepted")
	}
}

func TestDataTLSBothRolesRejectForeignSameProfileSPKI(t *testing.T) {
	ca := newEdgeTestCA(t)
	dataUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	siteA := issueEdgeTestLeaf(t, ca, "ignored-a", "site-a.campus-link", "spiffe://campus-link/c/site-a/data", dataUsages)
	foreignSiteA := issueEdgeTestLeaf(t, ca, "ignored-a", "site-a.campus-link", "spiffe://campus-link/c/site-a/data", dataUsages)
	siteB := issueEdgeTestLeaf(t, ca, "ignored-b", "site-b.campus-link", "spiffe://campus-link/c/site-b/data", dataUsages)
	foreignSiteB := issueEdgeTestLeaf(t, ca, "ignored-b", "site-b.campus-link", "spiffe://campus-link/c/site-b/data", dataUsages)
	siteACertPath, siteAKeyPath, caPath := writeEdgeTestMaterial(t, "site-a-data", siteA, ca)
	siteBCertPath, siteBKeyPath, _ := writeEdgeTestMaterial(t, "site-b-data", siteB, ca)
	siteAPin, _ := identity.SPKIPin(siteA.Leaf)
	siteBPin, _ := identity.SPKIPin(siteB.Leaf)

	clientRunner, err := New(config.Edge{
		Site: "site-a", Role: "client", Generation: "ga", Circuit: "c", DeploymentID: edgeTestDeploymentID,
		Prefix: "10.81.0.0/24", RemotePrefix: "10.82.0.0/24",
		RelayAddress: "relay:443", ControlServerName: "gz.campus-link",
		ControlIdentity: config.IdentityAuthorization{URI: "spiffe://campus-link/c/relay/control", CurrentSPKI: zeroSPKIPin},
		DataServerName:  "site-b.campus-link", DataCert: siteACertPath, DataKey: siteAKeyPath, DataCA: caPath,
		DataIdentity: config.IdentityAuthorization{URI: "spiffe://campus-link/c/site-b/data", CurrentSPKI: siteBPin},
	}, "test")
	if err != nil {
		t.Fatal(err)
	}
	clientTLSConfig, err := clientRunner.dataTLS()
	if err != nil {
		t.Fatal(err)
	}
	if clientTLSConfig.MinVersion != tls.VersionTLS13 || clientTLSConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("data client TLS versions are not pinned to TLS 1.3: min=%x max=%x", clientTLSConfig.MinVersion, clientTLSConfig.MaxVersion)
	}
	serverBase := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: edgeTestPool(t, ca),
		MinVersion: tls.VersionTLS13, NextProtos: []string{"campus-link/1"},
	}
	validServer := serverBase.Clone()
	validServer.Certificates = []tls.Certificate{siteB}
	if err := runEdgeTLSHandshake(clientTLSConfig, validServer); err != nil {
		t.Fatalf("site-a client to site-b server handshake failed: %v", err)
	}
	foreignServer := serverBase.Clone()
	foreignServer.Certificates = []tls.Certificate{foreignSiteB}
	if err := runEdgeTLSHandshake(clientTLSConfig, foreignServer); err == nil {
		t.Fatal("data client accepted foreign same-root, same-DNS, same-URI, same-EKU SPKI")
	}

	serverRunner, err := New(config.Edge{
		Site: "site-b", Role: "server", Generation: "gb", Circuit: "c", DeploymentID: edgeTestDeploymentID,
		Prefix: "10.82.0.0/24", RemotePrefix: "10.81.0.0/24",
		RelayAddress: "relay:443", ControlServerName: "gz.campus-link",
		ControlIdentity: config.IdentityAuthorization{URI: "spiffe://campus-link/c/relay/control", CurrentSPKI: zeroSPKIPin},
		DataServerName:  "site-b.campus-link", DataCert: siteBCertPath, DataKey: siteBKeyPath, DataCA: caPath,
		DataIdentity: config.IdentityAuthorization{URI: "spiffe://campus-link/c/site-a/data", CurrentSPKI: siteAPin},
	}, "test")
	if err != nil {
		t.Fatal(err)
	}
	serverTLSConfig, err := serverRunner.dataTLS()
	if err != nil {
		t.Fatal(err)
	}
	if serverTLSConfig.MinVersion != tls.VersionTLS13 || serverTLSConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("data server TLS versions are not pinned to TLS 1.3: min=%x max=%x", serverTLSConfig.MinVersion, serverTLSConfig.MaxVersion)
	}
	clientBase := &tls.Config{
		RootCAs: edgeTestPool(t, ca), ServerName: "site-b.campus-link",
		MinVersion: tls.VersionTLS13, NextProtos: []string{"campus-link/1"},
	}
	validClient := clientBase.Clone()
	validClient.Certificates = []tls.Certificate{siteA}
	if err := runEdgeTLSHandshake(validClient, serverTLSConfig); err != nil {
		t.Fatalf("site-a client certificate at site-b server role failed: %v", err)
	}
	foreignClient := clientBase.Clone()
	foreignClient.Certificates = []tls.Certificate{foreignSiteA}
	if err := runEdgeTLSHandshake(foreignClient, serverTLSConfig); err == nil {
		t.Fatal("data server accepted foreign same-root, same-DNS, same-URI, same-EKU SPKI")
	}
}

func TestLocalCredentialPreflightRequiresExactEdgeIdentities(t *testing.T) {
	ca := newEdgeTestCA(t)
	control := issueEdgeTestLeaf(t, ca, "ignored", "", "spiffe://campus-link/c/site-b/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	data := issueEdgeTestLeaf(t, ca, "ignored", "site-b.campus-link", "spiffe://campus-link/c/site-b/data", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	cfg := config.Edge{
		Site: "site-b", Role: "server", Generation: "g", Circuit: "c", DeploymentID: edgeTestDeploymentID,
		Prefix: "10.82.0.0/24", RemotePrefix: "10.81.0.0/24",
		RelayAddress: "not-resolved.invalid:443", ControlServerName: "gz.campus-link",
		ControlIdentity: config.IdentityAuthorization{URI: "spiffe://campus-link/c/relay/control", CurrentSPKI: zeroSPKIPin},
		DataIdentity:    config.IdentityAuthorization{URI: "spiffe://campus-link/c/site-a/data", CurrentSPKI: oneSPKIPin},
	}
	authorizeEdgeLocals(t, &cfg, control, data)
	runner, err := New(cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	pool := edgeTestPool(t, ca)
	if err := runner.validateLocalIdentities(control, pool, data, pool); err != nil {
		t.Fatalf("valid local identities rejected: %v", err)
	}
	wrongControl := issueEdgeTestLeaf(t, ca, "ignored", "", "spiffe://campus-link/c/site-a/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if err := runner.validateLocalIdentities(wrongControl, pool, data, pool); err == nil {
		t.Fatal("wrong local control URI accepted")
	}
	wrongDataUsage := issueEdgeTestLeaf(t, ca, "ignored", "site-b.campus-link", "spiffe://campus-link/c/site-b/data", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err := runner.validateLocalIdentities(control, pool, wrongDataUsage, pool); err == nil {
		t.Fatal("wrong local data EKU accepted")
	}
	wrongDataDNS := issueEdgeTestLeaf(t, ca, "ignored", "foreign.campus-link", "spiffe://campus-link/c/site-b/data", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	if err := runner.validateLocalIdentities(control, pool, wrongDataDNS, pool); err == nil {
		t.Fatal("wrong local data DNS identity accepted")
	}
	missingDataDNS := issueEdgeTestLeaf(t, ca, "ignored", "", "spiffe://campus-link/c/site-b/data", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	if err := runner.validateLocalIdentities(control, pool, missingDataDNS, pool); err == nil {
		t.Fatal("missing local data DNS identity accepted")
	}
	wildcardDataDNS := issueEdgeTestLeaf(t, ca, "ignored", "*.campus-link", "spiffe://campus-link/c/site-b/data", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	if err := runner.validateLocalIdentities(control, pool, wildcardDataDNS, pool); err == nil {
		t.Fatal("wildcard local data DNS identity accepted")
	}
	extraDataDNS := issueEdgeTestLeafWithDNSNames(t, ca, "ignored", []string{"site-b.campus-link", "other.campus-link"}, "spiffe://campus-link/c/site-b/data", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	if err := runner.validateLocalIdentities(control, pool, extraDataDNS, pool); err == nil {
		t.Fatal("local data identity with an extra DNS SAN accepted")
	}
	runner.cfg.DataServerName = "foreign.campus-link"
	if err := runner.validateLocalIdentities(control, pool, wrongDataDNS, pool); err == nil {
		t.Fatal("data_server_name redefined the canonical local server DNS identity")
	}
}

func TestValidateConfigBuildsBothTLSPlanesWithoutNetwork(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux production policy requires root-owned credential fixtures")
	}
	ca := newEdgeTestCA(t)
	control := issueEdgeTestLeaf(t, ca, "ignored", "", "spiffe://campus-link/c/site-b/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	data := issueEdgeTestLeaf(t, ca, "ignored", "site-b.campus-link", "spiffe://campus-link/c/site-b/data", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	controlCert, controlKey, controlCA := writeEdgeTestMaterial(t, "control", control, ca)
	dataCert, dataKey, dataCA := writeEdgeTestMaterial(t, "data", data, ca)
	cfg := config.Edge{
		Site: "site-b", Role: "server", Generation: "g", Circuit: "c", DeploymentID: edgeTestDeploymentID,
		Prefix: "10.82.0.0/24", RemotePrefix: "10.81.0.0/24",
		RelayAddress: "not-resolved.invalid:443", ControlServerName: "gz.campus-link",
		ControlCert: controlCert, ControlKey: controlKey, ControlCA: controlCA,
		ControlIdentity: config.IdentityAuthorization{URI: "spiffe://campus-link/c/relay/control", CurrentSPKI: zeroSPKIPin},
		DataServerName:  "site-b.campus-link", DataCert: dataCert, DataKey: dataKey, DataCA: dataCA,
		DataIdentity: config.IdentityAuthorization{URI: "spiffe://campus-link/c/site-a/data", CurrentSPKI: oneSPKIPin},
	}
	authorizeEdgeLocals(t, &cfg, control, data)
	runner, err := New(cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.ValidateConfig(); err != nil {
		t.Fatalf("offline edge preflight failed: %v", err)
	}
}

func TestLocalCredentialPreflightRejectsReconnectMarginAndCapturesExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca := newEdgeTestCA(t)
	control := issueEdgeTestLeafWithValidity(t, ca, "ignored", nil, "spiffe://campus-link/c/site-b/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now.Add(-time.Hour), now.Add(time.Hour))
	data := issueEdgeTestLeafWithValidity(t, ca, "ignored", []string{"site-b.campus-link"}, "spiffe://campus-link/c/site-b/data", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, now.Add(-time.Hour), now.Add(2*time.Hour))
	cfg := config.Edge{
		Site: "site-b", Role: "server", Generation: "g", Circuit: "c", DeploymentID: edgeTestDeploymentID,
		Prefix: "10.82.0.0/24", RemotePrefix: "10.81.0.0/24",
		RelayAddress: "not-resolved.invalid:443", ControlServerName: "gz.campus-link",
		ControlIdentity: config.IdentityAuthorization{URI: "spiffe://campus-link/c/relay/control", CurrentSPKI: zeroSPKIPin},
		DataIdentity:    config.IdentityAuthorization{URI: "spiffe://campus-link/c/site-a/data", CurrentSPKI: oneSPKIPin},
	}
	authorizeEdgeLocals(t, &cfg, control, data)
	runner, err := New(cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	pool := edgeTestPool(t, ca)
	controlVerified, dataVerified, err := runner.verifyLocalIdentities(control, pool, data, pool, now)
	if err != nil {
		t.Fatalf("safe local identities rejected: %v", err)
	}
	if controlVerified.PinSlot != 0 || dataVerified.PinSlot != 0 ||
		!controlVerified.NotAfter.Equal(control.Leaf.NotAfter) || !dataVerified.NotAfter.Equal(data.Leaf.NotAfter) {
		t.Fatalf("local verification metadata was not captured: control=%#v data=%#v", controlVerified, dataVerified)
	}
	expiringControl := issueEdgeTestLeafWithValidity(t, ca, "ignored", nil, "spiffe://campus-link/c/site-b/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now.Add(-time.Hour), now.Add(identity.ReconnectMargin))
	expiringControlPin, _ := identity.SPKIPin(expiringControl.Leaf)
	runner.cfg.LocalControlIdentity.CurrentSPKI = expiringControlPin
	if _, _, err := runner.verifyLocalIdentities(expiringControl, pool, data, pool, now); !errors.Is(err, identity.ErrReconnectMargin) {
		t.Fatalf("control leaf inside reconnect margin accepted: %v", err)
	}
	expiringData := issueEdgeTestLeafWithValidity(t, ca, "ignored", []string{"site-b.campus-link"}, "spiffe://campus-link/c/site-b/data", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, now.Add(-time.Hour), now.Add(identity.ReconnectMargin))
	authorizeEdgeLocals(t, &runner.cfg, control, expiringData)
	if _, _, err := runner.verifyLocalIdentities(control, pool, expiringData, pool, now); !errors.Is(err, identity.ErrReconnectMargin) {
		t.Fatalf("data leaf inside reconnect margin accepted: %v", err)
	}
}

func TestEdgeStatusContainsOnlySanitizedIdentityLifetime(t *testing.T) {
	expiry := time.Date(2026, 8, 1, 2, 3, 4, 0, time.UTC)
	statusPath := filepath.Join(t.TempDir(), "edge-status.json")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay, _ := newControlSurvivalConnectionPair()
	mux, err := datapath.New(ctx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	snapshot := mux.Snapshot()
	runner := &Runner{
		cfg: config.Edge{
			StatusPath: statusPath, RelayAddress: "198.51.100.9:443",
			ControlIdentity: config.IdentityAuthorization{CurrentSPKI: "sha256/secret-pin"},
		},
		state:        edgeState{Site: "site-a", Control: "authenticated"},
		localControl: identity.Verified{NotAfter: expiry, PinSlot: 0},
		peerControl:  identity.Verified{NotAfter: expiry.Add(time.Hour), PinSlot: 1},
		localData:    identity.Verified{NotAfter: expiry.Add(2 * time.Hour), PinSlot: 0},
		pathPeerData: map[pathIdentityKey]identity.Verified{
			{mux: mux, path: datapath.SelectedRelay, instanceID: snapshot.RelayInstanceID}: {
				NotAfter: expiry.Add(3 * time.Hour), PinSlot: 1,
			},
		},
		pathMux: mux,
	}
	runner.state.Path = pathStatus(snapshot, "idle")
	runner.writeStatus()
	wire, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"sha256/secret-pin", "198.51.100.9", "secret-token", "BEGIN CERTIFICATE"} {
		if strings.Contains(string(wire), secret) {
			t.Fatalf("status exposed sensitive material %q: %s", secret, wire)
		}
	}
	var decoded edgeState
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	statuses := []*certificateStatus{
		decoded.ControlIdentity.Local, decoded.ControlIdentity.Peer,
		decoded.DataIdentity.Local, decoded.DataIdentity.Peer,
	}
	for index, status := range statuses {
		if status == nil {
			t.Fatalf("identity status %d missing", index)
		}
		if _, err := time.Parse(time.RFC3339, status.Expires); err != nil {
			t.Fatalf("identity status %d has non-RFC3339 expiry %q", index, status.Expires)
		}
		if status.PinSlot != "current" && status.PinSlot != "next" {
			t.Fatalf("identity status %d exposed invalid slot %q", index, status.PinSlot)
		}
	}
	if sanitizedCertificateStatus(identity.Verified{NotAfter: expiry, PinSlot: 2}) != nil {
		t.Fatal("invalid pin slot was exposed")
	}
}
