package relay

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/identity"
)

type relayLocalAuthorizationFixture struct {
	server   *Server
	pool     *x509.CertPool
	local    tls.Certificate
	localPin string
	siteAPin string
	siteBPin string
}

func relayCertificatePin(t *testing.T, certificate tls.Certificate) string {
	t.Helper()
	pin, err := identity.SPKIPin(certificate.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	return pin
}

func newRelayLocalAuthorizationFixture(t *testing.T) relayLocalAuthorizationFixture {
	t.Helper()
	ca := newRelayTestCA(t)
	local := issueRelayTestLeaf(t, ca, "ignored", "gz.campus-link", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	siteA := issueRelayTestLeaf(t, ca, "ignored", "", "spiffe://campus-link/c/site-a/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	siteB := issueRelayTestLeaf(t, ca, "ignored", "", "spiffe://campus-link/c/site-b/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	fixture := relayLocalAuthorizationFixture{
		pool: relayTestPool(t, ca), local: local,
		localPin: relayCertificatePin(t, local), siteAPin: relayCertificatePin(t, siteA), siteBPin: relayCertificatePin(t, siteB),
	}
	cfg := validRelayConfig(t)
	cfg.LocalControlIdentity = config.IdentityAuthorization{
		URI: "spiffe://campus-link/c/relay/control", CurrentSPKI: fixture.localPin,
	}
	cfg.ControlIdentities = map[string]config.IdentityAuthorization{
		"site-a": {URI: "spiffe://campus-link/c/site-a/control", CurrentSPKI: fixture.siteAPin},
		"site-b": {URI: "spiffe://campus-link/c/site-b/control", CurrentSPKI: fixture.siteBPin},
	}
	server, err := newTestRelay(cfg, relayTestVersion)
	if err != nil {
		t.Fatal(err)
	}
	fixture.server = server
	return fixture
}

func TestRelayLocalNextSlotDrivesSanitizedStatus(t *testing.T) {
	fixture := newRelayLocalAuthorizationFixture(t)
	ca := newRelayTestCA(t)
	oldLocal := issueRelayTestLeaf(t, ca, "ignored", "gz.campus-link", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	fixture.server.cfg.LocalControlIdentity = config.IdentityAuthorization{
		URI:         "spiffe://campus-link/c/relay/control",
		CurrentSPKI: relayCertificatePin(t, oldLocal), NextSPKI: fixture.localPin,
	}
	verified, err := fixture.server.verifyLocalIdentity(fixture.local, fixture.pool, time.Now())
	if err != nil {
		t.Fatalf("authorized local relay next slot rejected: %v", err)
	}
	if verified.PinSlot != 1 {
		t.Fatalf("loaded relay next slot was mislabeled: %d", verified.PinSlot)
	}
	fixture.server.cfg.StatusPath = "status-is-not-written-by-this-test"
	fixture.server.mu.Lock()
	fixture.server.localControl = verified
	fixture.server.queueStatusLocked()
	fixture.server.mu.Unlock()
	status := <-fixture.server.statusQueue
	if status.LocalIdentity == nil || status.LocalIdentity.PinSlot != "next" {
		t.Fatalf("sanitized relay status did not preserve verified local next slot: %#v", status.LocalIdentity)
	}
}

func TestRelayLocalAuthorizationCannotSelfPinLoadedCertificate(t *testing.T) {
	fixture := newRelayLocalAuthorizationFixture(t)
	foreignCA := newRelayTestCA(t)
	configuredCurrent := issueRelayTestLeaf(t, foreignCA, "ignored", "gz.campus-link", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	fixture.server.cfg.LocalControlIdentity.CurrentSPKI = relayCertificatePin(t, configuredCurrent)
	if _, err := fixture.server.verifyLocalIdentity(fixture.local, fixture.pool, time.Now()); !errors.Is(err, identity.ErrPeerIdentity) {
		t.Fatalf("loaded but unauthorized relay certificate self-pinned as current: %v", err)
	}
}

func TestRelayLocalAuthorizationMissingDuplicateOrCollidingSlotsFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		want   error
		mutate func(relayLocalAuthorizationFixture)
	}{
		{name: "missing local authorization", want: identity.ErrPeerIdentity, mutate: func(f relayLocalAuthorizationFixture) {
			f.server.cfg.LocalControlIdentity = config.IdentityAuthorization{}
		}},
		{name: "duplicate local slots", want: identity.ErrPeerIdentity, mutate: func(f relayLocalAuthorizationFixture) {
			f.server.cfg.LocalControlIdentity.NextSPKI = f.localPin
		}},
		{name: "local next collides with site-a current", want: identity.ErrKeyIsolation, mutate: func(f relayLocalAuthorizationFixture) {
			f.server.cfg.LocalControlIdentity.NextSPKI = f.siteAPin
		}},
		{name: "local next collides with site-b current", want: identity.ErrKeyIsolation, mutate: func(f relayLocalAuthorizationFixture) {
			f.server.cfg.LocalControlIdentity.NextSPKI = f.siteBPin
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRelayLocalAuthorizationFixture(t)
			test.mutate(fixture)
			if _, err := fixture.server.verifyLocalIdentity(fixture.local, fixture.pool, time.Now()); !errors.Is(err, test.want) {
				t.Fatalf("invalid local relay authorization did not fail closed with %v: %v", test.want, err)
			}
		})
	}
}
