package relay

import (
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/identity"
)

func TestRelayPreflightRejectsLocalSPKIReuseByAuthorizedSite(t *testing.T) {
	ca := newRelayTestCA(t)
	local := issueRelayTestLeaf(t, ca, "ignored", "gz.campus-link", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	siteA := issueRelayTestLeaf(t, ca, "ignored", "", "spiffe://campus-link/c/site-a/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	siteB := issueRelayTestLeaf(t, ca, "ignored", "", "spiffe://campus-link/c/site-b/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	localPin, _ := identity.SPKIPin(local.Leaf)
	siteAPin, _ := identity.SPKIPin(siteA.Leaf)
	siteBPin, _ := identity.SPKIPin(siteB.Leaf)

	tests := []struct {
		name   string
		setPin func(*config.Relay)
	}{
		{name: "site-a current", setPin: func(cfg *config.Relay) {
			a := cfg.ControlIdentities["site-a"]
			a.CurrentSPKI = localPin
			cfg.ControlIdentities["site-a"] = a
		}},
		{name: "site-b next", setPin: func(cfg *config.Relay) {
			b := cfg.ControlIdentities["site-b"]
			b.NextSPKI = localPin
			cfg.ControlIdentities["site-b"] = b
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validRelayConfig(t)
			authorizeRelayLocal(t, &cfg, local)
			cfg.ControlIdentities = map[string]config.IdentityAuthorization{
				"site-a": {URI: "spiffe://campus-link/c/site-a/control", CurrentSPKI: siteAPin},
				"site-b": {URI: "spiffe://campus-link/c/site-b/control", CurrentSPKI: siteBPin},
			}
			test.setPin(&cfg)
			server, err := newTestRelay(cfg, relayTestVersion)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := server.verifyLocalIdentity(local, relayTestPool(t, ca), time.Now()); !errors.Is(err, identity.ErrKeyIsolation) {
				t.Fatalf("relay-local SPKI reuse did not fail the isolation gate: %v", err)
			}
		})
	}
}

func TestRelayPreflightAcceptsDistinctLocalAndAuthorizedSPKIs(t *testing.T) {
	ca := newRelayTestCA(t)
	local := issueRelayTestLeaf(t, ca, "ignored", "gz.campus-link", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	cfg := validRelayConfig(t)
	authorizeRelayLocal(t, &cfg, local)
	server, err := newTestRelay(cfg, relayTestVersion)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.verifyLocalIdentity(local, relayTestPool(t, ca), time.Now()); err != nil {
		t.Fatalf("distinct relay identity key rejected: %v", err)
	}
}
