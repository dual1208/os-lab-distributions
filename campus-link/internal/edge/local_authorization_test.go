package edge

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/identity"
)

type edgeLocalAuthorizationFixture struct {
	runner           *Runner
	pool             *x509.CertPool
	control          tls.Certificate
	data             tls.Certificate
	controlPin       string
	dataPin          string
	remoteControlPin string
	remoteDataPin    string
}

func edgeCertificatePin(t *testing.T, certificate tls.Certificate) string {
	t.Helper()
	pin, err := identity.SPKIPin(certificate.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	return pin
}

func newEdgeLocalAuthorizationFixture(t *testing.T) edgeLocalAuthorizationFixture {
	t.Helper()
	ca := newEdgeTestCA(t)
	dataUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	control := issueEdgeTestLeaf(t, ca, "ignored", "", "spiffe://campus-link/c/site-b/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	data := issueEdgeTestLeaf(t, ca, "ignored", "site-b.campus-link", "spiffe://campus-link/c/site-b/data", dataUsages)
	remoteControl := issueEdgeTestLeaf(t, ca, "ignored", "gz.campus-link", "spiffe://campus-link/c/relay/control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	remoteData := issueEdgeTestLeaf(t, ca, "ignored", "site-a.campus-link", "spiffe://campus-link/c/site-a/data", dataUsages)
	fixture := edgeLocalAuthorizationFixture{
		pool: edgeTestPool(t, ca), control: control, data: data,
		controlPin: edgeCertificatePin(t, control), dataPin: edgeCertificatePin(t, data),
		remoteControlPin: edgeCertificatePin(t, remoteControl), remoteDataPin: edgeCertificatePin(t, remoteData),
	}
	fixture.runner = newKeyIsolationEdgeRunner(
		t, fixture.controlPin, fixture.dataPin, fixture.remoteControlPin, fixture.remoteDataPin,
	)
	return fixture
}

func TestEdgeLocalNextSlotsDriveSanitizedStatus(t *testing.T) {
	fixture := newEdgeLocalAuthorizationFixture(t)
	ca := newEdgeTestCA(t)
	// These certificates contribute only prospective current pins. They are
	// intentionally not the locally loaded credentials.
	oldControl := issueEdgeTestLeaf(t, ca, "ignored", "", "spiffe://campus-link/c/site-b/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	oldData := issueEdgeTestLeaf(t, ca, "ignored", "site-b.campus-link", "spiffe://campus-link/c/site-b/data", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	fixture.runner.cfg.LocalControlIdentity = config.IdentityAuthorization{
		URI:         "spiffe://campus-link/c/site-b/control",
		CurrentSPKI: edgeCertificatePin(t, oldControl), NextSPKI: fixture.controlPin,
	}
	fixture.runner.cfg.LocalDataIdentity = config.IdentityAuthorization{
		URI:         "spiffe://campus-link/c/site-b/data",
		CurrentSPKI: edgeCertificatePin(t, oldData), NextSPKI: fixture.dataPin,
	}
	control, data, err := fixture.runner.verifyLocalIdentities(
		fixture.control, fixture.pool, fixture.data, fixture.pool, time.Now(),
	)
	if err != nil {
		t.Fatalf("authorized local next slots rejected: %v", err)
	}
	if control.PinSlot != 1 || data.PinSlot != 1 {
		t.Fatalf("loaded next slots were mislabeled: control=%d data=%d", control.PinSlot, data.PinSlot)
	}

	fixture.runner.cfg.StatusPath = filepath.Join(t.TempDir(), "edge-status.json")
	fixture.runner.statusWake = nil
	fixture.runner.setLocalIdentities(control, data)
	if err := fixture.runner.writeStatusNow(); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(fixture.runner.cfg.StatusPath)
	if err != nil {
		t.Fatal(err)
	}
	var status edgeState
	if err := json.Unmarshal(wire, &status); err != nil {
		t.Fatal(err)
	}
	if status.ControlIdentity == nil || status.ControlIdentity.Local == nil ||
		status.ControlIdentity.Local.PinSlot != "next" || status.DataIdentity == nil ||
		status.DataIdentity.Local == nil || status.DataIdentity.Local.PinSlot != "next" {
		t.Fatalf("sanitized status did not preserve verified local next slots: %#v", status)
	}
}

func TestEdgeLocalAuthorizationCannotSelfPinLoadedCertificate(t *testing.T) {
	fixture := newEdgeLocalAuthorizationFixture(t)
	foreignCA := newEdgeTestCA(t)
	configuredCurrent := issueEdgeTestLeaf(t, foreignCA, "ignored", "", "spiffe://campus-link/c/site-b/control", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	fixture.runner.cfg.LocalControlIdentity.CurrentSPKI = edgeCertificatePin(t, configuredCurrent)
	if _, _, err := fixture.runner.verifyLocalIdentities(
		fixture.control, fixture.pool, fixture.data, fixture.pool, time.Now(),
	); !errors.Is(err, identity.ErrPeerIdentity) {
		t.Fatalf("loaded but unauthorized local certificate self-pinned as current: %v", err)
	}
}

func TestEdgeLocalAuthorizationMissingOrDuplicateSlotsFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Runner)
	}{
		{name: "missing local control authorization", mutate: func(runner *Runner) {
			runner.cfg.LocalControlIdentity = config.IdentityAuthorization{}
		}},
		{name: "missing local data authorization", mutate: func(runner *Runner) {
			runner.cfg.LocalDataIdentity = config.IdentityAuthorization{}
		}},
		{name: "duplicate local control slots", mutate: func(runner *Runner) {
			runner.cfg.LocalControlIdentity.NextSPKI = runner.cfg.LocalControlIdentity.CurrentSPKI
		}},
		{name: "duplicate local data slots", mutate: func(runner *Runner) {
			runner.cfg.LocalDataIdentity.NextSPKI = runner.cfg.LocalDataIdentity.CurrentSPKI
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEdgeLocalAuthorizationFixture(t)
			test.mutate(fixture.runner)
			if _, _, err := fixture.runner.verifyLocalIdentities(
				fixture.control, fixture.pool, fixture.data, fixture.pool, time.Now(),
			); !errors.Is(err, identity.ErrPeerIdentity) {
				t.Fatalf("invalid local authorization did not fail closed: %v", err)
			}
		})
	}
}

func TestEdgeProspectiveLocalSlotsAreGloballyIsolated(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(edgeLocalAuthorizationFixture)
	}{
		{name: "local control next collides with local data current", mutate: func(f edgeLocalAuthorizationFixture) {
			f.runner.cfg.LocalControlIdentity.NextSPKI = f.dataPin
		}},
		{name: "local data next collides with local control current", mutate: func(f edgeLocalAuthorizationFixture) {
			f.runner.cfg.LocalDataIdentity.NextSPKI = f.controlPin
		}},
		{name: "local control next collides with relay current", mutate: func(f edgeLocalAuthorizationFixture) {
			f.runner.cfg.LocalControlIdentity.NextSPKI = f.remoteControlPin
		}},
		{name: "local data next collides with peer data current", mutate: func(f edgeLocalAuthorizationFixture) {
			f.runner.cfg.LocalDataIdentity.NextSPKI = f.remoteDataPin
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEdgeLocalAuthorizationFixture(t)
			test.mutate(fixture)
			if _, _, err := fixture.runner.verifyLocalIdentities(
				fixture.control, fixture.pool, fixture.data, fixture.pool, time.Now(),
			); !errors.Is(err, identity.ErrKeyIsolation) {
				t.Fatalf("prospective local slot collision escaped isolation: %v", err)
			}
		})
	}
}
