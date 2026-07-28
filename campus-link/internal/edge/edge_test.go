package edge

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/rendezvous"
)

func TestServerRequiresExplicitDataPeerIdentity(t *testing.T) {
	trustedForeign := &x509.Certificate{Subject: pkix.Name{CommonName: "foreign-site"}}
	if err := verifyPeerIdentity([]*x509.Certificate{trustedForeign}, "site-a"); err == nil {
		t.Fatal("foreign identity accepted")
	}
	expected := &x509.Certificate{Subject: pkix.Name{CommonName: "site-a"}}
	if err := verifyPeerIdentity([]*x509.Certificate{expected}, "site-a"); err != nil {
		t.Fatalf("expected identity rejected: %v", err)
	}
	if err := verifyPeerIdentity([]*x509.Certificate{expected}, ""); err == nil {
		t.Fatal("empty expected identity accepted")
	}
}

func TestNewRejectsUnsafeConfiguration(t *testing.T) {
	valid := config.Edge{
		Site: "site-b", Role: "server", Generation: "g", Circuit: "c",
		Prefix: "10.82.0.0/24", RemotePrefix: "10.81.0.0/24",
		RelayAddress: "relay:443", ControlServerName: "relay.example",
		DataPeerName: "site-a", MTU: 1280,
	}
	if _, err := New(valid, "test"); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*config.Edge)
	}{
		{name: "missing peer", mutate: func(c *config.Edge) { c.DataPeerName = "" }},
		{name: "overlap", mutate: func(c *config.Edge) { c.RemotePrefix = c.Prefix }},
		{name: "IPv6", mutate: func(c *config.Edge) { c.RemotePrefix = "2001:db8::/64" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			tt.mutate(&cfg)
			if _, err := New(cfg, "test"); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

func TestHeartbeatRequiresMatchingAcknowledgement(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	r := &Runner{}
	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.heartbeat(ctx, cancel, client, json.NewEncoder(client), control.NewDecoder(client), errCh)
	go func() {
		dec := control.NewDecoder(server)
		enc := json.NewEncoder(server)
		var hb control.Heartbeat
		if dec.Decode(&hb) == nil {
			_ = enc.Encode(control.HeartbeatAck{Type: "heartbeat-ack", Sequence: hb.Sequence + 1})
		}
	}()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("mismatched acknowledgement returned nil")
		}
		if ctx.Err() == nil {
			t.Fatal("control failure did not cancel the data session")
		}
	case <-time.After(7 * time.Second):
		t.Fatal("heartbeat did not reject mismatched acknowledgement")
	}
}

func TestPacketCountersDoNotSynchronouslyWriteStatus(t *testing.T) {
	r := &Runner{state: edgeState{Site: "site-a"}}
	for range 10_000 {
		r.sent.Add(1)
		r.received.Add(1)
	}
	if r.sent.Load() != 10_000 || r.received.Load() != 10_000 {
		t.Fatal("packet counters lost updates")
	}
}

func TestRendezvousPlanMailboxIsBoundedAndMonotonic(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	r := &Runner{
		cfg:   config.Edge{Circuit: "campus", Generation: "ga"},
		plans: make(chan rendezvous.Plan, 1),
	}
	message := control.RendezvousPlan{
		Type: "rendezvous-plan", Circuit: "campus", Generation: "ga", PeerGeneration: "gb",
		Session:  hex.EncodeToString([]byte("0123456789abcdef")),
		ProbeKey: hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
		Role:     "sender", Attempt: 1, PathEpoch: 1,
		StartUnix: now.Add(time.Second).Unix(), ExpiresUnix: now.Add(45 * time.Second).Unix(),
		Candidates: []string{"203.0.113.2:40002"},
	}
	if err := r.acceptRendezvousPlan(message, now); err != nil {
		t.Fatal(err)
	}
	if got := <-r.plans; got.PathEpoch != 1 {
		t.Fatalf("unexpected plan: %#v", got)
	}
	if err := r.acceptRendezvousPlan(message, now); err != nil {
		t.Fatalf("duplicate was not idempotent: %v", err)
	}
	select {
	case <-r.plans:
		t.Fatal("duplicate plan was delivered twice")
	default:
	}

	message.PathEpoch = 2
	message.Candidates = []string{"100.100.100.200:80"}
	if err := r.acceptRendezvousPlan(message, now); err == nil {
		t.Fatal("unsafe newer plan accepted")
	}
	if r.planEpoch.Load() != 1 {
		t.Fatal("invalid plan advanced epoch")
	}
}
