package edge

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/binding"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
)

const zeroSPKIPin = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
const edgeTestDeploymentID = "0123456789abcdef0123456789abcdef"
const edgeTestRelayGeneration = "abcdef0123456789abcdef0123456789"

func TestBindUDPAuthenticatesAndCorrelatesEveryFlight(t *testing.T) {
	relayConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()
	edgeConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer edgeConn.Close()
	token := edgeBindingToken(0x10)
	serverErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 256)
		_ = relayConn.SetDeadline(time.Now().Add(2 * time.Second))
		n, src, err := relayConn.ReadFromUDP(buf)
		if err != nil {
			serverErr <- err
			return
		}
		request, ok := binding.ParseRequest(buf[:n], token)
		if !ok {
			serverErr <- errors.New("edge did not send authenticated request")
			return
		}

		foreignChallenge, _, err := binding.NewChallenge(request, edgeBindingToken(0x50))
		if err != nil {
			serverErr <- err
			return
		}
		_, _ = relayConn.WriteToUDP(foreignChallenge, src)
		wrongRequestPacket, wrongRequest, err := binding.NewRequest("site-a", 2, token)
		_ = wrongRequestPacket
		if err != nil {
			serverErr <- err
			return
		}
		wrongChallenge, wrongChallengeMeta, err := binding.NewChallenge(wrongRequest, token)
		if err != nil {
			serverErr <- err
			return
		}
		_, _ = relayConn.WriteToUDP(wrongChallenge, src)
		challengePacket, challenge, err := binding.NewChallenge(request, token)
		if err != nil {
			serverErr <- err
			return
		}
		_, _ = relayConn.WriteToUDP(challengePacket, src)

		var response binding.Metadata
		for {
			n, candidateSrc, readErr := relayConn.ReadFromUDP(buf)
			if readErr != nil {
				serverErr <- readErr
				return
			}
			if parsed, ok := binding.ParseResponse(buf[:n], token); ok && parsed.SameTransaction(challenge) {
				response = parsed
				src = candidateSrc
				break
			}
		}
		wrongResponse, err := binding.NewResponse(wrongChallengeMeta, token)
		if err != nil {
			serverErr <- err
			return
		}
		wrongResponseMeta, ok := binding.ParseResponse(wrongResponse, token)
		if !ok {
			serverErr <- errors.New("failed to construct wrong response metadata")
			return
		}
		wrongReady, err := binding.NewReady(wrongResponseMeta, token)
		if err != nil {
			serverErr <- err
			return
		}
		_, _ = relayConn.WriteToUDP(wrongReady, src)
		ready, err := binding.NewReady(response, token)
		if err != nil {
			serverErr <- err
			return
		}
		_, err = relayConn.WriteToUDP(ready, src)
		serverErr <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := bindUDPWithTimeouts(ctx, edgeConn, relayConn.LocalAddr().(*net.UDPAddr), "site-a", token, 2*time.Second, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestBindUDPAdvancesSequenceWhenChallengeIsLost(t *testing.T) {
	relayConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()
	edgeConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer edgeConn.Close()
	token := edgeBindingToken(0x70)
	serverErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 256)
		_ = relayConn.SetDeadline(time.Now().Add(2 * time.Second))
		var src *net.UDPAddr
		var challenge binding.Metadata
		for {
			n, candidateSrc, readErr := relayConn.ReadFromUDP(buf)
			if readErr != nil {
				serverErr <- readErr
				return
			}
			request, ok := binding.ParseRequest(buf[:n], token)
			if !ok || request.Sequence < 2 {
				continue
			}
			packet, candidate, challengeErr := binding.NewChallenge(request, token)
			if challengeErr != nil {
				serverErr <- challengeErr
				return
			}
			src, challenge = candidateSrc, candidate
			_, _ = relayConn.WriteToUDP(packet, src)
			break
		}
		for {
			n, candidateSrc, readErr := relayConn.ReadFromUDP(buf)
			if readErr != nil {
				serverErr <- readErr
				return
			}
			response, ok := binding.ParseResponse(buf[:n], token)
			if !ok || !response.SameTransaction(challenge) {
				continue
			}
			ready, readyErr := binding.NewReady(response, token)
			if readyErr == nil {
				_, readyErr = relayConn.WriteToUDP(ready, candidateSrc)
			}
			serverErr <- readyErr
			return
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := bindUDPWithTimeouts(ctx, edgeConn, relayConn.LocalAddr().(*net.UDPAddr), "site-a", token, time.Second, 20*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func edgeBindingToken(start byte) []byte {
	token := make([]byte, binding.TokenSize)
	for i := range token {
		token[i] = start + byte(i)
	}
	return token
}

func TestNewRejectsUnsafeConfiguration(t *testing.T) {
	valid := config.Edge{
		Site: "site-b", Role: "server", Generation: "g", Circuit: "c", DeploymentID: edgeTestDeploymentID,
		Prefix: "10.82.0.0/24", RemotePrefix: "10.81.0.0/24",
		RelayAddress: "relay:443", ControlServerName: "relay.example",
		ControlIdentity: config.IdentityAuthorization{
			URI: "spiffe://campus-link/c/relay/control", CurrentSPKI: zeroSPKIPin,
		},
		DataIdentity: config.IdentityAuthorization{
			URI: "spiffe://campus-link/c/site-a/data", CurrentSPKI: zeroSPKIPin,
		},
		MTU: 1200,
	}
	if _, err := New(valid, "test"); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*config.Edge)
	}{
		{name: "missing current control pin", mutate: func(c *config.Edge) { c.ControlIdentity.CurrentSPKI = "" }},
		{name: "wrong control URI", mutate: func(c *config.Edge) { c.ControlIdentity.URI = "spiffe://campus-link/c/site-a/control" }},
		{name: "wrong data site URI", mutate: func(c *config.Edge) { c.DataIdentity.URI = "spiffe://campus-link/c/site-b/data" }},
		{name: "case-smuggled pin prefix", mutate: func(c *config.Edge) {
			c.DataIdentity.CurrentSPKI = "SHA256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		}},
		{name: "unsafe circuit URI segment", mutate: func(c *config.Edge) { c.Circuit = "c/other" }},
		{name: "same-role topology", mutate: func(c *config.Edge) { c.Role = "client" }},
		{name: "overlap", mutate: func(c *config.Edge) { c.RemotePrefix = c.Prefix }},
		{name: "IPv6", mutate: func(c *config.Edge) { c.RemotePrefix = "2001:db8::/64" }},
		{name: "unsafe 1280 MTU", mutate: func(c *config.Edge) { c.MTU = 1280 }},
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
	go r.heartbeatWithInterval(ctx, cancel, client, json.NewEncoder(client), control.NewDecoder(client), errCh, 10*time.Millisecond)
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
	case <-time.After(time.Second):
		t.Fatal("heartbeat did not reject mismatched acknowledgement")
	}
}

func TestControlIODeadlineNeverExceedsCertificateCutoff(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cutoff := now.Add(2 * time.Second)
	deadline, err := controlIODeadline(now, 5*time.Second, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if !deadline.Equal(cutoff) {
		t.Fatalf("control deadline=%s exceeds cutoff=%s", deadline, cutoff)
	}
	if _, err := controlIODeadline(cutoff, time.Second, cutoff); err == nil {
		t.Fatal("elapsed certificate cutoff accepted")
	}
	runner := &Runner{}
	runner.setCertificateCutoff(now.Add(10 * time.Second))
	runner.setCertificateCutoff(cutoff)
	if got := runner.certificateDeadline(now.Add(20 * time.Second)); !got.Equal(cutoff) {
		t.Fatalf("active peer expiry did not tighten control cutoff: %s", got)
	}
}

func TestInvalidOptionalPlanDoesNotCancelHealthyControl(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	r := &Runner{cfg: config.Edge{Circuit: "c", Generation: "g", DeploymentID: edgeTestDeploymentID}, version: "test", plans: make(chan authorizedPlan, 1)}
	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.heartbeatWithInterval(ctx, cancel, client, json.NewEncoder(client), control.NewDecoder(client), errCh, 10*time.Millisecond)
	serverDone := make(chan error, 1)
	go func() {
		dec := control.NewDecoder(server)
		enc := json.NewEncoder(server)
		for i := 0; i < 2; i++ {
			var hb control.Heartbeat
			if err := dec.Decode(&hb); err != nil {
				serverDone <- err
				return
			}
			ack := validClockAckForTest(hb)
			time.Sleep(time.Millisecond)
			if i == 0 {
				ack.Plan = &control.RendezvousPlan{Type: "rendezvous-plan", Circuit: "wrong", PathEpoch: 1}
			}
			if err := enc.Encode(ack); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("control did not continue after invalid optional plan")
	}
	counterDeadline := time.Now().Add(500 * time.Millisecond)
	for r.rejectedPlans.Load() != 1 && time.Now().Before(counterDeadline) {
		time.Sleep(time.Millisecond)
	}
	if r.rejectedPlans.Load() != 1 {
		t.Fatalf("invalid plan counter=%d", r.rejectedPlans.Load())
	}
	select {
	case err := <-errCh:
		t.Fatalf("optional plan cancelled healthy control: %v", err)
	default:
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
		cfg:     config.Edge{Circuit: "campus", Generation: "ga", Site: "site-a", DeploymentID: edgeTestDeploymentID},
		version: "test",
		plans:   make(chan authorizedPlan, 1),
	}
	lease := r.beginPlanSession(edgeTestRelayGeneration)
	synchronizeClockForTest(r, lease, now)
	message := control.RendezvousPlan{
		Type: "rendezvous-plan", Circuit: "campus", Version: "test", DeploymentID: edgeTestDeploymentID,
		RelayGeneration: edgeTestRelayGeneration, Generation: "ga", PeerGeneration: "gb",
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
	if err := r.acceptRendezvousPlan(message, now); err != nil {
		t.Fatalf("newer plan was not admitted: %v", err)
	}
	if got := <-r.plans; got.PathEpoch != 2 {
		t.Fatalf("unexpected newer plan: %#v", got)
	}
	message.PathEpoch = 1
	if err := r.acceptRendezvousPlan(message, now); err == nil {
		t.Fatal("authenticated path epoch rollback was silently accepted")
	}

	message.PathEpoch = 3
	message.Candidates = []string{"100.100.100.200:80"}
	if err := r.acceptRendezvousPlan(message, now); err == nil {
		t.Fatal("unsafe newer plan accepted")
	}
	if r.planEpoch.Load() != 2 {
		t.Fatal("invalid plan advanced epoch")
	}
}
