package rendezvous

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

func TestPunchEstablishesAuthenticatedBidirectionalPath(t *testing.T) {
	a, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var session [16]byte
	var key [32]byte
	session[0], key[0] = 1, 2
	now := time.Now()
	base := Plan{Circuit: "campus", Version: testVersion, DeploymentID: testDeploymentID, RelayGeneration: testRelayGeneration,
		Generation: "g", PeerGeneration: "p", Session: session, ProbeKey: key, Attempt: 1, PathEpoch: 1, Start: now.Add(50 * time.Millisecond), Expires: now.Add(2 * time.Second)}
	aPlan, bPlan := base, base
	aPlan.Role, bPlan.Role = RoleSender, RoleReceiver
	aPlan.Candidates = []netip.AddrPort{b.LocalAddr().(*net.UDPAddr).AddrPort()}
	bPlan.Candidates = []netip.AddrPort{a.LocalAddr().(*net.UDPAddr).AddrPort()}
	type result struct {
		addr netip.AddrPort
		err  error
	}
	results := make(chan result, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		addr, err := Punch(ctx, a, aPlan, "site-a", bytes.NewReader(bytes.Repeat([]byte{3}, 16)), NewReplayCache(16))
		results <- result{addr, err}
	}()
	go func() {
		addr, err := Punch(ctx, b, bPlan, "site-b", bytes.NewReader(bytes.Repeat([]byte{4}, 16)), NewReplayCache(16))
		results <- result{addr, err}
	}()
	got1, got2 := <-results, <-results
	if got1.err != nil || got2.err != nil {
		t.Fatalf("punch failed: %v %v", got1.err, got2.err)
	}
	wantA, wantB := a.LocalAddr().(*net.UDPAddr).AddrPort(), b.LocalAddr().(*net.UDPAddr).AddrPort()
	if (got1.addr != wantA && got1.addr != wantB) || (got2.addr != wantA && got2.addr != wantB) || got1.addr == got2.addr {
		t.Fatalf("unexpected selected endpoints: %s %s", got1.addr, got2.addr)
	}
}

func TestPunchUsesQUICTransportNonQUICDemultiplexer(t *testing.T) {
	a, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	aTransport, bTransport := &quic.Transport{Conn: a}, &quic.Transport{Conn: b}
	defer aTransport.Close()
	defer bTransport.Close()

	var session [16]byte
	var key [32]byte
	session[0], key[0] = 9, 10
	now := time.Now()
	base := Plan{Circuit: "campus", Version: testVersion, DeploymentID: testDeploymentID, RelayGeneration: testRelayGeneration,
		Generation: "ga", PeerGeneration: "gb", Session: session,
		ProbeKey: key, Attempt: 2, PathEpoch: 3, Start: now.Add(50 * time.Millisecond), Expires: now.Add(2 * time.Second)}
	aPlan, bPlan := base, base
	aPlan.Role, bPlan.Role = RoleSender, RoleReceiver
	rejectedCandidate := netip.MustParseAddrPort("127.0.0.1:1")
	aPlan.Candidates = []netip.AddrPort{rejectedCandidate, b.LocalAddr().(*net.UDPAddr).AddrPort()}
	bPlan.Candidates = []netip.AddrPort{a.LocalAddr().(*net.UDPAddr).AddrPort()}
	type result struct {
		address netip.AddrPort
		err     error
	}
	results := make(chan result, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		io := &selectiveWriteFailure{NonQUICPacketIO: aTransport, rejected: rejectedCandidate}
		address, err := PunchNonQUIC(ctx, io, aPlan, "site-a", bytes.NewReader(bytes.Repeat([]byte{11}, 16)), NewReplayCache(16))
		results <- result{address: address, err: err}
	}()
	go func() {
		address, err := PunchNonQUIC(ctx, bTransport, bPlan, "site-b", bytes.NewReader(bytes.Repeat([]byte{12}, 16)), NewReplayCache(16))
		results <- result{address: address, err: err}
	}()
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("transport punch failed: %v %v", first.err, second.err)
	}
	if first.address == second.address {
		t.Fatalf("both sides selected one endpoint: %s", first.address)
	}
}

type selectiveWriteFailure struct {
	NonQUICPacketIO
	rejected netip.AddrPort
}

func (s *selectiveWriteFailure) WriteTo(packet []byte, address net.Addr) (int, error) {
	udpAddress, ok := address.(*net.UDPAddr)
	if ok && udpAddress.AddrPort() == s.rejected {
		return 0, errors.New("candidate unavailable")
	}
	return s.NonQUICPacketIO.WriteTo(packet, address)
}

func TestPunchRejectsUnauthenticatedPeer(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	var session [16]byte
	var key [32]byte
	session[0], key[0] = 1, 2
	plan := Plan{
		Circuit: "campus", Version: testVersion, DeploymentID: testDeploymentID, RelayGeneration: testRelayGeneration,
		Generation: "ga", PeerGeneration: "gb", Session: session, ProbeKey: key,
		Role: RoleSender, Attempt: 1, PathEpoch: 1,
		Start: time.Now(), Expires: time.Now().Add(250 * time.Millisecond),
		Candidates: []netip.AddrPort{peer.LocalAddr().(*net.UDPAddr).AddrPort()},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := Punch(ctx, conn, plan, "site-a", bytes.NewReader(bytes.Repeat([]byte{3}, 16)), NewReplayCache(16)); err == nil {
		t.Fatal("missing authenticated peer was accepted")
	}
}

func TestPunchRequiresSymmetricReachability(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	var session [16]byte
	var key [32]byte
	session[0], key[0] = 1, 2
	now := time.Now()
	plan := Plan{Circuit: "campus", Version: testVersion, DeploymentID: testDeploymentID, RelayGeneration: testRelayGeneration,
		Generation: "ga", PeerGeneration: "gb", Session: session, ProbeKey: key,
		Role: RoleSender, Attempt: 1, PathEpoch: 1,
		Start: now, Expires: now.Add(400 * time.Millisecond),
		Candidates: []netip.AddrPort{peer.LocalAddr().(*net.UDPAddr).AddrPort()}}
	go func() {
		buf := make([]byte, ProbeSize)
		_ = peer.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, source, readErr := peer.ReadFromUDP(buf)
		if readErr != nil {
			return
		}
		request, parseErr := Parse(buf[:n], key[:], Expect{Circuit: plan.Circuit, Session: session, Site: 1, Now: time.Now()})
		if parseErr != nil {
			return
		}
		request.Site, request.Role, request.Kind = 2, RoleReceiver, ProbeResponse
		response, marshalErr := request.Marshal(key[:])
		if marshalErr == nil {
			_, _ = peer.WriteToUDP(response, source)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := Punch(ctx, conn, plan, "site-a", bytes.NewReader(bytes.Repeat([]byte{3}, 16)), NewReplayCache(16)); !errors.Is(err, ErrPunchTimeout) {
		t.Fatalf("one-way reachability accepted: %v", err)
	}
}

func TestPunchRequiresResponseToEchoLocalNonce(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	var session [16]byte
	var key [32]byte
	session[0], key[0] = 1, 2
	now := time.Now()
	base := Plan{Circuit: "campus", Version: testVersion, DeploymentID: testDeploymentID, RelayGeneration: testRelayGeneration,
		Session: session, ProbeKey: key, Attempt: 1, PathEpoch: 1,
		Start: now, Expires: now.Add(3 * time.Second)}
	aPlan, bPlan := base, base
	aPlan.Generation, aPlan.PeerGeneration, aPlan.Role = "ga", "gb", RoleSender
	bPlan.Generation, bPlan.PeerGeneration, bPlan.Role = "gb", "ga", RoleReceiver
	aPlan.Candidates = []netip.AddrPort{peer.LocalAddr().(*net.UDPAddr).AddrPort()}
	bPlan.Candidates = []netip.AddrPort{conn.LocalAddr().(*net.UDPAddr).AddrPort()}
	type outcome struct {
		address netip.AddrPort
		err     error
	}
	results := make(chan outcome, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	go func() {
		address, err := Punch(ctx, conn, aPlan, "site-a", bytes.NewReader(bytes.Repeat([]byte{3}, 16)), NewReplayCache(16))
		results <- outcome{address: address, err: err}
	}()
	go func() {
		io := &wrongNonceResponseIO{NonQUICPacketIO: udpPacketIO{conn: peer}, plan: bPlan}
		address, err := PunchNonQUIC(ctx, io, bPlan, "site-b", bytes.NewReader(bytes.Repeat([]byte{4}, 16)), NewReplayCache(16))
		results <- outcome{address: address, err: err}
	}()
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("correlated punch failed: %v %v", first.err, second.err)
	}
	if first.address == second.address {
		t.Fatalf("both sides selected the same endpoint: %s", first.address)
	}
}

type wrongNonceResponseIO struct {
	NonQUICPacketIO
	plan     Plan
	injected bool
}

func (w *wrongNonceResponseIO) ReadNonQUICPacket(ctx context.Context, packet []byte) (int, net.Addr, error) {
	n, address, err := w.NonQUICPacketIO.ReadNonQUICPacket(ctx, packet)
	if err != nil || w.injected {
		return n, address, err
	}
	request, parseErr := Parse(packet[:n], w.plan.ProbeKey[:], Expect{
		Circuit: w.plan.Circuit, Session: w.plan.Session, Site: 1, Now: time.Now(),
	})
	if parseErr != nil || request.Kind != ProbeRequest {
		return n, address, err
	}
	wrong := request
	wrong.Site, wrong.Role, wrong.Kind = 2, RoleReceiver, ProbeResponse
	wrong.Nonce[0] ^= 0xff
	wrongPacket, marshalErr := wrong.Marshal(w.plan.ProbeKey[:])
	if marshalErr != nil {
		return 0, nil, marshalErr
	}
	w.injected = true
	if written, writeErr := w.WriteTo(wrongPacket, address); writeErr != nil || written != len(wrongPacket) {
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		return 0, nil, writeErr
	}
	return n, address, nil
}
