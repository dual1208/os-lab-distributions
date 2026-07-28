package rendezvous

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
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
	base := Plan{Circuit: "campus", Generation: "g", PeerGeneration: "p", Session: session, ProbeKey: key, Attempt: 1, PathEpoch: 1, Start: now.Add(50 * time.Millisecond), Expires: now.Add(2 * time.Second)}
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
		addr, err := Punch(ctx, a, aPlan, "site-a", bytes.NewReader(bytes.Repeat([]byte{3}, 16)))
		results <- result{addr, err}
	}()
	go func() {
		addr, err := Punch(ctx, b, bPlan, "site-b", bytes.NewReader(bytes.Repeat([]byte{4}, 16)))
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
		Circuit: "campus", Session: session, ProbeKey: key, Role: RoleSender, Attempt: 1,
		Start: time.Now(), Expires: time.Now().Add(250 * time.Millisecond),
		Candidates: []netip.AddrPort{peer.LocalAddr().(*net.UDPAddr).AddrPort()},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := Punch(ctx, conn, plan, "site-a", bytes.NewReader(bytes.Repeat([]byte{3}, 16))); err == nil {
		t.Fatal("missing authenticated peer was accepted")
	}
}
