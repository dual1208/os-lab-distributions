package relay

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/binding"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
)

func TestRelayTelemetrySnapshotIsCoherentUnderConcurrentForwarding(t *testing.T) {
	server := &Server{}
	const updates = uint64(20_000)
	start := make(chan struct{})
	done := make(chan struct{})
	failures := make(chan string, 1)

	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			<-start
			for {
				server.mu.Lock()
				snapshot := server.relayTelemetryLocked()
				server.mu.Unlock()
				if snapshot.ForwardedSiteB != snapshot.ForwardedSiteA*2 ||
					snapshot.ForwardedSiteABytes != snapshot.ForwardedSiteA*101 ||
					snapshot.ForwardedSiteBBytes != snapshot.ForwardedSiteA*202 ||
					snapshot.Dropped != snapshot.ForwardedSiteA/3 ||
					snapshot.DroppedBytes != (snapshot.ForwardedSiteA/3)*303 {
					select {
					case failures <- "relay telemetry counters were not one coherent snapshot":
					default:
					}
					return
				}
				select {
				case <-done:
					return
				default:
				}
			}
		}()
	}
	close(start)
	for value := uint64(1); value <= updates; value++ {
		server.mu.Lock()
		server.forwardA = value
		server.forwardABytes = value * 101
		server.forwardB = value * 2
		server.forwardBBytes = value * 202
		server.dropped = value / 3
		server.droppedBytes = (value / 3) * 303
		server.mu.Unlock()
	}
	close(done)
	readers.Wait()
	select {
	case failure := <-failures:
		t.Fatal(failure)
	default:
	}
	server.mu.Lock()
	final := server.relayTelemetryLocked()
	server.mu.Unlock()
	if final.ForwardedSiteA != updates || final.ForwardedSiteABytes != updates*101 ||
		final.ForwardedSiteB != updates*2 || final.ForwardedSiteBBytes != updates*202 ||
		final.Dropped != updates/3 || final.DroppedBytes != (updates/3)*303 {
		t.Fatalf("relay telemetry lost forwarding updates: %#v", final)
	}
}

func TestRelayAccountingCouplesPacketsAndExactBytes(t *testing.T) {
	server := &Server{}
	server.mu.Lock()
	if err := server.recordForwardedLocked("site-a", 1200); err != nil {
		t.Fatal(err)
	}
	if err := server.recordForwardedLocked("site-b", 333); err != nil {
		t.Fatal(err)
	}
	if err := server.recordDroppedLocked(2049); err != nil {
		t.Fatal(err)
	}
	snapshot := server.relayTelemetryLocked()
	server.mu.Unlock()
	if snapshot.ForwardedSiteA != 1 || snapshot.ForwardedSiteABytes != 1200 ||
		snapshot.ForwardedSiteB != 1 || snapshot.ForwardedSiteBBytes != 333 ||
		snapshot.Dropped != 1 || snapshot.DroppedBytes != 2049 {
		t.Fatalf("packet and byte accounting diverged: %#v", snapshot)
	}
}

func TestRelayAccountingOverflowFailsWithoutPartialMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		server *Server
		record func(*Server) error
	}{
		{
			name: "forwarded packet",
			server: &Server{
				forwardA: ^uint64(0), forwardABytes: 7,
			},
			record: func(server *Server) error { return server.recordForwardedLocked("site-a", 1) },
		},
		{
			name: "forwarded bytes",
			server: &Server{
				forwardB: 11, forwardBBytes: ^uint64(0) - 4,
			},
			record: func(server *Server) error { return server.recordForwardedLocked("site-b", 5) },
		},
		{
			name: "dropped packet",
			server: &Server{
				dropped: ^uint64(0), droppedBytes: 9,
			},
			record: func(server *Server) error { return server.recordDroppedLocked(1) },
		},
		{
			name: "dropped bytes",
			server: &Server{
				dropped: 13, droppedBytes: ^uint64(0) - 2,
			},
			record: func(server *Server) error { return server.recordDroppedLocked(3) },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := test.server.relayTelemetryLocked()
			if err := test.record(test.server); !errors.Is(err, errRelayTelemetryOverflow) {
				t.Fatalf("overflow returned %v", err)
			}
			after := test.server.relayTelemetryLocked()
			if after != before {
				t.Fatalf("overflow partially mutated accounting: before=%#v after=%#v", before, after)
			}
		})
	}
}

func TestRejectedBindingDatagramAccountsItsExactPayloadBytes(t *testing.T) {
	token := make([]byte, binding.TokenSize)
	for index := range token {
		token[index] = 0x5a
	}
	nonce := binding.Nonce{1}
	packet, _, err := binding.NewRequestWithNonce("site-a", 1, nonce, token)
	if err != nil {
		t.Fatal(err)
	}
	packet[len(packet)-1] ^= 0xff
	server := &Server{legs: map[string]*leg{}}
	consumed, err := server.handleBinding(packet, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})
	if err != nil {
		t.Fatal(err)
	}
	if !consumed {
		t.Fatal("malformed binding datagram escaped relay binding demultiplexing")
	}
	server.mu.Lock()
	snapshot := server.relayTelemetryLocked()
	server.mu.Unlock()
	if snapshot.Dropped != 1 || snapshot.DroppedBytes != uint64(len(packet)) {
		t.Fatalf("binding rejection accounting mismatch: %#v", snapshot)
	}
}

func TestRelayStatusPublishesExactPacketAndByteAccounting(t *testing.T) {
	server := &Server{
		cfg: config.Relay{StatusPath: "enabled-for-snapshot"},
		legs: map[string]*leg{
			"site-a": {},
			"site-b": {},
		},
		statusQueue: make(chan status, 1),
		forwardA:    4, forwardABytes: 400,
		forwardB: 5, forwardBBytes: 500,
		dropped: 6, droppedBytes: 600,
	}
	server.mu.Lock()
	server.queueStatusLocked()
	server.mu.Unlock()
	snapshot := <-server.statusQueue
	if len(snapshot.Forward) != 2 || snapshot.Forward["site-a"] != 4 || snapshot.Forward["site-b"] != 5 ||
		len(snapshot.ForwardBytes) != 2 || snapshot.ForwardBytes["site-a"] != 400 || snapshot.ForwardBytes["site-b"] != 500 ||
		snapshot.Dropped != 6 || snapshot.DroppedBytes != 600 {
		t.Fatalf("relay status accounting mismatch: %#v", snapshot)
	}
}

func TestSpliceUDPAccountsExactForwardedAndDroppedPayloadBytes(t *testing.T) {
	relaySocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relaySocket.Close()
	siteA := relayUDPClient(t)
	defer siteA.Close()
	siteB := relayUDPClient(t)
	defer siteB.Close()
	foreign := relayUDPClient(t)
	defer foreign.Close()

	server := &Server{
		udp: relaySocket,
		legs: map[string]*leg{
			"site-a": {online: true, bound: true, addr: siteA.LocalAddr().(*net.UDPAddr)},
			"site-b": {online: true, bound: true, addr: siteB.LocalAddr().(*net.UDPAddr)},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.spliceUDP(ctx) }()

	forwarded := make([]byte, 1200)
	for index := range forwarded {
		forwarded[index] = byte(index)
	}
	if _, err := siteA.WriteToUDP(forwarded, relaySocket.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	if received := relayReadUDPBounded(t, siteB, len(forwarded)); string(received) != string(forwarded) {
		t.Fatal("forwarded datagram changed")
	}

	dropped := make([]byte, maxOuterDatagramSize+1)
	if _, err := foreign.WriteToUDP(dropped, relaySocket.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		server.mu.Lock()
		snapshot := server.relayTelemetryLocked()
		server.mu.Unlock()
		if snapshot.Dropped == 1 {
			if snapshot.ForwardedSiteA != 1 || snapshot.ForwardedSiteABytes != uint64(len(forwarded)) ||
				snapshot.ForwardedSiteB != 0 || snapshot.ForwardedSiteBBytes != 0 ||
				snapshot.DroppedBytes != uint64(len(dropped)) {
				t.Fatalf("socket-path accounting mismatch: %#v", snapshot)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dropped datagram was not accounted: %#v", snapshot)
		}
		time.Sleep(time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("spliceUDP did not stop after cancellation")
	}
}

func relayReadUDPBounded(t *testing.T, conn *net.UDPConn, size int) []byte {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, size+1)
	n, _, err := conn.ReadFromUDP(packet)
	if err != nil {
		t.Fatal(err)
	}
	return packet[:n]
}
