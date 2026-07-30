package nonquic

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/binding"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/rendezvous"
)

func TestDispatcherSeparatesBindingAndRendezvousPackets(t *testing.T) {
	transport := newFakeTransport()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dispatcher, err := New(ctx, transport)
	if err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()
	leaseCtx, cancelLeases := context.WithTimeout(context.Background(), time.Second)
	defer cancelLeases()
	bindingLease, err := dispatcher.AcquireBinding(leaseCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer bindingLease.Release()
	punchLease, err := dispatcher.AcquireRendezvous(leaseCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer punchLease.Release()
	address := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	token := make([]byte, binding.TokenSize)
	token[0] = 1
	var nonce binding.Nonce
	nonce[0] = 2
	bindingPacket, _, err := binding.NewRequestWithNonce("site-a", 1, nonce, token)
	if err != nil {
		t.Fatal(err)
	}
	var session, probeNonce [16]byte
	var key [32]byte
	session[0], probeNonce[0], key[0] = 3, 4, 5
	probePacket, err := (rendezvous.Probe{Circuit: "campus", Session: session, Nonce: probeNonce, Site: 1,
		Role: rendezvous.RoleSender, Expires: time.Now().Add(time.Minute), Attempt: 1}).Marshal(key[:])
	if err != nil {
		t.Fatal(err)
	}
	transport.inject(bindingPacket, address)
	transport.inject(probePacket, address)
	if got := readPacket(t, bindingLease); len(got) != binding.PacketSize || !binding.IsProtocol(got) {
		t.Fatalf("binding packet misrouted: %x", got)
	}
	if got := readPacket(t, punchLease); !rendezvous.IsProtocol(got) {
		t.Fatalf("rendezvous packet misrouted: %x", got)
	}
	if transport.maxConcurrentReaders() != 1 {
		t.Fatalf("dispatcher used %d concurrent transport readers", transport.maxConcurrentReaders())
	}
}

func TestDispatcherBoundsMailboxesAndCountsUnknownPackets(t *testing.T) {
	transport := newFakeTransport()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dispatcher, err := New(ctx, transport)
	if err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()
	address := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	token := make([]byte, binding.TokenSize)
	token[0] = 1
	var nonce binding.Nonce
	nonce[0] = 2
	packet, _, err := binding.NewRequestWithNonce("site-a", 1, nonce, token)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < mailboxSize+8; index++ {
		transport.inject(packet, address)
	}
	transport.inject([]byte{0, 1, 2, 3}, address)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		counters := dispatcher.Counters()
		if counters.BindingDrops == 8 && counters.UnknownDrops == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("unexpected dispatcher counters: %#v", dispatcher.Counters())
}

func TestDispatcherLeasesAreExclusiveAndCloseFailsQueuedIO(t *testing.T) {
	transport := newFakeTransport()
	dispatcher, err := New(context.Background(), transport)
	if err != nil {
		t.Fatal(err)
	}
	leaseCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lease, err := dispatcher.AcquireBinding(leaseCtx)
	if err != nil {
		t.Fatal(err)
	}
	blockedCtx, cancelBlocked := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelBlocked()
	if _, err := dispatcher.AcquireBinding(blockedCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second binding consumer acquired mailbox: %v", err)
	}
	address := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	token := make([]byte, binding.TokenSize)
	token[0] = 1
	var nonce binding.Nonce
	nonce[0] = 2
	packet, _, err := binding.NewRequestWithNonce("site-a", 1, nonce, token)
	if err != nil {
		t.Fatal(err)
	}
	transport.inject(packet, address)
	time.Sleep(10 * time.Millisecond)
	dispatcher.Close()
	buffer := make([]byte, readSize)
	if _, _, err := lease.ReadNonQUICPacket(context.Background(), buffer); err == nil {
		t.Fatal("queued packet escaped after dispatcher close")
	}
	if _, err := lease.WriteTo(packet, address); err == nil {
		t.Fatal("write escaped after dispatcher close")
	}
	lease.Release()
}

func TestReleaseCancelsBlockedReaderBeforeLeaseReuse(t *testing.T) {
	transport := newFakeTransport()
	dispatcher, err := New(context.Background(), transport)
	if err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()
	firstCtx, cancelFirst := context.WithTimeout(context.Background(), time.Second)
	defer cancelFirst()
	first, err := dispatcher.AcquireBinding(firstCtx)
	if err != nil {
		t.Fatal(err)
	}
	readResult := make(chan error, 1)
	go func() {
		_, _, err := first.ReadNonQUICPacket(context.Background(), make([]byte, readSize))
		readResult <- err
	}()
	time.Sleep(10 * time.Millisecond)
	first.Release()
	if err := <-readResult; err == nil {
		t.Fatal("released reader remained live")
	}
	secondCtx, cancelSecond := context.WithTimeout(context.Background(), time.Second)
	defer cancelSecond()
	second, err := dispatcher.AcquireBinding(secondCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Release()
	address := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	token := make([]byte, binding.TokenSize)
	token[0] = 1
	var nonce binding.Nonce
	nonce[0] = 2
	packet, _, err := binding.NewRequestWithNonce("site-a", 1, nonce, token)
	if err != nil {
		t.Fatal(err)
	}
	transport.inject(packet, address)
	if got := readPacket(t, second); !binding.IsProtocol(got) {
		t.Fatal("replacement lease did not receive its packet")
	}
}

func TestCanceledAcquireAndDuplicateDispatcherFailClosed(t *testing.T) {
	transport := newFakeTransport()
	dispatcher, err := New(context.Background(), transport)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), transport); err == nil {
		t.Fatal("second dispatcher acquired the same transport")
	}
	for index := 0; index < 100; index++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		cancel()
		if _, err := dispatcher.AcquireBinding(ctx); err == nil {
			t.Fatal("canceled context acquired a mailbox")
		}
	}
	dispatcher.Close()
	replacement, err := New(context.Background(), transport)
	if err != nil {
		t.Fatalf("transport ownership was not released: %v", err)
	}
	replacement.Close()
}

func TestFatalTransportReadCancelsDispatcher(t *testing.T) {
	transport := newFakeTransport()
	dispatcher, err := New(context.Background(), transport)
	if err != nil {
		t.Fatal(err)
	}
	transport.fail <- errors.New("read failed")
	select {
	case <-dispatcher.Errors():
	case <-time.After(time.Second):
		t.Fatal("fatal transport error was not reported")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := dispatcher.AcquireBinding(ctx); err == nil {
		t.Fatal("fatal transport error left dispatcher authority live")
	}
	dispatcher.Close()
}

func readPacket(t *testing.T, endpoint *Lease) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	buffer := make([]byte, readSize)
	n, _, err := endpoint.ReadNonQUICPacket(ctx, buffer)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buffer[:n]...)
}

type fakePacket struct {
	data    []byte
	address net.Addr
}

type fakeTransport struct {
	inbound chan fakePacket
	fail    chan error
	mu      sync.Mutex
	active  int
	maximum int
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{inbound: make(chan fakePacket, 128), fail: make(chan error, 1)}
}

func (t *fakeTransport) WriteTo(packet []byte, address net.Addr) (int, error) {
	return len(packet), nil
}

func (t *fakeTransport) ReadNonQUICPacket(ctx context.Context, buffer []byte) (int, net.Addr, error) {
	t.mu.Lock()
	t.active++
	if t.active > t.maximum {
		t.maximum = t.active
	}
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		t.active--
		t.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	case err := <-t.fail:
		return 0, nil, err
	case packet := <-t.inbound:
		return copy(buffer, packet.data), packet.address, nil
	}
}

func (t *fakeTransport) inject(packet []byte, address net.Addr) {
	t.inbound <- fakePacket{data: append([]byte(nil), packet...), address: address}
}

func (t *fakeTransport) maxConcurrentReaders() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.maximum
}
