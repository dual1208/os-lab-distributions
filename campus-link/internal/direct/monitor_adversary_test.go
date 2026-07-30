package direct

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/rendezvous"
)

func TestDeliveryMonitorRejectsForgedAndWrongEpochProgress(t *testing.T) {
	for _, test := range []struct {
		name   string
		packet func(t *testing.T, result Result) []byte
	}{
		{
			name: "wrong epoch with valid MAC",
			packet: func(t *testing.T, result Result) []byte {
				return adversaryProgressPacket(t, result, result.PathEpoch+1, 7, false)
			},
		},
		{
			name: "forged MAC",
			packet: func(t *testing.T, result Result) []byte {
				return adversaryProgressPacket(t, result, result.PathEpoch, 7, true)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			local, peer := net.Pipe()
			defer local.Close()
			defer peer.Close()
			result := adversaryMonitorResult()
			monitor := newAdversaryMonitor(t, local, result, MonitorOptions{
				ProgressInterval: 5 * time.Millisecond,
				PingInterval:     time.Second,
				IdleTimeout:      2 * time.Second,
			})
			var acknowledgements, failures atomic.Uint64
			if err := monitor.Bind(func(uint64) bool {
				acknowledgements.Add(1)
				return true
			}, func() bool {
				failures.Add(1)
				return true
			}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := monitor.Start(ctx); err != nil {
				t.Fatal(err)
			}
			if err := peer.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := peer.Write(test.packet(t, result)); err != nil {
				t.Fatal(err)
			}
			select {
			case <-monitor.Done():
			case <-time.After(time.Second):
				t.Fatal("invalid authenticated progress did not stop the exact monitor")
			}
			if got := acknowledgements.Load(); got != 0 {
				t.Fatalf("invalid progress reached the mux callback %d time(s)", got)
			}
			if got := failures.Load(); got != 1 {
				t.Fatalf("invalid progress failed the exact path %d time(s), want 1", got)
			}
		})
	}
}

func TestDeliveryMonitorPreservesUint64AndToleratesDuplicateProgress(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	result := adversaryMonitorResult()
	monitor := newAdversaryMonitor(t, local, result, MonitorOptions{
		ProgressInterval: 5 * time.Millisecond,
		PingInterval:     time.Second,
		IdleTimeout:      2 * time.Second,
	})
	const progress = uint64(1)<<48 | 0x123456789abc
	acknowledged := make(chan uint64, 2)
	var failures atomic.Uint64
	if err := monitor.Bind(func(sequence uint64) bool {
		acknowledged <- sequence
		return true
	}, func() bool {
		failures.Add(1)
		return true
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := monitor.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	packet := adversaryProgressPacket(t, result, result.PathEpoch, progress, false)
	for copyIndex := 0; copyIndex < 2; copyIndex++ {
		if err := peer.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			cancel()
			t.Fatal(err)
		}
		if _, err := peer.Write(packet); err != nil {
			cancel()
			t.Fatal(err)
		}
	}
	for copyIndex := 0; copyIndex < 2; copyIndex++ {
		select {
		case got := <-acknowledged:
			if got != progress {
				t.Fatalf("progress truncated: got %#x want %#x", got, progress)
			}
		case <-time.After(time.Second):
			t.Fatal("duplicate authenticated progress was not processed")
		}
	}
	select {
	case <-monitor.Done():
		t.Fatal("duplicate authenticated progress stopped a healthy monitor")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	monitor.Stop()
	if got := failures.Load(); got != 0 {
		t.Fatalf("duplicate progress failed the path %d time(s)", got)
	}
}

func TestDeliveryMonitorIdlePingTimesOutSilentPeer(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	result := adversaryMonitorResult()
	monitor := newAdversaryMonitor(t, local, result, MonitorOptions{
		ProgressInterval: 5 * time.Millisecond,
		PingInterval:     10 * time.Millisecond,
		IdleTimeout:      40 * time.Millisecond,
	})
	var failures atomic.Uint64
	if err := monitor.Bind(func(uint64) bool { return true }, func() bool {
		failures.Add(1)
		return true
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := monitor.Start(ctx); err != nil {
		t.Fatal(err)
	}
	readPing := make(chan frame, 1)
	go func() {
		value, _ := readFrame(peer, result.bound.plan.ProbeKey[:])
		readPing <- value
	}()
	select {
	case ping := <-readPing:
		if ping.typeCode != typeHealthPing || ping.sequence == 0 {
			t.Fatalf("idle monitor emitted an invalid health probe: %#v", ping)
		}
	case <-time.After(time.Second):
		t.Fatal("idle monitor emitted no health probe")
	}
	select {
	case <-monitor.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("missing authenticated pong did not fail within the idle bound")
	}
	if got := failures.Load(); got != 1 {
		t.Fatalf("idle timeout failed the exact path %d time(s), want 1", got)
	}
}

// Stream.Write is allowed to block. A peer that stops reading must therefore
// still be bounded; the idle timer cannot start only after a blocking ping
// write returns.
func TestDeliveryMonitorWriteBlackholeIsBounded(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	result := adversaryMonitorResult()
	monitor := newAdversaryMonitor(t, local, result, MonitorOptions{
		ProgressInterval: 5 * time.Millisecond,
		PingInterval:     10 * time.Millisecond,
		IdleTimeout:      40 * time.Millisecond,
	})
	var failures atomic.Uint64
	if err := monitor.Bind(func(uint64) bool { return true }, func() bool {
		failures.Add(1)
		return true
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := monitor.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	select {
	case <-monitor.Done():
	case <-time.After(500 * time.Millisecond):
		cancel()
		monitor.Stop()
		t.Fatal("peer stopped reading and blocked the health writer beyond the idle bound")
	}
	cancel()
	if got := failures.Load(); got != 1 {
		t.Fatalf("write blackhole failed the exact path %d time(s), want 1", got)
	}
}

func newAdversaryMonitor(t *testing.T, stream Stream, result Result, options MonitorOptions) *DeliveryMonitor {
	t.Helper()
	monitor, err := NewDeliveryMonitor(stream, result, "site-a", options)
	if err != nil {
		t.Fatal(err)
	}
	return monitor
}

func adversaryMonitorResult() Result {
	var key [32]byte
	var localNonce, peerNonce [nonceSize]byte
	for index := range key {
		key[index] = byte(index + 1)
	}
	for index := range localNonce {
		localNonce[index] = byte(0x20 + index)
		peerNonce[index] = byte(0x80 + index)
	}
	contextHash := sha256.Sum256([]byte("delivery-monitor-adversary-context"))
	const epoch = uint64(77)
	return Result{
		PathEpoch: epoch,
		Validated: time.Now(),
		bound: BoundPlan{plan: rendezvous.Plan{
			PathEpoch: epoch,
			ProbeKey:  key,
		}},
		localNonce: localNonce,
		peerNonce:  peerNonce,
		context:    contextHash,
	}
}

func adversaryProgressPacket(t *testing.T, result Result, epoch, progress uint64, forge bool) []byte {
	t.Helper()
	var buffer bytes.Buffer
	value := frame{
		typeCode:  typeDeliveryProgress,
		siteCode:  2,
		roleCode:  byte(rendezvous.RoleReceiver),
		epoch:     epoch,
		progress:  progress,
		nonce:     result.peerNonce,
		peerNonce: result.localNonce,
		context:   result.context,
	}
	if err := writeFrame(&buffer, value, result.bound.plan.ProbeKey[:]); err != nil {
		t.Fatal(err)
	}
	packet := buffer.Bytes()
	if forge {
		packet[len(packet)-1] ^= 0x80
	}
	return packet
}
