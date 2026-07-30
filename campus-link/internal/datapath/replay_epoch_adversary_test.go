package datapath

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestHigherDirectEpochAcceptsRestartedSenderSequenceAndRejectsOldReplay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, relay := connectionPair()
	mux, err := NewDirectRequired(ctx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	oldSender, oldReceiver := connectionPair()
	if err := mux.ActivateDirect(41, oldReceiver); err != nil {
		t.Fatal(err)
	}
	if err := oldSender.SendDatagram(encode(kindDirect, 41, 5000, []byte{0x45, 1})); err != nil {
		t.Fatal(err)
	}
	if packet := receiveWithin(t, mux); len(packet) != 2 || packet[1] != 1 {
		t.Fatalf("old epoch packet=%x", packet)
	}

	// Model a one-sided sender restart: the authenticated epoch advances but
	// that process's outbound packet sequence begins again at one.
	newSender, newReceiver := connectionPair()
	if err := mux.ActivateDirect(42, newReceiver); err != nil {
		t.Fatal(err)
	}
	if err := newSender.SendDatagram(encode(kindDirect, 42, 1, []byte{0x45, 2})); err != nil {
		t.Fatal(err)
	}
	if packet := receiveWithin(t, mux); len(packet) != 2 || packet[1] != 2 {
		t.Fatalf("fresh higher-epoch packet=%x", packet)
	}

	if err := oldSender.SendDatagram(encode(kindDirect, 41, 5000, []byte{0x45, 3})); err != nil {
		t.Fatal(err)
	}
	readCtx, cancelRead := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelRead()
	if packet, err := mux.ReceivePacket(readCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("old replay delivered after epoch advance: packet=%x err=%v", packet, err)
	}
	if mux.Snapshot().Counters.DuplicatePacket == 0 {
		t.Fatal("old-epoch duplicate did not reach its epoch-scoped replay window")
	}
}

func TestSameEpochRetrySharesReplayWindow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, relay := connectionPair()
	mux, err := NewDirectRequired(ctx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	firstSender, firstReceiver := connectionPair()
	if err := mux.ActivateDirect(51, firstReceiver); err != nil {
		t.Fatal(err)
	}
	if err := firstSender.SendDatagram(encode(kindDirect, 51, 77, []byte{0x45, 1})); err != nil {
		t.Fatal(err)
	}
	_ = receiveWithin(t, mux)
	if !mux.DirectFailed(51) {
		t.Fatal("first exact path did not fail")
	}
	secondSender, secondReceiver := connectionPair()
	if err := mux.ActivateDirect(51, secondReceiver); err != nil {
		t.Fatal(err)
	}
	if err := secondSender.SendDatagram(encode(kindDirect, 51, 77, []byte{0x45, 2})); err != nil {
		t.Fatal(err)
	}
	readCtx, cancelRead := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelRead()
	if packet, err := mux.ReceivePacket(readCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("same-epoch retry replay delivered: packet=%x err=%v", packet, err)
	}
}
