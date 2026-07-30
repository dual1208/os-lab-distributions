package direct

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

type discardActivatedStream struct{ Stream }

func (s discardActivatedStream) Write(packet []byte) (int, error) {
	if len(packet) == wireSize && packet[8] == typeActivated {
		// Simulate a transport accepting the final frame locally immediately
		// before the path fails, so Write success is not peer commit evidence.
		return len(packet), nil
	}
	return s.Stream.Write(packet)
}

// The activation contract requires four authenticated flights: prepare,
// prepare-ack, select, and peer-selected-ack. If the select flight never
// reaches the receiver, neither endpoint may retain the new path as selected.
func TestActivationRequiresPeerSelectedAcknowledgement(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	aPlan, bPlan := directTestPlans(time.Now().Add(3 * time.Second))
	aBound, bBound := bindTestPlans(t, aPlan, bPlan)
	options := Options{Timeout: time.Second, StabilityDuration: 40 * time.Millisecond, ProbeInterval: 10 * time.Millisecond}
	type outcome struct {
		result Result
		err    error
	}
	aHandshake, bHandshake := make(chan outcome, 1), make(chan outcome, 1)
	handshakeCtx, cancelHandshake := context.WithTimeout(context.Background(), time.Second)
	defer cancelHandshake()
	go func() {
		result, err := Initiate(handshakeCtx, a, aBound, "site-a", bytes.NewReader(bytes.Repeat([]byte{1}, nonceSize)), options)
		aHandshake <- outcome{result: result, err: err}
	}()
	go func() {
		result, err := Accept(handshakeCtx, b, bBound, "site-b", bytes.NewReader(bytes.Repeat([]byte{2}, nonceSize)), options)
		bHandshake <- outcome{result: result, err: err}
	}()
	aResult, bResult := <-aHandshake, <-bHandshake
	if aResult.err != nil || bResult.err != nil {
		t.Fatalf("stability handshake failed: %v %v", aResult.err, bResult.err)
	}

	aActivation, bActivation := &testActivation{}, &testActivation{}
	aActivation.peer, bActivation.peer = bActivation, aActivation
	activationCtx, cancelActivation := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancelActivation()
	aDone, bDone := make(chan error, 1), make(chan error, 1)
	go func() {
		aDone <- ActivateInitiator(activationCtx, discardActivatedStream{a}, aResult.result, aActivation)
	}()
	go func() { bDone <- ActivateReceiver(activationCtx, b, bResult.result, bActivation) }()
	aErr, bErr := <-aDone, <-bDone
	if aErr == nil || bErr == nil {
		t.Fatalf("lost peer-select flight was accepted: initiator=%v receiver=%v", aErr, bErr)
	}
	if aActivation.selected.Load() || bActivation.selected.Load() {
		t.Fatalf("lost peer-select flight left one-sided selection: initiator=%v receiver=%v",
			aActivation.selected.Load(), bActivation.selected.Load())
	}
}
