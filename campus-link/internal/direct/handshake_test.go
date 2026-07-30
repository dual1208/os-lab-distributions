package direct

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/rendezvous"
)

func TestAuthenticatedBidirectionalStabilityHandshake(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	aPlan, bPlan := directTestPlans(time.Now().Add(3 * time.Second))
	aBound, bBound := bindTestPlans(t, aPlan, bPlan)
	options := Options{Timeout: 2 * time.Second, StabilityDuration: 80 * time.Millisecond, ProbeInterval: 20 * time.Millisecond}
	type outcome struct {
		result Result
		err    error
	}
	results := make(chan outcome, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		result, err := Initiate(ctx, a, aBound, "site-a", bytes.NewReader(bytes.Repeat([]byte{0xa1}, nonceSize)), options)
		results <- outcome{result: result, err: err}
	}()
	go func() {
		result, err := Accept(ctx, b, bBound, "site-b", bytes.NewReader(bytes.Repeat([]byte{0xb2}, nonceSize)), options)
		results <- outcome{result: result, err: err}
	}()
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("handshake failed: %v %v", first.err, second.err)
	}
	for _, result := range []Result{first.result, second.result} {
		if result.PathEpoch != aPlan.PathEpoch || result.ProbeCount != 4 || result.Validated.IsZero() {
			t.Fatalf("unexpected result: %#v", result)
		}
	}
}

func TestHandshakeRejectsMismatchedPlanContext(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*rendezvous.Plan)
	}{
		{name: "probe key", mutate: func(plan *rendezvous.Plan) { plan.ProbeKey[1] ^= 0xff }},
		{name: "source version", mutate: func(plan *rendezvous.Plan) { plan.Version = "other" }},
		{name: "deployment", mutate: func(plan *rendezvous.Plan) { plan.DeploymentID = "11111111111111111111111111111111" }},
		{name: "relay generation", mutate: func(plan *rendezvous.Plan) { plan.RelayGeneration = "22222222222222222222222222222222" }},
		{name: "peer generation", mutate: func(plan *rendezvous.Plan) { plan.PeerGeneration = "stale" }},
		{name: "path epoch", mutate: func(plan *rendezvous.Plan) { plan.PathEpoch++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			aPlan, bPlan := directTestPlans(time.Now().Add(2 * time.Second))
			test.mutate(&bPlan)
			aBound, bBound := bindTestPlans(t, aPlan, bPlan)
			options := Options{Timeout: time.Second, StabilityDuration: 40 * time.Millisecond, ProbeInterval: 10 * time.Millisecond}
			errorsCh := make(chan error, 2)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			go func() {
				_, err := Initiate(ctx, a, aBound, "site-a", bytes.NewReader(bytes.Repeat([]byte{1}, nonceSize)), options)
				errorsCh <- err
			}()
			go func() {
				_, err := Accept(ctx, b, bBound, "site-b", bytes.NewReader(bytes.Repeat([]byte{2}, nonceSize)), options)
				errorsCh <- err
			}()
			first, second := <-errorsCh, <-errorsCh
			if first == nil || second == nil {
				t.Fatalf("mismatched plan succeeded: %v %v", first, second)
			}
		})
	}
}

func TestActivationBarrierPreparesBothReceiversBeforeSelection(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	aPlan, bPlan := directTestPlans(time.Now().Add(3 * time.Second))
	aBound, bBound := bindTestPlans(t, aPlan, bPlan)
	options := Options{Timeout: 2 * time.Second, StabilityDuration: 40 * time.Millisecond, ProbeInterval: 10 * time.Millisecond}
	type outcome struct {
		result Result
		err    error
	}
	aHandshake, bHandshake := make(chan outcome, 1), make(chan outcome, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		result, err := Initiate(ctx, a, aBound, "site-a", bytes.NewReader(bytes.Repeat([]byte{1}, nonceSize)), options)
		aHandshake <- outcome{result: result, err: err}
	}()
	go func() {
		result, err := Accept(ctx, b, bBound, "site-b", bytes.NewReader(bytes.Repeat([]byte{2}, nonceSize)), options)
		bHandshake <- outcome{result: result, err: err}
	}()
	aResult, bResult := <-aHandshake, <-bHandshake
	if aResult.err != nil || bResult.err != nil {
		t.Fatalf("stability handshake failed: %v %v", aResult.err, bResult.err)
	}
	aActivation, bActivation := &testActivation{}, &testActivation{}
	aActivation.peer, bActivation.peer = bActivation, aActivation
	errorsCh := make(chan error, 2)
	go func() { errorsCh <- ActivateInitiator(ctx, a, aResult.result, aActivation) }()
	go func() { errorsCh <- ActivateReceiver(ctx, b, bResult.result, bActivation) }()
	if first, second := <-errorsCh, <-errorsCh; first != nil || second != nil {
		t.Fatalf("activation barrier failed: %v %v", first, second)
	}
	if !aActivation.selected.Load() || !bActivation.selected.Load() {
		t.Fatal("activation barrier did not select both paths")
	}
	if err := ActivateInitiator(context.Background(), a, Result{}, aActivation); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("unvalidated activation capability accepted: %v", err)
	}
}

type testActivation struct {
	peer     *testActivation
	prepared atomic.Bool
	selected atomic.Bool
}

func (a *testActivation) PrepareDirect(uint64) error {
	a.prepared.Store(true)
	return nil
}

func (a *testActivation) SelectDirect(uint64) error {
	if !a.prepared.Load() || a.peer == nil || !a.peer.prepared.Load() {
		return errors.New("peer receive path was not prepared")
	}
	a.selected.Store(true)
	return nil
}

func (a *testActivation) CommitDirect(uint64) error { return nil }

func (a *testActivation) AbortDirect(uint64) { a.selected.Store(false) }

func TestHandshakeRejectsWrongDeterministicRoles(t *testing.T) {
	aPlan, bPlan := directTestPlans(time.Now().Add(time.Second))
	aBound, bBound := bindTestPlans(t, aPlan, bPlan)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, err := Initiate(context.Background(), a, bBound, "site-b", nil, Options{}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("receiver initiated direct path: %v", err)
	}
	if _, err := Accept(context.Background(), b, aBound, "site-a", nil, Options{}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("sender accepted direct path: %v", err)
	}
}

func TestExporterBindingMatchesPeersAndRejectsBrokerOnlyKey(t *testing.T) {
	aPlan, bPlan := directTestPlans(time.Now().Add(time.Minute))
	exporter := bytes.Repeat([]byte{0x31}, sha256.Size)
	boundA, err := bindExporter(aPlan, "site-a", exporter)
	if err != nil {
		t.Fatal(err)
	}
	boundB, err := bindExporter(bPlan, "site-b", exporter)
	if err != nil {
		t.Fatal(err)
	}
	if boundA.plan.ProbeKey != boundB.plan.ProbeKey {
		t.Fatal("the two TLS peers derived different direct handshake keys")
	}
	if boundA.plan.ProbeKey == aPlan.ProbeKey {
		t.Fatal("broker-visible probe key remained the direct handshake key")
	}
	other, err := bindExporter(aPlan, "site-a", bytes.Repeat([]byte{0x32}, sha256.Size))
	if err != nil {
		t.Fatal(err)
	}
	if other.plan.ProbeKey == boundA.plan.ProbeKey {
		t.Fatal("different TLS exporter produced the same handshake key")
	}
	if _, err := bindExporter(aPlan, "site-a", exporter[:len(exporter)-1]); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("short TLS exporter accepted: %v", err)
	}
}

func TestFrameParserRejectsAuthenticatedReservedBits(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	var contextHash [sha256.Size]byte
	contextHash[0] = 1
	var wire bytes.Buffer
	if err := writeFrame(&wire, frame{typeCode: typeHello, siteCode: 1, roleCode: byte(rendezvous.RoleSender), epoch: 1, context: contextHash}, key); err != nil {
		t.Fatal(err)
	}
	packet := wire.Bytes()
	packet[88] = 1
	mac := hmac.New(sha256.New, key)
	mac.Write(packet[:wireSize-macSize])
	copy(packet[wireSize-macSize:], mac.Sum(nil))
	if _, err := readFrame(bytes.NewReader(packet), key); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("non-canonical reserved field accepted: %v", err)
	}
}

func directTestPlans(expires time.Time) (rendezvous.Plan, rendezvous.Plan) {
	var session [16]byte
	var key [32]byte
	session[0], key[0] = 3, 4
	base := rendezvous.Plan{
		Circuit: "campus", Version: "test", DeploymentID: "0123456789abcdef0123456789abcdef",
		RelayGeneration: "fedcba9876543210fedcba9876543210", Session: session, ProbeKey: key, Attempt: 1,
		PathEpoch: 7, Start: time.Now(), Expires: expires,
	}
	a, b := base, base
	a.Generation, a.PeerGeneration, a.Role = "generation-a", "generation-b", rendezvous.RoleSender
	b.Generation, b.PeerGeneration, b.Role = "generation-b", "generation-a", rendezvous.RoleReceiver
	return a, b
}

func bindTestPlans(t *testing.T, aPlan, bPlan rendezvous.Plan) (BoundPlan, BoundPlan) {
	t.Helper()
	exporter := bytes.Repeat([]byte{0x51}, sha256.Size)
	aBound, err := bindExporter(aPlan, "site-a", exporter)
	if err != nil {
		t.Fatal(err)
	}
	bBound, err := bindExporter(bPlan, "site-b", exporter)
	if err != nil {
		t.Fatal(err)
	}
	return aBound, bBound
}
