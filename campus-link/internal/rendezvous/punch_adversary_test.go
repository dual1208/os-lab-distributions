package rendezvous

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type adversaryPacket struct {
	data []byte
	from *net.UDPAddr
}

type adversaryPathNetwork struct {
	a, b   *adversaryPathIO
	aPaths []netip.AddrPort
	bPaths []netip.AddrPort
	drop   func(string, []byte) bool
}

type adversaryPathIO struct {
	side            string
	network         *adversaryPathNetwork
	inbound         chan adversaryPacket
	activeReads     atomic.Int32
	maxActiveReads  atomic.Int32
	blockReadExit   atomic.Bool
	readExitEntered chan struct{}
	releaseReadExit chan struct{}
	readExitOnce    sync.Once
}

func newAdversaryPathNetwork(paths int, drop func(string, []byte) bool) (*adversaryPathIO, *adversaryPathIO, []netip.AddrPort, []netip.AddrPort) {
	network := &adversaryPathNetwork{drop: drop}
	aAddresses := []string{"198.51.100.1:41001", "198.51.100.2:41002"}
	bAddresses := []string{"203.0.113.1:42001", "203.0.113.2:42002"}
	for index := 0; index < paths; index++ {
		network.aPaths = append(network.aPaths, netip.MustParseAddrPort(aAddresses[index]))
		network.bPaths = append(network.bPaths, netip.MustParseAddrPort(bAddresses[index]))
	}
	network.a = &adversaryPathIO{
		side: "a", network: network, inbound: make(chan adversaryPacket, 1024),
		readExitEntered: make(chan struct{}), releaseReadExit: make(chan struct{}),
	}
	network.b = &adversaryPathIO{
		side: "b", network: network, inbound: make(chan adversaryPacket, 1024),
		readExitEntered: make(chan struct{}), releaseReadExit: make(chan struct{}),
	}
	return network.a, network.b, network.aPaths, network.bPaths
}

func (p *adversaryPathIO) WriteTo(packet []byte, address net.Addr) (int, error) {
	destination := address.(*net.UDPAddr).AddrPort()
	var peer *adversaryPathIO
	var candidates, sources []netip.AddrPort
	if p.side == "a" {
		peer, candidates, sources = p.network.b, p.network.bPaths, p.network.aPaths
	} else {
		peer, candidates, sources = p.network.a, p.network.aPaths, p.network.bPaths
	}
	for index, candidate := range candidates {
		if destination != candidate {
			continue
		}
		if p.network.drop != nil && p.network.drop(p.side, packet) {
			return len(packet), nil
		}
		peer.inbound <- adversaryPacket{
			data: append([]byte(nil), packet...),
			from: net.UDPAddrFromAddrPort(sources[index]),
		}
		return len(packet), nil
	}
	return 0, ErrInvalidCandidate
}

func (p *adversaryPathIO) ReadNonQUICPacket(ctx context.Context, buffer []byte) (int, net.Addr, error) {
	active := p.activeReads.Add(1)
	defer p.activeReads.Add(-1)
	for observed := p.maxActiveReads.Load(); active > observed; observed = p.maxActiveReads.Load() {
		if p.maxActiveReads.CompareAndSwap(observed, active) {
			break
		}
	}
	var n int
	var address net.Addr
	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case packet := <-p.inbound:
		n, address = copy(buffer, packet.data), packet.from
	}
	if p.blockReadExit.Load() {
		p.readExitOnce.Do(func() { close(p.readExitEntered) })
		<-p.releaseReadExit
	}
	return n, address, err
}

func adversaryPlans(aPaths, bPaths []netip.AddrPort, lifetime time.Duration) (Plan, Plan) {
	var session [16]byte
	var key [32]byte
	session[0], key[0] = 0x71, 0x72
	now := time.Now()
	base := Plan{
		Circuit: "campus", Version: "test", DeploymentID: "11111111111111111111111111111111",
		RelayGeneration: "22222222222222222222222222222222", Session: session, ProbeKey: key,
		Attempt: 1, PathEpoch: 1, Start: now, Expires: now.Add(lifetime),
	}
	a, b := base, base
	a.Generation, a.PeerGeneration, a.Role, a.Candidates = "ga", "gb", RoleSender, bPaths
	b.Generation, b.PeerGeneration, b.Role, b.Candidates = "gb", "ga", RoleReceiver, aPaths
	return a, b
}

func TestPunchAdversaryTwoLiveCandidatesComplete(t *testing.T) {
	aIO, bIO, aPaths, bPaths := newAdversaryPathNetwork(2, nil)
	aPlan, bPlan := adversaryPlans(aPaths, bPaths, 4*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	type result struct {
		candidates []netip.AddrPort
		session    *PunchSession
		err        error
	}
	results := make(chan result, 2)
	go func() {
		session, err := PunchCandidatesNonQUIC(ctx, aIO, aPlan, "site-a", bytes.NewReader(bytes.Repeat([]byte{0x31}, 16)), NewReplayCache(64))
		results <- result{candidates: session.Candidates(), session: session, err: err}
	}()
	go func() {
		session, err := PunchCandidatesNonQUIC(ctx, bIO, bPlan, "site-b", bytes.NewReader(bytes.Repeat([]byte{0x42}, 16)), NewReplayCache(64))
		results <- result{candidates: session.Candidates(), session: session, err: err}
	}()
	first, second := <-results, <-results
	first.session.Stop()
	second.session.Stop()
	if first.err != nil || second.err != nil || len(first.candidates) != 2 || len(second.candidates) != 2 {
		t.Fatalf("two live candidates failed: first=%v/%v second=%v/%v", first.candidates, first.err, second.candidates, second.err)
	}
}

func TestPunchAdversaryFinalConfirmedLossRecoveredByService(t *testing.T) {
	dropUntil := time.Now().Add(900 * time.Millisecond)
	drop := func(side string, packet []byte) bool {
		return side == "b" && len(packet) == ProbeSize && ProbeKind(packet[11]) == ProbeConfirmed && time.Now().Before(dropUntil)
	}
	aIO, bIO, aPaths, bPaths := newAdversaryPathNetwork(1, drop)
	aPlan, bPlan := adversaryPlans(aPaths, bPaths, 4*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	results := make(chan *PunchSession, 2)
	errorsCh := make(chan error, 2)
	go func() {
		session, err := PunchCandidatesNonQUIC(ctx, aIO, aPlan, "site-a", bytes.NewReader(bytes.Repeat([]byte{0x51}, 16)), NewReplayCache(64))
		results <- session
		errorsCh <- err
	}()
	go func() {
		session, err := PunchCandidatesNonQUIC(ctx, bIO, bPlan, "site-b", bytes.NewReader(bytes.Repeat([]byte{0x62}, 16)), NewReplayCache(64))
		results <- session
		errorsCh <- err
	}()
	firstSession, secondSession := <-results, <-results
	if first, second := <-errorsCh, <-errorsCh; first != nil || second != nil {
		t.Fatalf("background service failed to recover final-flight loss: %v %v", first, second)
	}
	firstSession.Stop()
	secondSession.Stop()
}

func TestPunchAdversaryStopJoinsReaderBeforeReplacement(t *testing.T) {
	aIO, bIO, aPaths, bPaths := newAdversaryPathNetwork(1, nil)
	aPlan, bPlan := adversaryPlans(aPaths, bPaths, 7*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	type result struct {
		session *PunchSession
		err     error
	}
	runPair := func(aPlan, bPlan Plan, aNonce, bNonce byte) (result, result) {
		results := make(chan result, 2)
		go func() {
			session, err := PunchCandidatesNonQUIC(ctx, aIO, aPlan, "site-a", bytes.NewReader(bytes.Repeat([]byte{aNonce}, 16)), NewReplayCache(64))
			results <- result{session: session, err: err}
		}()
		go func() {
			session, err := PunchCandidatesNonQUIC(ctx, bIO, bPlan, "site-b", bytes.NewReader(bytes.Repeat([]byte{bNonce}, 16)), NewReplayCache(64))
			results <- result{session: session, err: err}
		}()
		return <-results, <-results
	}

	first, second := runPair(aPlan, bPlan, 0x73, 0x74)
	if first.err != nil || second.err != nil || first.session == nil || second.session == nil {
		t.Fatalf("initial punch sessions failed: %v %v", first.err, second.err)
	}

	var aSession, bSession *PunchSession
	for _, session := range []*PunchSession{first.session, second.session} {
		candidates := session.Candidates()
		if len(candidates) != 1 {
			t.Fatalf("initial session returned %d candidates", len(candidates))
		}
		if candidates[0] == bPaths[0] {
			aSession = session
		} else if candidates[0] == aPaths[0] {
			bSession = session
		}
	}
	if aSession == nil || bSession == nil {
		t.Fatal("could not identify initial site sessions")
	}

	deadline := time.Now().Add(time.Second)
	for aIO.activeReads.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if aIO.activeReads.Load() != 1 {
		t.Fatalf("site-a background reader was not singular and active: %d", aIO.activeReads.Load())
	}
	aIO.blockReadExit.Store(true)
	stopReturned := make(chan struct{})
	go func() {
		aSession.Stop()
		close(stopReturned)
	}()
	select {
	case <-aIO.readExitEntered:
	case <-stopReturned:
		t.Fatal("Stop returned before the background reader exited")
	case <-time.After(time.Second):
		t.Fatal("canceled background reader did not begin exiting")
	}
	select {
	case <-stopReturned:
		t.Fatal("Stop did not join the blocked background reader")
	default:
	}
	close(aIO.releaseReadExit)
	select {
	case <-stopReturned:
	case <-time.After(time.Second):
		t.Fatal("Stop did not return after the background reader exited")
	}
	if reads := aIO.activeReads.Load(); reads != 0 {
		t.Fatalf("old site-a reader remained active after Stop: %d", reads)
	}
	aIO.blockReadExit.Store(false)
	bSession.Stop()
	if reads := bIO.activeReads.Load(); reads != 0 {
		t.Fatalf("old site-b reader remained active after Stop: %d", reads)
	}

	secondA, secondB := adversaryPlans(aPaths, bPaths, 4*time.Second)
	secondA.Session[0], secondB.Session[0] = 0x75, 0x75
	secondA.ProbeKey[0], secondB.ProbeKey[0] = 0x76, 0x76
	secondA.Attempt, secondB.Attempt = 2, 2
	secondA.PathEpoch, secondB.PathEpoch = 2, 2
	aIO.maxActiveReads.Store(0)
	bIO.maxActiveReads.Store(0)
	replacementFirst, replacementSecond := runPair(secondA, secondB, 0x77, 0x78)
	if replacementFirst.err != nil || replacementSecond.err != nil ||
		replacementFirst.session == nil || replacementSecond.session == nil {
		t.Fatalf("replacement punch sessions failed: %v %v", replacementFirst.err, replacementSecond.err)
	}
	replacementFirst.session.Stop()
	replacementSecond.session.Stop()
	if aIO.maxActiveReads.Load() > 1 || bIO.maxActiveReads.Load() > 1 {
		t.Fatalf("replacement overlapped old mailbox readers: site-a=%d site-b=%d",
			aIO.maxActiveReads.Load(), bIO.maxActiveReads.Load())
	}
}
