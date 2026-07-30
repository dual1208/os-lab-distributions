package rendezvous

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
)

const (
	punchInterval = 100 * time.Millisecond
	punchLinger   = 500 * time.Millisecond
)

var ErrPunchTimeout = errors.New("rendezvous punch timed out")

type PunchSession struct {
	candidates []netip.AddrPort
	cancel     context.CancelFunc
	done       chan struct{}
	stopOnce   sync.Once
}

func (s *PunchSession) Candidates() []netip.AddrPort {
	if s == nil {
		return nil
	}
	return append([]netip.AddrPort(nil), s.candidates...)
}

// Stop cancels and joins the sole background mailbox reader. Callers must
// invoke it before acquiring the mailbox for another plan.
func (s *PunchSession) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(s.cancel)
	<-s.done
}

// NonQUICPacketIO is implemented by quic.Transport. It keeps one owner for the
// UDP socket while allowing authenticated rendezvous packets to coexist with
// any number of QUIC connections.
type NonQUICPacketIO interface {
	WriteTo([]byte, net.Addr) (int, error)
	ReadNonQUICPacket(context.Context, []byte) (int, net.Addr, error)
}

// Punch is the raw-UDP compatibility entry point used by isolated unit tests.
// Production callers must use PunchNonQUIC with the socket-owning QUIC
// transport; they must never read the underlying UDPConn concurrently.
func Punch(ctx context.Context, conn *net.UDPConn, plan Plan, site string, random io.Reader, replay *ReplayCache) (netip.AddrPort, error) {
	if conn == nil {
		return netip.AddrPort{}, ErrInvalidPlan
	}
	return PunchNonQUIC(ctx, udpPacketIO{conn: conn}, plan, site, random, replay)
}

// PunchNonQUIC proves bidirectional reachability to an authenticated plan
// candidate using the QUIC transport's bounded non-QUIC queue.
func PunchNonQUIC(ctx context.Context, conn NonQUICPacketIO, plan Plan, site string, random io.Reader, replay *ReplayCache) (netip.AddrPort, error) {
	session, err := PunchCandidatesNonQUIC(ctx, conn, plan, site, random, replay)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return session.candidates[0], nil
}

// PunchCandidatesNonQUIC returns every candidate that completed the
// authenticated bidirectional exchange. Production callers try the returned
// set while the function's bounded background service keeps final flights and
// NAT mappings alive until the attempt context ends.
func PunchCandidatesNonQUIC(ctx context.Context, conn NonQUICPacketIO, plan Plan, site string, random io.Reader, replay *ReplayCache) (*PunchSession, error) {
	if ctx == nil || conn == nil || !validSite(site) || len(plan.Candidates) == 0 || len(plan.Candidates) > MaxCandidates ||
		!validRole(plan.Role) || (site == "site-a" && plan.Role != RoleSender) || (site == "site-b" && plan.Role != RoleReceiver) ||
		plan.Circuit == "" || plan.Generation == "" || plan.PeerGeneration == "" || plan.Generation == plan.PeerGeneration ||
		!control.ValidSourceVersion(plan.Version) || !control.ValidDeploymentID(plan.DeploymentID) || !control.ValidRelayGeneration(plan.RelayGeneration) ||
		plan.Session == ([16]byte{}) || plan.ProbeKey == ([32]byte{}) || plan.Attempt == 0 || plan.PathEpoch == 0 ||
		!plan.Expires.After(plan.Start) || plan.Expires.Sub(plan.Start) > MaxSessionTTL || replay == nil {
		return nil, ErrInvalidPlan
	}
	if random == nil {
		random = rand.Reader
	}
	now := time.Now()
	if plan.Start.After(now.Add(MaxSessionTTL)) {
		return nil, ErrInvalidPlan
	}
	if !plan.Start.After(now) {
		// Start immediately.
	} else {
		timer := time.NewTimer(time.Until(plan.Start))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if !time.Now().Before(plan.Expires) {
		return nil, ErrPunchTimeout
	}
	localCode, peerCode := byte(1), byte(2)
	if site == "site-b" {
		localCode, peerCode = peerCode, localCode
	}
	var nonce [16]byte
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		return nil, err
	}
	if nonce == ([16]byte{}) {
		return nil, ErrInvalidPlan
	}
	request, err := (Probe{
		Circuit: plan.Circuit, Session: plan.Session, Nonce: nonce, Site: localCode,
		Role: plan.Role, Expires: plan.Expires, Attempt: plan.Attempt,
	}).Marshal(plan.ProbeKey[:])
	if err != nil {
		return nil, err
	}
	candidates := make([]*net.UDPAddr, 0, len(plan.Candidates))
	allowed := make(map[netip.AddrPort]struct{}, len(plan.Candidates))
	for _, candidate := range plan.Candidates {
		if !candidate.IsValid() || !candidate.Addr().Is4() || candidate.Port() == 0 {
			return nil, ErrInvalidCandidate
		}
		candidate = netip.AddrPortFrom(candidate.Addr().Unmap(), candidate.Port())
		if _, duplicate := allowed[candidate]; duplicate {
			return nil, ErrInvalidCandidate
		}
		allowed[candidate] = struct{}{}
		candidates = append(candidates, net.UDPAddrFromAddrPort(candidate))
	}
	send := func() error {
		var failures []error
		sent := false
		for _, candidate := range candidates {
			written, err := conn.WriteTo(request, candidate)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			if written != len(request) {
				failures = append(failures, io.ErrShortWrite)
				continue
			}
			sent = true
		}
		if !sent {
			return errors.Join(failures...)
		}
		return nil
	}
	var lastSendError error
	if err := send(); err != nil {
		lastSendError = fmt.Errorf("send punch request: %w", err)
	}
	nextSend := time.Now().Add(punchInterval)
	buf := make([]byte, ProbeSize+1)
	type candidateProgress struct {
		peerNonce       [16]byte
		havePeerRequest bool
		responseSeen    bool
		localConfirmed  bool
		peerConfirmed   bool
	}
	progress := make(map[netip.AddrPort]*candidateProgress, len(candidates))
	var readyAt time.Time
	sendFlight := func(kind ProbeKind, flightNonce [16]byte, source net.Addr) error {
		packet, err := (Probe{
			Circuit: plan.Circuit, Session: plan.Session, Nonce: flightNonce, Site: localCode,
			Role: plan.Role, Kind: kind, Expires: plan.Expires, Attempt: plan.Attempt,
		}).Marshal(plan.ProbeKey[:])
		if err != nil {
			return err
		}
		written, err := conn.WriteTo(packet, source)
		if err != nil {
			return err
		}
		if written != len(packet) {
			return io.ErrShortWrite
		}
		return nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		now = time.Now()
		if !now.Before(plan.Expires) {
			return nil, errors.Join(ErrPunchTimeout, lastSendError)
		}
		if !readyAt.IsZero() && now.Sub(readyAt) >= punchLinger {
			ready := make([]netip.AddrPort, 0, len(progress))
			for candidate, state := range progress {
				if state.localConfirmed && state.peerConfirmed {
					ready = append(ready, candidate)
				}
			}
			sort.Slice(ready, func(i, j int) bool { return ready[i].Compare(ready[j]) < 0 })
			if len(ready) == 0 {
				return nil, ErrPunchTimeout
			}
			serviceCtx, cancelService := context.WithCancel(ctx)
			done := make(chan struct{})
			go func() {
				defer close(done)
				servicePunch(serviceCtx, conn, plan, localCode, peerCode, nonce, request, candidates, allowed)
			}()
			return &PunchSession{candidates: ready, cancel: cancelService, done: done}, nil
		}
		if !now.Before(nextSend) {
			if err := send(); err != nil {
				lastSendError = fmt.Errorf("retry punch request: %w", err)
			} else {
				lastSendError = nil
			}
			for !nextSend.After(now) {
				nextSend = nextSend.Add(punchInterval)
			}
		}
		readUntil := nextSend
		if plan.Expires.Before(readUntil) {
			readUntil = plan.Expires
		}
		if !readyAt.IsZero() && readyAt.Add(punchLinger).Before(readUntil) {
			readUntil = readyAt.Add(punchLinger)
		}
		readCtx, cancelRead := context.WithDeadline(ctx, readUntil)
		n, source, readErr := conn.ReadNonQUICPacket(readCtx, buf)
		cancelRead()
		if readErr != nil {
			if errors.Is(readErr, context.DeadlineExceeded) {
				continue
			}
			return nil, readErr
		}
		udpSource, ok := source.(*net.UDPAddr)
		if !ok || udpSource.IP == nil || udpSource.Port <= 0 || udpSource.Port > 65535 {
			continue
		}
		sourceAddr, ok := netip.AddrFromSlice(udpSource.IP)
		if !ok {
			continue
		}
		sourcePort := netip.AddrPortFrom(sourceAddr.Unmap(), uint16(udpSource.Port))
		if _, ok := allowed[sourcePort]; !ok {
			continue
		}
		peer, err := Parse(buf[:n], plan.ProbeKey[:], Expect{
			Circuit: plan.Circuit, Session: plan.Session, Site: peerCode, Now: time.Now(),
		})
		if err != nil || peer.Attempt != plan.Attempt || peer.Role == plan.Role {
			continue
		}
		state := progress[sourcePort]
		if state == nil {
			state = &candidateProgress{}
			progress[sourcePort] = state
		}
		switch peer.Kind {
		case ProbeRequest:
			if state.havePeerRequest && state.peerNonce != peer.Nonce {
				continue
			}
			if !state.havePeerRequest {
				if !replay.AcceptCandidate(plan.Circuit, plan.Version, plan.DeploymentID, plan.RelayGeneration,
					plan.Session, plan.Attempt, sourcePort, peer.Nonce, peer.Expires, time.Now()) {
					continue
				}
				state.peerNonce = peer.Nonce
				state.havePeerRequest = true
			}
			if err := sendFlight(ProbeResponse, peer.Nonce, source); err != nil {
				lastSendError = fmt.Errorf("send punch response: %w", err)
			}
		case ProbeResponse:
			if peer.Nonce != nonce {
				continue
			}
			state.responseSeen = true
			if err := sendFlight(ProbeConfirm, nonce, source); err != nil {
				lastSendError = fmt.Errorf("send punch confirmation: %w", err)
			}
		case ProbeConfirm:
			if !state.havePeerRequest || peer.Nonce != state.peerNonce {
				continue
			}
			if err := sendFlight(ProbeConfirmed, peer.Nonce, source); err != nil {
				lastSendError = fmt.Errorf("send punch confirmed: %w", err)
				continue
			}
			state.peerConfirmed = true
		case ProbeConfirmed:
			if peer.Nonce != nonce || !state.responseSeen {
				continue
			}
			state.localConfirmed = true
		}
		if state.localConfirmed && state.peerConfirmed && readyAt.IsZero() {
			readyAt = time.Now()
		}
	}
}

func servicePunch(
	ctx context.Context,
	conn NonQUICPacketIO,
	plan Plan,
	localCode, peerCode byte,
	localNonce [16]byte,
	request []byte,
	candidates []*net.UDPAddr,
	allowed map[netip.AddrPort]struct{},
) {
	buf := make([]byte, ProbeSize+1)
	nextSend := time.Now()
	send := func(kind ProbeKind, nonce [16]byte, destination net.Addr) {
		packet, err := (Probe{
			Circuit: plan.Circuit, Session: plan.Session, Nonce: nonce, Site: localCode,
			Role: plan.Role, Kind: kind, Expires: plan.Expires, Attempt: plan.Attempt,
		}).Marshal(plan.ProbeKey[:])
		if err != nil {
			return
		}
		written, err := conn.WriteTo(packet, destination)
		if err != nil || written != len(packet) {
			return
		}
	}
	for {
		if ctx.Err() != nil || !time.Now().Before(plan.Expires) {
			return
		}
		now := time.Now()
		if !now.Before(nextSend) {
			for _, candidate := range candidates {
				_, _ = conn.WriteTo(request, candidate)
			}
			nextSend = now.Add(punchInterval)
		}
		readUntil := nextSend
		if plan.Expires.Before(readUntil) {
			readUntil = plan.Expires
		}
		readCtx, cancel := context.WithDeadline(ctx, readUntil)
		n, source, err := conn.ReadNonQUICPacket(readCtx, buf)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				continue
			}
			return
		}
		udpSource, ok := source.(*net.UDPAddr)
		if !ok || udpSource.IP == nil || udpSource.Port <= 0 || udpSource.Port > 65535 {
			continue
		}
		sourceAddress, ok := netip.AddrFromSlice(udpSource.IP)
		if !ok {
			continue
		}
		sourcePort := netip.AddrPortFrom(sourceAddress.Unmap(), uint16(udpSource.Port))
		if _, ok := allowed[sourcePort]; !ok {
			continue
		}
		peer, err := Parse(buf[:n], plan.ProbeKey[:], Expect{
			Circuit: plan.Circuit, Session: plan.Session, Site: peerCode, Now: time.Now(),
		})
		if err != nil || peer.Attempt != plan.Attempt || peer.Role == plan.Role {
			continue
		}
		switch peer.Kind {
		case ProbeRequest:
			send(ProbeResponse, peer.Nonce, source)
		case ProbeResponse:
			if peer.Nonce == localNonce {
				send(ProbeConfirm, localNonce, source)
			}
		case ProbeConfirm:
			send(ProbeConfirmed, peer.Nonce, source)
		}
	}
}

type udpPacketIO struct {
	conn *net.UDPConn
}

func (u udpPacketIO) WriteTo(packet []byte, address net.Addr) (int, error) {
	udpAddress, ok := address.(*net.UDPAddr)
	if !ok {
		return 0, ErrInvalidCandidate
	}
	return u.conn.WriteToUDP(packet, udpAddress)
}

func (u udpPacketIO) ReadNonQUICPacket(ctx context.Context, packet []byte) (int, net.Addr, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0, nil, errors.New("bounded non-QUIC read requires a deadline")
	}
	if err := u.conn.SetReadDeadline(deadline); err != nil {
		return 0, nil, err
	}
	n, address, err := u.conn.ReadFromUDP(packet)
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		if ctx.Err() != nil {
			return 0, nil, ctx.Err()
		}
		return 0, nil, context.DeadlineExceeded
	}
	return n, address, err
}
