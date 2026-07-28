package rendezvous

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

const punchInterval = 100 * time.Millisecond

var ErrPunchTimeout = errors.New("rendezvous punch timed out")

func Punch(ctx context.Context, conn *net.UDPConn, plan Plan, site string, random io.Reader) (netip.AddrPort, error) {
	if conn == nil || !validSite(site) || len(plan.Candidates) == 0 || !validRole(plan.Role) ||
		plan.Circuit == "" || plan.Session == ([16]byte{}) || plan.ProbeKey == ([32]byte{}) ||
		!plan.Expires.After(plan.Start) || plan.Expires.Sub(plan.Start) > MaxSessionTTL {
		return netip.AddrPort{}, ErrInvalidPlan
	}
	if random == nil {
		random = rand.Reader
	}
	now := time.Now()
	if !plan.Start.After(now) {
		// Start immediately.
	} else {
		timer := time.NewTimer(time.Until(plan.Start))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return netip.AddrPort{}, ctx.Err()
		case <-timer.C:
		}
	}
	if !time.Now().Before(plan.Expires) {
		return netip.AddrPort{}, ErrPunchTimeout
	}
	localCode, peerCode := byte(1), byte(2)
	if site == "site-b" {
		localCode, peerCode = peerCode, localCode
	}
	var nonce [16]byte
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		return netip.AddrPort{}, err
	}
	request, err := (Probe{
		Circuit: plan.Circuit, Session: plan.Session, Nonce: nonce, Site: localCode,
		Role: plan.Role, Expires: plan.Expires, Attempt: plan.Attempt,
	}).Marshal(plan.ProbeKey[:])
	if err != nil {
		return netip.AddrPort{}, err
	}
	candidates := make([]*net.UDPAddr, 0, len(plan.Candidates))
	allowed := make(map[netip.AddrPort]struct{}, len(plan.Candidates))
	for _, candidate := range plan.Candidates {
		if !candidate.IsValid() || !candidate.Addr().Is4() || candidate.Port() == 0 {
			return netip.AddrPort{}, ErrInvalidCandidate
		}
		candidate = netip.AddrPortFrom(candidate.Addr().Unmap(), candidate.Port())
		allowed[candidate] = struct{}{}
		candidates = append(candidates, net.UDPAddrFromAddrPort(candidate))
	}
	defer conn.SetReadDeadline(time.Time{})
	ticker := time.NewTicker(punchInterval)
	defer ticker.Stop()
	send := func() {
		for _, candidate := range candidates {
			_, _ = conn.WriteToUDP(request, candidate)
		}
	}
	send()
	buf := make([]byte, ProbeSize+1)
	for {
		if err := ctx.Err(); err != nil {
			return netip.AddrPort{}, err
		}
		now = time.Now()
		if !now.Before(plan.Expires) {
			return netip.AddrPort{}, ErrPunchTimeout
		}
		readUntil := now.Add(punchInterval)
		if plan.Expires.Before(readUntil) {
			readUntil = plan.Expires
		}
		_ = conn.SetReadDeadline(readUntil)
		n, source, readErr := conn.ReadFromUDP(buf)
		if readErr != nil {
			var netErr net.Error
			if errors.As(readErr, &netErr) && netErr.Timeout() {
				select {
				case <-ctx.Done():
					return netip.AddrPort{}, ctx.Err()
				case <-ticker.C:
					send()
				default:
				}
				continue
			}
			return netip.AddrPort{}, readErr
		}
		sourceAddr, ok := netip.AddrFromSlice(source.IP)
		if !ok {
			continue
		}
		sourcePort := netip.AddrPortFrom(sourceAddr.Unmap(), uint16(source.Port))
		if _, ok := allowed[sourcePort]; !ok {
			continue
		}
		peer, err := Parse(buf[:n], plan.ProbeKey[:], Expect{
			Circuit: plan.Circuit, Session: plan.Session, Site: peerCode, Now: time.Now(),
		})
		if err != nil || peer.Attempt != plan.Attempt || peer.Role == plan.Role {
			continue
		}
		if !peer.Response {
			response := Probe{
				Circuit: plan.Circuit, Session: plan.Session, Nonce: nonce, Site: localCode,
				Role: plan.Role, Response: true, Expires: plan.Expires, Attempt: plan.Attempt,
			}
			packet, err := response.Marshal(plan.ProbeKey[:])
			if err != nil {
				return netip.AddrPort{}, fmt.Errorf("encode punch response: %w", err)
			}
			if _, err := conn.WriteToUDP(packet, source); err != nil {
				return netip.AddrPort{}, fmt.Errorf("send punch response: %w", err)
			}
		}
		return sourcePort, nil
	}
}
