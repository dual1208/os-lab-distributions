package relay

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/binding"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/rendezvous"
)

type leg struct {
	owner            uint64
	control          net.Conn
	token            []byte
	generation       string
	online           bool
	bound            bool
	addr             *net.UDPAddr
	pendingAddr      *net.UDPAddr
	pendingChallenge []byte
}

type Server struct {
	cfg         config.Relay
	mu          sync.Mutex
	legs        map[string]*leg
	forwardA    uint64
	forwardB    uint64
	dropped     uint64
	nextOwner   uint64
	established bool
	udp         *net.UDPConn
	planner     *rendezvous.Planner
}

const maxOuterDatagramSize = 2048

type status struct {
	Circuit string                `json:"circuit"`
	Sites   map[string]siteStatus `json:"sites"`
	Forward map[string]uint64     `json:"forwarded_packets"`
	Dropped uint64                `json:"dropped_packets"`
	Updated time.Time             `json:"updated"`
}

type siteStatus struct {
	Control string `json:"control"`
	UDP     string `json:"udp"`
}

func New(cfg config.Relay) (*Server, error) {
	if cfg.Circuit == "" || cfg.Prefixes["site-a"] == "" || cfg.Prefixes["site-b"] == "" {
		return nil, errors.New("relay requires one circuit and fixed site-a/site-b prefixes")
	}
	return &Server{
		cfg: cfg, legs: map[string]*leg{"site-a": {}, "site-b": {}},
		planner: rendezvous.NewPlanner(nil, cfg.Circuit),
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	tlsConfig, err := relayTLS(s.cfg)
	if err != nil {
		return err
	}
	tcp, err := tls.Listen("tcp", s.cfg.ControlListen, tlsConfig)
	if err != nil {
		return fmt.Errorf("control listen: %w", err)
	}
	defer tcp.Close()
	udpAddr, err := net.ResolveUDPAddr("udp", s.cfg.UDPListen)
	if err != nil {
		return err
	}
	s.udp, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("UDP listen: %w", err)
	}
	defer s.udp.Close()

	errCh := make(chan error, 2)
	go func() { errCh <- s.acceptControl(ctx, tcp) }()
	go func() { errCh <- s.spliceUDP(ctx) }()
	go s.writeStatusLoop(ctx)
	log.Printf("campus-link relay ready: circuit=%s", s.cfg.Circuit)
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) acceptControl(ctx context.Context, listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleControl(conn)
	}
}

func (s *Server) handleControl(raw net.Conn) {
	defer raw.Close()
	conn, ok := raw.(*tls.Conn)
	if !ok {
		return
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if err := conn.Handshake(); err != nil {
		return
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) != 1 {
		return
	}
	identity := state.PeerCertificates[0].Subject.CommonName
	if identity != "site-a" && identity != "site-b" {
		return
	}
	dec := control.NewDecoder(conn)
	enc := json.NewEncoder(conn)
	var reg control.Register
	if err := dec.Decode(&reg); err != nil {
		return
	}
	if reg.Type != "register" || reg.Site != identity || reg.Circuit != s.cfg.Circuit || reg.Prefix != s.cfg.Prefixes[identity] || reg.Generation == "" {
		_ = enc.Encode(control.Error{Type: "error", Message: "registration rejected"})
		return
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return
	}
	s.mu.Lock()
	owner := s.activateLegLocked(identity, reg.Generation, token, conn)
	s.writeStatusLocked()
	s.mu.Unlock()
	if err := enc.Encode(control.Registered{Type: "registered", BindToken: hex.EncodeToString(token)}); err != nil {
		return
	}
	log.Printf("control authenticated: site=%s", identity)
	_ = conn.SetDeadline(time.Time{})
	for {
		_ = conn.SetReadDeadline(time.Now().Add(45 * time.Second))
		var hb control.Heartbeat
		if err := dec.Decode(&hb); err != nil {
			break
		}
		if hb.Type != "heartbeat" || hb.Sequence == 0 {
			break
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		var plan *control.RendezvousPlan
		if candidate, ok := s.planner.PlanFor(identity, owner); ok {
			plan = &candidate
		}
		if err := enc.Encode(control.HeartbeatAck{Type: "heartbeat-ack", Sequence: hb.Sequence, Plan: plan}); err != nil {
			break
		}
	}
	s.mu.Lock()
	s.clearLegLocked(identity, owner)
	s.writeStatusLocked()
	s.mu.Unlock()
	log.Printf("control disconnected: site=%s", identity)
}

func (s *Server) spliceUDP(ctx context.Context) error {
	buf := make([]byte, maxOuterDatagramSize+1)
	for {
		_ = s.udp.SetReadDeadline(time.Now().Add(time.Second))
		n, src, err := s.udp.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return nil
				}
				continue
			}
			return err
		}
		packet := append([]byte(nil), buf[:n]...)
		if n > maxOuterDatagramSize {
			s.mu.Lock()
			s.dropped++
			s.mu.Unlock()
			continue
		}
		if s.handleBinding(packet, src) {
			continue
		}
		s.mu.Lock()
		var dst *net.UDPAddr
		switch {
		case sameAddr(src, s.legs["site-a"].addr) && s.legs["site-a"].bound && s.legs["site-b"].bound:
			dst = cloneAddr(s.legs["site-b"].addr)
			s.forwardA++
		case sameAddr(src, s.legs["site-b"].addr) && s.legs["site-a"].bound && s.legs["site-b"].bound:
			dst = cloneAddr(s.legs["site-a"].addr)
			s.forwardB++
		default:
			s.dropped++
		}
		s.mu.Unlock()
		if dst != nil {
			if _, err := s.udp.WriteToUDP(packet, dst); err != nil {
				return err
			}
		}
	}
}

func (s *Server) activateLegLocked(site, generation string, token []byte, conn net.Conn) uint64 {
	if s.legs[site].online {
		s.planner.Invalidate(site, s.legs[site].owner)
		_ = s.legs[site].control.Close()
		*s.legs[site] = leg{}
	}
	if s.established {
		peer := otherSite(site)
		if s.legs[peer].online {
			s.planner.Invalidate(peer, s.legs[peer].owner)
			_ = s.legs[peer].control.Close()
			*s.legs[peer] = leg{}
		}
		s.established = false
	}
	s.nextOwner++
	owner := s.nextOwner
	*s.legs[site] = leg{
		owner:      owner,
		control:    conn,
		token:      append([]byte(nil), token...),
		generation: generation,
		online:     true,
	}
	_ = s.planner.Register(site, generation, owner)
	if s.legs["site-a"].online && s.legs["site-b"].online {
		s.established = true
	}
	return owner
}

func (s *Server) clearLegLocked(site string, owner uint64) bool {
	l := s.legs[site]
	if l.owner != owner {
		return false
	}
	*l = leg{}
	s.planner.Invalidate(site, owner)
	if s.established {
		peer := otherSite(site)
		if s.legs[peer].online {
			s.planner.Invalidate(peer, s.legs[peer].owner)
			_ = s.legs[peer].control.Close()
			*s.legs[peer] = leg{}
		}
		s.established = false
	}
	return true
}

func otherSite(site string) string {
	if site == "site-a" {
		return "site-b"
	}
	return "site-a"
}

func (s *Server) handleBinding(packet []byte, src *net.UDPAddr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for site, l := range s.legs {
		if !l.online || len(l.token) == 0 {
			continue
		}
		if got, ok := binding.ParseRequest(packet, l.token); ok && got == site {
			challengePacket, challenge, err := binding.NewChallenge()
			if err != nil {
				return true
			}
			l.pendingAddr = cloneAddr(src)
			l.pendingChallenge = challenge
			_, _ = s.udp.WriteToUDP(challengePacket, src)
			return true
		}
		if got, challenge, ok := binding.ParseResponse(packet, l.token); ok && got == site {
			if sameAddr(src, l.pendingAddr) && string(challenge) == string(l.pendingChallenge) {
				l.addr = cloneAddr(src)
				l.bound = true
				l.pendingAddr = nil
				l.pendingChallenge = nil
				if ip, ok := netip.AddrFromSlice(src.IP); ok {
					_ = s.planner.Observe(site, l.owner, netip.AddrPortFrom(ip.Unmap(), uint16(src.Port)), time.Now())
				}
				log.Printf("UDP tuple authenticated: site=%s", site)
				if s.legs["site-a"].bound && s.legs["site-b"].bound {
					_, _ = s.udp.WriteToUDP([]byte(binding.ReadyMagic), s.legs["site-a"].addr)
					_, _ = s.udp.WriteToUDP([]byte(binding.ReadyMagic), s.legs["site-b"].addr)
				}
				s.writeStatusLocked()
			}
			return true
		}
	}
	return binding.IsProtocol(packet)
}

func (s *Server) writeStatusLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			s.writeStatusLocked()
			s.mu.Unlock()
		}
	}
}

func (s *Server) writeStatusLocked() {
	if s.cfg.StatusPath == "" {
		return
	}
	st := status{Circuit: s.cfg.Circuit, Sites: map[string]siteStatus{}, Forward: map[string]uint64{"site-a": s.forwardA, "site-b": s.forwardB}, Dropped: s.dropped, Updated: time.Now().UTC()}
	for name, l := range s.legs {
		controlState, udpState := "offline", "unbound"
		if l.online {
			controlState = "authenticated"
		}
		if l.bound {
			udpState = "bound"
		} else if l.pendingAddr != nil {
			udpState = "challenging"
		}
		st.Sites[name] = siteStatus{Control: controlState, UDP: udpState}
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(s.cfg.StatusPath), 0755)
	tmp := s.cfg.StatusPath + ".tmp"
	if os.WriteFile(tmp, append(b, '\n'), 0644) == nil {
		_ = os.Rename(tmp, s.cfg.StatusPath)
	}
}

func relayTLS(cfg config.Relay) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.ControlCert, cfg.ControlKey)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(cfg.ControlCA)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("invalid control CA")
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13}, nil
}

func sameAddr(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.IP.Equal(b.IP)
}

func cloneAddr(a *net.UDPAddr) *net.UDPAddr {
	if a == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), a.IP...), Port: a.Port, Zone: a.Zone}
}
