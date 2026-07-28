package edge

import (
	"context"
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
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/binding"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
	cltun "github.com/dual1208/os-lab-distributions/campus-link/internal/tun"
)

type Runner struct {
	cfg      config.Edge
	version  string
	sent     atomic.Uint64
	received atomic.Uint64
	dropped  atomic.Uint64
	mu       sync.Mutex
	state    edgeState
}

type edgeState struct {
	Site       string    `json:"site"`
	Control    string    `json:"control"`
	UDP        string    `json:"udp"`
	QUIC       string    `json:"quic"`
	TUN        string    `json:"tun"`
	Sent       uint64    `json:"sent_packets"`
	Received   uint64    `json:"received_packets"`
	Dropped    uint64    `json:"dropped_packets"`
	LastUpdate time.Time `json:"updated"`
}

func New(cfg config.Edge, version string) (*Runner, error) {
	if cfg.Site != "site-a" && cfg.Site != "site-b" {
		return nil, errors.New("site must be site-a or site-b")
	}
	if cfg.Role != "client" && cfg.Role != "server" {
		return nil, errors.New("role must be client or server")
	}
	if cfg.Circuit == "" || cfg.Generation == "" || cfg.RelayAddress == "" || cfg.ControlServerName == "" {
		return nil, errors.New("circuit, generation, relay address, and control server name are required")
	}
	localPrefix, err := netip.ParsePrefix(cfg.Prefix)
	if err != nil || !localPrefix.Addr().Is4() {
		return nil, errors.New("valid local IPv4 prefix is required")
	}
	remotePrefix, err := netip.ParsePrefix(cfg.RemotePrefix)
	if err != nil || !remotePrefix.Addr().Is4() || localPrefix.Overlaps(remotePrefix) {
		return nil, errors.New("valid non-overlapping remote IPv4 prefix is required")
	}
	if cfg.Role == "client" && cfg.DataServerName == "" {
		return nil, errors.New("client data server identity is required")
	}
	if cfg.Role == "server" && cfg.DataPeerName == "" {
		return nil, errors.New("server data peer identity is required")
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1280
	}
	if cfg.MTU > 1280 || cfg.MTU < 576 {
		return nil, errors.New("Phase-1 MTU must be between 576 and 1280")
	}
	return &Runner{cfg: cfg, version: version, state: edgeState{Site: cfg.Site, Control: "offline", UDP: "unbound", QUIC: "idle", TUN: "down"}}, nil
}

func (r *Runner) Run(ctx context.Context) error {
	statusCtx, cancelStatus := context.WithCancel(ctx)
	defer cancelStatus()
	go r.writeStatusLoop(statusCtx)
	controlTLS, err := clientTLS(r.cfg.ControlCert, r.cfg.ControlKey, r.cfg.ControlCA, r.cfg.ControlServerName)
	if err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	controlConn, err := tls.DialWithDialer(dialer, "tcp", r.cfg.RelayAddress, controlTLS)
	if err != nil {
		return fmt.Errorf("control dial: %w", err)
	}
	defer controlConn.Close()
	enc, dec := json.NewEncoder(controlConn), control.NewDecoder(controlConn)
	reg := control.Register{Type: "register", Site: r.cfg.Site, Generation: r.cfg.Generation, Version: r.version, Circuit: r.cfg.Circuit, Prefix: r.cfg.Prefix, Transports: []string{"quic-datagram"}}
	if err := enc.Encode(reg); err != nil {
		return err
	}
	var registered control.Registered
	if err := dec.Decode(&registered); err != nil || registered.Type != "registered" {
		return errors.New("control registration rejected")
	}
	token, err := hex.DecodeString(registered.BindToken)
	if err != nil || len(token) != 32 {
		return errors.New("invalid bind token")
	}
	r.setState("authenticated", "unbound", "idle", "down")
	defer r.setState("offline", "unbound", "idle", "down")
	sessionCtx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()
	controlErr := make(chan error, 1)
	go r.heartbeat(sessionCtx, cancelSession, controlConn, enc, dec, controlErr)

	relayUDP, err := net.ResolveUDPAddr("udp", r.cfg.RelayAddress)
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return err
	}
	defer udp.Close()
	if err := bindUDP(sessionCtx, udp, relayUDP, r.cfg.Site, token); err != nil {
		return err
	}
	r.setState("authenticated", "bound", "handshaking", "creating")

	tunFile, err := cltun.Open(r.cfg.TunName)
	if err != nil {
		return fmt.Errorf("open TUN: %w", err)
	}
	defer tunFile.Close()
	r.setState("authenticated", "bound", "handshaking", "ready")

	dataTLS, err := r.dataTLS()
	if err != nil {
		return err
	}
	quicConfig := &quic.Config{EnableDatagrams: true, KeepAlivePeriod: 3 * time.Second, MaxIdleTimeout: 12 * time.Second}
	var conn *quic.Conn
	if r.cfg.Role == "server" {
		listener, err := quic.Listen(udp, dataTLS, quicConfig)
		if err != nil {
			return err
		}
		defer listener.Close()
		conn, err = listener.Accept(sessionCtx)
		if err != nil {
			return err
		}
	} else {
		conn, err = quic.Dial(sessionCtx, udp, relayUDP, dataTLS, quicConfig)
		if err != nil {
			return err
		}
	}
	defer conn.CloseWithError(0, "shutdown")
	if !conn.ConnectionState().SupportsDatagrams.Local || !conn.ConnectionState().SupportsDatagrams.Remote {
		return errors.New("peer did not negotiate QUIC DATAGRAM")
	}
	r.setState("authenticated", "bound", "active", "ready")
	err = r.bridge(sessionCtx, conn, tunFile, controlErr)
	if err == nil && ctx.Err() == nil && sessionCtx.Err() != nil {
		err = errors.New("control session lost")
	}
	return err
}

func (r *Runner) bridge(ctx context.Context, conn *quic.Conn, tunFile *os.File, controlErr <-chan error) error {
	localPrefix, err := netip.ParsePrefix(r.cfg.Prefix)
	if err != nil {
		return err
	}
	remotePrefix, err := netip.ParsePrefix(r.cfg.RemotePrefix)
	if err != nil {
		return err
	}
	errCh := make(chan error, 2)
	go func() {
		buf := make([]byte, r.cfg.MTU+1)
		for {
			n, err := tunFile.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			if n > r.cfg.MTU {
				r.dropped.Add(1)
				continue
			}
			total, err := cltun.AuthorizeIPv4(buf[:n], localPrefix, remotePrefix)
			if err != nil {
				r.dropped.Add(1)
				continue
			}
			if err := conn.SendDatagram(append([]byte(nil), buf[:total]...)); err != nil {
				errCh <- err
				return
			}
			r.sent.Add(1)
		}
	}()
	go func() {
		for {
			packet, err := conn.ReceiveDatagram(ctx)
			if err != nil {
				errCh <- err
				return
			}
			if len(packet) > r.cfg.MTU {
				r.dropped.Add(1)
				continue
			}
			total, err := cltun.AuthorizeIPv4(packet, remotePrefix, localPrefix)
			if err != nil {
				r.dropped.Add(1)
				continue
			}
			if _, err := tunFile.Write(packet[:total]); err != nil {
				errCh <- err
				return
			}
			r.received.Add(1)
		}
	}()
	select {
	case <-ctx.Done():
		select {
		case err := <-controlErr:
			return err
		default:
			return nil
		}
	case err := <-errCh:
		return err
	case err := <-controlErr:
		return err
	}
}

func (r *Runner) writeStatusLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.writeStatus()
		}
	}
}

func bindUDP(ctx context.Context, conn *net.UDPConn, relay *net.UDPAddr, site string, token []byte) error {
	request, err := binding.NewRequest(site, token)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(30 * time.Second)
	last := request
	buf := make([]byte, 256)
	for time.Now().Before(deadline) {
		if _, err := conn.WriteToUDP(last, relay); err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		if !src.IP.Equal(relay.IP) || src.Port != relay.Port {
			continue
		}
		if challenge, ok := binding.ParseChallenge(buf[:n]); ok {
			last, err = binding.NewResponse(site, challenge, token)
			if err != nil {
				return err
			}
			continue
		}
		if binding.IsReady(buf[:n]) {
			_ = conn.SetReadDeadline(time.Time{})
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	return errors.New("UDP tuple binding timed out")
}

func (r *Runner) heartbeat(ctx context.Context, cancel context.CancelFunc, conn net.Conn, enc *json.Encoder, dec *control.Decoder, errCh chan<- error) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var sequence uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sequence++
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := enc.Encode(control.Heartbeat{Type: "heartbeat", Sequence: sequence}); err != nil {
				failControl(cancel, errCh, fmt.Errorf("control heartbeat write: %w", err))
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			var ack control.HeartbeatAck
			if err := dec.Decode(&ack); err != nil {
				failControl(cancel, errCh, fmt.Errorf("control heartbeat acknowledgement: %w", err))
				return
			}
			if ack.Type != "heartbeat-ack" || ack.Sequence != sequence {
				failControl(cancel, errCh, errors.New("invalid control heartbeat acknowledgement"))
				return
			}
		}
	}
}

func failControl(cancel context.CancelFunc, errCh chan<- error, err error) {
	select {
	case errCh <- err:
	default:
	}
	cancel()
}

func (r *Runner) dataTLS() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(r.cfg.DataCert, r.cfg.DataKey)
	if err != nil {
		return nil, err
	}
	pool, err := certPool(r.cfg.DataCA)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"campus-link/1"}}
	if r.cfg.Role == "server" {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = pool
		expected := r.cfg.DataPeerName
		cfg.VerifyConnection = func(state tls.ConnectionState) error {
			return verifyPeerIdentity(state.PeerCertificates, expected)
		}
	} else {
		cfg.RootCAs = pool
		cfg.ServerName = r.cfg.DataServerName
	}
	return cfg, nil
}

func verifyPeerIdentity(certs []*x509.Certificate, expected string) error {
	if expected == "" {
		return errors.New("expected data peer identity is required")
	}
	if len(certs) != 1 {
		return errors.New("exactly one data peer certificate is required")
	}
	leaf := certs[0]
	if leaf.VerifyHostname(expected) == nil || leaf.Subject.CommonName == expected {
		return nil
	}
	return fmt.Errorf("data peer identity mismatch")
}

func clientTLS(certPath, keyPath, caPath, serverName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	pool, err := certPool(caPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS13}, nil
}

func certPool(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("invalid CA")
	}
	return pool, nil
}

func (r *Runner) setState(controlState, udpState, quicState, tunState string) {
	r.mu.Lock()
	r.state.Control, r.state.UDP, r.state.QUIC, r.state.TUN = controlState, udpState, quicState, tunState
	r.mu.Unlock()
	r.writeStatus()
	log.Printf("state control=%s udp=%s quic=%s tun=%s", controlState, udpState, quicState, tunState)
}

func (r *Runner) writeStatus() {
	if r.cfg.StatusPath == "" {
		return
	}
	r.mu.Lock()
	st := r.state
	r.mu.Unlock()
	st.Sent, st.Received, st.Dropped, st.LastUpdate = r.sent.Load(), r.received.Load(), r.dropped.Load(), time.Now().UTC()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(r.cfg.StatusPath), 0755)
	tmp := r.cfg.StatusPath + ".tmp"
	if os.WriteFile(tmp, append(b, '\n'), 0644) == nil {
		_ = os.Rename(tmp, r.cfg.StatusPath)
	}
}
