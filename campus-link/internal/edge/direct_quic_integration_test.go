package edge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/datapath"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/direct"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/identity"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/rendezvous"
)

func TestDirectQUICIntegrationActivationAndFullDuplexTransfer(t *testing.T) {
	const (
		innerMTU        = 1200
		pathEpoch       = 23
		bulkPacketCount = 2048
		bulkBytes       = bulkPacketCount * innerMTU
	)

	now := time.Now()
	pki := newDirectIntegrationPKI(t, now)
	dataUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	requireA := identity.Requirements{URI: pki.uriA, Pins: []string{pki.pinA}, Usages: dataUsages, Now: now}
	requireB := identity.Requirements{URI: pki.uriB, Pins: []string{pki.pinB}, Usages: dataUsages, Now: now}

	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{pki.siteA},
		RootCAs:      pki.roots,
		ServerName:   pki.serverName,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"campus-link-direct-integration/1"},
		VerifyConnection: func(state tls.ConnectionState) error {
			_, err := identity.VerifyConnection(state, requireB)
			return err
		},
	}
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{pki.siteB},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.roots,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"campus-link-direct-integration/1"},
		VerifyConnection: func(state tls.ConnectionState) error {
			_, err := identity.VerifyConnection(state, requireA)
			return err
		},
	}
	quicConfig := &quic.Config{
		EnableDatagrams:      true,
		InitialPacketSize:    1400,
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       20 * time.Second,
		KeepAlivePeriod:      2 * time.Second,
	}

	clientSocket := listenDirectIntegrationUDP(t)
	serverSocket := listenDirectIntegrationUDP(t)
	clientTransport := &quic.Transport{Conn: clientSocket}
	serverTransport := &quic.Transport{Conn: serverSocket}
	t.Cleanup(func() {
		_ = clientTransport.Close()
		_ = serverTransport.Close()
	})
	listener, err := serverTransport.Listen(serverTLS, quicConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	accepted := make(chan directIntegrationAccept, 1)
	go func() {
		connection, acceptErr := listener.Accept(ctx)
		accepted <- directIntegrationAccept{connection: connection, err: acceptErr}
	}()
	clientConnection, err := clientTransport.Dial(ctx, serverSocket.LocalAddr(), clientTLS, quicConfig)
	if err != nil {
		t.Fatalf("direct QUIC dial: %v", err)
	}
	serverAccepted := <-accepted
	if serverAccepted.err != nil {
		t.Fatalf("direct QUIC accept: %v", serverAccepted.err)
	}
	serverConnection := serverAccepted.connection
	defer func() {
		_ = clientConnection.CloseWithError(directCloseCode, "integration complete")
		_ = serverConnection.CloseWithError(directCloseCode, "integration complete")
	}()
	if clientConnection.ConnectionState().TLS.Version != tls.VersionTLS13 ||
		serverConnection.ConnectionState().TLS.Version != tls.VersionTLS13 {
		t.Fatal("direct peers did not negotiate TLS 1.3")
	}
	if err := validateDatagramConnection(clientConnection, innerMTU+datapath.WireOverhead); err != nil {
		t.Fatalf("client DATAGRAM capacity: %v", err)
	}
	if err := validateDatagramConnection(serverConnection, innerMTU+datapath.WireOverhead); err != nil {
		t.Fatalf("server DATAGRAM capacity: %v", err)
	}

	planA, planB := directIntegrationPlans(t, now, pathEpoch)
	boundA, verifiedB, err := direct.BindTLSExporter(planA, "site-a", clientConnection.ConnectionState().TLS, requireB)
	if err != nil {
		t.Fatalf("site-a TLS exporter binding: %v", err)
	}
	boundB, verifiedA, err := direct.BindTLSExporter(planB, "site-b", serverConnection.ConnectionState().TLS, requireA)
	if err != nil {
		t.Fatalf("site-b TLS exporter binding: %v", err)
	}
	if verifiedA.PinSlot != 0 || verifiedB.PinSlot != 0 {
		t.Fatalf("unexpected direct identity pin slots: site-a=%d site-b=%d", verifiedA.PinSlot, verifiedB.PinSlot)
	}

	clientStream, err := clientConnection.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open direct authentication stream: %v", err)
	}
	defer clientStream.Close()

	handshakeOptions := direct.Options{
		Timeout:           5 * time.Second,
		StabilityDuration: 120 * time.Millisecond,
		ProbeInterval:     20 * time.Millisecond,
	}
	type handshakeResult struct {
		site   string
		stream direct.Stream
		result direct.Result
		err    error
	}
	handshakes := make(chan handshakeResult, 2)
	go func() {
		serverStream, acceptErr := serverConnection.AcceptStream(ctx)
		if acceptErr != nil {
			handshakes <- handshakeResult{site: "site-b", err: acceptErr}
			return
		}
		result, handshakeErr := direct.Accept(ctx, serverStream, boundB, "site-b", nil, handshakeOptions)
		handshakes <- handshakeResult{site: "site-b", stream: serverStream, result: result, err: handshakeErr}
	}()
	go func() {
		result, handshakeErr := direct.Initiate(ctx, clientStream, boundA, "site-a", nil, handshakeOptions)
		handshakes <- handshakeResult{site: "site-a", result: result, err: handshakeErr}
	}()
	firstHandshake, secondHandshake := <-handshakes, <-handshakes
	if firstHandshake.err != nil || secondHandshake.err != nil {
		t.Fatalf("direct stability handshake: %v / %v", firstHandshake.err, secondHandshake.err)
	}
	if firstHandshake.result.PathEpoch != pathEpoch || secondHandshake.result.PathEpoch != pathEpoch {
		t.Fatalf("stability handshake epochs: %d / %d", firstHandshake.result.PathEpoch, secondHandshake.result.PathEpoch)
	}
	if firstHandshake.result.ProbeCount < 2 || secondHandshake.result.ProbeCount < 2 {
		t.Fatalf("stability interval was not exercised: %d / %d probes", firstHandshake.result.ProbeCount, secondHandshake.result.ProbeCount)
	}
	var resultA, resultB direct.Result
	var serverStream direct.Stream
	for _, outcome := range []handshakeResult{firstHandshake, secondHandshake} {
		switch outcome.site {
		case "site-a":
			resultA = outcome.result
		case "site-b":
			resultB = outcome.result
			serverStream = outcome.stream
		default:
			t.Fatalf("unknown handshake role %q", outcome.site)
		}
	}
	if serverStream == nil {
		t.Fatal("server direct authentication stream unavailable")
	}
	defer serverStream.Close()

	relayA, relayB := newDirectIntegrationUnusedRelay(), newDirectIntegrationUnusedRelay()
	muxOptions := datapath.Options{
		RequireDirect:         true,
		DirectProgressTimeout: 5 * time.Second,
		NoPathRecoveryTimeout: 30 * time.Second,
	}
	muxA, err := datapath.NewWithOptions(ctx, innerMTU, relayA, muxOptions)
	if err != nil {
		t.Fatal(err)
	}
	muxB, err := datapath.NewWithOptions(ctx, innerMTU, relayB, muxOptions)
	if err != nil {
		muxA.Close()
		t.Fatal(err)
	}
	defer muxA.Close()
	defer muxB.Close()

	releaseReceiverCommit := make(chan struct{})
	var releaseReceiverOnce sync.Once
	defer releaseReceiverOnce.Do(func() { close(releaseReceiverCommit) })
	receiverCommitEntered := make(chan struct{})
	monitorOptions := direct.MonitorOptions{
		ProgressInterval: 5 * time.Millisecond,
		PingInterval:     50 * time.Millisecond,
		IdleTimeout:      500 * time.Millisecond,
	}
	monitorA, err := direct.NewDeliveryMonitor(clientStream, resultA, "site-a", monitorOptions)
	if err != nil {
		t.Fatal(err)
	}
	monitorB, err := direct.NewDeliveryMonitor(serverStream, resultB, "site-b", monitorOptions)
	if err != nil {
		t.Fatal(err)
	}
	directConnectionA := &quicDataConnection{Conn: clientConnection, delivery: monitorA}
	directConnectionB := &quicDataConnection{Conn: serverConnection, delivery: monitorB}
	activationA := &directIntegrationActivation{
		mux: muxA, connection: directConnectionA, epoch: pathEpoch,
	}
	activationB := &directIntegrationActivation{
		mux: muxB, connection: directConnectionB, epoch: pathEpoch,
		commitEntered: receiverCommitEntered, commitRelease: releaseReceiverCommit,
	}
	activationResults := make(chan error, 2)
	go func() { activationResults <- direct.ActivateReceiver(ctx, serverStream, resultB, activationB) }()
	go func() { activationResults <- direct.ActivateInitiator(ctx, clientStream, resultA, activationA) }()

	select {
	case <-receiverCommitEntered:
	case <-ctx.Done():
		t.Fatalf("receiver never reached delayed commit: %v", ctx.Err())
	}
	initiatorCommitDeadline := time.Now().Add(2 * time.Second)
	for !activationA.committed.Load() && time.Now().Before(initiatorCommitDeadline) {
		time.Sleep(time.Millisecond)
	}
	if !activationA.prepared.Load() || !activationB.prepared.Load() ||
		!activationA.selected.Load() || !activationA.committed.Load() ||
		!activationB.selected.Load() || activationB.committed.Load() {
		t.Fatal("activation barrier did not reach the asymmetric final-commit window")
	}

	firstPacket := directIntegrationPayload(0xa1, 0, innerMTU)
	if err := muxA.SendPacket(firstPacket); err != nil {
		t.Fatalf("first full-MTU packet on selected direct path: %v", err)
	}
	provisionalCtx, cancelProvisional := context.WithTimeout(ctx, 100*time.Millisecond)
	if provisionalPacket, provisionalErr := muxB.ReceivePacket(provisionalCtx); provisionalErr == nil {
		cancelProvisional()
		t.Fatalf("uncommitted direct packet escaped provisional buffer: %x", provisionalPacket)
	} else if !errors.Is(provisionalErr, context.DeadlineExceeded) {
		cancelProvisional()
		t.Fatalf("provisional receive returned unexpected error: %v", provisionalErr)
	}
	cancelProvisional()
	releaseReceiverOnce.Do(func() { close(releaseReceiverCommit) })
	for completed := 0; completed < 2; completed++ {
		select {
		case err := <-activationResults:
			if err != nil {
				t.Fatalf("activation after receiver commit delay: %v", err)
			}
		case <-ctx.Done():
			t.Fatalf("activation did not complete: %v", ctx.Err())
		}
	}
	if !activationA.committed.Load() || !activationB.selected.Load() || !activationB.committed.Load() {
		t.Fatal("both peers did not commit the confirmed direct path")
	}
	if snapshotA, snapshotB := muxA.Snapshot(), muxB.Snapshot(); snapshotA.Selected != datapath.SelectedDirect || !snapshotA.DirectHealthy ||
		snapshotB.Selected != datapath.SelectedDirect || !snapshotB.DirectHealthy {
		t.Fatalf("committed direct path was not healthy: site-a=%#v site-b=%#v", snapshotA, snapshotB)
	}
	receivedFirst, err := muxB.ReceivePacket(ctx)
	if err != nil {
		t.Fatalf("committed receiver lost buffered first full-MTU packet: %v snapshot=%#v", err, muxB.Snapshot())
	}
	if !bytes.Equal(receivedFirst, firstPacket) {
		t.Fatal("first full-MTU packet changed during provisional replay")
	}
	if err := directConnectionA.StartDelivery(clientConnection.Context()); err != nil {
		t.Fatalf("start site-a delivery monitor: %v", err)
	}
	defer monitorA.Stop()
	if err := directConnectionB.StartDelivery(serverConnection.Context()); err != nil {
		t.Fatalf("start site-b delivery monitor: %v", err)
	}
	defer monitorB.Stop()

	expectedAB := directIntegrationDigest(0xa2, bulkPacketCount, innerMTU)
	expectedBA := directIntegrationDigest(0xb2, bulkPacketCount, innerMTU)
	type transferResult struct {
		name   string
		digest [sha256.Size]byte
		err    error
	}
	transfers := make(chan transferResult, 4)
	go func() {
		transfers <- transferResult{name: "send-a-b", err: directIntegrationSend(muxA, 0xa2, bulkPacketCount, innerMTU)}
	}()
	go func() {
		transfers <- transferResult{name: "send-b-a", err: directIntegrationSend(muxB, 0xb2, bulkPacketCount, innerMTU)}
	}()
	go func() {
		digest, receiveErr := directIntegrationReceive(ctx, muxB, 0xa2, bulkPacketCount, innerMTU)
		transfers <- transferResult{name: "receive-a-b", digest: digest, err: receiveErr}
	}()
	go func() {
		digest, receiveErr := directIntegrationReceive(ctx, muxA, 0xb2, bulkPacketCount, innerMTU)
		transfers <- transferResult{name: "receive-b-a", digest: digest, err: receiveErr}
	}()
	for range 4 {
		result := <-transfers
		if result.err != nil {
			t.Fatalf("%s (%d bytes per direction): %v", result.name, bulkBytes, result.err)
		}
		switch result.name {
		case "receive-a-b":
			if result.digest != expectedAB {
				t.Fatal("site-a to site-b aggregate digest mismatch")
			}
		case "receive-b-a":
			if result.digest != expectedBA {
				t.Fatal("site-b to site-a aggregate digest mismatch")
			}
		}
	}

	snapshotA, snapshotB := muxA.Snapshot(), muxB.Snapshot()
	if snapshotA.Selected != datapath.SelectedDirect || snapshotB.Selected != datapath.SelectedDirect ||
		!snapshotA.DirectHealthy || !snapshotB.DirectHealthy {
		t.Fatalf("direct path not healthy after full-duplex transfer: %#v / %#v", snapshotA, snapshotB)
	}
	if snapshotA.Counters.DirectSent != bulkPacketCount+1 || snapshotA.Counters.DirectReceived != bulkPacketCount ||
		snapshotB.Counters.DirectSent != bulkPacketCount || snapshotB.Counters.DirectReceived != bulkPacketCount+1 {
		t.Fatalf("direct counters do not cover the complete transfer: %#v / %#v", snapshotA.Counters, snapshotB.Counters)
	}
	if snapshotA.Counters.RelaySent != 0 || snapshotA.Counters.RelayReceived != 0 ||
		snapshotB.Counters.RelaySent != 0 || snapshotB.Counters.RelayReceived != 0 ||
		relayA.sendAttempts.Load() != 0 || relayB.sendAttempts.Load() != 0 {
		t.Fatalf("bulk transfer touched the relay path: %#v / %#v; attempts=%d/%d",
			snapshotA.Counters, snapshotB.Counters, relayA.sendAttempts.Load(), relayB.sendAttempts.Load())
	}
	if snapshotA.Counters.QueueDrops != 0 || snapshotB.Counters.QueueDrops != 0 ||
		snapshotA.Counters.InvalidPackets != 0 || snapshotB.Counters.InvalidPackets != 0 ||
		snapshotA.Counters.DuplicatePacket != 0 || snapshotB.Counters.DuplicatePacket != 0 {
		t.Fatalf("loss, corruption, or replay observed: %#v / %#v", snapshotA.Counters, snapshotB.Counters)
	}
	if snapshotA.Counters.DirectProgress == 0 || snapshotB.Counters.DirectProgress == 0 ||
		snapshotA.Counters.WatchdogFailure != 0 || snapshotB.Counters.WatchdogFailure != 0 {
		t.Fatalf("authenticated delivery progress was not maintained: %#v / %#v", snapshotA.Counters, snapshotB.Counters)
	}
}

type directIntegrationAccept struct {
	connection *quic.Conn
	err        error
}

type directIntegrationPKI struct {
	siteA, siteB tls.Certificate
	roots        *x509.CertPool
	uriA, uriB   string
	pinA, pinB   string
	serverName   string
}

func newDirectIntegrationPKI(t *testing.T, now time.Time) directIntegrationPKI {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "campus-link direct integration root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)

	const (
		uriA       = "spiffe://campus-link/integration/site-a/data"
		uriB       = "spiffe://campus-link/integration/site-b/data"
		serverName = "site-b.campus-link"
	)
	issue := func(serial int64, dnsName, uriText string) tls.Certificate {
		publicKey, privateKey, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		uri, parseErr := url.Parse(uriText)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: "ignored"},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			DNSNames:              []string{dnsName},
			URIs:                  []*url.URL{uri},
			BasicConstraintsValid: true,
		}
		der, createErr := x509.CreateCertificate(rand.Reader, template, root, publicKey, rootPrivate)
		if createErr != nil {
			t.Fatal(createErr)
		}
		leaf, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey, Leaf: leaf}
	}
	siteA := issue(2, "site-a.campus-link", uriA)
	siteB := issue(3, serverName, uriB)
	pinA, err := identity.SPKIPin(siteA.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	pinB, err := identity.SPKIPin(siteB.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	return directIntegrationPKI{
		siteA: siteA, siteB: siteB, roots: roots, uriA: uriA, uriB: uriB,
		pinA: pinA, pinB: pinB, serverName: serverName,
	}
}

func listenDirectIntegrationUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	// This test checks activation, identity, framing, and full-duplex integrity
	// on a no-loss loopback path. Size the kernel queues above the complete
	// simultaneous burst so host scheduling cannot turn it into an accidental
	// packet-loss test; impaired-path TCP reliability is covered separately.
	if err := connection.SetReadBuffer(8 << 20); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	if err := connection.SetWriteBuffer(8 << 20); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	return connection
}

func directIntegrationPlans(t *testing.T, now time.Time, epoch uint64) (rendezvous.Plan, rendezvous.Plan) {
	t.Helper()
	var session [16]byte
	var probeKey [32]byte
	if _, err := rand.Read(session[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(probeKey[:]); err != nil {
		t.Fatal(err)
	}
	base := rendezvous.Plan{
		Circuit: "integration", Version: "integration-v1", DeploymentID: "0123456789abcdef0123456789abcdef",
		RelayGeneration: "abcdef0123456789abcdef0123456789", Session: session, ProbeKey: probeKey,
		Attempt: 1, PathEpoch: epoch, Start: now, Expires: now.Add(20 * time.Second),
	}
	planA, planB := base, base
	planA.Generation, planA.PeerGeneration, planA.Role = "integration-a", "integration-b", rendezvous.RoleSender
	planB.Generation, planB.PeerGeneration, planB.Role = "integration-b", "integration-a", rendezvous.RoleReceiver
	return planA, planB
}

type directIntegrationActivation struct {
	mux           *datapath.Mux
	connection    datapath.Connection
	epoch         uint64
	commitEntered chan struct{}
	commitRelease <-chan struct{}
	prepared      atomic.Bool
	selected      atomic.Bool
	committed     atomic.Bool
	enterOnce     sync.Once
}

func (a *directIntegrationActivation) PrepareDirect(epoch uint64) error {
	if epoch != a.epoch {
		return datapath.ErrStalePath
	}
	if err := a.mux.PrepareDirect(epoch, a.connection); err != nil {
		return err
	}
	a.prepared.Store(true)
	return nil
}

func (a *directIntegrationActivation) SelectDirect(epoch uint64) error {
	if epoch != a.epoch || !a.prepared.Load() {
		return datapath.ErrStalePath
	}
	if err := a.mux.SelectDirect(epoch); err != nil {
		return err
	}
	a.selected.Store(true)
	return nil
}

func (a *directIntegrationActivation) CommitDirect(epoch uint64) error {
	if epoch != a.epoch || !a.selected.Load() {
		return datapath.ErrStalePath
	}
	if a.commitEntered != nil {
		a.enterOnce.Do(func() { close(a.commitEntered) })
	}
	if a.commitRelease != nil {
		<-a.commitRelease
	}
	if err := a.mux.CommitDirect(epoch); err != nil {
		return err
	}
	a.committed.Store(true)
	return nil
}

func (a *directIntegrationActivation) AbortDirect(epoch uint64) {
	a.mux.AbortDirect(epoch)
	a.selected.Store(false)
	a.committed.Store(false)
}

type directIntegrationUnusedRelay struct {
	closed       chan struct{}
	closeOnce    sync.Once
	sendAttempts atomic.Uint64
}

func newDirectIntegrationUnusedRelay() *directIntegrationUnusedRelay {
	return &directIntegrationUnusedRelay{closed: make(chan struct{})}
}

func (r *directIntegrationUnusedRelay) SendDatagram([]byte) error {
	r.sendAttempts.Add(1)
	return errors.New("integration relay path was used")
}

func (r *directIntegrationUnusedRelay) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.closed:
		return nil, errors.New("integration relay closed")
	}
}

func (r *directIntegrationUnusedRelay) Close(string) error {
	r.closeOnce.Do(func() { close(r.closed) })
	return nil
}

func directIntegrationPayload(direction byte, sequence, size int) []byte {
	payload := make([]byte, size)
	payload[0] = direction
	binary.BigEndian.PutUint64(payload[1:9], uint64(sequence))
	seed := uint64(direction)<<56 ^ uint64(sequence+1)*0x9e3779b97f4a7c15
	for offset := 9; offset < len(payload); offset++ {
		seed ^= seed << 13
		seed ^= seed >> 7
		seed ^= seed << 17
		payload[offset] = byte(seed)
	}
	return payload
}

func directIntegrationSend(mux *datapath.Mux, direction byte, count, size int) error {
	for sequence := 0; sequence < count; sequence++ {
		if err := mux.SendPacket(directIntegrationPayload(direction, sequence, size)); err != nil {
			return err
		}
	}
	return nil
}

func directIntegrationReceive(ctx context.Context, mux *datapath.Mux, direction byte, count, size int) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	buffer := make([]byte, count*size)
	seen := make([]bool, count)
	for received := 0; received < count; received++ {
		packet, err := mux.ReceivePacket(ctx)
		if err != nil {
			return zero, err
		}
		if len(packet) != size || packet[0] != direction {
			return zero, errors.New("unexpected full-duplex packet shape")
		}
		sequence := binary.BigEndian.Uint64(packet[1:9])
		if sequence >= uint64(count) || seen[sequence] {
			return zero, errors.New("duplicate or out-of-range full-duplex packet")
		}
		expected := directIntegrationPayload(direction, int(sequence), size)
		if !bytes.Equal(packet, expected) {
			return zero, errors.New("corrupted full-duplex packet")
		}
		seen[sequence] = true
		copy(buffer[int(sequence)*size:], packet)
	}
	return sha256.Sum256(buffer), nil
}

func directIntegrationDigest(direction byte, count, size int) [sha256.Size]byte {
	digest := sha256.New()
	for sequence := 0; sequence < count; sequence++ {
		digest.Write(directIntegrationPayload(direction, sequence, size))
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}
