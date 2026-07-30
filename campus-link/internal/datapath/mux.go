// Package datapath selects between a warm relayed QUIC connection and an
// authenticated direct QUIC connection without duplicating tunnel packets.
package datapath

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
)

const (
	wireMagic  = "CLP1"
	headerSize = 24
	queueSize  = 256

	kindRelay  = 1
	kindDirect = 2

	replayWindowSize     = 4096
	maxDrainingPaths     = 2
	maxSendPathAttempts  = 16
	maxActivationPackets = 256
	maxActivationBytes   = 512 * 1024

	DirectDrainDuration   = 2 * time.Second
	SendTimeout           = 2 * time.Second
	DirectProgressTimeout = 5 * time.Second
	NoPathRecoveryTimeout = 30 * time.Second
	ActivationBufferTime  = 5 * time.Second
	WireOverhead          = headerSize
)

var (
	ErrNoHealthyPath       = errors.New("no authenticated data path is healthy")
	ErrInvalidPacket       = errors.New("invalid campus-link packet envelope")
	ErrStalePath           = errors.New("stale data path")
	ErrPacketTooLarge      = errors.New("packet exceeds current QUIC DATAGRAM capacity")
	ErrClosed              = errors.New("data path mux is closed")
	ErrInstanceIDExhausted = errors.New("data path instance identifiers exhausted")
	ErrActivationCapacity  = errors.New("inbound queue cannot atomically admit provisional direct packets")
)

type Selected string

const (
	SelectedNone   Selected = "none"
	SelectedRelay  Selected = "relay"
	SelectedDirect Selected = "direct"
)

// Connection is the QUIC DATAGRAM subset used by the path selector.
type Connection interface {
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
	Close(string) error
}

// DeliveryBinding lets an exporter-authenticated direct control stream report
// peer progress or fail the exact connection instance that owns the stream.
type DeliveryBinding struct {
	Acknowledge func(uint64) bool
	Fail        func() bool
}

// DeliveryAwareConnection is optional. Production direct connections use it;
// isolated fakes that omit it intentionally exercise the no-progress timeout.
type DeliveryAwareConnection interface {
	BindDelivery(DeliveryBinding)
	DatagramDelivered(uint64)
}

type Options struct {
	DirectProgressTimeout time.Duration
	NoPathRecoveryTimeout time.Duration
	RequireDirect         bool
}

type Counters struct {
	RelaySent       uint64
	DirectSent      uint64
	RelayReceived   uint64
	DirectReceived  uint64
	Fallbacks       uint64
	InvalidPackets  uint64
	DuplicatePacket uint64
	QueueDrops      uint64
	DirectProgress  uint64
	WatchdogFailure uint64
}

type Snapshot struct {
	Selected                Selected
	DirectRequired          bool
	RelayHealthy            bool
	DirectHealthy           bool
	DirectEpoch             uint64
	RelayInstanceID         uint64
	DirectInstanceID        uint64
	SelectedPathTransitions uint64
	Counters                Counters
}

type selectedPathAuthority struct {
	selected Selected
	epoch    uint64
	id       uint64
}

type receivedPacket struct {
	payload []byte
}

type activationPacket struct {
	payload  []byte
	sequence uint64
}

// activationBuffer belongs to one exact selected-but-uncommitted connection.
// Payload and byte accounting are protected by Mux.mu. deliveryMu only
// serializes release with discard, allowing shutdown/failure to stop release
// without holding Mux.mu across the inbound/TUN handoff.
type activationBuffer struct {
	packets  []activationPacket
	bytes    int
	expires  time.Time
	timer    *time.Timer
	release  chan struct{}
	released sync.Once
	replay   sequenceWindow
	base     sequenceWindow
	hadBase  bool

	deliveryMu sync.Mutex
	discarded  bool
}

type pathSlot struct {
	connection         Connection
	sender             *sendActor
	epoch              uint64
	id                 uint64
	healthy            bool
	retried            bool
	timer              *time.Timer
	progressTimer      *time.Timer
	progressGeneration uint64
	lastSent           uint64
	lastAcknowledged   uint64
	activation         *activationBuffer
}

type replayKey struct {
	kind  byte
	epoch uint64
}

type sendRequest struct {
	packet []byte
	result chan error
}

// sendActor bounds every connection to one potentially blocked QUIC send and
// a fixed request queue. Closing the connection is the cancellation mechanism
// for a SendDatagram call that makes no progress.
type sendActor struct {
	ctx        context.Context
	cancel     context.CancelFunc
	connection Connection
	requests   chan sendRequest
	closeOnce  sync.Once
}

func newSendActor(parent context.Context, connection Connection) *sendActor {
	ctx, cancel := context.WithCancel(parent)
	a := &sendActor{ctx: ctx, cancel: cancel, connection: connection, requests: make(chan sendRequest, 32)}
	go a.run()
	return a
}

func (a *sendActor) run() {
	for {
		select {
		case <-a.ctx.Done():
			return
		case request := <-a.requests:
			err := a.connection.SendDatagram(request.packet)
			select {
			case request.result <- err:
			case <-a.ctx.Done():
				return
			}
		}
	}
}

func (a *sendActor) Send(ctx context.Context, packet []byte) error {
	if a == nil {
		return ErrNoHealthyPath
	}
	request := sendRequest{packet: append([]byte(nil), packet...), result: make(chan error, 1)}
	timer := time.NewTimer(SendTimeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-a.ctx.Done():
		return ErrClosed
	case <-timer.C:
		a.Close("datagram send queue timeout")
		return errors.New("datagram send made no progress")
	case a.requests <- request:
	}
	select {
	case <-ctx.Done():
		a.Close("data path shutdown")
		return context.Cause(ctx)
	case <-a.ctx.Done():
		return ErrClosed
	case <-timer.C:
		a.Close("datagram send timeout")
		return errors.New("datagram send made no progress")
	case err := <-request.result:
		return classifySendError(err)
	}
}

func (a *sendActor) Close(reason string) {
	if a == nil {
		return
	}
	a.closeOnce.Do(func() {
		a.cancel()
		_ = a.connection.Close(reason)
	})
}

func classifySendError(err error) error {
	if err == nil {
		return nil
	}
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return errors.Join(ErrPacketTooLarge, err)
	}
	return err
}

type Mux struct {
	ctx    context.Context
	cancel context.CancelFunc
	mtu    int

	mu                sync.Mutex
	inboundMu         sync.Mutex
	notifyMu          sync.Mutex
	pathAuthority     selectedPathAuthority
	pathAuthoritySet  bool
	sequenceExhausted bool
	relay             pathSlot
	direct            pathSlot
	pending           pathSlot
	draining          map[uint64]pathSlot
	selected          Selected
	replay            map[replayKey]*sequenceWindow
	nextID            uint64
	closed            bool
	rollbackEpoch     uint64
	rollbackDirectID  uint64
	rollbackSelected  Selected
	closeOnce         sync.Once
	receivers         sync.WaitGroup

	sequence      atomic.Uint64
	inbound       chan receivedPacket
	changes       chan Snapshot
	failures      chan error
	relayRecovery chan struct{}
	pathChanged   chan struct{}
	sendToken     chan struct{}

	relaySent        atomic.Uint64
	directSent       atomic.Uint64
	relayReceived    atomic.Uint64
	directReceived   atomic.Uint64
	fallbacks        atomic.Uint64
	invalidPackets   atomic.Uint64
	duplicatePacket  atomic.Uint64
	queueDrops       atomic.Uint64
	directProgress   atomic.Uint64
	watchdogFailure  atomic.Uint64
	pathTransitions  atomic.Uint64
	progressTimeout  time.Duration
	noPathTimeout    time.Duration
	noPathTimer      *time.Timer
	noPathGeneration uint64
	noPathFailed     bool
	requireDirect    bool
}

func (m *Mux) selectedPathAuthorityLocked() selectedPathAuthority {
	switch {
	case m.selected == SelectedDirect && m.direct.healthy && m.direct.id != 0:
		return selectedPathAuthority{selected: SelectedDirect, epoch: m.direct.epoch, id: m.direct.id}
	case m.selected == SelectedRelay && m.relay.healthy && m.relay.id != 0:
		return selectedPathAuthority{selected: SelectedRelay, id: m.relay.id}
	default:
		return selectedPathAuthority{selected: SelectedNone}
	}
}

func (m *Mux) noteSelectedPathAuthorityLocked() {
	current := m.selectedPathAuthorityLocked()
	if m.pathAuthoritySet {
		if current != m.pathAuthority {
			for {
				prior := m.pathTransitions.Load()
				if prior == ^uint64(0) || m.pathTransitions.CompareAndSwap(prior, prior+1) {
					break
				}
			}
		}
	} else {
		m.pathAuthoritySet = true
	}
	m.pathAuthority = current
}

func (m *Mux) setSelectedLocked(selected Selected) {
	m.selected = selected
	m.noteSelectedPathAuthorityLocked()
}

func New(ctx context.Context, mtu int, relay Connection) (*Mux, error) {
	return NewWithOptions(ctx, mtu, relay, Options{})
}

// NewDirectRequired constructs the production profile. The relay remains a
// control/liveness association and can never become an application data path.
func NewDirectRequired(ctx context.Context, mtu int, relay Connection) (*Mux, error) {
	return NewWithOptions(ctx, mtu, relay, Options{RequireDirect: true})
}

func NewWithOptions(ctx context.Context, mtu int, relay Connection, options Options) (*Mux, error) {
	if ctx == nil || mtu < 576 || mtu > 65535 || relay == nil {
		return nil, ErrNoHealthyPath
	}
	if options.DirectProgressTimeout == 0 {
		options.DirectProgressTimeout = DirectProgressTimeout
	}
	if options.NoPathRecoveryTimeout == 0 {
		options.NoPathRecoveryTimeout = NoPathRecoveryTimeout
	}
	if options.DirectProgressTimeout <= 0 || options.NoPathRecoveryTimeout <= 0 {
		return nil, ErrNoHealthyPath
	}
	muxCtx, cancel := context.WithCancel(ctx)
	m := &Mux{
		ctx: muxCtx, cancel: cancel, mtu: mtu, inbound: make(chan receivedPacket, queueSize),
		changes: make(chan Snapshot, 1), failures: make(chan error, 1), relayRecovery: make(chan struct{}, 1),
		pathChanged: make(chan struct{}),
		sendToken:   make(chan struct{}, 1),
		nextID:      1, draining: make(map[uint64]pathSlot), replay: make(map[replayKey]*sequenceWindow),
		progressTimeout: options.DirectProgressTimeout,
		noPathTimeout:   options.NoPathRecoveryTimeout,
		requireDirect:   options.RequireDirect,
	}
	m.sendToken <- struct{}{}
	m.relay = m.newSlot(relay, 0, 1, true)
	if options.RequireDirect {
		m.setSelectedLocked(SelectedNone)
	} else {
		m.setSelectedLocked(SelectedRelay)
	}
	m.startReceiver(m.relay, kindRelay)
	m.notify()
	return m, nil
}

func (m *Mux) newSlot(connection Connection, epoch, id uint64, healthy bool) pathSlot {
	slot := pathSlot{connection: connection, sender: newSendActor(m.ctx, connection), epoch: epoch, id: id, healthy: healthy}
	if epoch != 0 {
		if aware, ok := connection.(DeliveryAwareConnection); ok {
			aware.BindDelivery(DeliveryBinding{
				Acknowledge: func(sequence uint64) bool { return m.acknowledgeDirect(epoch, id, sequence) },
				Fail:        func() bool { return m.directFailed(epoch, id) },
			})
		}
	}
	return slot
}

func (m *Mux) startActivationBufferLocked(slot *pathSlot) {
	if slot == nil || slot.connection == nil || slot.id == 0 || slot.epoch == 0 {
		return
	}
	buffer := &activationBuffer{
		expires: time.Now().Add(ActivationBufferTime),
		release: make(chan struct{}),
	}
	if window := m.replay[replayKey{kind: kindDirect, epoch: slot.epoch}]; window != nil {
		buffer.replay = *window
		buffer.base = *window
		buffer.hadBase = true
	}
	slot.activation = buffer
	epoch, id := slot.epoch, slot.id
	buffer.timer = time.AfterFunc(ActivationBufferTime, func() {
		m.activationBufferExpired(epoch, id, buffer)
	})
}

// discardActivationLocked prevents any further release before destroying all
// retained payloads. The per-activation lock is intentionally distinct from
// Mux.mu: release never holds it while acquiring Mux.mu.
func (m *Mux) discardActivationLocked(slot *pathSlot) {
	if slot == nil || slot.activation == nil {
		return
	}
	buffer := slot.activation
	if buffer.timer != nil {
		buffer.timer.Stop()
		buffer.timer = nil
	}
	buffer.packets = nil
	buffer.bytes = 0
	buffer.replay = sequenceWindow{}
	buffer.base = sequenceWindow{}
	buffer.hadBase = false
	buffer.deliveryMu.Lock()
	buffer.discarded = true
	buffer.released.Do(func() { close(buffer.release) })
	buffer.deliveryMu.Unlock()
	slot.activation = nil
}

// abortProvisionalLocked removes only the exact pending instance. The caller
// closes its connection and publishes the unchanged committed-path snapshot
// after releasing Mux.mu.
func (m *Mux) abortProvisionalLocked(epoch, id uint64, buffer *activationBuffer) (pathSlot, bool) {
	if epoch == 0 || id == 0 || buffer == nil || m.rollbackEpoch != epoch ||
		m.pending.epoch != epoch || m.pending.id != id || m.pending.activation != buffer {
		return pathSlot{}, false
	}
	failed := m.pending
	m.discardActivationLocked(&failed)
	m.pending = pathSlot{}
	m.rollbackEpoch = 0
	m.rollbackDirectID = 0
	m.rollbackSelected = SelectedNone
	m.pruneDirectReplayLocked(epoch)
	return failed, true
}

func (m *Mux) activationBufferExpired(epoch, id uint64, buffer *activationBuffer) {
	m.mu.Lock()
	failed, aborted := m.abortProvisionalLocked(epoch, id, buffer)
	m.mu.Unlock()
	if !aborted {
		return
	}
	m.notify()
	failed.sender.Close("direct activation buffer expired")
}

func (m *Mux) startReceiver(slot pathSlot, kind byte) {
	m.receivers.Add(1)
	go func() {
		defer m.receivers.Done()
		m.receiveLoop(slot.connection, kind, slot.epoch, slot.id)
	}()
}

func (m *Mux) allocateInstanceIDLocked() (uint64, error) {
	if m.nextID == ^uint64(0) {
		return 0, ErrInstanceIDExhausted
	}
	m.nextID++
	return m.nextID, nil
}

// RelayRecoveryNeeded reports current-relay failure as one coalesced edge.
// The channel is deliberately not closed: callers bound its lifetime with the
// same context that owns the mux.
func (m *Mux) RelayRecoveryNeeded() <-chan struct{} {
	if m == nil {
		return nil
	}
	return m.relayRecovery
}

// ReplaceRelay atomically installs an already authenticated and
// capacity-validated warm relay connection. A healthy direct path remains
// selected. The retired relay is closed only after the fresh instance ID owns
// the slot, so any delayed failure callback carries an inert ID.
func (m *Mux) ReplaceRelay(connection Connection) error {
	_, err := m.ReplaceRelayWithInstance(connection)
	return err
}

// ReplaceRelayWithInstance returns the fresh, non-reusable mux instance ID
// assigned to the authenticated replacement. Callers use this ID to bind
// separately verified metadata without an epoch or replacement ABA race.
func (m *Mux) ReplaceRelayWithInstance(connection Connection) (uint64, error) {
	return m.replaceRelay(connection, nil, false)
}

// ReplaceRelayWithBinding atomically publishes caller metadata for the fresh
// instance before the replacement can become visible. bind runs under m.mu and
// must not lock or block. The caller's lock must precede m.mu; retired-path
// cleanup is detached so that lock is never held across a connection close.
func (m *Mux) ReplaceRelayWithBinding(connection Connection, bind func(uint64)) (uint64, error) {
	if bind == nil {
		return 0, ErrNoHealthyPath
	}
	return m.replaceRelay(connection, bind, true)
}

func (m *Mux) replaceRelay(connection Connection, bind func(uint64), detachedRetirement bool) (uint64, error) {
	if connection == nil {
		return 0, ErrNoHealthyPath
	}
	var retired pathSlot
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return 0, ErrClosed
	}
	if m.noPathFailed {
		m.mu.Unlock()
		if detachedRetirement {
			go connection.Close("terminal no-path failure")
		} else {
			_ = connection.Close("terminal no-path failure")
		}
		return 0, ErrNoHealthyPath
	}
	id, err := m.allocateInstanceIDLocked()
	if err != nil {
		m.mu.Unlock()
		return 0, err
	}
	replacement := m.newSlot(connection, 0, id, true)
	if bind != nil {
		bind(id)
	}
	retired = m.relay
	m.relay = replacement
	if m.direct.healthy {
		m.setSelectedLocked(SelectedDirect)
	} else if !m.requireDirect {
		m.setSelectedLocked(SelectedRelay)
	} else {
		m.setSelectedLocked(SelectedNone)
	}
	m.startReceiver(replacement, kindRelay)
	m.mu.Unlock()

	m.notify()
	if detachedRetirement {
		go retired.sender.Close("relay path replaced")
	} else {
		retired.sender.Close("relay path replaced")
	}
	return id, nil
}

// PrepareDirect starts a receive-only path. It cannot change the selected
// sender; SelectDirect is a separate authenticated barrier step.
func (m *Mux) PrepareDirect(epoch uint64, connection Connection) error {
	_, err := m.PrepareDirectWithInstance(epoch, connection)
	return err
}

// PrepareDirectWithInstance returns the fresh, non-reusable mux instance ID
// before the path can become selected. Verified peer metadata can therefore be
// published only for this exact connection, including same-epoch retries.
func (m *Mux) PrepareDirectWithInstance(epoch uint64, connection Connection) (uint64, error) {
	if epoch == 0 || connection == nil {
		return 0, ErrStalePath
	}
	var superseded pathSlot
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return 0, ErrClosed
	}
	if m.noPathFailed {
		m.mu.Unlock()
		go connection.Close("terminal no-path failure")
		return 0, ErrNoHealthyPath
	}
	sameEpochRetry := epoch == m.direct.epoch && m.direct.connection != nil && !m.direct.healthy
	if m.rollbackEpoch != 0 || epoch < m.direct.epoch || (epoch == m.direct.epoch && !sameEpochRetry) ||
		(m.pending.epoch != 0 && epoch <= m.pending.epoch) {
		m.mu.Unlock()
		return 0, ErrStalePath
	}
	id, err := m.allocateInstanceIDLocked()
	if err != nil {
		m.mu.Unlock()
		return 0, err
	}
	slot := m.newSlot(connection, epoch, id, false)
	slot.retried = sameEpochRetry
	superseded = m.pending
	m.discardActivationLocked(&superseded)
	m.pending = slot
	m.pruneDirectReplayLocked(superseded.epoch)
	m.startReceiver(slot, kindDirect)
	m.mu.Unlock()
	if superseded.connection != nil {
		superseded.sender.Close("direct preparation superseded")
	}
	return id, nil
}

// SelectDirect atomically cuts the sender over to a prepared receive path.
func (m *Mux) SelectDirect(epoch uint64) error {
	var closeNow []pathSlot
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	if m.noPathFailed {
		pending := m.pending
		m.discardActivationLocked(&pending)
		m.pending = pathSlot{}
		m.pruneDirectReplayLocked(pending.epoch)
		m.mu.Unlock()
		m.notify()
		if pending.sender != nil {
			go pending.sender.Close("terminal no-path failure")
		}
		return ErrNoHealthyPath
	}
	if epoch == 0 || m.pending.epoch != epoch || m.pending.connection == nil || m.rollbackEpoch != 0 {
		m.mu.Unlock()
		return ErrStalePath
	}
	if m.requireDirect {
		// Selection is deliberately provisional in the production profile.
		// Keep the committed path in m.direct, including its delivery watchdog,
		// until the authenticated four-flight barrier reaches CommitDirect.
		m.rollbackEpoch = epoch
		m.rollbackSelected = m.selected
		m.rollbackDirectID = m.direct.id
		m.pending.healthy = true
		m.startActivationBufferLocked(&m.pending)
		m.mu.Unlock()
		m.notify()
		return nil
	}
	m.rollbackEpoch = epoch
	m.rollbackSelected = m.selected
	m.rollbackDirectID = 0
	if m.direct.connection != nil {
		if m.direct.healthy {
			m.stopProgressTimerLocked(&m.direct)
			for len(m.draining) >= maxDrainingPaths {
				var oldest uint64
				for id := range m.draining {
					if oldest == 0 || id < oldest {
						oldest = id
					}
				}
				evicted := m.draining[oldest]
				delete(m.draining, oldest)
				if evicted.timer != nil {
					evicted.timer.Stop()
				}
				closeNow = append(closeNow, evicted)
			}
			retired := m.direct
			retiredID := retired.id
			retired.timer = nil
			m.draining[retiredID] = retired
			m.rollbackDirectID = retiredID
		} else {
			closeNow = append(closeNow, m.direct)
		}
	}
	m.pending.healthy = true
	m.direct = m.pending
	m.pending = pathSlot{}
	m.setSelectedLocked(SelectedDirect)
	for _, slot := range closeNow {
		m.pruneDirectReplayLocked(slot.epoch)
	}
	m.mu.Unlock()
	m.notify()
	for _, slot := range closeNow {
		go slot.sender.Close("direct receive drain evicted")
	}
	return nil
}

// CommitDirect makes a selected activation irreversible. The prior direct
// path remains receive-only until its normal drain timer expires.
func (m *Mux) CommitDirect(epoch uint64) error {
	var closeNow []pathSlot
	var committed pathSlot
	var activation *activationBuffer
	var buffered []activationPacket
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	if m.noPathFailed {
		m.mu.Unlock()
		m.AbortDirect(epoch)
		return ErrNoHealthyPath
	}
	if m.requireDirect {
		if epoch == 0 || m.rollbackEpoch != epoch || m.pending.epoch != epoch || !m.pending.healthy ||
			m.pending.activation == nil {
			m.mu.Unlock()
			return ErrStalePath
		}
		activation = m.pending.activation
		if !time.Now().Before(activation.expires) {
			failed, _ := m.abortProvisionalLocked(epoch, m.pending.id, activation)
			m.mu.Unlock()
			m.notify()
			failed.sender.Close("direct activation buffer expired before commit")
			return ErrStalePath
		}
		base := m.replay[replayKey{kind: kindDirect, epoch: epoch}]
		if (base != nil) != activation.hadBase || (base != nil && *base != activation.base) {
			failed, _ := m.abortProvisionalLocked(epoch, m.pending.id, activation)
			m.mu.Unlock()
			m.notify()
			failed.sender.Close("direct activation replay base changed")
			return ErrStalePath
		}
		m.inboundMu.Lock()
		if cap(m.inbound)-len(m.inbound) < len(activation.packets) {
			failed, _ := m.abortProvisionalLocked(epoch, m.pending.id, activation)
			m.inboundMu.Unlock()
			m.mu.Unlock()
			m.notify()
			failed.sender.Close("direct activation inbound reservation failed")
			return ErrActivationCapacity
		}
		if m.direct.connection != nil {
			if m.direct.healthy {
				m.stopProgressTimerLocked(&m.direct)
				for len(m.draining) >= maxDrainingPaths {
					var oldest uint64
					for id := range m.draining {
						if oldest == 0 || id < oldest {
							oldest = id
						}
					}
					evicted := m.draining[oldest]
					delete(m.draining, oldest)
					if evicted.timer != nil {
						evicted.timer.Stop()
					}
					closeNow = append(closeNow, evicted)
				}
				retired := m.direct
				retiredID := retired.id
				retired.timer = time.AfterFunc(DirectDrainDuration, func() { m.expireDraining(retiredID) })
				m.draining[retiredID] = retired
			} else {
				closeNow = append(closeNow, m.direct)
			}
		}
		if activation.timer != nil {
			activation.timer.Stop()
			activation.timer = nil
		}
		buffered = activation.packets
		activation.packets = nil
		activation.bytes = 0
		publishedReplay := activation.replay
		m.replay[replayKey{kind: kindDirect, epoch: epoch}] = &publishedReplay
		activation.replay = sequenceWindow{}
		activation.base = sequenceWindow{}
		activation.hadBase = false
		committed = m.pending
		m.direct = committed
		m.pending = pathSlot{}
		m.setSelectedLocked(SelectedDirect)
		for _, slot := range closeNow {
			m.pruneDirectReplayLocked(slot.epoch)
		}
		m.rollbackEpoch = 0
		m.rollbackDirectID = 0
		m.rollbackSelected = SelectedNone
		m.mu.Unlock()
		delivered, released := m.releaseActivationPackets(activation, buffered)
		m.inboundMu.Unlock()
		m.mu.Lock()
		if m.direct.id == committed.id && m.direct.epoch == committed.epoch && m.direct.activation == activation {
			m.direct.activation = nil
		}
		closed := m.closed
		m.mu.Unlock()
		for _, sequence := range delivered {
			m.noteReceivedDelivery(committed.connection, kindDirect, sequence)
		}
		m.notify()
		for _, slot := range closeNow {
			go slot.sender.Close("direct receive drain evicted")
		}
		if !released {
			if closed {
				return ErrClosed
			}
			m.directFailed(committed.epoch, committed.id)
			return ErrNoHealthyPath
		}
		return nil
	}
	if epoch == 0 || m.rollbackEpoch != epoch || m.direct.epoch != epoch || !m.direct.healthy {
		m.mu.Unlock()
		return ErrStalePath
	}
	if retired, ok := m.draining[m.rollbackDirectID]; ok && m.rollbackDirectID != 0 {
		retiredID := retired.id
		retired.timer = time.AfterFunc(DirectDrainDuration, func() { m.expireDraining(retiredID) })
		m.draining[retiredID] = retired
	}
	m.rollbackEpoch = 0
	m.rollbackDirectID = 0
	m.rollbackSelected = SelectedNone
	m.mu.Unlock()
	m.notify()
	return nil
}

// releaseActivationPackets preserves candidate receive order without holding
// Mux.mu across the inbound handoff that the edge drains into TUN. A concurrent
// failure or shutdown acquires deliveryMu, marks the buffer discarded, and
// prevents every not-yet-released payload from reaching the application queue.
func (m *Mux) releaseActivationPackets(buffer *activationBuffer, packets []activationPacket) ([]uint64, bool) {
	deliveredSequences := make([]uint64, 0, len(packets))
	released := true
	for _, packet := range packets {
		buffer.deliveryMu.Lock()
		if buffer.discarded {
			buffer.deliveryMu.Unlock()
			released = false
			break
		}
		delivered, closed := m.enqueueReceivedLocked(kindDirect, packet.payload)
		buffer.deliveryMu.Unlock()
		if delivered {
			deliveredSequences = append(deliveredSequences, packet.sequence)
		} else {
			released = false
		}
		if closed {
			break
		}
	}
	buffer.deliveryMu.Lock()
	buffer.released.Do(func() { close(buffer.release) })
	buffer.deliveryMu.Unlock()
	return deliveredSequences, released && len(deliveredSequences) == len(packets)
}

// AbortDirect closes a prepared path, or demotes a just-selected path when the
// final activation acknowledgement could not be sent.
func (m *Mux) AbortDirect(epoch uint64) {
	var closePath pathSlot
	var changed bool
	m.mu.Lock()
	if m.requireDirect && m.rollbackEpoch == epoch && m.pending.epoch == epoch {
		closePath = m.pending
		m.stopProgressTimerLocked(&m.pending)
		m.discardActivationLocked(&closePath)
		m.pending = pathSlot{}
		m.rollbackEpoch = 0
		m.rollbackDirectID = 0
		m.rollbackSelected = SelectedNone
		m.pruneDirectReplayLocked(epoch)
		m.mu.Unlock()
		m.notify()
		go closePath.sender.Close("direct activation rolled back")
		return
	}
	if m.pending.epoch == epoch {
		closePath = m.pending
		m.discardActivationLocked(&closePath)
		m.pending = pathSlot{}
		m.pruneDirectReplayLocked(epoch)
		m.mu.Unlock()
		go closePath.sender.Close("direct activation aborted")
		return
	}
	if m.rollbackEpoch == epoch && m.direct.epoch == epoch {
		closePath = m.direct
		m.stopProgressTimerLocked(&m.direct)
		restored, ok := m.draining[m.rollbackDirectID]
		if ok && m.rollbackDirectID != 0 {
			delete(m.draining, m.rollbackDirectID)
			if restored.timer != nil {
				restored.timer.Stop()
				restored.timer = nil
			}
			restored.healthy = true
			m.direct = restored
		} else {
			m.direct = pathSlot{}
		}
		switch {
		case m.rollbackSelected == SelectedDirect && m.direct.healthy:
			m.setSelectedLocked(SelectedDirect)
		case !m.requireDirect && m.rollbackSelected == SelectedRelay && m.relay.healthy:
			m.setSelectedLocked(SelectedRelay)
		case m.direct.healthy:
			m.setSelectedLocked(SelectedDirect)
		case !m.requireDirect && m.relay.healthy:
			m.setSelectedLocked(SelectedRelay)
		default:
			m.setSelectedLocked(SelectedNone)
		}
		m.rollbackEpoch = 0
		m.rollbackDirectID = 0
		m.rollbackSelected = SelectedNone
		if m.direct.healthy && m.direct.lastAcknowledged < m.direct.lastSent {
			m.armProgressTimerLocked(&m.direct)
		}
		changed = true
		m.mu.Unlock()
		m.notify()
		go closePath.sender.Close("direct activation rolled back")
		return
	}
	m.mu.Unlock()
	if !changed {
		m.DirectFailed(epoch)
	}
}

// ActivateDirect is retained for tests and callers that already provide an
// external activation barrier.
func (m *Mux) ActivateDirect(epoch uint64, connection Connection) error {
	if err := m.PrepareDirect(epoch, connection); err != nil {
		return err
	}
	if err := m.SelectDirect(epoch); err != nil {
		m.AbortDirect(epoch)
		return err
	}
	if err := m.CommitDirect(epoch); err != nil {
		m.AbortDirect(epoch)
		return err
	}
	return nil
}

// DirectFailed changes selection only when epoch still owns the active direct
// slot. A delayed failure from a replaced connection cannot clear a newer one.
func (m *Mux) DirectFailed(epoch uint64) bool {
	m.mu.Lock()
	if m.closed || epoch == 0 || epoch != m.direct.epoch || !m.direct.healthy || m.direct.retried {
		m.mu.Unlock()
		return false
	}
	id := m.direct.id
	m.mu.Unlock()
	return m.directFailed(epoch, id)
}

// RetireDirect atomically removes every direct-path instance from the current
// authority namespace. Unlike DirectFailed, it does not identify a path by an
// epoch that a later namespace may reuse. The exact current, pending, and drain
// instance IDs are captured under m.mu, so delayed failures from those
// connections cannot demote a subsequently activated direct path.
func (m *Mux) RetireDirect() bool {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return false
	}
	unique := make(map[uint64]pathSlot, 2+len(m.draining))
	retain := func(slot pathSlot) {
		if slot.connection == nil || slot.id == 0 {
			return
		}
		m.stopProgressTimerLocked(&slot)
		if slot.timer != nil {
			slot.timer.Stop()
		}
		unique[slot.id] = slot
	}
	retain(m.direct)
	retain(m.pending)
	m.discardActivationLocked(&m.direct)
	m.discardActivationLocked(&m.pending)
	for _, slot := range m.draining {
		retain(slot)
	}
	hadHealthyDirect := m.direct.healthy
	m.direct = pathSlot{}
	m.pending = pathSlot{}
	m.draining = make(map[uint64]pathSlot)
	for key := range m.replay {
		if key.kind == kindDirect {
			delete(m.replay, key)
		}
	}
	m.rollbackEpoch = 0
	m.rollbackDirectID = 0
	m.rollbackSelected = SelectedNone
	if m.selected == SelectedDirect {
		if !m.requireDirect && m.relay.healthy {
			m.setSelectedLocked(SelectedRelay)
			if hadHealthyDirect {
				m.fallbacks.Add(1)
			}
		} else {
			m.setSelectedLocked(SelectedNone)
		}
	}
	m.mu.Unlock()
	m.notify()
	for _, slot := range unique {
		slot.sender.Close("direct authority namespace retired")
	}
	return true
}

func (m *Mux) directFailed(epoch, id uint64) bool {
	m.mu.Lock()
	if !m.requireDirect && m.rollbackEpoch == epoch && m.direct.id == id && m.direct.epoch == epoch {
		m.mu.Unlock()
		m.AbortDirect(epoch)
		return true
	}
	if draining, ok := m.draining[id]; ok && id != 0 && draining.epoch == epoch {
		delete(m.draining, id)
		if draining.timer != nil {
			draining.timer.Stop()
		}
		m.stopProgressTimerLocked(&draining)
		m.pruneDirectReplayLocked(epoch)
		m.mu.Unlock()
		draining.sender.Close("retired direct path failed")
		return true
	}
	if m.closed || epoch == 0 || id == 0 || id != m.direct.id || epoch != m.direct.epoch || !m.direct.healthy {
		m.mu.Unlock()
		return false
	}
	failed := m.direct
	m.stopProgressTimerLocked(&m.direct)
	m.discardActivationLocked(&m.direct)
	m.direct.healthy = false
	if m.selected == SelectedDirect {
		if !m.requireDirect && m.relay.healthy {
			m.setSelectedLocked(SelectedRelay)
			m.fallbacks.Add(1)
		} else {
			m.setSelectedLocked(SelectedNone)
		}
	}
	m.mu.Unlock()
	m.notify()
	failed.sender.Close("direct path failed")
	return true
}

func (m *Mux) noteDirectSent(epoch, id, sequence uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || sequence == 0 {
		return
	}
	if draining, ok := m.draining[id]; ok && id != 0 && draining.epoch == epoch && draining.healthy {
		if sequence > draining.lastSent {
			draining.lastSent = sequence
			m.draining[id] = draining
		}
		return
	}
	if m.direct.epoch != epoch || m.direct.id != id || !m.direct.healthy {
		return
	}
	wasCaughtUp := m.direct.lastAcknowledged >= m.direct.lastSent
	if sequence > m.direct.lastSent {
		m.direct.lastSent = sequence
	}
	if wasCaughtUp && m.direct.lastAcknowledged < m.direct.lastSent {
		m.armProgressTimerLocked(&m.direct)
	}
}

func (m *Mux) acknowledgeDirect(epoch, id, sequence uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || sequence == 0 {
		return false
	}
	if draining, ok := m.draining[id]; ok && id != 0 && draining.epoch == epoch && draining.healthy {
		if sequence > draining.lastSent {
			return false
		}
		if sequence > draining.lastAcknowledged {
			draining.lastAcknowledged = sequence
			m.directProgress.Add(1)
			m.draining[id] = draining
		}
		return true
	}
	if m.direct.epoch != epoch || m.direct.id != id || !m.direct.healthy || sequence > m.direct.lastSent {
		return false
	}
	if sequence <= m.direct.lastAcknowledged {
		return true
	}
	m.direct.lastAcknowledged = sequence
	m.directProgress.Add(1)
	if m.direct.lastAcknowledged >= m.direct.lastSent {
		m.stopProgressTimerLocked(&m.direct)
	} else {
		m.armProgressTimerLocked(&m.direct)
	}
	return true
}

func (m *Mux) armProgressTimerLocked(slot *pathSlot) {
	if slot == nil || slot.connection == nil || !slot.healthy || m.progressTimeout <= 0 {
		return
	}
	if slot.progressTimer != nil {
		slot.progressTimer.Stop()
	}
	slot.progressGeneration++
	epoch, id, generation := slot.epoch, slot.id, slot.progressGeneration
	slot.progressTimer = time.AfterFunc(m.progressTimeout, func() {
		m.directProgressExpired(epoch, id, generation)
	})
}

func (m *Mux) stopProgressTimerLocked(slot *pathSlot) {
	if slot == nil {
		return
	}
	if slot.progressTimer != nil {
		slot.progressTimer.Stop()
		slot.progressTimer = nil
	}
	slot.progressGeneration++
}

func (m *Mux) directProgressExpired(epoch, id, generation uint64) {
	m.mu.Lock()
	current := !m.closed && m.direct.epoch == epoch && m.direct.id == id && m.direct.healthy &&
		m.direct.progressGeneration == generation && m.direct.lastAcknowledged < m.direct.lastSent
	if !current {
		m.mu.Unlock()
		return
	}
	if m.rollbackEpoch == epoch {
		m.stopProgressTimerLocked(&m.direct)
		m.discardActivationLocked(&m.direct)
		m.direct.healthy = false
		m.noteSelectedPathAuthorityLocked()
		m.mu.Unlock()
		m.AbortDirect(epoch)
		m.watchdogFailure.Add(1)
		return
	}
	failed := m.direct
	m.stopProgressTimerLocked(&m.direct)
	m.discardActivationLocked(&m.direct)
	m.direct.healthy = false
	if m.selected == SelectedDirect {
		if !m.requireDirect && m.relay.healthy {
			m.setSelectedLocked(SelectedRelay)
			m.fallbacks.Add(1)
		} else {
			m.setSelectedLocked(SelectedNone)
		}
	}
	m.mu.Unlock()
	m.watchdogFailure.Add(1)
	m.notify()
	failed.sender.Close("direct delivery progress timed out")
}

func (m *Mux) SendPacket(packet []byte) error {
	return m.SendPacketContext(m.ctx, packet)
}

// SendPacketContext owns one packet sequence across the complete bounded
// recovery operation. Reusing that sequence on a replacement path lets the
// peer replay window suppress a send-timeout ambiguity without duplicating an
// inner packet.
func (m *Mux) SendPacketContext(ctx context.Context, packet []byte) error {
	if ctx == nil {
		return context.Canceled
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-m.ctx.Done():
		return m.closedPathError()
	case <-m.sendToken:
	}
	defer func() { m.sendToken <- struct{}{} }()
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if len(packet) == 0 || len(packet) > m.mtu {
		return ErrInvalidPacket
	}
	if m.sequenceExhausted {
		return ErrInvalidPacket
	}
	sequence := m.sequence.Add(1)
	if sequence == 0 {
		m.sequenceExhausted = true
		return ErrInvalidPacket
	}
	attempted := make(map[[2]uint64]struct{}, 3)
	var lastError error
	for len(attempted) < maxSendPathAttempts {
		selected, slot := m.selectedSlot()
		if slot.connection == nil || !slot.healthy {
			if err := m.WaitForHealthy(ctx); err != nil {
				if lastError != nil {
					return errors.Join(ErrNoHealthyPath, err, lastError)
				}
				return errors.Join(ErrNoHealthyPath, err)
			}
			continue
		}
		kind, epoch := byte(kindRelay), uint64(0)
		if selected == SelectedDirect {
			kind, epoch = kindDirect, slot.epoch
		}
		key := [2]uint64{uint64(kind), slot.id}
		if _, duplicate := attempted[key]; duplicate {
			return errors.Join(ErrNoHealthyPath, lastError)
		}
		attempted[key] = struct{}{}
		if selected == SelectedDirect {
			// Reserve the exact sequence before enqueue. A peer on a fast
			// path may acknowledge it before SendDatagram returns.
			m.noteDirectSent(slot.epoch, slot.id, sequence)
		}
		err := m.send(ctx, slot, encode(kind, epoch, sequence, packet))
		if err == nil {
			if selected == SelectedDirect {
				m.directSent.Add(1)
			} else {
				m.relaySent.Add(1)
			}
			return nil
		}
		lastError = err
		if selected == SelectedDirect {
			m.directFailed(slot.epoch, slot.id)
		} else {
			m.relayFailed(slot.id)
		}
	}
	return errors.Join(ErrNoHealthyPath, lastError)
}

func (m *Mux) selectedSlot() (Selected, pathSlot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.noPathFailed {
		return SelectedNone, pathSlot{}
	}
	if m.selected == SelectedDirect {
		if direct, healthy := m.committedDirectLocked(); healthy {
			return SelectedDirect, direct
		}
	}
	if !m.requireDirect && m.selected == SelectedRelay && m.relay.healthy {
		return SelectedRelay, m.relay
	}
	return SelectedNone, pathSlot{}
}

func (m *Mux) ReceivePacket(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		return nil, context.Canceled
	}
	if err := m.ctx.Err(); err != nil {
		return nil, m.closedPathError()
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.ctx.Done():
		return nil, m.closedPathError()
	case packet := <-m.inbound:
		if m.ctx.Err() != nil {
			return nil, m.closedPathError()
		}
		return packet.payload, nil
	}
}

func (m *Mux) closedPathError() error {
	m.mu.Lock()
	terminal := m.noPathFailed
	m.mu.Unlock()
	if terminal {
		return ErrNoHealthyPath
	}
	return ErrClosed
}

// WaitForHealthy blocks one already policy-checked caller until an exact
// authenticated path is selected. Only the strict selected-but-uncommitted
// activation buffer may retain packet payload while this wait is unresolved.
func (m *Mux) WaitForHealthy(ctx context.Context) error {
	if m == nil || ctx == nil {
		return context.Canceled
	}
	for {
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return ErrClosed
		}
		if m.noPathFailed {
			m.mu.Unlock()
			return ErrNoHealthyPath
		}
		if m.selectedHealthyLocked() {
			m.mu.Unlock()
			return nil
		}
		changed := m.pathChanged
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.ctx.Done():
			return m.closedPathError()
		case <-changed:
		}
	}
}

func (m *Mux) Changes() <-chan Snapshot { return m.changes }

func (m *Mux) Errors() <-chan error { return m.failures }

func (m *Mux) Snapshot() Snapshot {
	m.mu.Lock()
	selected := m.selected
	direct, directHealthy := m.committedDirectLocked()
	if selected == SelectedDirect && !directHealthy {
		selected = SelectedNone
	}
	snapshot := Snapshot{
		Selected: selected, DirectRequired: m.requireDirect, RelayHealthy: m.relay.healthy,
		DirectHealthy: directHealthy, DirectEpoch: direct.epoch,
		RelayInstanceID: m.relay.id, DirectInstanceID: direct.id,
		SelectedPathTransitions: m.pathTransitions.Load(),
	}
	m.mu.Unlock()
	snapshot.Counters = Counters{
		RelaySent: m.relaySent.Load(), DirectSent: m.directSent.Load(),
		RelayReceived: m.relayReceived.Load(), DirectReceived: m.directReceived.Load(),
		Fallbacks: m.fallbacks.Load(), InvalidPackets: m.invalidPackets.Load(),
		DuplicatePacket: m.duplicatePacket.Load(), QueueDrops: m.queueDrops.Load(),
		DirectProgress: m.directProgress.Load(), WatchdogFailure: m.watchdogFailure.Load(),
	}
	return snapshot
}

func (m *Mux) Close() {
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		if m.noPathTimer != nil {
			m.noPathTimer.Stop()
			m.noPathTimer = nil
			m.noPathGeneration++
		}
		m.setSelectedLocked(SelectedNone)
		m.relay.healthy = false
		m.stopProgressTimerLocked(&m.direct)
		m.stopProgressTimerLocked(&m.pending)
		m.discardActivationLocked(&m.direct)
		m.discardActivationLocked(&m.pending)
		m.direct.healthy = false
		m.rollbackEpoch = 0
		m.rollbackDirectID = 0
		m.rollbackSelected = SelectedNone
		slots := []pathSlot{m.relay, m.direct, m.pending}
		m.pending = pathSlot{}
		m.replay = make(map[replayKey]*sequenceWindow)
		for id, slot := range m.draining {
			m.stopProgressTimerLocked(&slot)
			if slot.timer != nil {
				slot.timer.Stop()
			}
			slots = append(slots, slot)
			delete(m.draining, id)
		}
		m.mu.Unlock()
		m.cancel()
		for _, slot := range slots {
			slot.sender.Close("data path shutdown")
		}
		m.receivers.Wait()
		m.notify()
	})
}

func (m *Mux) enqueueReceived(kind byte, payload []byte) (delivered, closed bool) {
	m.inboundMu.Lock()
	defer m.inboundMu.Unlock()
	return m.enqueueReceivedLocked(kind, payload)
}

// enqueueReceivedLocked requires inboundMu. Commit holds that lock from its
// all-or-nothing capacity reservation through the complete FIFO release.
func (m *Mux) enqueueReceivedLocked(kind byte, payload []byte) (delivered, closed bool) {
	select {
	case <-m.ctx.Done():
		return false, true
	case m.inbound <- receivedPacket{payload: payload}:
		if kind == kindRelay {
			m.relayReceived.Add(1)
		} else {
			m.directReceived.Add(1)
		}
		return true, false
	default:
		m.queueDrops.Add(1)
		return false, false
	}
}

func (m *Mux) noteReceivedDelivery(connection Connection, kind byte, sequence uint64) {
	if kind != kindDirect {
		return
	}
	if aware, ok := connection.(DeliveryAwareConnection); ok {
		aware.DatagramDelivered(sequence)
	}
}

func (m *Mux) receiveLoop(connection Connection, kind byte, epoch, id uint64) {
receiveNext:
	for {
		wire, err := connection.ReceiveDatagram(m.ctx)
		if err != nil {
			if m.ctx.Err() != nil {
				return
			}
			if kind == kindDirect {
				m.directReceiveFailed(epoch, id)
			} else {
				m.relayFailed(id)
			}
			return
		}
		packetKind, packetEpoch, sequence, payload, err := decode(wire, m.mtu)
		if err != nil || packetKind != kind || packetEpoch != epoch {
			m.invalidPackets.Add(1)
			continue
		}
		if m.requireDirect && kind == kindRelay {
			m.invalidPackets.Add(1)
			continue
		}

		// Reclassify the already decoded datagram after a commit-release barrier.
		// Replay acceptance happens below, so waiting never evaluates it twice.
		for {
			m.mu.Lock()
			_, draining := m.draining[id]
			directCurrent := m.direct.id == id && m.direct.epoch == epoch && m.direct.healthy
			if directCurrent && m.direct.activation != nil {
				release := m.direct.activation.release
				select {
				case <-release:
					// Release completed or was discarded; exact-slot authority is
					// re-evaluated below while Mux.mu is still held.
				default:
					m.mu.Unlock()
					select {
					case <-m.ctx.Done():
						return
					case <-release:
						continue
					}
				}
			}
			directPending := kind == kindDirect && m.requireDirect && m.rollbackEpoch == epoch &&
				m.pending.id == id && m.pending.epoch == epoch && m.pending.healthy && m.pending.activation != nil
			current := (kind == kindRelay && m.relay.id == id) ||
				(kind == kindDirect && (directCurrent || directPending || draining))
			if !current {
				m.mu.Unlock()
				m.invalidPackets.Add(1)
				continue receiveNext
			}

			key := replayKey{kind: kind, epoch: epoch}
			window := m.replay[key]
			if directPending {
				buffer := m.pending.activation
				if !time.Now().Before(buffer.expires) {
					failed, aborted := m.abortProvisionalLocked(epoch, id, buffer)
					m.mu.Unlock()
					if aborted {
						m.notify()
						failed.sender.Close("direct activation buffer expired")
					}
					continue receiveNext
				}
				candidate := buffer.replay
				if !candidate.Accept(sequence) {
					m.mu.Unlock()
					m.duplicatePacket.Add(1)
					continue receiveNext
				}
				if len(buffer.packets) >= maxActivationPackets ||
					buffer.bytes+len(payload) > maxActivationBytes {
					failed, aborted := m.abortProvisionalLocked(epoch, id, buffer)
					m.mu.Unlock()
					if aborted {
						m.notify()
						failed.sender.Close("direct activation buffer overflow")
					}
					continue receiveNext
				}
				buffer.replay = candidate
				buffer.packets = append(buffer.packets, activationPacket{
					payload: append([]byte(nil), payload...), sequence: sequence,
				})
				buffer.bytes += len(payload)
				m.mu.Unlock()
				continue receiveNext
			}

			if window == nil {
				window = &sequenceWindow{}
				m.replay[key] = window
			}
			if !window.Accept(sequence) {
				m.mu.Unlock()
				m.duplicatePacket.Add(1)
				continue receiveNext
			}
			m.mu.Unlock()
			copyOfPayload := append([]byte(nil), payload...)
			delivered, closed := m.enqueueReceived(kind, copyOfPayload)
			if delivered {
				m.noteReceivedDelivery(connection, kind, sequence)
			}
			if closed {
				return
			}
			continue receiveNext
		}
	}
}

func (m *Mux) directReceiveFailed(epoch, id uint64) {
	var failed pathSlot
	var changed bool
	m.mu.Lock()
	if m.requireDirect && m.rollbackEpoch == epoch && m.pending.id == id && m.pending.epoch == epoch {
		failed, aborted := m.abortProvisionalLocked(epoch, id, m.pending.activation)
		m.mu.Unlock()
		if aborted {
			m.notify()
			failed.sender.Close("provisional direct receive path failed")
		}
		return
	}
	if !m.requireDirect && m.rollbackEpoch == epoch && m.direct.id == id && m.direct.epoch == epoch {
		m.mu.Unlock()
		m.AbortDirect(epoch)
		return
	}
	switch {
	case m.closed:
		m.mu.Unlock()
		return
	case m.pending.id == id && m.pending.epoch == epoch:
		failed = m.pending
		m.stopProgressTimerLocked(&m.pending)
		m.discardActivationLocked(&m.pending)
		m.pending = pathSlot{}
		m.pruneDirectReplayLocked(epoch)
	case m.direct.id == id && m.direct.epoch == epoch && m.direct.healthy:
		failed = m.direct
		m.stopProgressTimerLocked(&m.direct)
		m.discardActivationLocked(&m.direct)
		m.direct.healthy = false
		if m.selected == SelectedDirect {
			if !m.requireDirect && m.relay.healthy {
				m.setSelectedLocked(SelectedRelay)
				m.fallbacks.Add(1)
			} else {
				m.setSelectedLocked(SelectedNone)
			}
			changed = true
		}
	case m.draining[id].epoch == epoch:
		failed = m.draining[id]
		delete(m.draining, id)
		if failed.timer != nil {
			failed.timer.Stop()
		}
		m.pruneDirectReplayLocked(epoch)
	default:
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()
	if changed {
		m.notify()
	}
	failed.sender.Close("direct receive path failed")
}

func (m *Mux) relayFailed(id uint64) {
	m.mu.Lock()
	if m.closed || m.relay.id != id || !m.relay.healthy {
		m.mu.Unlock()
		return
	}
	failed := m.relay
	m.relay.healthy = false
	if m.selected == SelectedRelay {
		if m.direct.healthy {
			m.setSelectedLocked(SelectedDirect)
		} else {
			m.setSelectedLocked(SelectedNone)
		}
	}
	m.mu.Unlock()
	select {
	case m.relayRecovery <- struct{}{}:
	default:
	}
	m.notify()
	failed.sender.Close("relay path failed")
}

func (m *Mux) send(ctx context.Context, slot pathSlot, packet []byte) error {
	return slot.sender.Send(ctx, packet)
}

func (m *Mux) fail(err error) {
	select {
	case m.failures <- err:
	default:
	}
}

// committedDirectLocked returns only a direct path that crossed the final
// activation barrier. In the direct-required profile, SelectDirect is
// provisional: a first activation must not cancel the no-path deadline or
// carry packets, and a replacement must keep the prior committed connection
// authoritative until CommitDirect succeeds.
func (m *Mux) committedDirectLocked() (pathSlot, bool) {
	direct := m.direct
	return direct, direct.connection != nil && direct.healthy
}

func (m *Mux) selectedHealthyLocked() bool {
	if m.selected == SelectedDirect {
		if _, healthy := m.committedDirectLocked(); healthy {
			return true
		}
	}
	return !m.requireDirect && m.selected == SelectedRelay && m.relay.healthy
}

// updateNoPathDeadline owns one non-extendable deadline for a contiguous
// no-path interval. Repeated notifications cannot postpone process restart.
func (m *Mux) updateNoPathDeadline() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.noPathFailed {
		return
	}
	if m.closed || m.selectedHealthyLocked() {
		if m.noPathTimer != nil {
			m.noPathTimer.Stop()
			m.noPathTimer = nil
			m.noPathGeneration++
		}
		return
	}
	if m.noPathTimer != nil {
		return
	}
	m.noPathGeneration++
	generation := m.noPathGeneration
	m.noPathTimer = time.AfterFunc(m.noPathTimeout, func() { m.noPathExpired(generation) })
}

func (m *Mux) noPathExpired(generation uint64) {
	var pending pathSlot
	m.mu.Lock()
	if m.closed || generation != m.noPathGeneration || m.noPathTimer == nil {
		m.mu.Unlock()
		return
	}
	if m.selectedHealthyLocked() {
		m.noPathTimer = nil
		m.noPathGeneration++
		m.mu.Unlock()
		return
	}
	m.noPathTimer = nil
	m.noPathFailed = true
	pending = m.pending
	m.discardActivationLocked(&m.pending)
	m.pending = pathSlot{}
	m.rollbackEpoch = 0
	m.rollbackDirectID = 0
	m.rollbackSelected = SelectedNone
	m.pruneDirectReplayLocked(pending.epoch)
	close(m.pathChanged)
	m.pathChanged = make(chan struct{})
	m.cancel()
	m.mu.Unlock()
	pending.sender.Close("terminal no-path failure")
	m.fail(ErrNoHealthyPath)
}

func (m *Mux) notify() {
	m.notifyMu.Lock()
	defer m.notifyMu.Unlock()
	m.updateNoPathDeadline()
	m.mu.Lock()
	close(m.pathChanged)
	m.pathChanged = make(chan struct{})
	m.mu.Unlock()
	snapshot := m.Snapshot()
	select {
	case <-m.changes:
	default:
	}
	select {
	case m.changes <- snapshot:
	default:
	}
}

func (m *Mux) expireDraining(id uint64) {
	m.mu.Lock()
	slot, ok := m.draining[id]
	if ok {
		delete(m.draining, id)
		m.pruneDirectReplayLocked(slot.epoch)
	}
	m.mu.Unlock()
	if ok {
		slot.sender.Close("direct receive drain expired")
	}
}

func (m *Mux) pruneDirectReplayLocked(epoch uint64) {
	if epoch == 0 || (m.direct.connection != nil && m.direct.epoch == epoch) ||
		(m.pending.connection != nil && m.pending.epoch == epoch) {
		return
	}
	for _, slot := range m.draining {
		if slot.connection != nil && slot.epoch == epoch {
			return
		}
	}
	delete(m.replay, replayKey{kind: kindDirect, epoch: epoch})
}

func encode(kind byte, epoch, sequence uint64, payload []byte) []byte {
	wire := make([]byte, headerSize+len(payload))
	copy(wire[:4], wireMagic)
	wire[4] = kind
	binary.BigEndian.PutUint64(wire[8:16], epoch)
	binary.BigEndian.PutUint64(wire[16:24], sequence)
	copy(wire[headerSize:], payload)
	return wire
}

func decode(wire []byte, mtu int) (byte, uint64, uint64, []byte, error) {
	if len(wire) <= headerSize || len(wire) > headerSize+mtu || string(wire[:4]) != wireMagic ||
		(wire[4] != kindRelay && wire[4] != kindDirect) || wire[5] != 0 || wire[6] != 0 || wire[7] != 0 {
		return 0, 0, 0, nil, ErrInvalidPacket
	}
	epoch := binary.BigEndian.Uint64(wire[8:16])
	sequence := binary.BigEndian.Uint64(wire[16:24])
	if sequence == 0 || (wire[4] == kindRelay && epoch != 0) || (wire[4] == kindDirect && epoch == 0) {
		return 0, 0, 0, nil, ErrInvalidPacket
	}
	return wire[4], epoch, sequence, wire[headerSize:], nil
}

type sequenceWindow struct {
	max  uint64
	bits [replayWindowSize / 64]uint64
}

func (w *sequenceWindow) Accept(sequence uint64) bool {
	if sequence == 0 {
		return false
	}
	if w.max == 0 {
		w.max = sequence
		w.bits[0] = 1
		return true
	}
	if sequence > w.max {
		delta := sequence - w.max
		w.shift(delta)
		w.max = sequence
		w.bits[0] |= 1
		return true
	}
	distance := w.max - sequence
	if distance >= replayWindowSize {
		return false
	}
	word, bit := distance/64, distance%64
	mask := uint64(1) << bit
	if w.bits[word]&mask != 0 {
		return false
	}
	w.bits[word] |= mask
	return true
}

func (w *sequenceWindow) shift(delta uint64) {
	if delta >= replayWindowSize {
		w.bits = [replayWindowSize / 64]uint64{}
		return
	}
	wordShift, bitShift := int(delta/64), uint(delta%64)
	for destination := len(w.bits) - 1; destination >= 0; destination-- {
		source := destination - wordShift
		var value uint64
		if source >= 0 {
			value = w.bits[source] << bitShift
			if bitShift != 0 && source > 0 {
				value |= w.bits[source-1] >> (64 - bitShift)
			}
		}
		w.bits[destination] = value
	}
}
