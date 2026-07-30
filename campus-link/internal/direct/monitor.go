package direct

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/rendezvous"
)

const (
	DeliveryProgressInterval = 50 * time.Millisecond
	DeliveryPingInterval     = 3 * time.Second
	DeliveryIdleTimeout      = 12 * time.Second
	DeliveryWriteTimeout     = 2 * time.Second
)

type MonitorOptions struct {
	ProgressInterval time.Duration
	PingInterval     time.Duration
	IdleTimeout      time.Duration
	WriteTimeout     time.Duration
}

// DeliveryMonitor retains the exporter-bound activation stream as a bounded,
// authenticated path-progress channel. It never retransmits tunnel packets.
type DeliveryMonitor struct {
	stream  Stream
	result  Result
	site    string
	options MonitorOptions

	highestDelivered atomic.Uint64
	deliverySignal   chan struct{}
	pongRequests     chan uint32
	pongReceived     chan uint32

	mu          sync.Mutex
	acknowledge func(uint64) bool
	fail        func() bool
	started     bool
	cancel      context.CancelFunc
	done        chan struct{}
	failOnce    sync.Once
}

func NewDeliveryMonitor(stream Stream, result Result, site string, options MonitorOptions) (*DeliveryMonitor, error) {
	if stream == nil || result.Validated.IsZero() || result.PathEpoch == 0 || result.bound.plan.PathEpoch != result.PathEpoch ||
		result.context == ([sha256.Size]byte{}) || (site != "site-a" && site != "site-b") {
		return nil, ErrAuthentication
	}
	if options.ProgressInterval == 0 {
		options.ProgressInterval = DeliveryProgressInterval
	}
	if options.PingInterval == 0 {
		options.PingInterval = DeliveryPingInterval
	}
	if options.IdleTimeout == 0 {
		options.IdleTimeout = DeliveryIdleTimeout
	}
	if options.WriteTimeout == 0 {
		options.WriteTimeout = DeliveryWriteTimeout
		if options.WriteTimeout >= options.IdleTimeout {
			options.WriteTimeout = options.IdleTimeout / 2
		}
	}
	if options.ProgressInterval <= 0 || options.PingInterval <= 0 || options.IdleTimeout <= options.PingInterval ||
		options.WriteTimeout <= 0 || options.WriteTimeout >= options.IdleTimeout {
		return nil, ErrAuthentication
	}
	return &DeliveryMonitor{
		stream: stream, result: result, site: site, options: options,
		deliverySignal: make(chan struct{}, 1), pongRequests: make(chan uint32, 8),
		pongReceived: make(chan uint32, 8), done: make(chan struct{}),
	}, nil
}

// Bind installs exact-instance callbacks once. The mux supplies callbacks
// only after assigning the connection its non-reusable local instance ID.
func (m *DeliveryMonitor) Bind(acknowledge func(uint64) bool, fail func() bool) error {
	if m == nil || acknowledge == nil || fail == nil {
		return ErrAuthentication
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started || m.acknowledge != nil || m.fail != nil {
		return ErrAuthentication
	}
	m.acknowledge = acknowledge
	m.fail = fail
	return nil
}

// DatagramDelivered coalesces the highest packet sequence accepted into the
// local receive queue. It is nonblocking on the packet forwarding path.
func (m *DeliveryMonitor) DatagramDelivered(sequence uint64) {
	if m == nil || sequence == 0 {
		return
	}
	for current := m.highestDelivered.Load(); sequence > current; current = m.highestDelivered.Load() {
		if m.highestDelivered.CompareAndSwap(current, sequence) {
			break
		}
	}
	select {
	case m.deliverySignal <- struct{}{}:
	default:
	}
}

func (m *DeliveryMonitor) Start(parent context.Context) error {
	if m == nil || parent == nil {
		return ErrAuthentication
	}
	m.mu.Lock()
	if m.started || m.acknowledge == nil || m.fail == nil {
		m.mu.Unlock()
		return ErrAuthentication
	}
	ctx, cancel := context.WithCancel(parent)
	m.started = true
	m.cancel = cancel
	m.mu.Unlock()
	go m.run(ctx)
	return nil
}

func (m *DeliveryMonitor) Stop() {
	if m == nil {
		return
	}
	m.mu.Lock()
	started, cancel := m.started, m.cancel
	m.mu.Unlock()
	if !started {
		return
	}
	cancel()
	_ = m.stream.SetDeadline(time.Now())
	<-m.done
}

func (m *DeliveryMonitor) Done() <-chan struct{} {
	if m == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return m.done
}

func (m *DeliveryMonitor) run(ctx context.Context) {
	defer close(m.done)
	errCh := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		errCh <- m.readLoop(ctx)
	}()
	go func() {
		defer workers.Done()
		errCh <- m.writeLoop(ctx)
	}()
	var err error
	select {
	case <-ctx.Done():
	case err = <-errCh:
	}
	if err != nil && ctx.Err() == nil {
		m.failOnce.Do(func() {
			m.mu.Lock()
			fail := m.fail
			m.mu.Unlock()
			if fail != nil {
				fail()
			}
		})
	}
	m.mu.Lock()
	cancel := m.cancel
	m.mu.Unlock()
	cancel()
	_ = m.stream.SetDeadline(time.Now())
	workers.Wait()
}

func (m *DeliveryMonitor) readLoop(ctx context.Context) error {
	for {
		value, err := readFrame(m.stream, m.result.bound.plan.ProbeKey[:])
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if !m.matchesPeer(value) {
			return ErrAuthentication
		}
		if value.progress != 0 && !m.applyAcknowledgement(value.progress) {
			return ErrAuthentication
		}
		switch value.typeCode {
		case typeDeliveryProgress:
		case typeHealthPing:
			select {
			case m.pongRequests <- value.sequence:
			case <-ctx.Done():
				return nil
			default:
				return errors.New("direct health request queue overflow")
			}
		case typeHealthPong:
			select {
			case m.pongReceived <- value.sequence:
			case <-ctx.Done():
				return nil
			default:
				return errors.New("direct health response queue overflow")
			}
		default:
			return ErrAuthentication
		}
	}
}

func (m *DeliveryMonitor) writeLoop(ctx context.Context) error {
	pingTicker := time.NewTicker(m.options.PingInterval)
	defer pingTicker.Stop()
	var progressTimer, pongTimer *time.Timer
	var progressReady, pongExpired <-chan time.Time
	stopTimer := func(timer **time.Timer, channel *<-chan time.Time) {
		if *timer != nil {
			(*timer).Stop()
		}
		*timer = nil
		*channel = nil
	}
	defer stopTimer(&progressTimer, &progressReady)
	defer stopTimer(&pongTimer, &pongExpired)
	var sentProgress uint64
	var pingSequence, awaitingPong uint32
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-m.deliverySignal:
			if progressTimer == nil {
				progressTimer = time.NewTimer(m.options.ProgressInterval)
				progressReady = progressTimer.C
			}
		case <-progressReady:
			progressTimer, progressReady = nil, nil
			latest := m.highestDelivered.Load()
			if latest > sentProgress {
				if err := m.writeControlFrame(typeDeliveryProgress, 0, latest); err != nil {
					return err
				}
				sentProgress = latest
			}
			if m.highestDelivered.Load() > sentProgress {
				progressTimer = time.NewTimer(m.options.ProgressInterval)
				progressReady = progressTimer.C
			}
		case request := <-m.pongRequests:
			if request == 0 {
				return ErrAuthentication
			}
			if err := m.writeControlFrame(typeHealthPong, request, m.highestDelivered.Load()); err != nil {
				return err
			}
		case response := <-m.pongReceived:
			if awaitingPong == 0 || response != awaitingPong {
				return ErrAuthentication
			}
			awaitingPong = 0
			stopTimer(&pongTimer, &pongExpired)
		case <-pingTicker.C:
			if awaitingPong != 0 {
				continue
			}
			pingSequence++
			if pingSequence == 0 {
				return ErrAuthentication
			}
			if err := m.writeControlFrame(typeHealthPing, pingSequence, m.highestDelivered.Load()); err != nil {
				return err
			}
			awaitingPong = pingSequence
			pongTimer = time.NewTimer(m.options.IdleTimeout)
			pongExpired = pongTimer.C
		case <-pongExpired:
			return errors.New("direct authenticated health response timed out")
		}
	}
}

func (m *DeliveryMonitor) writeControlFrame(kind byte, sequence uint32, progress uint64) error {
	localSite, localRole := byte(1), rendezvous.RoleSender
	if m.site == "site-b" {
		localSite, localRole = 2, rendezvous.RoleReceiver
	}
	if err := m.stream.SetWriteDeadline(time.Now().Add(m.options.WriteTimeout)); err != nil {
		return err
	}
	err := writeFrame(m.stream, frame{
		typeCode: kind, siteCode: localSite, roleCode: byte(localRole), epoch: m.result.PathEpoch,
		sequence: sequence, progress: progress, nonce: m.result.localNonce, peerNonce: m.result.peerNonce,
		context: m.result.context,
	}, m.result.bound.plan.ProbeKey[:])
	if clearErr := m.stream.SetWriteDeadline(time.Time{}); err == nil {
		err = clearErr
	}
	return err
}

func (m *DeliveryMonitor) matchesPeer(value frame) bool {
	peerSite, peerRole := byte(2), rendezvous.RoleReceiver
	if m.site == "site-b" {
		peerSite, peerRole = 1, rendezvous.RoleSender
	}
	return value.siteCode == peerSite && value.roleCode == byte(peerRole) && value.epoch == m.result.PathEpoch &&
		subtle.ConstantTimeCompare(value.nonce[:], m.result.peerNonce[:]) == 1 &&
		subtle.ConstantTimeCompare(value.peerNonce[:], m.result.localNonce[:]) == 1 &&
		subtle.ConstantTimeCompare(value.context[:], m.result.context[:]) == 1
}

func (m *DeliveryMonitor) applyAcknowledgement(sequence uint64) bool {
	m.mu.Lock()
	acknowledge := m.acknowledge
	m.mu.Unlock()
	return acknowledge != nil && acknowledge(sequence)
}
