// Package nonquic provides the sole bounded consumer for quic.Transport's
// non-QUIC packet queue.
package nonquic

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/binding"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/rendezvous"
)

const (
	mailboxSize = 32
	readSize    = 2048
)

type Transport interface {
	WriteTo([]byte, net.Addr) (int, error)
	ReadNonQUICPacket(context.Context, []byte) (int, net.Addr, error)
}

type Packet struct {
	data    []byte
	address net.Addr
}

type Counters struct {
	BindingDrops    uint64
	RendezvousDrops uint64
	UnknownDrops    uint64
}

type Dispatcher struct {
	ctx        context.Context
	cancel     context.CancelFunc
	transport  Transport
	binding    chan Packet
	rendezvous chan Packet
	failures   chan error
	bindingUse chan struct{}
	punchUse   chan struct{}
	closeOnce  sync.Once
	done       chan struct{}
	ownerKey   any

	bindingDrops    atomic.Uint64
	rendezvousDrops atomic.Uint64
	unknownDrops    atomic.Uint64
}

type Lease struct {
	dispatcher *Dispatcher
	mailbox    <-chan Packet
	permit     chan struct{}
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	inflight   sync.WaitGroup
	released   bool
}

var transportOwners sync.Map

func New(ctx context.Context, transport Transport) (*Dispatcher, error) {
	if ctx == nil || transport == nil {
		return nil, errors.New("non-QUIC dispatcher requires a context and transport")
	}
	typeOfTransport := reflect.TypeOf(transport)
	if typeOfTransport == nil || !typeOfTransport.Comparable() {
		return nil, errors.New("non-QUIC transport identity is not comparable")
	}
	if _, loaded := transportOwners.LoadOrStore(transport, struct{}{}); loaded {
		return nil, errors.New("non-QUIC transport already has a dispatcher")
	}
	dispatcherCtx, cancel := context.WithCancel(ctx)
	d := &Dispatcher{
		ctx: dispatcherCtx, cancel: cancel, transport: transport,
		binding: make(chan Packet, mailboxSize), rendezvous: make(chan Packet, mailboxSize), failures: make(chan error, 1),
		bindingUse: make(chan struct{}, 1), punchUse: make(chan struct{}, 1), done: make(chan struct{}), ownerKey: transport,
	}
	d.bindingUse <- struct{}{}
	d.punchUse <- struct{}{}
	// quic.Transport initializes its one non-QUIC mailbox lazily inside this
	// call. Do it synchronously before any endpoint can transmit, while keeping
	// this dispatcher the only consumer for the lifetime of the socket.
	initializeCtx, cancelInitialize := context.WithCancel(context.Background())
	cancelInitialize()
	_, _, err := transport.ReadNonQUICPacket(initializeCtx, make([]byte, 1))
	if err != nil && !errors.Is(err, context.Canceled) {
		cancel()
		transportOwners.Delete(transport)
		return nil, err
	}
	go d.run()
	return d, nil
}

func (d *Dispatcher) AcquireBinding(ctx context.Context) (*Lease, error) {
	return d.acquire(ctx, d.binding, d.bindingUse)
}

func (d *Dispatcher) AcquireRendezvous(ctx context.Context) (*Lease, error) {
	return d.acquire(ctx, d.rendezvous, d.punchUse)
}

func (d *Dispatcher) acquire(ctx context.Context, mailbox <-chan Packet, permit chan struct{}) (*Lease, error) {
	if d == nil || ctx == nil {
		return nil, io.ErrClosedPipe
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, errors.New("non-QUIC mailbox lease requires a deadline")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := d.ctx.Err(); err != nil {
		return nil, context.Cause(d.ctx)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.ctx.Done():
		return nil, context.Cause(d.ctx)
	case <-permit:
		if err := ctx.Err(); err != nil {
			permit <- struct{}{}
			return nil, err
		}
		if err := d.ctx.Err(); err != nil {
			return nil, context.Cause(d.ctx)
		}
		leaseCtx, cancel := context.WithCancel(d.ctx)
		lease := &Lease{dispatcher: d, mailbox: mailbox, permit: permit, ctx: leaseCtx, cancel: cancel}
		go func() {
			select {
			case <-ctx.Done():
				lease.Release()
			case <-leaseCtx.Done():
			}
		}()
		return lease, nil
	}
}

func (d *Dispatcher) Errors() <-chan error { return d.failures }

func (d *Dispatcher) Counters() Counters {
	return Counters{
		BindingDrops: d.bindingDrops.Load(), RendezvousDrops: d.rendezvousDrops.Load(), UnknownDrops: d.unknownDrops.Load(),
	}
}

func (d *Dispatcher) Close() {
	if d == nil {
		return
	}
	d.closeOnce.Do(d.cancel)
	<-d.done
}

func (e *Lease) WriteTo(packet []byte, address net.Addr) (int, error) {
	if !e.begin() {
		return 0, io.ErrClosedPipe
	}
	defer e.inflight.Done()
	if err := e.dispatcher.ctx.Err(); err != nil {
		return 0, context.Cause(e.dispatcher.ctx)
	}
	cloned, ok := cloneUDPAddress(address)
	if !ok {
		return 0, errors.New("non-QUIC destination is not UDP")
	}
	return e.dispatcher.transport.WriteTo(packet, cloned)
}

func (e *Lease) ReadNonQUICPacket(ctx context.Context, buffer []byte) (int, net.Addr, error) {
	if ctx == nil || !e.begin() {
		return 0, nil, io.ErrClosedPipe
	}
	defer e.inflight.Done()
	if err := e.dispatcher.ctx.Err(); err != nil {
		return 0, nil, context.Cause(e.dispatcher.ctx)
	}
	select {
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	case <-e.dispatcher.ctx.Done():
		return 0, nil, context.Cause(e.dispatcher.ctx)
	case <-e.ctx.Done():
		return 0, nil, io.ErrClosedPipe
	case packet := <-e.mailbox:
		if e.ctx.Err() != nil || e.dispatcher.ctx.Err() != nil {
			return 0, nil, io.ErrClosedPipe
		}
		n := copy(buffer, packet.data)
		if n != len(packet.data) {
			return n, packet.address, io.ErrShortBuffer
		}
		return n, packet.address, nil
	}
}

func (e *Lease) begin() bool {
	if e == nil || e.dispatcher == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.released || e.ctx.Err() != nil || e.dispatcher.ctx.Err() != nil {
		return false
	}
	e.inflight.Add(1)
	return true
}

func (e *Lease) Release() {
	if e == nil || e.dispatcher == nil {
		return
	}
	e.mu.Lock()
	if e.released {
		e.mu.Unlock()
		return
	}
	e.released = true
	e.cancel()
	e.mu.Unlock()
	e.inflight.Wait()
	select {
	case <-e.dispatcher.ctx.Done():
	case e.permit <- struct{}{}:
	}
}

func (d *Dispatcher) run() {
	defer func() {
		d.cancel()
		transportOwners.Delete(d.ownerKey)
		close(d.done)
	}()
	buffer := make([]byte, readSize)
	for {
		n, address, err := d.transport.ReadNonQUICPacket(d.ctx, buffer)
		if err != nil {
			if d.ctx.Err() == nil {
				d.cancel()
				select {
				case d.failures <- err:
				default:
				}
			}
			return
		}
		udpAddress, ok := cloneUDPAddress(address)
		if !ok {
			d.unknownDrops.Add(1)
			continue
		}
		packet := Packet{data: append([]byte(nil), buffer[:n]...), address: udpAddress}
		switch {
		case n == binding.PacketSize && binding.IsProtocol(packet.data):
			select {
			case d.binding <- packet:
			default:
				d.bindingDrops.Add(1)
			}
		case rendezvous.IsProtocol(packet.data):
			select {
			case d.rendezvous <- packet:
			default:
				d.rendezvousDrops.Add(1)
			}
		default:
			d.unknownDrops.Add(1)
		}
	}
}

func cloneUDPAddress(address net.Addr) (*net.UDPAddr, bool) {
	if udpAddress, ok := address.(*net.UDPAddr); ok && udpAddress != nil {
		if udpAddress.IP == nil || udpAddress.Port <= 0 || udpAddress.Port > 65535 {
			return nil, false
		}
		return &net.UDPAddr{IP: append(net.IP(nil), udpAddress.IP...), Port: udpAddress.Port, Zone: udpAddress.Zone}, true
	}
	return nil, false
}
