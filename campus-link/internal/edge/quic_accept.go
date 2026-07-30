package edge

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	quic "github.com/quic-go/quic-go"
)

var (
	errQUICAcceptUnavailable = errors.New("QUIC accept classifier unavailable")
	errQUICAcceptConflict    = errors.New("QUIC accept class already has an active request")
)

type quicConnectionListener interface {
	Accept(context.Context) (*quic.Conn, error)
}

type quicAcceptRequest struct {
	ctx        context.Context
	candidates []netip.AddrPort
	result     chan *quic.Conn
}

// quicAcceptDispatcher is the sole owner of Listener.Accept on site B. It
// classifies an authenticated QUIC connection by its observed UDP tuple before
// handing it to either the baseline-relay or current direct-plan consumer.
type quicAcceptDispatcher struct {
	ctx      context.Context
	cancel   context.CancelFunc
	listener quicConnectionListener
	relay    netip.AddrPort
	done     chan struct{}
	close    sync.Once

	mu            sync.Mutex
	stopped       bool
	runErr        error
	relayRequest  *quicAcceptRequest
	directRequest *quicAcceptRequest
}

func newQUICAcceptDispatcher(parent context.Context, listener quicConnectionListener, relay netip.AddrPort) (*quicAcceptDispatcher, error) {
	if parent == nil || listener == nil || !relay.IsValid() {
		return nil, errQUICAcceptUnavailable
	}
	ctx, cancel := context.WithCancel(parent)
	d := &quicAcceptDispatcher{
		ctx: ctx, cancel: cancel, listener: listener, relay: relay, done: make(chan struct{}),
	}
	go d.run()
	return d, nil
}

func (d *quicAcceptDispatcher) run() {
	for {
		connection, err := d.listener.Accept(d.ctx)
		if err != nil {
			d.finish(err)
			return
		}
		request := d.classify(connection)
		if request == nil {
			_ = connection.CloseWithError(directCloseCode, "unexpected QUIC source")
			continue
		}
		select {
		case request.result <- connection:
		case <-request.ctx.Done():
			_ = connection.CloseWithError(directCloseCode, "QUIC accept request ended")
		case <-d.ctx.Done():
			_ = connection.CloseWithError(directCloseCode, "QUIC accept classifier ended")
		}
	}
}

func (d *quicAcceptDispatcher) classify(connection *quic.Conn) *quicAcceptRequest {
	if d == nil || connection == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopped {
		return nil
	}
	address := connection.RemoteAddr()
	if sameDirectAddress(address, d.relay) {
		request := d.relayRequest
		d.relayRequest = nil
		return request
	}
	if d.directRequest != nil && sameDirectAddressAny(address, d.directRequest.candidates) {
		request := d.directRequest
		d.directRequest = nil
		return request
	}
	return nil
}

func (d *quicAcceptDispatcher) AcceptRelay(ctx context.Context) (*quic.Conn, error) {
	return d.accept(ctx, true, nil)
}

func (d *quicAcceptDispatcher) AcceptDirect(ctx context.Context, candidates []netip.AddrPort) (*quic.Conn, error) {
	if d == nil || len(candidates) == 0 {
		return nil, errQUICAcceptUnavailable
	}
	copyOfCandidates := append([]netip.AddrPort(nil), candidates...)
	for _, candidate := range copyOfCandidates {
		if !candidate.IsValid() || candidate == d.relay {
			return nil, errQUICAcceptUnavailable
		}
	}
	return d.accept(ctx, false, copyOfCandidates)
}

func (d *quicAcceptDispatcher) accept(ctx context.Context, relay bool, candidates []netip.AddrPort) (*quic.Conn, error) {
	if d == nil || ctx == nil {
		return nil, errQUICAcceptUnavailable
	}
	request := &quicAcceptRequest{ctx: ctx, candidates: candidates, result: make(chan *quic.Conn)}
	d.mu.Lock()
	if d.stopped {
		err := d.runErr
		d.mu.Unlock()
		if err == nil {
			err = errQUICAcceptUnavailable
		}
		return nil, err
	}
	if relay {
		if d.relayRequest != nil {
			d.mu.Unlock()
			return nil, errQUICAcceptConflict
		}
		d.relayRequest = request
	} else {
		if d.directRequest != nil {
			d.mu.Unlock()
			return nil, errQUICAcceptConflict
		}
		d.directRequest = request
	}
	d.mu.Unlock()
	defer d.unregister(request, relay)

	select {
	case connection := <-request.result:
		return connection, nil
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-d.done:
		d.mu.Lock()
		err := d.runErr
		d.mu.Unlock()
		if err == nil {
			err = errQUICAcceptUnavailable
		}
		return nil, err
	}
}

func (d *quicAcceptDispatcher) unregister(request *quicAcceptRequest, relay bool) {
	d.mu.Lock()
	if relay && d.relayRequest == request {
		d.relayRequest = nil
	}
	if !relay && d.directRequest == request {
		d.directRequest = nil
	}
	d.mu.Unlock()
}

func (d *quicAcceptDispatcher) finish(err error) {
	d.mu.Lock()
	if d.stopped {
		d.mu.Unlock()
		return
	}
	d.stopped = true
	if d.ctx.Err() != nil {
		err = context.Cause(d.ctx)
	}
	d.runErr = err
	d.mu.Unlock()
	close(d.done)
}

func (d *quicAcceptDispatcher) Close() {
	if d == nil {
		return
	}
	d.close.Do(func() {
		d.cancel()
		<-d.done
	})
}
