// Package binding implements the bounded UDP tuple-binding transaction.
//
// A binding token belongs to one authenticated control session. The HMACs in
// this package prove possession of that session token and correlate packets;
// they are not router identity. Router identity remains an asymmetric TLS
// property at the control and data-plane boundaries.
package binding

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	// The top two bits must remain zero. quic.Transport is the sole UDP
	// socket reader and routes this discriminator to ReadNonQUICPacket.
	protocolMagic = "\x03LBIND2\x00"

	// TokenSize is the size of a per-control-session binding token.
	TokenSize = 32
	// NonceSize is the size of request nonces and server challenges.
	NonceSize = 16
	macSize   = sha256.Size

	magicOffset        = 0
	typeOffset         = magicOffset + len(protocolMagic)
	siteOffset         = typeOffset + 1
	sequenceOffset     = siteOffset + 1
	requestNonceOffset = sequenceOffset + 8
	challengeOffset    = requestNonceOffset + NonceSize
	macOffset          = challengeOffset + NonceSize

	// PacketSize is the exact v2 binding packet size. Parsers reject both
	// truncated and oversized datagrams.
	PacketSize = macOffset + macSize
)

// MessageType identifies one flight of a binding transaction.
type MessageType byte

const (
	TypeRequest MessageType = iota + 1
	TypeChallenge
	TypeResponse
	TypeReady
)

// Nonce is a fixed-width transaction nonce.
type Nonce [NonceSize]byte

var zeroToken [TokenSize]byte

// Metadata identifies one binding transaction and one of its flights. The
// request has a zero Challenge. Every later flight repeats the request nonce
// and the server-generated challenge.
type Metadata struct {
	Type         MessageType
	Site         string
	Sequence     uint64
	RequestNonce Nonce
	Challenge    Nonce
}

// SameTransaction reports whether two flights have identical transaction
// scope. Their message types may differ.
func (m Metadata) SameTransaction(other Metadata) bool {
	return m.Site == other.Site &&
		m.Sequence == other.Sequence &&
		m.RequestNonce == other.RequestNonce &&
		m.Challenge == other.Challenge
}

// SameRequest reports whether two flights have the same site, sequence, and
// request nonce. It is used to correlate a challenge with the retained request
// before the request has learned the server challenge.
func (m Metadata) SameRequest(other Metadata) bool {
	return m.Site == other.Site &&
		m.Sequence == other.Sequence &&
		m.RequestNonce == other.RequestNonce
}

func SiteCode(site string) (byte, error) {
	switch site {
	case "site-a":
		return 1, nil
	case "site-b":
		return 2, nil
	default:
		return 0, errors.New("unknown site")
	}
}

func SiteName(code byte) (string, error) {
	switch code {
	case 1:
		return "site-a", nil
	case 2:
		return "site-b", nil
	default:
		return "", errors.New("unknown site code")
	}
}

// NewRequest starts a binding transaction for a monotonically increasing,
// non-zero sequence. The returned metadata must be retained and used to
// correlate the authenticated challenge and READY flights.
func NewRequest(site string, sequence uint64, token []byte) ([]byte, Metadata, error) {
	requestNonce, err := readNonce(rand.Reader)
	if err != nil {
		return nil, Metadata{}, fmt.Errorf("generate request nonce: %w", err)
	}
	return NewRequestWithNonce(site, sequence, requestNonce, token)
}

// NewRequestWithNonce is the deterministic form of NewRequest. Callers should
// normally use NewRequest; this form is useful when randomness is owned by a
// larger protocol state machine or by a deterministic test.
func NewRequestWithNonce(site string, sequence uint64, requestNonce Nonce, token []byte) ([]byte, Metadata, error) {
	meta := Metadata{
		Type:         TypeRequest,
		Site:         site,
		Sequence:     sequence,
		RequestNonce: requestNonce,
	}
	packet, err := marshal(meta, token)
	return packet, meta, err
}

// ParseRequest authenticates a request and returns all correlation metadata.
func ParseRequest(packet, token []byte) (Metadata, bool) {
	return parseType(packet, token, TypeRequest)
}

// NewChallenge creates an authenticated challenge for request.
func NewChallenge(request Metadata, token []byte) ([]byte, Metadata, error) {
	challenge, err := readNonce(rand.Reader)
	if err != nil {
		return nil, Metadata{}, fmt.Errorf("generate challenge: %w", err)
	}
	return NewChallengeWithNonce(request, challenge, token)
}

// NewChallengeWithNonce is the deterministic form of NewChallenge.
func NewChallengeWithNonce(request Metadata, challenge Nonce, token []byte) ([]byte, Metadata, error) {
	if request.Type != TypeRequest {
		return nil, Metadata{}, errors.New("challenge requires request metadata")
	}
	meta := request
	meta.Type = TypeChallenge
	meta.Challenge = challenge
	packet, err := marshal(meta, token)
	return packet, meta, err
}

// ParseChallenge authenticates a challenge and returns its correlation
// metadata. A client must compare it with the retained request metadata.
func ParseChallenge(packet, token []byte) (Metadata, bool) {
	return parseType(packet, token, TypeChallenge)
}

// NewResponse authenticates the response to challenge.
func NewResponse(challenge Metadata, token []byte) ([]byte, error) {
	if challenge.Type != TypeChallenge {
		return nil, errors.New("response requires challenge metadata")
	}
	meta := challenge
	meta.Type = TypeResponse
	return marshal(meta, token)
}

// ParseResponse authenticates a response and returns its correlation metadata.
func ParseResponse(packet, token []byte) (Metadata, bool) {
	return parseType(packet, token, TypeResponse)
}

// NewReady creates the authenticated completion flight for response.
func NewReady(response Metadata, token []byte) ([]byte, error) {
	if response.Type != TypeResponse {
		return nil, errors.New("READY requires response metadata")
	}
	meta := response
	meta.Type = TypeReady
	return marshal(meta, token)
}

// ParseReady authenticates READY and returns its correlation metadata. A
// client must not mark the tuple bound until it matches the active transaction.
func ParseReady(packet, token []byte) (Metadata, bool) {
	return parseType(packet, token, TypeReady)
}

// IsProtocol reports whether packet has the v2 binding protocol marker. It is
// intentionally independent of packet length and authentication so a socket
// demultiplexer can consume malformed binding packets instead of passing them
// to QUIC.
func IsProtocol(packet []byte) bool {
	return len(packet) >= len(protocolMagic) && string(packet[:len(protocolMagic)]) == protocolMagic
}

// ServerAction is the deterministic outcome of handling one client flight.
type ServerAction uint8

const (
	ActionRejectInvalid ServerAction = iota
	ActionRejectWrongSite
	ActionRejectStale
	ActionRejectConflict
	ActionRejectMismatch
	ActionRejectUnexpected
	ActionSendChallenge
	ActionSendReady
)

// ServerResult describes a server transition. Reply is set only for send
// actions. NewlyCompleted is true exactly once, when a matching response first
// completes the current transaction; duplicate requests and responses still
// receive READY but do not repeat the completion transition.
type ServerResult struct {
	Action         ServerAction
	Reply          []byte
	Metadata       Metadata
	NewlyCompleted bool
}

// ServerSnapshot is a secret-free view of the single retained transaction.
type ServerSnapshot struct {
	Active       bool
	Complete     bool
	Site         string
	Sequence     uint64
	RequestNonce Nonce
	Challenge    Nonce
}

// ServerState is scoped to one site and one authenticated control-session
// token. It retains exactly one transaction: accepting a higher sequence
// atomically replaces the prior transaction, so storage is constant and every
// older flight becomes stale.
type ServerState struct {
	mu sync.Mutex

	site   string
	token  [TokenSize]byte
	random io.Reader

	active   bool
	complete bool
	current  Metadata // canonical TypeChallenge metadata
}

// NewServerState returns empty state for one control session.
func NewServerState(site string, token []byte) (*ServerState, error) {
	return NewServerStateWithRandom(site, token, rand.Reader)
}

// NewServerStateWithRandom permits deterministic challenge generation. A nil
// reader is rejected rather than silently weakening challenge generation.
func NewServerStateWithRandom(site string, token []byte, random io.Reader) (*ServerState, error) {
	if _, err := SiteCode(site); err != nil {
		return nil, err
	}
	if !validToken(token) {
		return nil, fmt.Errorf("binding token must be %d non-zero bytes", TokenSize)
	}
	if random == nil {
		return nil, errors.New("nil challenge random source")
	}
	s := &ServerState{site: site, random: random}
	copy(s.token[:], token)
	return s, nil
}

// Handle authenticates and applies a request or response. Invalid, stale,
// conflicting, mismatched, and server-originated flights never mutate state.
// Duplicate flights replay the appropriate byte-identical authenticated reply.
func (s *ServerState) Handle(packet []byte) (ServerResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	meta, ok := parse(packet, s.token[:])
	if !ok {
		return ServerResult{Action: ActionRejectInvalid}, nil
	}
	if meta.Site != s.site {
		return ServerResult{Action: ActionRejectWrongSite, Metadata: meta}, nil
	}
	if meta.Type != TypeRequest && meta.Type != TypeResponse {
		return ServerResult{Action: ActionRejectUnexpected, Metadata: meta}, nil
	}

	if !s.active {
		if meta.Type != TypeRequest {
			return ServerResult{Action: ActionRejectUnexpected, Metadata: meta}, nil
		}
		return s.start(meta)
	}

	if meta.Sequence < s.current.Sequence {
		return ServerResult{Action: ActionRejectStale, Metadata: meta}, nil
	}
	if meta.Sequence > s.current.Sequence {
		if meta.Type != TypeRequest {
			return ServerResult{Action: ActionRejectUnexpected, Metadata: meta}, nil
		}
		return s.start(meta)
	}

	if meta.RequestNonce != s.current.RequestNonce {
		return ServerResult{Action: ActionRejectConflict, Metadata: meta}, nil
	}
	if meta.Type == TypeRequest {
		if s.complete {
			return s.ready(false)
		}
		return s.challenge()
	}
	if meta.Challenge != s.current.Challenge {
		return ServerResult{Action: ActionRejectMismatch, Metadata: meta}, nil
	}
	if s.complete {
		return s.ready(false)
	}
	return s.ready(true)
}

// Snapshot returns the one retained transaction without exposing the token.
func (s *ServerState) Snapshot() ServerSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	snapshot := ServerSnapshot{Active: s.active, Complete: s.complete, Site: s.site}
	if s.active {
		snapshot.Sequence = s.current.Sequence
		snapshot.RequestNonce = s.current.RequestNonce
		snapshot.Challenge = s.current.Challenge
	}
	return snapshot
}

func (s *ServerState) start(request Metadata) (ServerResult, error) {
	challenge, err := readNonce(s.random)
	if err != nil {
		return ServerResult{Action: ActionRejectInvalid}, fmt.Errorf("generate binding challenge: %w", err)
	}
	meta := request
	meta.Type = TypeChallenge
	meta.Challenge = challenge
	reply, err := marshal(meta, s.token[:])
	if err != nil {
		return ServerResult{Action: ActionRejectInvalid}, err
	}

	// Commit only after challenge generation and serialization succeed.
	s.active = true
	s.complete = false
	s.current = meta
	return ServerResult{Action: ActionSendChallenge, Reply: reply, Metadata: meta}, nil
}

func (s *ServerState) challenge() (ServerResult, error) {
	reply, err := marshal(s.current, s.token[:])
	if err != nil {
		return ServerResult{Action: ActionRejectInvalid}, err
	}
	return ServerResult{Action: ActionSendChallenge, Reply: reply, Metadata: s.current}, nil
}

func (s *ServerState) ready(newlyCompleted bool) (ServerResult, error) {
	meta := s.current
	meta.Type = TypeReady
	reply, err := marshal(meta, s.token[:])
	if err != nil {
		return ServerResult{Action: ActionRejectInvalid}, err
	}
	if newlyCompleted {
		s.complete = true
	}
	return ServerResult{
		Action:         ActionSendReady,
		Reply:          reply,
		Metadata:       meta,
		NewlyCompleted: newlyCompleted,
	}, nil
}

func parseType(packet, token []byte, want MessageType) (Metadata, bool) {
	meta, ok := parse(packet, token)
	return meta, ok && meta.Type == want
}

func parse(packet, token []byte) (Metadata, bool) {
	if !validToken(token) || len(packet) != PacketSize {
		return Metadata{}, false
	}
	if string(packet[magicOffset:typeOffset]) != protocolMagic {
		return Metadata{}, false
	}
	if !hmac.Equal(packet[macOffset:], sign(token, packet[:macOffset])) {
		return Metadata{}, false
	}

	site, err := SiteName(packet[siteOffset])
	if err != nil {
		return Metadata{}, false
	}
	meta := Metadata{
		Type:     MessageType(packet[typeOffset]),
		Site:     site,
		Sequence: binary.BigEndian.Uint64(packet[sequenceOffset:requestNonceOffset]),
	}
	copy(meta.RequestNonce[:], packet[requestNonceOffset:challengeOffset])
	copy(meta.Challenge[:], packet[challengeOffset:macOffset])
	if err := validate(meta); err != nil {
		return Metadata{}, false
	}
	return meta, true
}

func marshal(meta Metadata, token []byte) ([]byte, error) {
	if !validToken(token) {
		return nil, fmt.Errorf("binding token must be %d non-zero bytes", TokenSize)
	}
	if err := validate(meta); err != nil {
		return nil, err
	}
	code, err := SiteCode(meta.Site)
	if err != nil {
		return nil, err
	}

	packet := make([]byte, PacketSize)
	copy(packet[magicOffset:typeOffset], protocolMagic)
	packet[typeOffset] = byte(meta.Type)
	packet[siteOffset] = code
	binary.BigEndian.PutUint64(packet[sequenceOffset:requestNonceOffset], meta.Sequence)
	copy(packet[requestNonceOffset:challengeOffset], meta.RequestNonce[:])
	copy(packet[challengeOffset:macOffset], meta.Challenge[:])
	copy(packet[macOffset:], sign(token, packet[:macOffset]))
	return packet, nil
}

func validate(meta Metadata) error {
	if _, err := SiteCode(meta.Site); err != nil {
		return err
	}
	if meta.Sequence == 0 {
		return errors.New("binding sequence must be non-zero")
	}
	if meta.RequestNonce == (Nonce{}) {
		return errors.New("binding request nonce must be non-zero")
	}
	switch meta.Type {
	case TypeRequest:
		if meta.Challenge != (Nonce{}) {
			return errors.New("binding request has a challenge")
		}
	case TypeChallenge, TypeResponse, TypeReady:
		if meta.Challenge == (Nonce{}) {
			return errors.New("binding flight has an empty challenge")
		}
	default:
		return errors.New("unknown binding message type")
	}
	return nil
}

func readNonce(reader io.Reader) (Nonce, error) {
	var nonce Nonce
	if _, err := io.ReadFull(reader, nonce[:]); err != nil {
		return Nonce{}, err
	}
	if nonce == (Nonce{}) {
		return Nonce{}, errors.New("random source returned an all-zero nonce")
	}
	return nonce, nil
}

func validToken(token []byte) bool {
	return len(token) == TokenSize && !hmac.Equal(token, zeroToken[:])
}

func sign(token, body []byte) []byte {
	m := hmac.New(sha256.New, token)
	_, _ = m.Write(body)
	return m.Sum(nil)
}
