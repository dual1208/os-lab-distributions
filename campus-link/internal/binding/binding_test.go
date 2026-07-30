package binding

import (
	"bytes"
	"errors"
	"testing"
)

func TestAuthenticatedV2RoundTrip(t *testing.T) {
	token := testToken(0x40)
	requestNonce := testNonce(0x10)
	challengeNonce := testNonce(0x20)

	requestPacket, request, err := NewRequestWithNonce("site-a", 7, requestNonce, token)
	if err != nil {
		t.Fatal(err)
	}
	if len(requestPacket) != PacketSize {
		t.Fatalf("request size=%d want=%d", len(requestPacket), PacketSize)
	}
	if requestPacket[0]&0xc0 != 0 {
		t.Fatalf("binding discriminator collides with QUIC: %#x", requestPacket[0])
	}
	parsedRequest, ok := ParseRequest(requestPacket, token)
	if !ok || parsedRequest != request {
		t.Fatalf("request metadata=%#v ok=%v want=%#v", parsedRequest, ok, request)
	}

	challengePacket, challenge, err := NewChallengeWithNonce(request, challengeNonce, token)
	if err != nil {
		t.Fatal(err)
	}
	parsedChallenge, ok := ParseChallenge(challengePacket, token)
	if !ok || parsedChallenge != challenge || !parsedChallenge.SameRequest(request) {
		t.Fatalf("challenge metadata=%#v ok=%v want=%#v", parsedChallenge, ok, challenge)
	}

	responsePacket, err := NewResponse(parsedChallenge, token)
	if err != nil {
		t.Fatal(err)
	}
	response, ok := ParseResponse(responsePacket, token)
	if !ok || response.Type != TypeResponse || !response.SameTransaction(challenge) {
		t.Fatalf("response metadata=%#v ok=%v", response, ok)
	}

	readyPacket, err := NewReady(response, token)
	if err != nil {
		t.Fatal(err)
	}
	ready, ok := ParseReady(readyPacket, token)
	if !ok || ready.Type != TypeReady || !ready.SameTransaction(response) {
		t.Fatalf("READY metadata=%#v ok=%v", ready, ok)
	}

	for name, packet := range map[string][]byte{
		"request": requestPacket, "challenge": challengePacket,
		"response": responsePacket, "ready": readyPacket,
	} {
		if !IsProtocol(packet) {
			t.Fatalf("%s packet not recognized by demultiplexer", name)
		}
		t.Run(name+"-wrong-token", func(t *testing.T) {
			if _, ok := parse(packet, testToken(0x80)); ok {
				t.Fatal("packet authenticated with a different control-session token")
			}
		})
	}
	if !IsProtocol(requestPacket[:len(protocolMagic)]) {
		t.Fatal("truncated v2 binding packet was not reserved for binding demultiplexing")
	}
	if IsProtocol([]byte("CLBIND1\x00")) || IsProtocol([]byte("CLBIND2")) {
		t.Fatal("non-v2 protocol marker accepted")
	}
}

func TestServerStateDuplicateLossAndReorderTable(t *testing.T) {
	token := testToken(0x41)
	challengeNonce := testNonce(0x51)
	server, err := NewServerStateWithRandom("site-a", token, bytes.NewReader(challengeNonce[:]))
	if err != nil {
		t.Fatal(err)
	}
	requestPacket, request, err := NewRequestWithNonce("site-a", 11, testNonce(0x11), token)
	if err != nil {
		t.Fatal(err)
	}

	first := handleOK(t, server, requestPacket)
	if first.Action != ActionSendChallenge || first.NewlyCompleted {
		t.Fatalf("first request result=%#v", first)
	}
	challenge, ok := ParseChallenge(first.Reply, token)
	if !ok || challenge.RequestNonce != request.RequestNonce || challenge.Challenge != challengeNonce {
		t.Fatalf("bad challenge: %#v ok=%v", challenge, ok)
	}

	// A lost challenge is recovered by retransmitting the byte-identical request.
	duplicateRequest := handleOK(t, server, requestPacket)
	if duplicateRequest.Action != ActionSendChallenge || !bytes.Equal(duplicateRequest.Reply, first.Reply) {
		t.Fatalf("duplicate request did not replay challenge: %#v", duplicateRequest)
	}

	// Reordered server flights and a response for an unknown future request do
	// not advance or destroy the active transaction.
	if got := handleOK(t, server, first.Reply); got.Action != ActionRejectUnexpected {
		t.Fatalf("reflected challenge action=%v", got.Action)
	}
	future := challenge
	future.Type = TypeResponse
	future.Sequence++
	futurePacket, err := marshal(future, token)
	if err != nil {
		t.Fatal(err)
	}
	if got := handleOK(t, server, futurePacket); got.Action != ActionRejectUnexpected {
		t.Fatalf("future response action=%v", got.Action)
	}

	responsePacket, err := NewResponse(challenge, token)
	if err != nil {
		t.Fatal(err)
	}
	complete := handleOK(t, server, responsePacket)
	if complete.Action != ActionSendReady || !complete.NewlyCompleted {
		t.Fatalf("completion result=%#v", complete)
	}
	ready, ok := ParseReady(complete.Reply, token)
	if !ok || !ready.SameTransaction(challenge) {
		t.Fatalf("bad READY: %#v ok=%v", ready, ok)
	}

	steps := []struct {
		name   string
		packet []byte
	}{
		// A lost READY is recovered by retransmitting the response.
		{name: "duplicate response after lost READY", packet: responsePacket},
		// A severely reordered request after completion also gets READY rather
		// than restarting the challenge.
		{name: "duplicate request after completion", packet: requestPacket},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			got := handleOK(t, server, step.packet)
			if got.Action != ActionSendReady || got.NewlyCompleted || !bytes.Equal(got.Reply, complete.Reply) {
				t.Fatalf("result=%#v", got)
			}
		})
	}

	if snapshot := server.Snapshot(); !snapshot.Active || !snapshot.Complete ||
		snapshot.Sequence != request.Sequence || snapshot.RequestNonce != request.RequestNonce ||
		snapshot.Challenge != challengeNonce {
		t.Fatalf("snapshot=%#v", snapshot)
	}
}

func TestServerStateStaleConflictAndMonotonicReplacement(t *testing.T) {
	token := testToken(0x42)
	firstChallenge := testNonce(0x61)
	secondChallenge := testNonce(0x71)
	challenges := append(append([]byte(nil), firstChallenge[:]...), secondChallenge[:]...)
	server, err := NewServerStateWithRandom("site-a", token, bytes.NewReader(challenges))
	if err != nil {
		t.Fatal(err)
	}
	request9Packet, _, err := NewRequestWithNonce("site-a", 9, testNonce(0x19), token)
	if err != nil {
		t.Fatal(err)
	}
	challenge9 := handleOK(t, server, request9Packet)
	if challenge9.Action != ActionSendChallenge {
		t.Fatalf("sequence 9 action=%v", challenge9.Action)
	}

	conflictPacket, _, err := NewRequestWithNonce("site-a", 9, testNonce(0x29), token)
	if err != nil {
		t.Fatal(err)
	}
	if got := handleOK(t, server, conflictPacket); got.Action != ActionRejectConflict {
		t.Fatalf("same-sequence nonce conflict action=%v", got.Action)
	}

	mismatch := challenge9.Metadata
	mismatch.Type = TypeResponse
	mismatch.Challenge = testNonce(0x31)
	mismatchPacket, err := marshal(mismatch, token)
	if err != nil {
		t.Fatal(err)
	}
	if got := handleOK(t, server, mismatchPacket); got.Action != ActionRejectMismatch {
		t.Fatalf("challenge mismatch action=%v", got.Action)
	}

	request10Packet, request10, err := NewRequestWithNonce("site-a", 10, testNonce(0x1a), token)
	if err != nil {
		t.Fatal(err)
	}
	challenge10 := handleOK(t, server, request10Packet)
	if challenge10.Action != ActionSendChallenge || challenge10.Metadata.Sequence != 10 {
		t.Fatalf("replacement result=%#v", challenge10)
	}

	staleResponse, err := NewResponse(challenge9.Metadata, token)
	if err != nil {
		t.Fatal(err)
	}
	for name, packet := range map[string][]byte{
		"request":  request9Packet,
		"response": staleResponse,
	} {
		t.Run("stale-"+name, func(t *testing.T) {
			if got := handleOK(t, server, packet); got.Action != ActionRejectStale {
				t.Fatalf("action=%v", got.Action)
			}
		})
	}

	if snapshot := server.Snapshot(); snapshot.Sequence != request10.Sequence || snapshot.RequestNonce != request10.RequestNonce || snapshot.Complete {
		t.Fatalf("replacement snapshot=%#v", snapshot)
	}
}

func TestServerStateWrongSiteAndTokenDoNotMutate(t *testing.T) {
	token := testToken(0x43)
	challengeNonce := testNonce(0x63)
	server, err := NewServerStateWithRandom("site-a", token, bytes.NewReader(challengeNonce[:]))
	if err != nil {
		t.Fatal(err)
	}
	wrongSite, _, err := NewRequestWithNonce("site-b", 4, testNonce(0x14), token)
	if err != nil {
		t.Fatal(err)
	}
	wrongToken, _, err := NewRequestWithNonce("site-a", 4, testNonce(0x14), testToken(0x83))
	if err != nil {
		t.Fatal(err)
	}

	if got := handleOK(t, server, wrongSite); got.Action != ActionRejectWrongSite {
		t.Fatalf("wrong-site action=%v", got.Action)
	}
	if got := handleOK(t, server, wrongToken); got.Action != ActionRejectInvalid {
		t.Fatalf("wrong-token action=%v", got.Action)
	}
	if snapshot := server.Snapshot(); snapshot.Active {
		t.Fatalf("rejections mutated state: %#v", snapshot)
	}

	valid, _, err := NewRequestWithNonce("site-a", 4, testNonce(0x14), token)
	if err != nil {
		t.Fatal(err)
	}
	if got := handleOK(t, server, valid); got.Action != ActionSendChallenge {
		t.Fatalf("valid request action=%v", got.Action)
	}
}

func TestParsersRejectMalformedTruncatedAndOversized(t *testing.T) {
	token := testToken(0x44)
	serverChallenge := testNonce(0x35)
	server, err := NewServerStateWithRandom("site-a", token, bytes.NewReader(serverChallenge[:]))
	if err != nil {
		t.Fatal(err)
	}
	requestPacket, request, err := NewRequestWithNonce("site-a", 5, testNonce(0x15), token)
	if err != nil {
		t.Fatal(err)
	}
	challengePacket, challenge, err := NewChallengeWithNonce(request, testNonce(0x25), token)
	if err != nil {
		t.Fatal(err)
	}
	responsePacket, err := NewResponse(challenge, token)
	if err != nil {
		t.Fatal(err)
	}
	response, ok := ParseResponse(responsePacket, token)
	if !ok {
		t.Fatal("valid response rejected")
	}
	readyPacket, err := NewReady(response, token)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		packet []byte
	}{
		{name: "empty", packet: nil},
		{name: "short magic", packet: []byte("CLB")},
		{name: "truncated request", packet: requestPacket[:len(requestPacket)-1]},
		{name: "truncated challenge", packet: challengePacket[:len(challengePacket)-1]},
		{name: "truncated response", packet: responsePacket[:len(responsePacket)-1]},
		{name: "truncated ready", packet: readyPacket[:len(readyPacket)-1]},
		{name: "oversized request", packet: append(append([]byte(nil), requestPacket...), 0)},
		{name: "oversized challenge", packet: append(append([]byte(nil), challengePacket...), 0)},
		{name: "oversized response", packet: append(append([]byte(nil), responsePacket...), 0)},
		{name: "oversized ready", packet: append(append([]byte(nil), readyPacket...), 0)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, ok := parse(test.packet, token); ok {
				t.Fatal("generic parser accepted malformed packet")
			}
			if _, ok := ParseRequest(test.packet, token); ok {
				t.Fatal("request parser accepted malformed packet")
			}
			if _, ok := ParseChallenge(test.packet, token); ok {
				t.Fatal("challenge parser accepted malformed packet")
			}
			if _, ok := ParseResponse(test.packet, token); ok {
				t.Fatal("response parser accepted malformed packet")
			}
			if _, ok := ParseReady(test.packet, token); ok {
				t.Fatal("READY parser accepted malformed packet")
			}
			result, err := server.Handle(test.packet)
			if err != nil || result.Action != ActionRejectInvalid || len(result.Reply) != 0 {
				t.Fatalf("server result=%#v err=%v", result, err)
			}
		})
	}
	if snapshot := server.Snapshot(); snapshot.Active {
		t.Fatalf("malformed length table mutated server: %#v", snapshot)
	}

	canonicalFailures := []Metadata{
		{Type: TypeRequest, Site: "site-a", Sequence: 0, RequestNonce: testNonce(1)},
		{Type: TypeRequest, Site: "site-a", Sequence: 1},
		{Type: TypeRequest, Site: "site-a", Sequence: 1, RequestNonce: testNonce(1), Challenge: testNonce(2)},
		{Type: TypeChallenge, Site: "site-a", Sequence: 1, RequestNonce: testNonce(1)},
		{Type: MessageType(99), Site: "site-a", Sequence: 1, RequestNonce: testNonce(1), Challenge: testNonce(2)},
	}
	for i, meta := range canonicalFailures {
		if _, err := marshal(meta, token); err == nil {
			t.Fatalf("non-canonical metadata %d serialized: %#v", i, meta)
		}
	}

	// These packets have a correct HMAC over deliberately non-canonical fields.
	// Authentication must not bypass structural validation.
	signedMalformed := []struct {
		name   string
		offset int
		value  byte
	}{
		{name: "unknown type", offset: typeOffset, value: 99},
		{name: "unknown site", offset: siteOffset, value: 99},
		{name: "zero sequence", offset: sequenceOffset, value: 0},
		{name: "zero request nonce", offset: requestNonceOffset, value: 0},
		{name: "zero response challenge", offset: challengeOffset, value: 0},
	}
	for _, test := range signedMalformed {
		t.Run("signed-"+test.name, func(t *testing.T) {
			packet := append([]byte(nil), responsePacket...)
			switch test.name {
			case "zero sequence":
				clear(packet[sequenceOffset:requestNonceOffset])
			case "zero request nonce":
				clear(packet[requestNonceOffset:challengeOffset])
			case "zero response challenge":
				clear(packet[challengeOffset:macOffset])
			default:
				packet[test.offset] = test.value
			}
			copy(packet[macOffset:], sign(token, packet[:macOffset]))
			if _, ok := parse(packet, token); ok {
				t.Fatal("authenticated non-canonical packet accepted")
			}
			result, err := server.Handle(packet)
			if err != nil || result.Action != ActionRejectInvalid {
				t.Fatalf("server result=%#v err=%v", result, err)
			}
		})
	}
	if snapshot := server.Snapshot(); snapshot.Active {
		t.Fatalf("authenticated malformed table mutated server: %#v", snapshot)
	}
	if got := handleOK(t, server, requestPacket); got.Action != ActionSendChallenge {
		t.Fatalf("valid request after malformed table action=%v", got.Action)
	}
}

func TestEveryAuthenticatedFieldRejectsTampering(t *testing.T) {
	token := testToken(0x45)
	requestPacket, request, err := NewRequestWithNonce("site-a", 0x0102030405060708, testNonce(0x16), token)
	if err != nil {
		t.Fatal(err)
	}
	challengePacket, challenge, err := NewChallengeWithNonce(request, testNonce(0x26), token)
	if err != nil {
		t.Fatal(err)
	}
	responsePacket, err := NewResponse(challenge, token)
	if err != nil {
		t.Fatal(err)
	}
	response, ok := ParseResponse(responsePacket, token)
	if !ok {
		t.Fatal("valid response rejected")
	}
	readyPacket, err := NewReady(response, token)
	if err != nil {
		t.Fatal(err)
	}
	packets := []struct {
		name   string
		packet []byte
	}{
		{name: "request", packet: requestPacket},
		{name: "challenge", packet: challengePacket},
		{name: "response", packet: responsePacket},
		{name: "READY", packet: readyPacket},
	}

	fields := []struct {
		name   string
		offset int
	}{
		{name: "magic", offset: magicOffset},
		{name: "type", offset: typeOffset},
		{name: "site", offset: siteOffset},
		{name: "sequence", offset: sequenceOffset + 3},
		{name: "request nonce", offset: requestNonceOffset + 5},
		{name: "challenge", offset: challengeOffset + 7},
		{name: "MAC", offset: macOffset + 9},
	}
	for _, flight := range packets {
		for _, field := range fields {
			t.Run(flight.name+"-"+field.name, func(t *testing.T) {
				tampered := append([]byte(nil), flight.packet...)
				tampered[field.offset] ^= 0x80
				if _, ok := parse(tampered, token); ok {
					t.Fatal("tampered packet authenticated")
				}
			})
		}
	}
}

func TestServerStateIsConstantSpaceAndFailsClosedOnRandomError(t *testing.T) {
	token := testToken(0x46)
	server, err := NewServerStateWithRandom("site-a", token, errorReader{})
	if err != nil {
		t.Fatal(err)
	}
	requestPacket, _, err := NewRequestWithNonce("site-a", 1, testNonce(0x17), token)
	if err != nil {
		t.Fatal(err)
	}
	result, err := server.Handle(requestPacket)
	if err == nil || result.Action != ActionRejectInvalid {
		t.Fatalf("random failure result=%#v err=%v", result, err)
	}
	if snapshot := server.Snapshot(); snapshot.Active {
		t.Fatalf("random failure committed state: %#v", snapshot)
	}

	const transactions = 256
	randomBytes := make([]byte, transactions*NonceSize)
	for i := range randomBytes {
		randomBytes[i] = byte(i%251 + 1)
	}
	server, err = NewServerStateWithRandom("site-a", token, bytes.NewReader(randomBytes))
	if err != nil {
		t.Fatal(err)
	}
	for sequence := uint64(1); sequence <= transactions; sequence++ {
		packet, _, err := NewRequestWithNonce("site-a", sequence, nonceFromSequence(sequence), token)
		if err != nil {
			t.Fatal(err)
		}
		if got := handleOK(t, server, packet); got.Action != ActionSendChallenge {
			t.Fatalf("sequence=%d action=%v", sequence, got.Action)
		}
	}
	if snapshot := server.Snapshot(); !snapshot.Active || snapshot.Complete || snapshot.Sequence != transactions {
		t.Fatalf("final bounded snapshot=%#v", snapshot)
	}
}

func TestConstructorsRejectInvalidScope(t *testing.T) {
	token := testToken(0x47)
	zeroToken := make([]byte, TokenSize)
	if _, _, err := NewRequestWithNonce("site-c", 1, testNonce(1), token); err == nil {
		t.Fatal("unknown site accepted")
	}
	if _, _, err := NewRequestWithNonce("site-a", 0, testNonce(1), token); err == nil {
		t.Fatal("zero sequence accepted")
	}
	if _, _, err := NewRequestWithNonce("site-a", 1, Nonce{}, token); err == nil {
		t.Fatal("zero request nonce accepted")
	}
	if _, _, err := NewRequestWithNonce("site-a", 1, testNonce(1), token[:TokenSize-1]); err == nil {
		t.Fatal("short token accepted")
	}
	if _, _, err := NewRequestWithNonce("site-a", 1, testNonce(1), zeroToken); err == nil {
		t.Fatal("all-zero token accepted")
	}
	if _, err := NewServerState("site-c", token); err == nil {
		t.Fatal("server accepted unknown site")
	}
	if _, err := NewServerState("site-a", token[:TokenSize-1]); err == nil {
		t.Fatal("server accepted short token")
	}
	if _, err := NewServerState("site-a", zeroToken); err == nil {
		t.Fatal("server accepted all-zero token")
	}
	if _, err := NewServerStateWithRandom("site-a", token, nil); err == nil {
		t.Fatal("server accepted nil random source")
	}

	packet, _, err := NewRequestWithNonce("site-a", 1, testNonce(1), token)
	if err != nil {
		t.Fatal(err)
	}
	copy(packet[macOffset:], sign(zeroToken, packet[:macOffset]))
	if _, ok := ParseRequest(packet, zeroToken); ok {
		t.Fatal("parser authenticated a packet in the all-zero token domain")
	}
}

func FuzzBindingParsers(f *testing.F) {
	token := testToken(0x48)
	requestPacket, request, _ := NewRequestWithNonce("site-a", 1, testNonce(1), token)
	challengePacket, challenge, _ := NewChallengeWithNonce(request, testNonce(2), token)
	responsePacket, _ := NewResponse(challenge, token)
	response, _ := ParseResponse(responsePacket, token)
	readyPacket, _ := NewReady(response, token)
	for _, packet := range [][]byte{requestPacket, challengePacket, responsePacket, readyPacket, nil} {
		f.Add(packet)
	}
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 2048 {
			t.Skip()
		}
		_, _ = ParseRequest(packet, token)
		_, _ = ParseChallenge(packet, token)
		_, _ = ParseResponse(packet, token)
		_, _ = ParseReady(packet, token)
		_ = IsProtocol(packet)
	})
}

func handleOK(t *testing.T, server *ServerState, packet []byte) ServerResult {
	t.Helper()
	result, err := server.Handle(packet)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func testToken(start byte) []byte {
	token := make([]byte, TokenSize)
	for i := range token {
		token[i] = start + byte(i)
	}
	return token
}

func testNonce(start byte) Nonce {
	var nonce Nonce
	for i := range nonce {
		nonce[i] = start + byte(i)
	}
	return nonce
}

func nonceFromSequence(sequence uint64) Nonce {
	var nonce Nonce
	for i := range nonce {
		nonce[i] = byte(sequence>>uint(i%8*8)) ^ byte(i+1)
	}
	return nonce
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("random unavailable") }
