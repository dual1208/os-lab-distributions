package binding

import "testing"

func TestChallengeRoundTrip(t *testing.T) {
	token := []byte("01234567890123456789012345678901")
	req, err := NewRequest("site-a", token)
	if err != nil {
		t.Fatal(err)
	}
	if site, ok := ParseRequest(req, token); !ok || site != "site-a" {
		t.Fatalf("request rejected: site=%q ok=%v", site, ok)
	}
	packet, challenge, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	parsed, ok := ParseChallenge(packet)
	if !ok {
		t.Fatal("challenge rejected")
	}
	resp, err := NewResponse("site-a", parsed, token)
	if err != nil {
		t.Fatal(err)
	}
	if site, got, ok := ParseResponse(resp, token); !ok || site != "site-a" || string(got) != string(challenge) {
		t.Fatal("response rejected")
	}
	resp[len(resp)-1] ^= 1
	if _, _, ok := ParseResponse(resp, token); ok {
		t.Fatal("tampered response accepted")
	}
}

func FuzzBindingParsers(f *testing.F) {
	token := []byte("01234567890123456789012345678901")
	request, _ := NewRequest("site-a", token)
	challengePacket, _, _ := NewChallenge()
	response, _ := NewResponse("site-b", make([]byte, nonceSize), token)
	f.Add(request)
	f.Add(challengePacket)
	f.Add(response)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 2048 {
			t.Skip()
		}
		_, _ = ParseRequest(packet, token)
		_, _ = ParseChallenge(packet)
		_, _, _ = ParseResponse(packet, token)
		_ = IsReady(packet)
		_ = IsProtocol(packet)
	})
}
