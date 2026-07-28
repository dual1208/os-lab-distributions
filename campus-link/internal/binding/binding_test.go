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
