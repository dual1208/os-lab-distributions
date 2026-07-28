package binding

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

const (
	requestMagic   = "CLBIND1\x00"
	challengeMagic = "CLCHAL1\x00"
	responseMagic  = "CLRESP1\x00"
	ReadyMagic     = "CLREADY1"
	nonceSize      = 16
	macSize        = 32
)

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

func Random(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func NewRequest(site string, token []byte) ([]byte, error) {
	code, err := SiteCode(site)
	if err != nil {
		return nil, err
	}
	nonce, err := Random(nonceSize)
	if err != nil {
		return nil, err
	}
	body := append([]byte{code}, nonce...)
	return append(append([]byte(requestMagic), body...), sign(token, body)...), nil
}

func ParseRequest(packet, token []byte) (string, bool) {
	if len(packet) != len(requestMagic)+1+nonceSize+macSize || string(packet[:len(requestMagic)]) != requestMagic {
		return "", false
	}
	body := packet[len(requestMagic) : len(requestMagic)+1+nonceSize]
	if !hmac.Equal(packet[len(requestMagic)+len(body):], sign(token, body)) {
		return "", false
	}
	site, err := SiteName(body[0])
	return site, err == nil
}

func NewChallenge() ([]byte, []byte, error) {
	challenge, err := Random(nonceSize)
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(challengeMagic), challenge...), challenge, nil
}

func ParseChallenge(packet []byte) ([]byte, bool) {
	if len(packet) != len(challengeMagic)+nonceSize || string(packet[:len(challengeMagic)]) != challengeMagic {
		return nil, false
	}
	return append([]byte(nil), packet[len(challengeMagic):]...), true
}

func NewResponse(site string, challenge, token []byte) ([]byte, error) {
	if len(challenge) != nonceSize {
		return nil, errors.New("invalid challenge")
	}
	code, err := SiteCode(site)
	if err != nil {
		return nil, err
	}
	body := append([]byte{code}, challenge...)
	return append(append([]byte(responseMagic), body...), sign(token, body)...), nil
}

func ParseResponse(packet, token []byte) (string, []byte, bool) {
	if len(packet) != len(responseMagic)+1+nonceSize+macSize || string(packet[:len(responseMagic)]) != responseMagic {
		return "", nil, false
	}
	body := packet[len(responseMagic) : len(responseMagic)+1+nonceSize]
	if !hmac.Equal(packet[len(responseMagic)+len(body):], sign(token, body)) {
		return "", nil, false
	}
	site, err := SiteName(body[0])
	return site, append([]byte(nil), body[1:]...), err == nil
}

func IsReady(packet []byte) bool { return string(packet) == ReadyMagic }

func IsProtocol(packet []byte) bool {
	if len(packet) < 8 {
		return false
	}
	s := string(packet[:8])
	return s == requestMagic || s == challengeMagic || s == responseMagic || s == ReadyMagic
}

func sign(token, body []byte) []byte {
	m := hmac.New(sha256.New, token)
	_, _ = m.Write(body)
	return m.Sum(nil)
}
