package rendezvous

import (
	"crypto/sha256"
	"errors"
	"testing"
)

func TestCanonicalLinuxBootIDIsSanitizedBeforePersistence(t *testing.T) {
	const raw = "12345678-9abc-def0-1234-56789abcdef0"
	digest, err := hashCanonicalLinuxBootID([]byte(raw + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if digest != sha256.Sum256([]byte(raw)) {
		t.Fatal("boot identifier was not hashed in its canonical form")
	}
}

func TestCanonicalLinuxBootIDRejectsAmbiguousOrMalformedValues(t *testing.T) {
	for _, value := range []string{
		"", "00000000-0000-0000-0000-000000000000",
		"12345678-9ABC-def0-1234-56789abcdef0",
		"123456789abc-def0-1234-56789abcdef0",
		"12345678-9abc-def0-1234-56789abcdef0\r\n",
		"12345678-9abc-def0-1234-56789abcdef0\n\n",
		"12345678-9abc-def0-1234-56789abcdefg",
	} {
		if _, err := hashCanonicalLinuxBootID([]byte(value)); !errors.Is(err, ErrBootAnchor) {
			t.Fatalf("malformed boot identifier %q returned %v", value, err)
		}
	}
}

func TestReadBootAnchorFailsClosed(t *testing.T) {
	if _, err := readBootAnchor(nil); !errors.Is(err, ErrBootAnchor) {
		t.Fatalf("nil boot anchor source returned %v", err)
	}
	if _, err := readBootAnchor(BootAnchorSourceFunc(func() ([32]byte, error) {
		return [32]byte{}, nil
	})); !errors.Is(err, ErrBootAnchor) {
		t.Fatalf("zero boot anchor returned %v", err)
	}
	if _, err := readBootAnchor(BootAnchorSourceFunc(func() ([32]byte, error) {
		return [32]byte{}, errors.New("injected source failure")
	})); !errors.Is(err, ErrBootAnchor) {
		t.Fatalf("failed boot anchor source returned %v", err)
	}
}
