//go:build linux

package rendezvous

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxBootAnchorSourceMatchesKernelBootID(t *testing.T) {
	raw, err := os.ReadFile(linuxBootIDPath)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hashCanonicalLinuxBootID(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := (platformBootAnchorSource{}).BootAnchorDigest()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("production boot anchor did not match sanitized kernel boot ID")
	}
}

func TestLinuxBootAnchorFailsClosedOnUnavailableOrMalformedSource(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := readLinuxBootAnchor(missing); !errors.Is(err, ErrBootAnchor) {
		t.Fatalf("missing boot ID returned %v", err)
	}
	malformed := filepath.Join(t.TempDir(), "boot_id")
	if err := os.WriteFile(malformed, []byte("not-a-boot-id\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readLinuxBootAnchor(malformed); !errors.Is(err, ErrBootAnchor) {
		t.Fatalf("malformed boot ID returned %v", err)
	}
}

func TestLinuxEpochStatePersistsOnlySanitizedBootAnchor(t *testing.T) {
	raw, err := os.ReadFile(linuxBootIDPath)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := hashCanonicalLinuxBootID(raw)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "epochs.json")
	if _, err := OpenFileEpochStore(
		path, testDeploymentID, bytes.NewReader(bytes.Repeat([]byte{0x6a}, 48)),
	); err != nil {
		t.Fatal(err)
	}
	state, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(state, bytes.TrimSpace(raw)) {
		t.Fatal("raw Linux boot identifier leaked into persistent state")
	}
	if !bytes.Contains(state, []byte(hex.EncodeToString(digest[:]))) {
		t.Fatal("sanitized boot anchor digest missing from persistent state")
	}
}
