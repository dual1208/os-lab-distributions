//go:build linux

package credential

import (
	"os"
	"syscall"
	"testing"
	"time"
)

type policyFileInfo struct {
	mode os.FileMode
	uid  uint32
	gid  uint32
}

func (i policyFileInfo) Name() string       { return "credential" }
func (i policyFileInfo) Size() int64        { return 1 }
func (i policyFileInfo) Mode() os.FileMode  { return i.mode }
func (i policyFileInfo) ModTime() time.Time { return time.Time{} }
func (i policyFileInfo) IsDir() bool        { return i.mode.IsDir() }
func (i policyFileInfo) Sys() any           { return &syscall.Stat_t{Uid: i.uid, Gid: i.gid} }

func TestLinuxCredentialModePolicy(t *testing.T) {
	effectiveGID := uint32(os.Getegid())
	tests := []struct {
		name string
		mode os.FileMode
		kind Kind
		ok   bool
	}{
		{name: "public 0644", mode: 0644, kind: PublicCertificate, ok: true},
		{name: "public group writable", mode: 0664, kind: PublicCertificate},
		{name: "edge 0600", mode: 0600, kind: EdgePrivateKey, ok: true},
		{name: "edge group readable", mode: 0640, kind: EdgePrivateKey, ok: true},
		{name: "relay 0600", mode: 0600, kind: RelayPrivateKey, ok: true},
		{name: "relay group readable", mode: 0640, kind: RelayPrivateKey, ok: true},
		{name: "relay group writable", mode: 0660, kind: RelayPrivateKey},
		{name: "relay world readable", mode: 0644, kind: RelayPrivateKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePlatformPolicy(policyFileInfo{mode: tt.mode, uid: 0, gid: effectiveGID}, true, tt.kind)
			if (err == nil) != tt.ok {
				t.Fatalf("mode %04o accepted=%t want=%t err=%v", tt.mode, err == nil, tt.ok, err)
			}
		})
	}
}

func TestLinuxGroupReadablePrivateKeyRequiresEffectiveGID(t *testing.T) {
	effectiveGID := uint32(os.Getegid())
	otherGID := effectiveGID + 1
	if otherGID == effectiveGID {
		otherGID--
	}
	for _, kind := range []Kind{EdgePrivateKey, RelayPrivateKey} {
		if err := validatePlatformPolicy(policyFileInfo{mode: 0640, uid: 0, gid: effectiveGID}, true, kind); err != nil {
			t.Fatalf("kind %d matching effective GID rejected: %v", kind, err)
		}
		if err := validatePlatformPolicy(policyFileInfo{mode: 0640, uid: 0, gid: otherGID}, true, kind); err == nil {
			t.Fatalf("kind %d 0640 key with a foreign GID accepted", kind)
		}
	}
	if err := validatePlatformPolicy(policyFileInfo{mode: 0600, uid: 0, gid: otherGID}, true, RelayPrivateKey); err != nil {
		t.Fatalf("0600 relay key incorrectly depended on GID: %v", err)
	}
}

func TestLinuxCredentialOwnershipAndParentPolicy(t *testing.T) {
	if err := validatePlatformPolicy(policyFileInfo{mode: 0600, uid: 1000}, true, EdgePrivateKey); err == nil {
		t.Fatal("non-root-owned key accepted")
	}
	if err := validatePlatformPolicy(policyFileInfo{mode: os.ModeDir | 0755, uid: 0}, false, PublicCertificate); err != nil {
		t.Fatalf("safe parent rejected: %v", err)
	}
	if err := validatePlatformPolicy(policyFileInfo{mode: os.ModeDir | 0775, uid: 0}, false, PublicCertificate); err == nil {
		t.Fatal("group-writable parent accepted")
	}
}
