package edge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/identity"
)

func TestStatusRequestsCoalesceWithoutFilesystemIO(t *testing.T) {
	runner := &Runner{
		cfg:        config.Edge{StatusPath: filepath.Join(t.TempDir(), "blocked", "status.json")},
		statusWake: make(chan struct{}, 1),
	}
	done := make(chan struct{})
	go func() {
		for index := 0; index < 100000; index++ {
			runner.writeStatus()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("status requests blocked a caller")
	}
	if len(runner.statusWake) != 1 {
		t.Fatalf("coalesced queue length=%d want=1", len(runner.statusWake))
	}
	if _, err := os.Stat(runner.cfg.StatusPath); !os.IsNotExist(err) {
		t.Fatalf("request path performed filesystem I/O: %v", err)
	}
}

func TestStatusWriterUsesAtomicPrivateFileAndReportsFailures(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "edge.json")
	expiry := time.Now().Add(time.Hour)
	runner := &Runner{
		cfg:          config.Edge{StatusPath: path},
		state:        edgeState{Site: "site-a"},
		localControl: identity.Verified{NotAfter: expiry, PinSlot: 0},
	}
	if err := runner.writeStatusNow(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("status mode=%v is not a regular file", info.Mode())
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0640 {
		t.Fatalf("status permissions=%#o want=0640", info.Mode().Perm())
	}
	temporaries, err := filepath.Glob(filepath.Join(directory, ".campus-link-status.*"))
	if err != nil || len(temporaries) != 0 {
		t.Fatalf("temporary status files remain: files=%v err=%v", temporaries, err)
	}

	blocked := filepath.Join(directory, "not-a-directory")
	if err := os.WriteFile(blocked, []byte("block"), 0600); err != nil {
		t.Fatal(err)
	}
	runner.cfg.StatusPath = filepath.Join(blocked, "edge.json")
	runner.writeStatus()
	if runner.statusFailures.Load() != 1 {
		t.Fatalf("status failures=%d want=1", runner.statusFailures.Load())
	}
	runner.cfg.StatusPath = path
	if err := runner.writeStatusNow(); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded edgeState
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.StatusFailures != 1 {
		t.Fatalf("published status failures=%d want=1", decoded.StatusFailures)
	}
}

func TestLocalRuntimeCutoffUsesEarlierControlLeaf(t *testing.T) {
	now := time.Now()
	control := identity.Verified{NotAfter: now.Add(time.Hour)}
	data := identity.Verified{NotAfter: now.Add(2 * time.Hour)}
	cutoff, err := localRuntimeCutoff(now, control, data)
	if err != nil {
		t.Fatal(err)
	}
	if want := control.NotAfter.Add(-identity.ReconnectMargin); !cutoff.Equal(want) {
		t.Fatalf("runtime cutoff=%s want=%s", cutoff, want)
	}
}
