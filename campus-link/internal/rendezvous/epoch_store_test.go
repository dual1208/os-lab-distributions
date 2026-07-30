package rendezvous

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

const secondTestDeploymentID = "fedcba9876543210fedcba9876543210"

func fixedBootAnchor(value byte) BootAnchorSource {
	return BootAnchorSourceFunc(func() ([32]byte, error) {
		var digest [32]byte
		for index := range digest {
			digest[index] = value
		}
		return digest, nil
	})
}

func openTestEpochStore(path, deploymentID string, random *bytes.Reader) (*FileEpochStore, error) {
	return OpenFileEpochStoreWithAnchor(path, deploymentID, random, fixedBootAnchor(0xa1))
}

func TestFileEpochStoreSurvivesRestartWithoutEpochOrMaterialReuse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "epochs.json")
	entropy := bytes.NewReader(bytes.Repeat([]byte{0x31}, 48))
	firstStore, err := openTestEpochStore(path, testDeploymentID, entropy)
	if err != nil {
		t.Fatal(err)
	}
	first, err := firstStore.ReserveEpoch()
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := openTestEpochStore(path, testDeploymentID, bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	second, err := restarted.ReserveEpoch()
	if err != nil {
		t.Fatal(err)
	}
	if first.Epoch != 1 || second.Epoch != 2 {
		t.Fatalf("restart reused or skipped unexpected epochs: %d then %d", first.Epoch, second.Epoch)
	}
	if firstStore.Namespace() != restarted.Namespace() {
		t.Fatal("ordinary restart changed authenticated relay generation")
	}
	firstSession, firstKey := derivePlanMaterial(first, "campus", testVersion, testDeploymentID, firstStore.Namespace().RelayGeneration)
	secondSession, secondKey := derivePlanMaterial(second, "campus", testVersion, testDeploymentID, restarted.Namespace().RelayGeneration)
	if firstSession == secondSession || firstKey == secondKey || firstSession == ([16]byte{}) || firstKey == ([32]byte{}) {
		t.Fatal("restart produced zero or reused rendezvous material")
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm() != 0600) {
		t.Fatalf("epoch state is not service-private regular data: %v", info.Mode())
	}
}

func TestFileEpochStoreDeploymentRollbackResumesPriorNamespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "epochs.json")
	entropy := append(bytes.Repeat([]byte{0x21}, 48), bytes.Repeat([]byte{0x42}, 48)...)
	firstDeployment, err := openTestEpochStore(path, testDeploymentID, bytes.NewReader(entropy))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := firstDeployment.ReserveEpoch(); err != nil {
		t.Fatal(err)
	}
	firstGeneration := firstDeployment.Namespace().RelayGeneration
	secondDeployment, err := openTestEpochStore(path, secondTestDeploymentID, bytes.NewReader(entropy[48:]))
	if err != nil {
		t.Fatal(err)
	}
	if secondDeployment.Namespace().RelayGeneration == firstGeneration {
		t.Fatal("new deployment reused relay authority generation")
	}
	if reservation, err := secondDeployment.ReserveEpoch(); err != nil || reservation.Epoch != 1 {
		t.Fatalf("new deployment did not start its own namespace: %#v %v", reservation, err)
	}

	rolledBack, err := openTestEpochStore(path, testDeploymentID, bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := rolledBack.ReserveEpoch()
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.Namespace().RelayGeneration != firstGeneration || reservation.Epoch != 2 {
		t.Fatalf("rollback reset prior authority namespace: %#v %#v", rolledBack.Namespace(), reservation)
	}
}

func TestFileEpochStoreSnapshotRollbackRotatesAuthorityOnNewBoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "epochs.json")
	first, err := OpenFileEpochStoreWithAnchor(
		path, testDeploymentID, bytes.NewReader(bytes.Repeat([]byte{0x23}, 48)), fixedBootAnchor(0xa1),
	)
	if err != nil {
		t.Fatal(err)
	}
	oldGeneration, oldSeed := first.Namespace().RelayGeneration, first.seed
	if _, err := first.ReserveEpoch(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.ReserveEpoch(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, snapshot, 0600); err != nil {
		t.Fatal(err)
	}
	beforeRejectedRotation, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileEpochStoreWithAnchor(
		path, testDeploymentID, bytes.NewReader(bytes.Repeat([]byte{0x23}, 48*namespaceCreateAttempts)), fixedBootAnchor(0xb2),
	); !errors.Is(err, ErrNamespaceEntropy) {
		t.Fatalf("boot rotation accepted reused authority entropy: %v", err)
	}
	afterRejectedRotation, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeRejectedRotation, afterRejectedRotation) {
		t.Fatal("rejected authority rotation mutated persistent state")
	}

	recovered, err := OpenFileEpochStoreWithAnchor(
		path, testDeploymentID, bytes.NewReader(bytes.Repeat([]byte{0x67}, 48)), fixedBootAnchor(0xb2),
	)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Namespace().RelayGeneration == oldGeneration || recovered.seed == oldSeed {
		t.Fatal("snapshot restore retained replayable relay authority material")
	}
	reservation, err := recovered.ReserveEpoch()
	if err != nil {
		t.Fatal(err)
	}
	if reservation.Epoch != 1 {
		t.Fatalf("rotated boot namespace did not restart at epoch one: %d", reservation.Epoch)
	}
	if _, err := first.ReserveEpoch(); !errors.Is(err, ErrEpochState) {
		t.Fatalf("pre-rotation store retained authority after boot change: %v", err)
	}
	restarted, err := OpenFileEpochStoreWithAnchor(path, testDeploymentID, bytes.NewReader(nil), fixedBootAnchor(0xb2))
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Namespace() != recovered.Namespace() || restarted.seed != recovered.seed {
		t.Fatal("same-boot process restart rotated authority unexpectedly")
	}
}

func TestFileEpochStoreBootChangeRotatesEveryDeploymentAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "epochs.json")
	first, err := OpenFileEpochStoreWithAnchor(
		path, testDeploymentID, bytes.NewReader(bytes.Repeat([]byte{0x11}, 48)), fixedBootAnchor(0xa1),
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenFileEpochStoreWithAnchor(
		path, secondTestDeploymentID, bytes.NewReader(bytes.Repeat([]byte{0x22}, 48)), fixedBootAnchor(0xa1),
	)
	if err != nil {
		t.Fatal(err)
	}
	oldFirst, oldSecond := first.Namespace(), second.Namespace()
	beforeFailedRotation, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileEpochStoreWithAnchor(
		path, testDeploymentID, bytes.NewReader(bytes.Repeat([]byte{0x33}, 48)), fixedBootAnchor(0xb2),
	); err == nil {
		t.Fatal("partial multi-deployment rotation unexpectedly succeeded")
	}
	afterFailedRotation, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeFailedRotation, afterFailedRotation) {
		t.Fatal("failed multi-deployment rotation partially mutated persistent state")
	}

	rotationEntropy := append(bytes.Repeat([]byte{0x44}, 48), bytes.Repeat([]byte{0x55}, 48)...)
	rotatedFirst, err := OpenFileEpochStoreWithAnchor(
		path, testDeploymentID, bytes.NewReader(rotationEntropy), fixedBootAnchor(0xb2),
	)
	if err != nil {
		t.Fatal(err)
	}
	rotatedSecond, err := OpenFileEpochStoreWithAnchor(
		path, secondTestDeploymentID, bytes.NewReader(nil), fixedBootAnchor(0xb2),
	)
	if err != nil {
		t.Fatal(err)
	}
	if rotatedFirst.Namespace().RelayGeneration == oldFirst.RelayGeneration ||
		rotatedSecond.Namespace().RelayGeneration == oldSecond.RelayGeneration ||
		rotatedFirst.Namespace().RelayGeneration == rotatedSecond.Namespace().RelayGeneration {
		t.Fatal("boot change did not rotate every deployment to unique authority")
	}
}

func TestFileEpochStoreFailsBeforeMutationWithoutBootAnchor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "epochs.json")
	source := BootAnchorSourceFunc(func() ([32]byte, error) {
		return [32]byte{}, errors.New("injected unavailable anchor")
	})
	if _, err := OpenFileEpochStoreWithAnchor(
		path, testDeploymentID, bytes.NewReader(bytes.Repeat([]byte{0x77}, 48)), source,
	); !errors.Is(err, ErrBootAnchor) {
		t.Fatalf("unavailable boot anchor returned %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("failed boot anchor mutated epoch state: %v", err)
	}
}

func TestFileEpochStoreRejectsMalformedPersistedBootAnchor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "epochs.json")
	if _, err := openTestEpochStore(
		path, testDeploymentID, bytes.NewReader(bytes.Repeat([]byte{0x71}, 48)),
	); err != nil {
		t.Fatal(err)
	}
	state, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	validAnchor := bytes.Repeat([]byte("a1"), 32)
	zeroAnchor := bytes.Repeat([]byte("00"), 32)
	corrupted := bytes.Replace(state, validAnchor, zeroAnchor, 1)
	if bytes.Equal(corrupted, state) {
		t.Fatal("test could not locate persisted boot anchor")
	}
	if err := os.WriteFile(path, corrupted, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openTestEpochStore(path, testDeploymentID, bytes.NewReader(nil)); !errors.Is(err, ErrEpochState) {
		t.Fatalf("malformed persisted boot anchor returned %v", err)
	}
}

func TestFileEpochStoreSerializesConcurrentAllocators(t *testing.T) {
	path := filepath.Join(t.TempDir(), "epochs.json")
	first, err := openTestEpochStore(path, testDeploymentID, bytes.NewReader(bytes.Repeat([]byte{0x37}, 48)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := openTestEpochStore(path, testDeploymentID, bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	const allocations = 32
	results := make(chan uint64, allocations)
	errorsSeen := make(chan error, allocations)
	var wait sync.WaitGroup
	for index := range allocations {
		wait.Add(1)
		store := first
		if index%2 != 0 {
			store = second
		}
		go func() {
			defer wait.Done()
			reservation, err := store.ReserveEpoch()
			if err != nil {
				errorsSeen <- err
				return
			}
			results <- reservation.Epoch
		}()
	}
	wait.Wait()
	close(results)
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatal(err)
	}
	seen := make(map[uint64]struct{}, allocations)
	for epoch := range results {
		if epoch == 0 {
			t.Fatal("zero epoch allocated")
		}
		if _, duplicate := seen[epoch]; duplicate {
			t.Fatalf("concurrent allocators reused epoch %d", epoch)
		}
		seen[epoch] = struct{}{}
	}
	if len(seen) != allocations {
		t.Fatalf("got %d unique allocations, want %d", len(seen), allocations)
	}
}

func TestFileEpochStoreRejectsZeroAndReusedNamespaceEntropy(t *testing.T) {
	zeroPath := filepath.Join(t.TempDir(), "zero.json")
	if _, err := openTestEpochStore(zeroPath, testDeploymentID, bytes.NewReader(make([]byte, 48*namespaceCreateAttempts))); !errors.Is(err, ErrNamespaceEntropy) {
		t.Fatalf("zero entropy returned %v", err)
	}

	directory := t.TempDir()
	path := filepath.Join(directory, "reused.json")
	if _, err := openTestEpochStore(path, testDeploymentID, bytes.NewReader(bytes.Repeat([]byte{0x55}, 48))); err != nil {
		t.Fatal(err)
	}
	if _, err := openTestEpochStore(path, secondTestDeploymentID, bytes.NewReader(bytes.Repeat([]byte{0x55}, 48*namespaceCreateAttempts))); !errors.Is(err, ErrNamespaceEntropy) {
		t.Fatalf("reused namespace entropy returned %v", err)
	}
}

func TestFileEpochStoreRejectsNonPrivateOrMalformedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "epochs.json")
	if _, err := openTestEpochStore(path, testDeploymentID, bytes.NewReader(bytes.Repeat([]byte{0x61}, 48))); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := openTestEpochStore(path, testDeploymentID, bytes.NewReader(nil)); !errors.Is(err, ErrEpochState) {
			t.Fatalf("non-private state returned %v", err)
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, []byte(`{"schema":1,"deployments":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openTestEpochStore(path, testDeploymentID, bytes.NewReader(nil)); !errors.Is(err, ErrEpochState) {
		t.Fatalf("malformed state returned %v", err)
	}
}
