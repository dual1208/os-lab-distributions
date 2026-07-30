package rendezvous

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
)

const (
	epochStateSchema        = 2
	maxEpochStateSize       = 256 * 1024
	maxDeploymentNamespaces = 256
	namespaceCreateAttempts = 16
)

var (
	ErrEpochState       = errors.New("invalid rendezvous epoch state")
	ErrEpochExhausted   = errors.New("rendezvous path epoch exhausted")
	ErrNamespaceEntropy = errors.New("invalid or reused rendezvous namespace entropy")
)

// EpochNamespace is the authenticated, deployment-scoped portion of every
// rendezvous plan. RelayGeneration is stable across ordinary process restarts.
type EpochNamespace struct {
	DeploymentID    string
	RelayGeneration string
}

// EpochReservation is durably consumed before a planner publishes a plan.
// Skipped epochs after a crash are safe; reused epochs are not.
type EpochReservation struct {
	Epoch        uint64
	MaterialSeed [32]byte
}

// EpochStore lets OpenWrt use a crash-safe file implementation while tests can
// inject a deterministic persistence model.
type EpochStore interface {
	Namespace() EpochNamespace
	ReserveEpoch() (EpochReservation, error)
}

type persistedEpochState struct {
	Schema           int                           `json:"schema"`
	BootAnchorSHA256 string                        `json:"boot_anchor_sha256"`
	Deployments      map[string]persistedNamespace `json:"deployments"`
}

type persistedNamespace struct {
	RelayGeneration string `json:"relay_generation"`
	MaterialSeed    string `json:"material_seed"`
	NextEpoch       uint64 `json:"next_epoch"`
}

// FileEpochStore persists every deployment namespace so a controlled rollback
// resumes its prior monotonic epoch instead of silently starting again at one.
type FileEpochStore struct {
	mu         sync.Mutex
	path       string
	bootAnchor [sha256.Size]byte
	namespace  EpochNamespace
	seed       [32]byte
}

// OpenFileEpochStore opens or creates a service-private, atomically replaced
// state file. The file must be owned by the effective relay identity and the
// containing directory must not be writable by group or other users.
func OpenFileEpochStore(path, deploymentID string, random io.Reader) (*FileEpochStore, error) {
	return OpenFileEpochStoreWithAnchor(path, deploymentID, random, platformBootAnchorSource{})
}

// OpenFileEpochStoreWithAnchor is the injectable form used by platform-safe
// tests. Production callers must use OpenFileEpochStore so the Linux boot ID
// cannot be replaced with a snapshotted or caller-controlled value.
func OpenFileEpochStoreWithAnchor(path, deploymentID string, random io.Reader, anchorSource BootAnchorSource) (*FileEpochStore, error) {
	if !filepath.IsAbs(path) || !control.ValidDeploymentID(deploymentID) {
		return nil, ErrEpochState
	}
	bootAnchor, err := readBootAnchor(anchorSource)
	if err != nil {
		return nil, err
	}
	bootAnchorHex := hex.EncodeToString(bootAnchor[:])
	if random == nil {
		random = rand.Reader
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, fmt.Errorf("epoch state directory: %w", err)
	}
	if err := validateEpochDirectory(directory); err != nil {
		return nil, err
	}
	release, err := lockEpochState(path)
	if err != nil {
		return nil, err
	}
	defer release()
	store := &FileEpochStore{path: path, bootAnchor: bootAnchor}
	store.mu.Lock()
	defer store.mu.Unlock()
	state, exists, err := store.loadLocked()
	if err != nil {
		return nil, err
	}
	if !exists {
		state = persistedEpochState{
			Schema: epochStateSchema, BootAnchorSHA256: bootAnchorHex,
			Deployments: make(map[string]persistedNamespace),
		}
	}
	dirty := !exists
	usedEntropy := collectNamespaceEntropy(state.Deployments)
	if exists && state.BootAnchorSHA256 != bootAnchorHex {
		if err := rotateAllNamespaces(&state, random, usedEntropy); err != nil {
			return nil, err
		}
		state.BootAnchorSHA256 = bootAnchorHex
		dirty = true
	}
	namespace, ok := state.Deployments[deploymentID]
	if !ok {
		if len(state.Deployments) >= maxDeploymentNamespaces {
			return nil, fmt.Errorf("%w: deployment namespace limit reached", ErrEpochState)
		}
		namespace, err = newPersistedNamespace(random, usedEntropy)
		if err != nil {
			return nil, err
		}
		state.Deployments[deploymentID] = namespace
		dirty = true
	}
	if dirty {
		if err := store.persistLocked(state); err != nil {
			return nil, err
		}
	}
	seed, err := decodeMaterialSeed(namespace.MaterialSeed)
	if err != nil {
		return nil, err
	}
	store.namespace = EpochNamespace{DeploymentID: deploymentID, RelayGeneration: namespace.RelayGeneration}
	store.seed = seed
	return store, nil
}

func (s *FileEpochStore) Namespace() EpochNamespace { return s.namespace }

func (s *FileEpochStore) ReserveEpoch() (EpochReservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := lockEpochState(s.path)
	if err != nil {
		return EpochReservation{}, err
	}
	defer release()
	state, exists, err := s.loadLocked()
	if err != nil || !exists {
		if err == nil {
			err = ErrEpochState
		}
		return EpochReservation{}, err
	}
	if state.BootAnchorSHA256 != hex.EncodeToString(s.bootAnchor[:]) {
		return EpochReservation{}, ErrEpochState
	}
	namespace, ok := state.Deployments[s.namespace.DeploymentID]
	if !ok || namespace.RelayGeneration != s.namespace.RelayGeneration || namespace.NextEpoch == 0 {
		return EpochReservation{}, ErrEpochState
	}
	seed, err := decodeMaterialSeed(namespace.MaterialSeed)
	if err != nil || seed != s.seed {
		return EpochReservation{}, ErrEpochState
	}
	if namespace.NextEpoch == math.MaxUint64 {
		return EpochReservation{}, ErrEpochExhausted
	}
	reservation := EpochReservation{Epoch: namespace.NextEpoch, MaterialSeed: seed}
	namespace.NextEpoch++
	state.Deployments[s.namespace.DeploymentID] = namespace
	if err := s.persistLocked(state); err != nil {
		return EpochReservation{}, err
	}
	return reservation, nil
}

func (s *FileEpochStore) loadLocked() (persistedEpochState, bool, error) {
	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return persistedEpochState{}, false, nil
	}
	if err != nil {
		return persistedEpochState{}, false, err
	}
	if err := validateEpochStateInfo(info); err != nil {
		return persistedEpochState{}, false, err
	}
	file, err := os.Open(s.path)
	if err != nil {
		return persistedEpochState{}, false, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxEpochStateSize+1))
	if err != nil || len(data) > maxEpochStateSize {
		return persistedEpochState{}, false, ErrEpochState
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var state persistedEpochState
	if err := dec.Decode(&state); err != nil {
		return persistedEpochState{}, false, ErrEpochState
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return persistedEpochState{}, false, ErrEpochState
	}
	if err := validatePersistedState(state); err != nil {
		return persistedEpochState{}, false, err
	}
	canonical, err := json.Marshal(state)
	if err != nil || !bytes.Equal(bytes.TrimSpace(data), canonical) {
		return persistedEpochState{}, false, ErrEpochState
	}
	return state, true, nil
}

func (s *FileEpochStore) persistLocked(state persistedEpochState) error {
	if err := validatePersistedState(state); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil || len(data)+1 > maxEpochStateSize {
		return ErrEpochState
	}
	directory := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(directory, ".campus-link-epochs.*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	closeWithError := func(cause error) error {
		_ = tmp.Close()
		return cause
	}
	if err := tmp.Chmod(0600); err != nil {
		return closeWithError(err)
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		return closeWithError(err)
	}
	if err := tmp.Sync(); err != nil {
		return closeWithError(err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return err
	}
	return syncEpochDirectory(directory)
}

type namespaceEntropy struct {
	generations map[string]struct{}
	seeds       map[string]struct{}
}

func collectNamespaceEntropy(existing map[string]persistedNamespace) *namespaceEntropy {
	used := &namespaceEntropy{
		generations: make(map[string]struct{}, len(existing)*2),
		seeds:       make(map[string]struct{}, len(existing)*2),
	}
	for _, namespace := range existing {
		used.generations[namespace.RelayGeneration] = struct{}{}
		used.seeds[namespace.MaterialSeed] = struct{}{}
	}
	return used
}

func newPersistedNamespace(random io.Reader, used *namespaceEntropy) (persistedNamespace, error) {
	if random == nil || used == nil || used.generations == nil || used.seeds == nil {
		return persistedNamespace{}, ErrNamespaceEntropy
	}
	for range namespaceCreateAttempts {
		generationBytes := make([]byte, control.RelayGenerationLength/2)
		seed := make([]byte, 32)
		if _, err := io.ReadFull(random, generationBytes); err != nil {
			return persistedNamespace{}, err
		}
		if _, err := io.ReadFull(random, seed); err != nil {
			return persistedNamespace{}, err
		}
		generation := hex.EncodeToString(generationBytes)
		seedHex := hex.EncodeToString(seed)
		_, generationReused := used.generations[generation]
		_, seedReused := used.seeds[seedHex]
		if allZero(generationBytes) || allZero(seed) || generationReused || seedReused {
			continue
		}
		used.generations[generation] = struct{}{}
		used.seeds[seedHex] = struct{}{}
		return persistedNamespace{RelayGeneration: generation, MaterialSeed: seedHex, NextEpoch: 1}, nil
	}
	return persistedNamespace{}, ErrNamespaceEntropy
}

func rotateAllNamespaces(state *persistedEpochState, random io.Reader, used *namespaceEntropy) error {
	if state == nil || len(state.Deployments) == 0 {
		return ErrEpochState
	}
	deploymentIDs := make([]string, 0, len(state.Deployments))
	for deploymentID := range state.Deployments {
		deploymentIDs = append(deploymentIDs, deploymentID)
	}
	sort.Strings(deploymentIDs)
	rotated := make(map[string]persistedNamespace, len(state.Deployments))
	for _, deploymentID := range deploymentIDs {
		namespace, err := newPersistedNamespace(random, used)
		if err != nil {
			return err
		}
		rotated[deploymentID] = namespace
	}
	state.Deployments = rotated
	return nil
}

func validatePersistedState(state persistedEpochState) error {
	if state.Schema != epochStateSchema || !validSHA256Hex(state.BootAnchorSHA256) ||
		len(state.Deployments) == 0 || len(state.Deployments) > maxDeploymentNamespaces {
		return ErrEpochState
	}
	seenGenerations := make(map[string]struct{}, len(state.Deployments))
	seenSeeds := make(map[string]struct{}, len(state.Deployments))
	for deploymentID, namespace := range state.Deployments {
		if !control.ValidDeploymentID(deploymentID) || !control.ValidRelayGeneration(namespace.RelayGeneration) || namespace.NextEpoch == 0 {
			return ErrEpochState
		}
		seed, err := decodeMaterialSeed(namespace.MaterialSeed)
		if err != nil {
			return err
		}
		if _, duplicate := seenGenerations[namespace.RelayGeneration]; duplicate {
			return ErrEpochState
		}
		if _, duplicate := seenSeeds[namespace.MaterialSeed]; duplicate {
			return ErrEpochState
		}
		seenGenerations[namespace.RelayGeneration] = struct{}{}
		seenSeeds[hex.EncodeToString(seed[:])] = struct{}{}
	}
	return nil
}

func validSHA256Hex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && !allZero(decoded) && hex.EncodeToString(decoded) == value
}

func decodeMaterialSeed(value string) ([32]byte, error) {
	var seed [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(seed) || allZero(decoded) || hex.EncodeToString(decoded) != value {
		return seed, ErrEpochState
	}
	copy(seed[:], decoded)
	return seed, nil
}

func validateEpochDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrEpochState
	}
	return validateEpochDirectorySecurity(info)
}

func validateEpochStateInfo(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return ErrEpochState
	}
	return validateEpochStateSecurity(info)
}

func allZero(value []byte) bool {
	var combined byte
	for _, b := range value {
		combined |= b
	}
	return combined == 0
}
