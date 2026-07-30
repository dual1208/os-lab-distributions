package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"time"
)

const (
	DeploymentIDLength     = 32
	RelayGenerationLength  = 32
	SourceVersionMaxLength = 64
	MaxMonotonicSample     = uint64(1<<63 - 1)
)

var (
	lowercaseHex32   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	sourceVersion    = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$`)
	clockUnixNanoMin = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC).UnixNano()
	clockUnixNanoMax = time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC).UnixNano()
)

// ValidSourceVersion reports whether value is a bounded canonical build
// version suitable for an authenticated namespace. Restricting it to ASCII
// prevents alternate Unicode or control-character encodings of one release.
func ValidSourceVersion(value string) bool {
	return len(value) <= SourceVersionMaxLength && sourceVersion.MatchString(value)
}

// ValidDeploymentID reports whether value is the canonical deployment
// transaction identifier carried inside the authenticated control channel.
func ValidDeploymentID(value string) bool {
	return len(value) == DeploymentIDLength && lowercaseHex32.MatchString(value)
}

// ValidRelayGeneration reports whether value is a canonical relay authority
// generation. The value is opaque to edges and authenticated by control mTLS.
func ValidRelayGeneration(value string) bool {
	return len(value) == RelayGenerationLength && lowercaseHex32.MatchString(value)
}

// ValidClockUnixNano restricts authenticated wall samples to one canonical,
// subtraction-safe era. It intentionally rejects zero-valued fields emitted
// by protocol versions that predate clock-bound plan authority.
func ValidClockUnixNano(value int64) bool {
	return value >= clockUnixNanoMin && value < clockUnixNanoMax
}

// ValidMonotonicSample reports whether the opaque edge-local correlation
// sample is canonical. It is echoed by the relay but never interpreted there.
func ValidMonotonicSample(value uint64) bool {
	return value > 0 && value <= MaxMonotonicSample
}

type Register struct {
	Type         string   `json:"type"`
	Site         string   `json:"site"`
	Generation   string   `json:"generation"`
	Version      string   `json:"version"`
	DeploymentID string   `json:"deployment_id"`
	Circuit      string   `json:"circuit"`
	Prefix       string   `json:"prefix"`
	Transports   []string `json:"transports"`
}

type Registered struct {
	Type            string `json:"type"`
	BindToken       string `json:"bind_token"`
	Version         string `json:"version"`
	DeploymentID    string `json:"deployment_id"`
	RelayGeneration string `json:"relay_generation"`
}

type Heartbeat struct {
	Type              string `json:"type"`
	Sequence          uint64 `json:"sequence"`
	EdgeWallUnixNano  int64  `json:"edge_wall_unix_nano"`
	EdgeMonotonicNano uint64 `json:"edge_monotonic_nano"`
}

type HeartbeatAck struct {
	Type                 string          `json:"type"`
	Sequence             uint64          `json:"sequence"`
	EdgeMonotonicNano    uint64          `json:"edge_monotonic_nano"`
	RelayReceiveUnixNano int64           `json:"relay_receive_unix_nano"`
	RelaySendUnixNano    int64           `json:"relay_send_unix_nano"`
	Telemetry            *RelayTelemetry `json:"relay_telemetry,omitempty"`
	Plan                 *RendezvousPlan `json:"rendezvous_plan,omitempty"`
}

// RelayTelemetry is deliberately fixed-width and contains no peer identifiers
// or routing metadata. Its enclosing HeartbeatAck authenticates and binds it to
// one exact control heartbeat sequence.
type RelayTelemetry struct {
	ForwardedSiteA      uint64 `json:"forwarded_site_a"`
	ForwardedSiteABytes uint64 `json:"forwarded_site_a_bytes"`
	ForwardedSiteB      uint64 `json:"forwarded_site_b"`
	ForwardedSiteBBytes uint64 `json:"forwarded_site_b_bytes"`
	Dropped             uint64 `json:"dropped"`
	DroppedBytes        uint64 `json:"dropped_bytes"`
}

// UnmarshalJSON makes the authenticated telemetry object an exact schema.
// encoding/json otherwise accepts absent numeric fields as zero, which would
// let an older three-counter relay silently omit byte accounting.
func (t *RelayTelemetry) UnmarshalJSON(data []byte) error {
	if err := validateCanonicalJSONObject(data, reflect.TypeOf(RelayTelemetry{})); err != nil {
		return err
	}
	type relayTelemetryWire struct {
		ForwardedSiteA      *uint64 `json:"forwarded_site_a"`
		ForwardedSiteABytes *uint64 `json:"forwarded_site_a_bytes"`
		ForwardedSiteB      *uint64 `json:"forwarded_site_b"`
		ForwardedSiteBBytes *uint64 `json:"forwarded_site_b_bytes"`
		Dropped             *uint64 `json:"dropped"`
		DroppedBytes        *uint64 `json:"dropped_bytes"`
	}
	var wire relayTelemetryWire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("relay telemetry contains multiple JSON values")
		}
		return err
	}
	if wire.ForwardedSiteA == nil || wire.ForwardedSiteABytes == nil ||
		wire.ForwardedSiteB == nil || wire.ForwardedSiteBBytes == nil ||
		wire.Dropped == nil || wire.DroppedBytes == nil {
		return errors.New("relay telemetry requires all six counters")
	}
	*t = RelayTelemetry{
		ForwardedSiteA: *wire.ForwardedSiteA, ForwardedSiteABytes: *wire.ForwardedSiteABytes,
		ForwardedSiteB: *wire.ForwardedSiteB, ForwardedSiteBBytes: *wire.ForwardedSiteBBytes,
		Dropped: *wire.Dropped, DroppedBytes: *wire.DroppedBytes,
	}
	return nil
}

type Error struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// RendezvousPlan is delivered only over the authenticated control session.
// Candidate addresses and ProbeKey must never be included in logs or status.
type RendezvousPlan struct {
	Type            string   `json:"type"`
	Circuit         string   `json:"circuit"`
	Version         string   `json:"version"`
	DeploymentID    string   `json:"deployment_id"`
	RelayGeneration string   `json:"relay_generation"`
	Generation      string   `json:"generation"`
	PeerGeneration  string   `json:"peer_generation"`
	Session         string   `json:"session"`
	ProbeKey        string   `json:"probe_key"`
	Role            string   `json:"role"`
	Attempt         uint32   `json:"attempt"`
	PathEpoch       uint64   `json:"path_epoch"`
	StartUnix       int64    `json:"start_unix"`
	ExpiresUnix     int64    `json:"expires_unix"`
	Candidates      []string `json:"candidates"`
}

type PathReport struct {
	Type      string `json:"type"`
	Session   string `json:"session"`
	PathEpoch uint64 `json:"path_epoch"`
	State     string `json:"state"`
	Reason    string `json:"reason,omitempty"`
}
