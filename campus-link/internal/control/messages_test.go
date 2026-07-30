package control

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCanonicalAuthenticatedNamespaceIdentifiers(t *testing.T) {
	if !ValidDeploymentID("0123456789abcdef0123456789abcdef") ||
		!ValidRelayGeneration("abcdef0123456789abcdef0123456789") {
		t.Fatal("canonical namespace identifier rejected")
	}
	for _, value := range []string{
		"", "0123", "ABCDEF0123456789ABCDEF0123456789",
		"g123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef00",
	} {
		if ValidDeploymentID(value) || ValidRelayGeneration(value) {
			t.Fatalf("non-canonical namespace identifier accepted: %q", value)
		}
	}
}

func TestCanonicalSourceVersion(t *testing.T) {
	for _, value := range []string{"dev", "test", "phase1-f0a60eee2fe0-0123456789ab", "v1.2.3+build_7"} {
		if !ValidSourceVersion(value) {
			t.Fatalf("canonical source version rejected: %q", value)
		}
	}
	for _, value := range []string{"", " leading", "trailing ", "a/b", "a\x00b", "v1\u00e9", "a" + string(make([]byte, SourceVersionMaxLength))} {
		if ValidSourceVersion(value) {
			t.Fatalf("non-canonical source version accepted: %q", value)
		}
	}
}

func TestCanonicalAuthenticatedClockFields(t *testing.T) {
	if !ValidClockUnixNano(time.Date(2026, time.July, 29, 0, 0, 0, 0, time.UTC).UnixNano()) ||
		!ValidMonotonicSample(1) || !ValidMonotonicSample(MaxMonotonicSample) {
		t.Fatal("canonical authenticated clock field rejected")
	}
	for _, value := range []int64{0, clockUnixNanoMin - 1, clockUnixNanoMax, int64(^uint64(0) >> 1)} {
		if ValidClockUnixNano(value) {
			t.Fatalf("noncanonical wall sample accepted: %d", value)
		}
	}
	if ValidMonotonicSample(0) || ValidMonotonicSample(MaxMonotonicSample+1) {
		t.Fatal("noncanonical monotonic sample accepted")
	}
}

func TestRelayTelemetryWireSchemaIsFixedAndIncludesBytes(t *testing.T) {
	telemetry := RelayTelemetry{
		ForwardedSiteA: 1, ForwardedSiteABytes: 11,
		ForwardedSiteB: 2, ForwardedSiteBBytes: 22,
		Dropped: 3, DroppedBytes: 33,
	}
	wire, err := json.Marshal(telemetry)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]uint64
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	want := map[string]uint64{
		"forwarded_site_a": 1, "forwarded_site_a_bytes": 11,
		"forwarded_site_b": 2, "forwarded_site_b_bytes": 22,
		"dropped": 3, "dropped_bytes": 33,
	}
	if len(decoded) != len(want) {
		t.Fatalf("relay telemetry schema=%v want=%v", decoded, want)
	}
	for key, value := range want {
		if decoded[key] != value {
			t.Fatalf("relay telemetry field %q=%d want=%d", key, decoded[key], value)
		}
	}
	for key := range want {
		missing := make(map[string]uint64, len(want)-1)
		for candidate, value := range want {
			if candidate != key {
				missing[candidate] = value
			}
		}
		malformed, err := json.Marshal(missing)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(malformed, &RelayTelemetry{}); err == nil {
			t.Fatalf("relay telemetry accepted missing field %q", key)
		}
	}
	withExtra := append([]byte(nil), wire[:len(wire)-1]...)
	withExtra = append(withExtra, []byte(`,"unexpected":1}`)...)
	if err := json.Unmarshal(withExtra, &RelayTelemetry{}); err == nil {
		t.Fatal("relay telemetry accepted an expanded schema")
	}
	duplicate := []byte(`{"forwarded_site_a":1,"forwarded_site_a":2,` +
		`"forwarded_site_a_bytes":11,"forwarded_site_b":2,"forwarded_site_b_bytes":22,` +
		`"dropped":3,"dropped_bytes":33}`)
	if err := json.Unmarshal(duplicate, &RelayTelemetry{}); err == nil {
		t.Fatal("relay telemetry accepted a duplicate field")
	}
	escaped := []byte(`{"forwarded_\u0073ite_a":1,"forwarded_site_a_bytes":11,` +
		`"forwarded_site_b":2,"forwarded_site_b_bytes":22,"dropped":3,"dropped_bytes":33}`)
	if err := json.Unmarshal(escaped, &RelayTelemetry{}); err == nil {
		t.Fatal("relay telemetry accepted an escaped field spelling")
	}
	noncanonicalCase := []byte(`{"Forwarded_site_a":1,"forwarded_site_a_bytes":11,` +
		`"forwarded_site_b":2,"forwarded_site_b_bytes":22,"dropped":3,"dropped_bytes":33}`)
	if err := json.Unmarshal(noncanonicalCase, &RelayTelemetry{}); err == nil {
		t.Fatal("relay telemetry accepted noncanonical field case")
	}
}
