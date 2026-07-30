package control

import (
	"errors"
	"strings"
	"testing"
)

func TestDecoderBoundsAndStrictness(t *testing.T) {
	tests := []struct {
		name string
		wire string
		want error
	}{
		{name: "valid", wire: `{"type":"heartbeat"}` + "\n"},
		{name: "escaped value remains canonical", wire: `{"type":"heart\nbeat"}` + "\n"},
		{name: "unknown field", wire: `{"type":"heartbeat","secret":"no"}` + "\n", want: errors.New("reject")},
		{name: "noncanonical field case", wire: `{"Type":"heartbeat"}` + "\n", want: errors.New("reject")},
		{name: "duplicate field", wire: `{"type":"heartbeat","type":"register"}` + "\n", want: errors.New("reject")},
		{name: "escaped field", wire: `{"\u0074ype":"heartbeat"}` + "\n", want: errors.New("reject")},
		{name: "two values", wire: `{"type":"heartbeat"} {}` + "\n", want: errors.New("reject")},
		{name: "non-object", wire: `[]` + "\n", want: errors.New("reject")},
		{name: "no delimiter", wire: `{"type":"heartbeat"}`, want: errors.New("reject")},
		{name: "oversized", wire: strings.Repeat("x", MaxMessageSize+1) + "\n", want: ErrMessageTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Heartbeat
			err := NewDecoder(strings.NewReader(tt.wire)).Decode(&got)
			if tt.want == nil && err != nil {
				t.Fatalf("valid message rejected: %v", err)
			}
			if tt.want != nil && err == nil {
				t.Fatal("invalid message accepted")
			}
			if errors.Is(tt.want, ErrMessageTooLarge) && !errors.Is(err, ErrMessageTooLarge) {
				t.Fatalf("got %v, want size error", err)
			}
		})
	}
}

func TestDecoderRejectsDuplicateNestedTelemetryField(t *testing.T) {
	wire := `{"type":"heartbeat-ack","sequence":1,"edge_monotonic_nano":1,` +
		`"relay_receive_unix_nano":1,"relay_send_unix_nano":1,"relay_telemetry":{` +
		`"forwarded_site_a":1,"forwarded_site_a":2,"forwarded_site_a_bytes":3,` +
		`"forwarded_site_b":4,"forwarded_site_b_bytes":5,"dropped":6,"dropped_bytes":7}}` + "\n"
	var got HeartbeatAck
	if err := NewDecoder(strings.NewReader(wire)).Decode(&got); err == nil {
		t.Fatal("nested duplicate control field was accepted")
	}
}

func TestDecoderRejectsNoncanonicalNestedTelemetryFieldCase(t *testing.T) {
	wire := `{"type":"heartbeat-ack","sequence":1,"edge_monotonic_nano":1,` +
		`"relay_receive_unix_nano":1,"relay_send_unix_nano":1,"relay_telemetry":{` +
		`"Forwarded_site_a":1,"forwarded_site_a_bytes":3,"forwarded_site_b":4,` +
		`"forwarded_site_b_bytes":5,"dropped":6,"dropped_bytes":7}}` + "\n"
	var got HeartbeatAck
	if err := NewDecoder(strings.NewReader(wire)).Decode(&got); err == nil {
		t.Fatal("nested noncanonical control field case was accepted")
	}
}

func FuzzDecoder(f *testing.F) {
	f.Add([]byte(`{"type":"heartbeat"}` + "\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > MaxMessageSize*2 {
			t.Skip()
		}
		var got Heartbeat
		_ = NewDecoder(strings.NewReader(string(wire))).Decode(&got)
	})
}
