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
		{name: "unknown field", wire: `{"type":"heartbeat","secret":"no"}` + "\n", want: errors.New("reject")},
		{name: "two values", wire: `{"type":"heartbeat"} {}` + "\n", want: errors.New("reject")},
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
