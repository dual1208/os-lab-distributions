package relay

import (
	"testing"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
)

func TestRegistrationRequiresExactSupportedTransport(t *testing.T) {
	server := &Server{
		cfg: config.Relay{
			Circuit: "campus", DeploymentID: relayTestDeploymentID,
			Prefixes: map[string]string{"site-a": "10.81.0.0/24", "site-b": "10.82.0.0/24"},
		},
		version: relayTestVersion,
	}
	valid := control.Register{
		Type: "register", Site: "site-a", Generation: "generation-a", Version: relayTestVersion,
		DeploymentID: relayTestDeploymentID, Circuit: "campus", Prefix: "10.81.0.0/24",
		Transports: []string{"quic-datagram"},
	}
	if !server.validRegistration(valid, "site-a") {
		t.Fatal("exact supported transport registration was rejected")
	}
	tests := []struct {
		name       string
		transports []string
	}{
		{name: "missing"},
		{name: "empty", transports: []string{}},
		{name: "unsupported", transports: []string{"tcp"}},
		{name: "extra", transports: []string{"quic-datagram", "unexpected"}},
		{name: "duplicate", transports: []string{"quic-datagram", "quic-datagram"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			candidate.Transports = test.transports
			if server.validRegistration(candidate, "site-a") {
				t.Fatal("registration without the exact supported transport was accepted")
			}
		})
	}
}
