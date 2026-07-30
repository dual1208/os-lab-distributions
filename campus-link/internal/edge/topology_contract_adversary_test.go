package edge

import (
	"testing"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
)

func TestEdgeConstructorEnforcesFixedCampusPrefixes(t *testing.T) {
	for _, site := range []string{"site-a", "site-b"} {
		if _, err := New(adversaryFixedEdgeConfig(site), "test-v1"); err != nil {
			t.Fatalf("valid %s fixed topology rejected: %v", site, err)
		}
	}
	tests := []struct {
		name   string
		site   string
		mutate func(*config.Edge)
	}{
		{name: "site-a arbitrary networks", site: "site-a", mutate: func(cfg *config.Edge) {
			cfg.Prefix, cfg.RemotePrefix = "192.0.2.0/24", "198.51.100.0/24"
		}},
		{name: "site-b arbitrary networks", site: "site-b", mutate: func(cfg *config.Edge) {
			cfg.Prefix, cfg.RemotePrefix = "198.51.100.0/24", "192.0.2.0/24"
		}},
		{name: "site-a reversed ordering", site: "site-a", mutate: func(cfg *config.Edge) {
			cfg.Prefix, cfg.RemotePrefix = cfg.RemotePrefix, cfg.Prefix
		}},
		{name: "site-b reversed ordering", site: "site-b", mutate: func(cfg *config.Edge) {
			cfg.Prefix, cfg.RemotePrefix = cfg.RemotePrefix, cfg.Prefix
		}},
		{name: "local host bits", site: "site-a", mutate: func(cfg *config.Edge) {
			cfg.Prefix = "10.81.0.1/24"
		}},
		{name: "remote host bits", site: "site-b", mutate: func(cfg *config.Edge) {
			cfg.RemotePrefix = "10.81.0.1/24"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := adversaryFixedEdgeConfig(test.site)
			test.mutate(&cfg)
			if _, err := New(cfg, "test-v1"); err == nil {
				t.Fatal("edge constructor accepted topology outside the fixed prefix contract")
			}
		})
	}
}

func adversaryFixedEdgeConfig(site string) config.Edge {
	cfg := config.Edge{
		Site: site, Generation: "edge-generation", Circuit: "campus", DeploymentID: edgeTestDeploymentID,
		RelayAddress: "relay:443", ControlServerName: "relay.example",
		ControlIdentity: config.IdentityAuthorization{
			URI: "spiffe://campus-link/campus/relay/control", CurrentSPKI: zeroSPKIPin,
		},
		MTU: 1200,
	}
	if site == "site-a" {
		cfg.Role, cfg.Prefix, cfg.RemotePrefix = "client", "10.81.0.0/24", "10.82.0.0/24"
		cfg.DataServerName = "site-b.example"
		cfg.DataIdentity = config.IdentityAuthorization{
			URI: "spiffe://campus-link/campus/site-b/data", CurrentSPKI: zeroSPKIPin,
		}
	} else {
		cfg.Role, cfg.Prefix, cfg.RemotePrefix = "server", "10.82.0.0/24", "10.81.0.0/24"
		cfg.DataIdentity = config.IdentityAuthorization{
			URI: "spiffe://campus-link/campus/site-a/data", CurrentSPKI: zeroSPKIPin,
		}
	}
	return cfg
}
