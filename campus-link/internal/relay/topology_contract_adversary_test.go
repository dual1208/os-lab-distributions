package relay

import "testing"

func TestRelayConstructorEnforcesFixedCampusPrefixes(t *testing.T) {
	if _, err := NewForPreflight(validRelayConfig(t), relayTestVersion); err != nil {
		t.Fatalf("valid fixed relay topology rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(map[string]string)
	}{
		{name: "arbitrary networks", mutate: func(prefixes map[string]string) {
			prefixes["site-a"], prefixes["site-b"] = "192.0.2.0/24", "198.51.100.0/24"
		}},
		{name: "reversed ordering", mutate: func(prefixes map[string]string) {
			prefixes["site-a"], prefixes["site-b"] = prefixes["site-b"], prefixes["site-a"]
		}},
		{name: "site-a host bits", mutate: func(prefixes map[string]string) {
			prefixes["site-a"] = "10.81.0.1/24"
		}},
		{name: "site-b host bits", mutate: func(prefixes map[string]string) {
			prefixes["site-b"] = "10.82.0.1/24"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validRelayConfig(t)
			test.mutate(cfg.Prefixes)
			if _, err := NewForPreflight(cfg, relayTestVersion); err == nil {
				t.Fatal("relay constructor accepted topology outside the fixed prefix contract")
			}
		})
	}
}
