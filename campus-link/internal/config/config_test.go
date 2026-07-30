package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadEdgeJSON(t *testing.T, wire string) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "edge.json")
	if err := os.WriteFile(path, []byte(wire), 0600); err != nil {
		t.Fatal(err)
	}
	var cfg Edge
	return Load(path, &cfg)
}

func TestLoadRejectsOversizedConfigurationBeforeDecode(t *testing.T) {
	if err := loadEdgeJSON(t, strings.Repeat(" ", MaxConfigSize+1)); err == nil {
		t.Fatal("oversized configuration accepted")
	}
}

func TestLoadAcceptsOneCanonicalJSONValue(t *testing.T) {
	wire := `{
		"site":"site-a",
		"control_identity":{"uri":"spiffe://campus-link/c/relay/control","current_spki":"sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		"data_identity":{"uri":"spiffe://campus-link/c/site-b/data","current_spki":"sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	}`
	if err := loadEdgeJSON(t, wire); err != nil {
		t.Fatalf("canonical configuration rejected: %v", err)
	}
}

func TestLoadRejectsUnknownDuplicateCaseSmuggledAndTrailingJSON(t *testing.T) {
	tests := []struct {
		name string
		wire string
	}{
		{name: "unknown top-level field", wire: `{"site":"site-a","secret":"no"}`},
		{name: "legacy identity fallback", wire: `{"site":"site-a","data_peer_name":"site-b"}`},
		{name: "duplicate top-level field", wire: `{"site":"site-a","site":"site-b"}`},
		{name: "escaped duplicate map key", wire: `{"prefixes":{"site-a":"one","\u0073ite-a":"two"}}`},
		{name: "escaped canonical field", wire: `{"\u0073ite":"site-a"}`},
		{name: "case-smuggled field", wire: `{"Site":"site-a"}`},
		{name: "case-smuggled duplicate", wire: `{"site":"site-a","Site":"site-b"}`},
		{name: "unknown nested field", wire: `{"control_identity":{"uri":"x","current_spki":"y","extra":"no"}}`},
		{name: "case-smuggled nested field", wire: `{"control_identity":{"URI":"x","current_spki":"y"}}`},
		{name: "duplicate nested field", wire: `{"control_identity":{"uri":"x","uri":"y","current_spki":"z"}}`},
		{name: "second JSON value", wire: `{"site":"site-a"} {}`},
		{name: "trailing garbage", wire: `{"site":"site-a"} nope`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := loadEdgeJSON(t, test.wire); err == nil {
				t.Fatal("non-canonical configuration accepted")
			}
		})
	}
}

func TestLoadRejectsNullWithoutRetainingPopulatedConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`null`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Edge{Site: "site-a", Generation: "must-not-be-silently-retained"}
	if err := Load(path, &cfg); err == nil {
		t.Fatal("top-level null accepted for a populated destination")
	}
}

func TestLoadRequiresNonNilPointerDestination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Load(path, nil); err == nil {
		t.Fatal("nil destination accepted")
	}
	var cfg *Edge
	if err := Load(path, cfg); err == nil {
		t.Fatal("nil pointer destination accepted")
	}
}

func TestLoadPreservesAuthenticatedDeploymentNamespaceFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.json")
	wire := `{
		"circuit":"campus",
		"deployment_id":"0123456789abcdef0123456789abcdef",
		"epoch_state_path":"/var/lib/campus-link/rendezvous-epochs.json"
	}`
	if err := os.WriteFile(path, []byte(wire), 0600); err != nil {
		t.Fatal(err)
	}
	var cfg Relay
	if err := Load(path, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.DeploymentID != "0123456789abcdef0123456789abcdef" ||
		cfg.EpochStatePath != "/var/lib/campus-link/rendezvous-epochs.json" {
		t.Fatalf("deployment namespace fields changed during decode: %#v", cfg)
	}
}
