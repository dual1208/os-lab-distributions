package edge

import (
	"encoding/binary"
	"testing"
)

func TestPlanAuthorityNamespaceUsesCanonicalLengthPrefixes(t *testing.T) {
	version := "v25.12.5+f0a60eee"
	deploymentID := "0123456789abcdef0123456789abcdef"
	relayGeneration := "fedcba9876543210fedcba9876543210"

	got, err := planAuthorityNamespace(version, deploymentID, relayGeneration)
	if err != nil {
		t.Fatal(err)
	}
	values := []string{planAuthorityNamespaceDomain, version, deploymentID, relayGeneration}
	want := make([]byte, 0)
	for _, value := range values {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		want = append(want, length[:]...)
		want = append(want, value...)
	}
	if got != string(want) {
		t.Fatal("plan authority namespace is not the canonical uint32 length-prefixed encoding")
	}
	legacy := version + "\x00" + deploymentID + "\x00" + relayGeneration
	if got == legacy {
		t.Fatal("plan authority namespace retained the forbidden delimiter encoding")
	}
}

func TestPlanAuthorityNamespaceRejectsNonCanonicalInputs(t *testing.T) {
	validVersion := "v25.12.5+f0a60eee"
	validDeployment := "0123456789abcdef0123456789abcdef"
	validRelayGeneration := "fedcba9876543210fedcba9876543210"
	tests := []struct {
		name, version, deployment, generation string
	}{
		{name: "empty version", version: "", deployment: validDeployment, generation: validRelayGeneration},
		{name: "delimiter in version", version: "v25\x00smuggled", deployment: validDeployment, generation: validRelayGeneration},
		{name: "unicode version", version: "v25-β", deployment: validDeployment, generation: validRelayGeneration},
		{name: "uppercase deployment", version: validVersion, deployment: "0123456789ABCDEF0123456789ABCDEF", generation: validRelayGeneration},
		{name: "short relay generation", version: validVersion, deployment: validDeployment, generation: "abcd"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := planAuthorityNamespace(test.version, test.deployment, test.generation); err == nil {
				t.Fatal("non-canonical namespace input accepted")
			}
		})
	}
}
