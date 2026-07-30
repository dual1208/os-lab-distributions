package rendezvous

import "testing"

func TestPlanMaterialNamespaceEncodingIsUnambiguous(t *testing.T) {
	reservation := EpochReservation{Epoch: 9}
	reservation.MaterialSeed[0] = 0x91
	firstSession, firstKey := derivePlanMaterial(
		reservation, "alpha", "beta\x00gamma", testDeploymentID, testRelayGeneration,
	)
	secondSession, secondKey := derivePlanMaterial(
		reservation, "alpha\x00beta", "gamma", testDeploymentID, testRelayGeneration,
	)
	if firstSession == secondSession || firstKey == secondKey {
		t.Fatal("distinct circuit/version namespaces collided through delimiter injection")
	}
}
