package edge

import (
	"testing"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/datapath"
)

func TestPublishedDirectInstanceExistsOnlyForHealthySelectedPath(t *testing.T) {
	withdrawn := pathStatus(datapath.Snapshot{
		Selected: datapath.SelectedNone, DirectEpoch: 7, DirectInstanceID: 99,
	}, "recovering")
	if withdrawn.DirectInstance != 0 {
		t.Fatalf("withdrawn path exposed a usable instance: %#v", withdrawn)
	}
	active := pathStatus(datapath.Snapshot{
		Selected: datapath.SelectedDirect, DirectHealthy: true,
		DirectEpoch: 7, DirectInstanceID: 100,
	}, "active")
	if active.DirectInstance != 100 {
		t.Fatalf("healthy selected path lost its instance: %#v", active)
	}
}
