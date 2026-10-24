package fleet

import (
	"os"
	"testing"

	"github.com/litevirt/litevirt/internal/pci"
	"github.com/litevirt/litevirt/internal/pitoverlay"
)

// TestMain lets point-in-time overlays sit in the harness's temporary
// directories, which may be a tmpfs; production refuses an overlay there
// (pitoverlay.Placement).
func TestMain(m *testing.M) {
	pitoverlay.AllowVolatileForTest()
	// No node reads the machine's own NVIDIA driver; the MIG tests install a
	// fake nvidia-smi.
	pci.SetNvidiaSMI("/nonexistent/litevirt-test/nvidia-smi")
	os.Exit(m.Run())
}
