package fleet

import (
	"os"
	"testing"

	"github.com/litevirt/litevirt/internal/pitoverlay"
)

// TestMain lets point-in-time overlays sit in the harness's temporary
// directories, which may be a tmpfs; production refuses an overlay there
// (pitoverlay.Placement).
func TestMain(m *testing.M) {
	pitoverlay.AllowVolatileForTest()
	pitoverlay.OpenFeatureForTest()
	os.Exit(m.Run())
}
