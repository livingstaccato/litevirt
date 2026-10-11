package pitoverlay

import (
	"os"
	"testing"
)

// TestMain opens the pit_overlay release feature for the package's tests;
// the tests of the closed gate close it themselves.
func TestMain(m *testing.M) {
	OpenFeatureForTest()
	os.Exit(m.Run())
}
