//go:build !race

package corrosion

import (
	"github.com/litevirt/litevirt/internal/automation/contract"
	"runtime"
	"testing"
)

var outerAllocationSequence uint64
var outerAllocationError bool

// This serial observation detects retention of the size-only outer marshal.
// It is intentionally excluded from race mode and makes no timing assertion.
func TestAutomationDecisionOuterAllocation(t *testing.T) {
	_, envelope := outerSizeFixture(t, 1<<20)
	v := ClaimValue{Automation: &AutomationClaimValue{Envelope: envelope}}
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	measure := func(f func(ClaimValue) (contract.Decision, error)) float64 {
		return testing.AllocsPerRun(10, func() {
			d, e := f(v)
			outerAllocationSequence = d.Sequence
			outerAllocationError = e != nil
		})
	}
	actual, old := measure(automationDecision), measure(oldAutomationDecision)
	if outerAllocationSequence != 2 || outerAllocationError {
		t.Fatal("measured invalid fixture")
	}
	t.Logf("serial AllocsPerRun(10): actual=%g literal-old=%g", actual, old)
	if actual >= old {
		t.Fatalf("size-only outer marshal allocations remain: actual=%g literal-old=%g; want actual < literal-old", actual, old)
	}
}
