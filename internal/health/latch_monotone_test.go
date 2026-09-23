package health

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// TestDurablyLatchedIsMonotone pins the property the operator documentation
// used to get backwards.
//
// capabilities.go told operators that the way to stop minting lease terms was
// to "stop the fleet being uniform — roll a host back below this build —
// which the latch already reacts to". The mint gate calls
// Checker.DurablyLatched, and DurablyLatched reads the PERSISTED ACTIVATION
// MARKERS. It never consults current peer support, deliberately: a fail-closed
// latch must not re-open the legacy path because a peer went away.
//
// So a rollback stops nothing. The latched nodes keep minting statement shapes
// the downgraded binary cannot resolve, and an unregistered shape
// back-pressures its whole replication stream — the host rolled back to regain
// control is the one that stops replicating. An operator following that
// procedure during an incident makes it worse.
//
// If this test ever goes red, the latch has become non-monotone and the
// corrected documentation in capabilities.go and docs/operating-model.md has
// to be revisited with it.
func TestDurablyLatchedIsMonotone(t *testing.T) {
	base := filepath.Join(t.TempDir(), "split_brain_activated")
	tok := capabilities.LeaseTermLedgerV1

	// A node that has already latched: the marker is on disk, exactly as it
	// would be after the fleet went uniform once.
	if err := os.WriteFile(base+"."+tok, []byte("1\n"), 0o600); err != nil {
		t.Fatalf("seed marker: %v", err)
	}

	c := NewChecker("h1", "/etc/litevirt/pki", nil)
	c.SetActivationMarker(base)

	if !c.DurablyLatched(tok) {
		t.Fatalf("fixture inert: a node with a persisted %s marker must read as latched", tok)
	}

	// Now the fleet stops being uniform. Every peer stops advertising the
	// token — a rollback, or simply every peer becoming unreachable. Nothing
	// here consults peers, so nothing changes.
	c.SetPeerPinger(nil)

	if !c.DurablyLatched(tok) {
		t.Fatal("DurablyLatched stopped reporting a latched token once peer support went " +
			"away; the latch is supposed to be monotone, and the operator docs now say so " +
			"explicitly — if this is a deliberate change, update capabilities.go and " +
			"docs/operating-model.md, which currently tell operators a rollback CANNOT " +
			"stand the ledger down")
	}
}
