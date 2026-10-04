package corrosion

import (
	"sync"
	"testing"
)

// TestSplitGates_SetWhileReplicationReads: the credentials-split and
// lease-term-ledger gates are read on replication goroutines (the WAL apply
// path) that may already be running when a gate is set — the daemon wires
// them at start, and tests swap them mid-run. Under -race, a plain func field
// here is a data race (seen in TestFleet_CredentialsSplit_DualWriteKeepsBothCopies
// on the 2026-09-30 race sweep of 955a57db). The sibling gates already hold an
// atomic.Pointer; these two must too.
//
// Mutation: revert either setter to a plain field assignment — -race reports it.
func TestSplitGates_SetWhileReplicationReads(t *testing.T) {
	c := NewTestClientT(t)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	started := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		close(started)
		for {
			select {
			case <-stop:
				return
			default:
				_ = c.MayWriteCredentialTables()
				_ = c.MayMintLeaseTerm()
			}
		}
	}()
	<-started
	for i := 0; i < 20000; i++ {
		open := i%2 == 0
		c.SetCredentialsSplitGate(func() bool { return open })
		c.SetLeaseTermLedgerGate(func() bool { return open })
	}
	close(stop)
	wg.Wait()
	c.SetCredentialsSplitGate(func() bool { return true })
	if !c.MayWriteCredentialTables() {
		t.Fatal("credentials gate set open reads closed")
	}
	c.SetCredentialsSplitGate(nil)
	if c.MayWriteCredentialTables() {
		t.Fatal("a nil credentials gate must fail closed")
	}
}
