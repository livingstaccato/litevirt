package grpcapi

import (
	"sync"
	"testing"
	"time"
)

// The replicator calls DeclaredCapabilities from its own goroutine
// (SetReplicator -> SetAdvertisedCapabilities) while a fleet test wires the
// gate and the enforcement flags on the already-running server. Under -race a
// plain field behind either setter is a data race; this flips each setter while
// DeclaredCapabilities is read.
func TestLateWiringIsSafeAgainstDeclaredCapabilities(t *testing.T) {
	s := testServer(t)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = s.DeclaredCapabilities()
			}
		}
	}()
	deadline := time.Now().Add(300 * time.Millisecond)
	for i := 0; time.Now().Before(deadline); i++ {
		on := i%2 == 0
		s.SetRecoveryClaimEnforce(on)
		s.SetOwnerEpochEnforce(on)
		s.SetProjectAuthorityEnforce(on)
		s.SetEnforcementConfig(on, on, on, on, on, on)
		s.SetGate(fakeServerGate{enforced: on})
	}
	close(stop)
	wg.Wait()
}
