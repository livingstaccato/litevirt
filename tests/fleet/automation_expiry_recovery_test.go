package fleet

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// A renewed healthy quorum must recover a lagging replica even if the only
// other up-to-date replica is unavailable after stored certificates expire.
func TestAutomationReplayExpiredHeadLaggingQuorum(t *testing.T) {
	for _, coordinator := range []int{2, 0} {
		t.Run(fmt.Sprintf("coordinator-%d", coordinator), func(t *testing.T) {
			expiry := time.Now().Add(18 * time.Second).Truncate(time.Second)
			f := newAutomationFixtureWith(t, 3, true, func(c *Cluster) { shortAutomationCertificates(t, c, expiry) })
			f.Isolate(2)
			for _, id := range []string{"review-expiry-two", "review-expiry-three"} {
				if _, err := f.Engine(0).Submit(f.Context(), f.Barrier(0, id)); err != nil {
					t.Fatal(err)
				}
			}
			if f.Head(t, 2).Sequence != 1 {
				t.Fatal("lagging replica unexpectedly advanced")
			}
			f.Heal(2)
			for _, n := range f.cluster.Nodes {
				serial, err := pki.CertSerial(filepath.Join(n.PKIDir, "host.crt"))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := corrosion.RecordOwnCertSerial(f.Context(), n.DB, n.Name, serial); err != nil {
					t.Fatal(err)
				}
			}
			f.cluster.WaitConverged(t, convergeTimeout)
			for _, n := range f.cluster.Nodes {
				installRenewal(t, f.cluster, n)
			}
			f.Isolate(1)
			time.Sleep(time.Until(expiry.Add(100 * time.Millisecond)))
			if f.Head(t, 0).Sequence != 3 || f.Head(t, 2).Sequence != 1 {
				t.Fatal("unexpected recovery precondition")
			}
			ctx, cancel := context.WithTimeout(f.Context(), 6*time.Second)
			defer cancel()
			if err := f.Engine(coordinator).Recover(ctx); err != nil {
				t.Fatalf("renewed two-voter quorum could not recover expired head through its missing predecessor: %v", err)
			}
			if f.Head(t, 2) != f.Head(t, 0) {
				t.Fatal("reachable quorum failed to converge")
			}

		})
	}
}
