package corrosion

import (
	"context"
	"testing"
	"time"
)

// Review PB-m2: a membership or fence read that fails leaves a removed
// owner unproven, with the error — never a proof. RemovedHostProvedOff reads
// the host's last life from host_membership and then the fence rows; either
// failing returns false and the error, and so do SharedDiskOwnerProvedOff
// (the reattach and every start built from the disk rows) and
// HostProofGradeFence (--dead, the supersede evidence, the removed-host pass).
// The fence on record here would prove the host off if it were read.
//
// Mutation "membership error read as no life" (hostFenceLife's error dropped
// in RemovedHostProvedOff, every row then counted) — red.
func TestRemovedHostProvedOff_AReadErrorIsNoProof(t *testing.T) {
	ctx := context.Background()
	for _, broken := range []string{"host_membership", "fencing_log"} {
		t.Run(broken, func(t *testing.T) {
			c := testClient(t)
			seedHost(t, c, "h1")
			c.SetHostMembershipGate(func() bool { return true })
			if _, err := c.SplitHostMembership(ctx); err != nil || !c.HostMembershipLive() {
				t.Fatalf("split: live=%v err=%v", c.HostMembershipLive(), err)
			}
			if err := c.Execute(ctx, `INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
				VALUES ('f', 'h1', 'ipmi', 'fenced', ?, '')`, time.Now().UTC().Format(time.RFC3339)); err != nil {
				t.Fatal(err)
			}
			if err := DeleteHost(ctx, c, "h1"); err != nil {
				t.Fatal(err)
			}
			if ok, err := RemovedHostProvedOff(ctx, c, "h1"); err != nil || !ok {
				t.Fatalf("before the fault: RemovedHostProvedOff = %v, %v; want the fence counted", ok, err)
			}
			if _, err := c.DB().Exec(`ALTER TABLE ` + broken + ` RENAME TO ` + broken + `_gone`); err != nil {
				t.Fatal(err)
			}
			if ok, err := RemovedHostProvedOff(ctx, c, "h1"); err == nil || ok {
				t.Errorf("RemovedHostProvedOff = %v, %v; want false and the read error", ok, err)
			}
			if _, ok, err := SharedDiskOwnerProvedOff(ctx, c, "h1"); err == nil || ok {
				t.Errorf("SharedDiskOwnerProvedOff = %v, %v; want false and the read error", ok, err)
			}
			if _, ok, err := HostProofGradeFence(ctx, c, "h1"); err == nil || ok {
				t.Errorf("HostProofGradeFence = %v, %v; want false and the read error", ok, err)
			}
		})
	}
}
