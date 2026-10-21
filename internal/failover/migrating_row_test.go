package failover

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A VM recorded migrating on a fenced host is rescheduled only on
// SettleMigratingRow's MigratingRecover. Unwired, or on Hold or Settled, its
// row is left as it is, and a hold names the VM on the host's hold reason
// and owes a retry of the recovery. A running VM beside it is rescheduled
// either way, so the recovery ran.
//
// Mutation: drop the migrating check in recoverWorkloads — every arm but
// "recover" sees mg1 rescheduled pending to good.
func TestRecoverWorkloads_MigratingRowIsDecidedBySettleMigratingRow(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hook     bool
		verdict  MigratingVerdict
		moved    bool
		heldNote bool
	}{
		{name: "unwired", heldNote: true},
		{name: "hold", hook: true, verdict: MigratingHold, heldNote: true},
		{name: "settled", hook: true, verdict: MigratingSettled},
		{name: "recover", hook: true, verdict: MigratingRecover, moved: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestDB(t)
			ctx := context.Background()
			for _, h := range []corrosion.HostRecord{
				{Name: "bad", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "fenced", FenceStrategy: "manual", CPUTotal: 16, MemTotal: 65536},
				{Name: "good", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", FenceStrategy: "manual", CPUTotal: 16, MemTotal: 65536},
				{Name: "tgt", Address: "10.0.0.3", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "fenced", FenceStrategy: "manual", CPUTotal: 1, MemTotal: 1},
			} {
				if err := corrosion.InsertHost(ctx, db, h); err != nil {
					t.Fatal(err)
				}
			}
			for _, v := range []corrosion.VMRecord{
				{Name: "mg1", HostName: "bad", State: "migrating", StateDetail: "→ tgt"},
				{Name: "rv1", HostName: "bad", State: "running"},
			} {
				v.CPUActual, v.MemActual, v.Spec = 1, 512, `{"on_host_failure":"restart-any"}`
				if err := corrosion.InsertVM(ctx, db, v, nil, nil); err != nil {
					t.Fatal(err)
				}
			}
			c := newTestCoordinator("good", db)
			var asked []string
			if tc.hook {
				c.SettleMigratingRow = func(_ context.Context, vm corrosion.VMRecord, source string) (MigratingVerdict, string) {
					asked = append(asked, vm.Name+"@"+source)
					return tc.verdict, "the test's verdict"
				}
			}
			c.recoverWorkloads(ctx, &corrosion.HostRecord{Name: "bad", State: "fenced"})

			if vm, _ := corrosion.GetVM(ctx, db, "rv1"); vm == nil || vm.HostName != "good" {
				t.Fatalf("rv1 = %+v, want it rescheduled to good: the recovery did not run", vm)
			}
			if tc.hook && (len(asked) != 1 || asked[0] != "mg1@bad") {
				t.Fatalf("SettleMigratingRow was asked %v, want once for mg1 on bad", asked)
			}
			vm, _ := corrosion.GetVM(ctx, db, "mg1")
			if tc.moved {
				if vm == nil || vm.HostName != "good" || vm.State != "pending" {
					t.Fatalf("mg1 = %+v, want it rescheduled to good on MigratingRecover", vm)
				}
				return
			}
			if vm == nil || vm.HostName != "bad" || vm.State != "migrating" {
				t.Fatalf("mg1 = %+v, want its row left migrating on bad", vm)
			}
			held := strings.Contains(c.holdReason["bad"], "mg1")
			if held != tc.heldNote || held != c.claimRetry["bad"] {
				t.Fatalf("hold reason %q, retry owed %v; want a hold naming mg1 and a retry: %v",
					c.holdReason["bad"], c.claimRetry["bad"], tc.heldNote)
			}
		})
	}
}
