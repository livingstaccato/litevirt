package failover

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A VM recorded migrating on a fenced host is rescheduled only on
// SettleMigratingRows' MigratingRecover. Unwired, or on Hold or Settled (or
// no decision for it), its row is left as it is, and a hold names the VM on
// the host's hold reason and owes a retry of the recovery. A running VM
// beside it is rescheduled either way, so the recovery ran. The hook is
// called once per pass with every migrating VM of the host, so their targets
// are asked once, not once per VM.
//
// Mutation: drop the migrating check in recoverWorkloads — every arm but
// "recover" sees mg1 rescheduled pending to good.
func TestRecoverWorkloads_MigratingRowIsDecidedBySettleMigratingRows(t *testing.T) {
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
				// mg0 gets no decision from the hook: held, whatever the hook says of mg1.
				// It sorts first, so mg1's hold reason, when it has one, is the newest.
				{Name: "mg0", HostName: "bad", State: "migrating", StateDetail: "→ tgt"},
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
				c.SettleMigratingRows = func(_ context.Context, source string, vms []corrosion.VMRecord, _ time.Time) map[string]MigratingDecision {
					var names []string
					for _, vm := range vms {
						names = append(names, vm.Name)
					}
					asked = append(asked, strings.Join(names, ",")+"@"+source)
					return map[string]MigratingDecision{"mg1": {Verdict: tc.verdict, Detail: "the test's verdict"}}
				}
			}
			c.recoverWorkloads(ctx, &corrosion.HostRecord{Name: "bad", State: "fenced"})

			if vm, _ := corrosion.GetVM(ctx, db, "rv1"); vm == nil || vm.HostName != "good" {
				t.Fatalf("rv1 = %+v, want it rescheduled to good: the recovery did not run", vm)
			}
			if tc.hook && (len(asked) != 1 || asked[0] != "mg0,mg1@bad") {
				t.Fatalf("SettleMigratingRows was asked %v, want once for mg0 and mg1 on bad", asked)
			}
			if vm, _ := corrosion.GetVM(ctx, db, "mg0"); vm == nil || vm.HostName != "bad" || vm.State != "migrating" {
				t.Fatalf("mg0 = %+v, given no decision; want its row left migrating on bad", vm)
			}
			if !c.claimRetry["bad"] {
				t.Fatal("no retry is owed for mg0's hold")
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
			held := strings.Contains(c.holdReason["bad"], "VM mg1 ")
			if held != tc.heldNote {
				t.Fatalf("hold reason %q; want one naming mg1: %v", c.holdReason["bad"], tc.heldNote)
			}
		})
	}
}

// Every host a poll recovers asks its migration targets against ONE
// deadline, set when the poll starts: a second held source does not get a
// budget of its own, so held sources whose targets do not answer cost a poll
// at most MigratingAskBudget together.
//
// Mutation: take the deadline per recovered host (askClock()+budget in
// settleMigratingVMs) — the two hosts' deadlines differ, red.
func TestRecoverWorkloads_OneAskDeadlinePerPoll(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	for _, h := range []corrosion.HostRecord{
		{Name: "bad1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "fenced", FenceStrategy: "manual", CPUTotal: 16, MemTotal: 65536},
		{Name: "bad2", Address: "10.0.0.4", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "fenced", FenceStrategy: "manual", CPUTotal: 16, MemTotal: 65536},
		{Name: "good", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", FenceStrategy: "manual", CPUTotal: 16, MemTotal: 65536},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []corrosion.VMRecord{
		{Name: "m1", HostName: "bad1", State: "migrating", StateDetail: "→ tgt"},
		{Name: "m2", HostName: "bad2", State: "migrating", StateDetail: "→ tgt"},
	} {
		v.CPUActual, v.MemActual, v.Spec = 1, 512, `{"on_host_failure":"restart-any"}`
		if err := corrosion.InsertVM(ctx, db, v, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	c := newTestCoordinator("good", db)
	clock := time.Unix(1_800_000_000, 0)
	c.askNow = func() time.Time { clock = clock.Add(3 * time.Second); return clock }
	got := map[string]time.Time{}
	c.SettleMigratingRows = func(_ context.Context, source string, _ []corrosion.VMRecord, askBy time.Time) map[string]MigratingDecision {
		got[source] = askBy
		return nil
	}
	c.beginMigratingAsks()
	start := c.migratingAskBy.Add(-MigratingAskBudget)
	c.recoverWorkloads(ctx, &corrosion.HostRecord{Name: "bad1", State: "fenced"})
	c.recoverWorkloads(ctx, &corrosion.HostRecord{Name: "bad2", State: "fenced"})
	if len(got) != 2 || !got["bad1"].Equal(got["bad2"]) || !got["bad1"].Equal(start.Add(MigratingAskBudget)) {
		t.Fatalf("ask deadlines %v; want one, the poll's start + %s (%s)", got, MigratingAskBudget, start.Add(MigratingAskBudget))
	}
}
