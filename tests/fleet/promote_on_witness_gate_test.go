package fleet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// The witness promote answers the drain gate, not the worker gate, and that
// gate still holds the two checks that keep a promote from landing a second
// copy: the witness must not be self-fenced and must hold quorum. Neither
// refusal defines anything or moves the row.
//
// Mutation: no gate at all on the witness path (gateRefused forced false) -
// both rows go red.
func TestFleet_APromoteOnAWitnessStillNeedsQuorumAndNoSelfFence(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"self-fenced", health.ReasonSelfFenced},
		{"no quorum", health.ReasonNoQuorum},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wr := newWitnessReplica(t)
			ctx := context.Background()
			gates := enforceGateWithWitness(t, wr.c, wr.w)
			wr.loseOwner(t)
			g := gates[wr.w.Name]
			if tc.name == "self-fenced" {
				g.SetSelfFenced(func() bool { return true })
			} else {
				g.SeedPeersForTests(map[string]bool{wr.a.Name: false, wr.b.Name: false}) // it reaches nobody: a minority
			}
			if r := g.DrainExecutionGate(ctx); r.OK || r.Reason != tc.want {
				t.Fatalf("scenario: the witness's drain gate = %+v, want it refusing with %s", r, tc.want)
			}
			_, err := wr.promote(t)
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("promote on the %s witness: got %v, want FailedPrecondition naming %s", tc.name, err, tc.want)
			}
			if wr.w.Virt.DomainExists("db") {
				t.Errorf("the refused promote defined db on the witness")
			}
			if vm, _ := corrosion.GetVM(ctx, wr.b.DB, "db"); vm == nil || vm.HostName != wr.a.Name {
				t.Errorf("the refused promote moved the row: %+v", vm)
			}
		})
	}
}

// The operator's promote usually enters on a worker, which relays it to the
// witness holding the replica; and a renamed promote there is refused, with a
// message that says what a same-name promote is.
func TestFleet_APromoteOnAWitnessThroughAWorkerAndARenameRefused(t *testing.T) {
	wr := newWitnessReplica(t)
	ctx := context.Background()
	enforceGateWithWitness(t, wr.c, wr.w)
	wr.loseOwner(t)

	_, err := wr.promoteVia(t, wr.b, "db2")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "witness") || !strings.Contains(err.Error(), "host is down") {
		t.Fatalf("renamed promote of a replica on a witness: got %v, want a witness refusal that says what a same-name promote is", err)
	}
	if wr.w.Virt.DomainExists("db2") || wr.w.Virt.DomainExists("db") {
		t.Fatalf("the refused rename defined a domain on the witness")
	}

	done, err := wr.promoteVia(t, wr.b, "")
	if err != nil {
		t.Fatalf("promote entering on worker %s, relayed to the witness: %v", wr.b.Name, err)
	}
	if !strings.Contains(done, "NOT started") {
		t.Errorf("the relayed promote's status %q does not say the VM is not started", done)
	}
	if vm, _ := corrosion.GetVM(ctx, wr.b.DB, "db"); vm == nil || vm.HostName != wr.w.Name || vm.State != "stopped" {
		t.Fatalf("db after the relayed promote = %+v, want it stopped on %s", vm, wr.w.Name)
	}
	if active, _ := wr.w.Virt.DomainIsActive("db"); active {
		t.Fatalf("db runs on the witness")
	}
}

// A real failover through the coordinator: the owner of db is lost, db's only
// replica is on a witness. The coordinator holds db down, with its own reason
// in the audit (the witness and the steps), not "not point-in-time": nothing
// is defined or started anywhere, the row stays on the fenced owner, and the
// replica is untouched.
//
// Mutations: heldCause back to the not-point-in-time text - the audit row goes
// red; drop ErrReplicaOnWitness's wrap of ErrPromoteHeld - the VM is
// rescheduled instead of held (red).
func TestFleet_FailoverHoldsAVMWhoseOnlyReplicaIsOnAWitness(t *testing.T) {
	wr := newWitnessReplica(t)
	ctx := context.Background()
	replicas := func() string {
		ents, _ := os.ReadDir(filepath.Join(wr.c.tmpRoot, "dr", ".replicas"))
		var out []string
		for _, e := range ents {
			out = append(out, e.Name())
		}
		return strings.Join(out, ",")
	}
	before := replicas()
	if before == "" {
		t.Fatalf("scenario: no replica reached the witness's pool")
	}
	// The owner's observers: the coordinator's node, and the witness.
	failVictim(t, wr.b, wr.a, wr.b, wr.w)

	skips := failoverSkips(t, wr.b, "db")
	if len(skips) == 0 {
		t.Fatalf("no failover.skip audit row for db: the hold is not on the record")
	}
	for _, want := range []string{"witness", "lv replication promote", "lv migrate", "lv start"} {
		if !strings.Contains(skips[0], want) {
			t.Errorf("the audit row %q does not say %q", skips[0], want)
		}
	}
	if strings.Contains(skips[0], "point-in-time") {
		t.Errorf("the audit row gives the wrong cause: %q", skips[0])
	}
	vm, _ := corrosion.GetVM(ctx, wr.b.DB, "db")
	if vm == nil || vm.HostName != wr.a.Name {
		t.Fatalf("db after the failover = %+v, want it still on the fenced owner %s (held, not rescheduled)", vm, wr.a.Name)
	}
	for _, n := range []*Node{wr.w, wr.b} {
		if n.Virt.DomainExists("db") {
			t.Errorf("db was defined on %s", n.Name)
		}
	}
	if got := replicas(); got != before {
		t.Errorf("the replica changed: %q -> %q", before, got)
	}
	evs, err := corrosion.ListVMEvents(ctx, wr.b.DB, "db", 50, "")
	if err != nil {
		t.Fatal(err)
	}
	held := false
	for _, e := range evs {
		if e.Type == "vm.failover.held" && strings.Contains(e.Detail, "witness") {
			held = true
		}
	}
	if !held {
		t.Errorf("no vm.failover.held event naming the witness among %d events", len(evs))
	}
}
