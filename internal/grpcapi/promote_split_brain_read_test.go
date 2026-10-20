package grpcapi

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// The promotion's split-brain guard refuses as retryable when a read it
// needs fails: a rename's check for a VM of the new name, and a same-name
// takeover's check that the original's host is no longer healthy. Taken as
// "no such VM" or "no such host", the promotion would define and start a
// guest over another VM's name, or a second copy of a VM still running.
//
// Mutations: either read error ignored (the guard run only on a successful
// read) — the promotion goes ahead, red.
func TestPromoteSplitBrainRefusal_UnreadableReadRefusesAsRetryable(t *testing.T) {
	s, _ := provableCreateServer(t)
	vm := &corrosion.VMRecord{Name: "vm1", HostName: "peer", State: "running"}
	gone, cancel := context.WithCancel(adminCtx())
	cancel() // every read on it fails

	for _, tc := range []struct {
		name    string
		target  string
		renamed bool
	}{
		{"rename onto a name", "vm1-new", true},
		{"same-name takeover from a host", "vm1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := s.promoteSplitBrainRefusal(gone, vm, tc.target, tc.renamed, false)
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("split-brain guard with its read failing = %v; want Unavailable, retryable", err)
			}
			// The same guard with the read answering lets it through: the
			// refusal above is the read's, not the scenario's.
			if err := s.promoteSplitBrainRefusal(adminCtx(), vm, tc.target, tc.renamed, false); err != nil {
				t.Fatalf("split-brain guard with nothing in the way = %v; want nil", err)
			}
		})
	}
	// --force skips the healthy-host check, and with it its read.
	if err := s.promoteSplitBrainRefusal(gone, vm, "vm1", false, true); err != nil {
		t.Fatalf("forced same-name takeover = %v; want nil", err)
	}
}

// proveFencedOff records a proof-grade fence of host (an IPMI power-off).
func proveFencedOff(t *testing.T, s *Server, host string) {
	t.Helper()
	if err := corrosion.InsertFenceLog(context.Background(), s.db, corrosion.FenceLogRecord{
		ID: "ipmi-" + host, HostName: host, Method: "ipmi", Result: "fenced",
	}); err != nil {
		t.Fatal(err)
	}
}

// promoteSameName runs an operator's same-name promote of db (no --force)
// whose owner dead-host is recorded ownerState ("" for no host row), with a
// proof-grade fence of it on record when proved. With hide, a shut-off domain
// db is defined here and that table is hidden at the promotion's DomainState
// read of it, the last call before the split-brain guard.
func promoteSameName(t *testing.T, ownerState string, proved bool, hide string) (error, *libvirtfake.Fake) {
	t.Helper()
	s := testServer(t)
	poolDir := setPromoteVMRows(t, s, "db", nil)
	seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<20)
	if ownerState != "" {
		if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
			Name: "dead-host", Address: "10.0.0.77", State: ownerState,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if proved {
		proveFencedOff(t, s, "dead-host")
	}
	fake := s.virt.(*libvirtfake.Fake)
	if hide != "" {
		if err := fake.DefineDomain("<domain><name>db</name></domain>"); err != nil {
			t.Fatal(err)
		}
		hidden := false
		fake.FailDomainState = func(name string) error {
			if name == "db" && !hidden {
				hidden = true
				if err := s.db.Execute(adminCtx(), `ALTER TABLE `+hide+` RENAME TO `+hide+`_hidden`); err != nil {
					t.Errorf("hide %s: %v", hide, err)
				}
			}
			return nil
		}
	}
	stream := &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()}
	err := s.PromoteReplica(&pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", NoLocalize: true}, stream)
	return err, fake
}

// End to end through PromoteReplica: the guard's host read failing refuses
// as Unavailable, before the collision check and host admission (ccguard
// review M2).
//
// Mutation: the GetHost error ignored — the promotion goes on and fails
// elsewhere, not Unavailable from the guard, red.
func TestPromoteReplica_SameNameOwnerUnreadableRefusesAsRetryable(t *testing.T) {
	err, _ := promoteSameName(t, "active", false, "hosts")
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "still healthy cannot be read") {
		t.Fatalf("promote with hosts unreadable = %v; want Unavailable from the split-brain guard", err)
	}
}

// A same-name promote without --force goes ahead only when the original's
// host is no longer a member, or proven powered off the way a shared disk's
// owner is: fenced or removed over a proof-grade fence. Every other host may
// still run the guest: `lv host drain` records draining while its VMs still
// run there, maintenance, upgrading and offline hosts can be alive, and a
// fence that is not proof-grade (a manual or stale one) can leave the guest
// running (ccguard review I2, round 2).
//
// Mutations: refuse only an active owner (the rule before round 1) — db
// starts beside a live owner, red; accept a recorded fenced or removed state
// without its proof (round 1) — the unproven cases are not refused, red.
func TestPromoteReplica_SameNameRefusedUnlessOwnerProvenOff(t *testing.T) {
	for _, c := range []struct {
		state  string
		proved bool
	}{
		{"active", false}, {"draining", false}, {"maintenance", false}, {"upgrading", false},
		{"offline", false}, {"joining", false}, {"fenced", false}, {"removed", false},
		{"active", true}, {"draining", true},
	} {
		t.Run(fmt.Sprintf("%s proved=%v", c.state, c.proved), func(t *testing.T) {
			err, fake := promoteSameName(t, c.state, c.proved, "")
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "may still run on its host") ||
				!strings.Contains(err.Error(), "lv host fence") {
				t.Fatalf("promote with owner %s (proved %v) = %v; want FailedPrecondition naming the way out", c.state, c.proved, err)
			}
			if raw, _ := fake.RawState("db"); raw == libvirtfake.StateRunning {
				t.Fatalf("db started here while its owner is %s (proved %v)", c.state, c.proved)
			}
		})
	}
	for _, c := range []struct {
		state  string
		proved bool
	}{{"fenced", true}, {"removed", true}, {"", false}} {
		t.Run(fmt.Sprintf("%q proved=%v", c.state, c.proved), func(t *testing.T) {
			err, _ := promoteSameName(t, c.state, c.proved, "")
			if err != nil && strings.Contains(err.Error(), "may still run on its host") {
				t.Fatalf("promote with owner %q (proved %v) refused by the split-brain guard: %v", c.state, c.proved, err)
			}
		})
	}
}
