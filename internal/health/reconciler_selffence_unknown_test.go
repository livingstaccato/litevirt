package health

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A fenced host that comes back after a hard power loss finds a leftover domain
// for every VM that was rescheduled away, and libvirt reports each as
// `shut off (unknown)` — the shutoff reason does not survive the reboot. The
// reason allowlist alone cannot tell that apart from a domain whose history is
// genuinely unknown, so "unknown" is cleaned only on additional positive proof:
// no managed-save image, and the DB owner itself reporting the VM RUNNING in its
// own libvirt. These tests pin both halves: the leftover IS cleaned with the
// proof, and is NOT cleaned the moment any piece of it is missing.

// selfFenceUnknownFixture seeds vm1 owned by node-b, a local shut-off domain on
// node-a with the given reason, and returns the fake and a reconciler for node-a.
func selfFenceUnknownFixture(t *testing.T, reason string) (*libvirtfake.Fake, *Reconciler) {
	t.Helper()
	db := testReconcilerDB(t)
	if err := corrosion.InsertVM(context.Background(), db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-b", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateDefined) // coarse "stopped"
	fake.SetStateReason("vm1", reason)
	return fake, NewReconciler("node-a", t.TempDir(), db, fake)
}

// ownerRunsIt answers the peer probe the way node-b does when it really runs vm1,
// and every other host (and every other VM) the way an unrelated host does.
func ownerRunsIt(probed *[]string) func(context.Context, string, string) (string, error) {
	return func(_ context.Context, host, name string) (string, error) {
		*probed = append(*probed, host+"/"+name)
		if host == "node-b" && name == "vm1" {
			return RuntimeRunning, nil
		}
		return RuntimeAbsent, nil
	}
}

func TestReconciler_SelfFence_UnknownReasonLeftoverCleanedWhenOwnerRunsIt(t *testing.T) {
	fake, r := selfFenceUnknownFixture(t, "unknown")
	var probed []string
	r.SetPeerRuntimeChecker(ownerRunsIt(&probed))

	r.selfFence(context.Background())

	if fake.DomainExists("vm1") || !wasUndefined(fake, "vm1") || wasDestroyed(fake, "vm1") {
		t.Fatalf("a shut-off (unknown) leftover with no managed-save image, whose DB owner runs the VM, must be undefined without a destroy call; probed=%v", probed)
	}
	if len(probed) != 1 || probed[0] != "node-b/vm1" {
		t.Fatalf("the proof must come from the DB owner's own runtime, probed=%v", probed)
	}
}

func TestReconciler_SelfFence_UnknownReasonNotCleanedWithoutFullProof(t *testing.T) {
	errProbe := errors.New("peer unreachable")
	cases := []struct {
		name  string
		setup func(f *libvirtfake.Fake, r *Reconciler, probed *[]string)
	}{
		{"no peer checker wired", func(f *libvirtfake.Fake, r *Reconciler, _ *[]string) {}},
		{"managed-save image present", func(f *libvirtfake.Fake, r *Reconciler, p *[]string) {
			f.SetManagedSaveImage("vm1", true)
			r.SetPeerRuntimeChecker(ownerRunsIt(p))
		}},
		{"managed-save image unreadable", func(f *libvirtfake.Fake, r *Reconciler, p *[]string) {
			f.FailHasManagedSaveImage = func(string) error { return context.DeadlineExceeded }
			r.SetPeerRuntimeChecker(ownerRunsIt(p))
		}},
		{"owner unreachable", func(f *libvirtfake.Fake, r *Reconciler, _ *[]string) {
			r.SetPeerRuntimeChecker(func(context.Context, string, string) (string, error) { return "", errProbe })
		}},
		{"owner reports it absent", func(f *libvirtfake.Fake, r *Reconciler, _ *[]string) {
			r.SetPeerRuntimeChecker(func(context.Context, string, string) (string, error) { return RuntimeAbsent, nil })
		}},
		{"owner reports it defined but stopped", func(f *libvirtfake.Fake, r *Reconciler, _ *[]string) {
			r.SetPeerRuntimeChecker(func(context.Context, string, string) (string, error) { return RuntimeDefinedStopped, nil })
		}},
		{"owner reports unknown", func(f *libvirtfake.Fake, r *Reconciler, _ *[]string) {
			r.SetPeerRuntimeChecker(func(context.Context, string, string) (string, error) { return RuntimeUnknown, nil })
		}},
		{"only a non-owner runs it", func(f *libvirtfake.Fake, r *Reconciler, _ *[]string) {
			r.SetPeerRuntimeChecker(func(_ context.Context, host, _ string) (string, error) {
				if host == "node-b" {
					return RuntimeAbsent, nil
				}
				return RuntimeRunning, nil
			})
		}},
		{"local domain not stopped", func(f *libvirtfake.Fake, r *Reconciler, p *[]string) {
			f.SetState("vm1", libvirtfake.StateRunning) // reason stays "unknown"
			r.SetPeerRuntimeChecker(ownerRunsIt(p))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake, r := selfFenceUnknownFixture(t, "unknown")
			var probed []string
			tc.setup(fake, r, &probed)

			r.selfFence(context.Background())

			if !fake.DomainExists("vm1") || wasDestroyed(fake, "vm1") {
				t.Fatalf("a shut-off (unknown) domain must NOT be cleaned when %s", tc.name)
			}
		})
	}
}

// Every leftover of a fence-and-return names the same owner. When that owner is
// unreachable, selfFence probes it ONCE per pass: each probe can take
// peerRuntimeProbeTimeout, and one per leftover would hold the whole reconcile
// tick for timeout × leftovers.
func TestReconciler_SelfFence_UnreachableOwnerProbedOncePerPass(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	fake := libvirtfake.New()
	for _, name := range []string{"vm1", "vm2", "vm3"} {
		if err := corrosion.InsertVM(ctx, db,
			corrosion.VMRecord{Name: name, HostName: "node-b", Spec: "{}", State: "running"}, nil, nil); err != nil {
			t.Fatalf("InsertVM: %v", err)
		}
		fake.SetState(name, libvirtfake.StateDefined)
		fake.SetStateReason(name, "unknown")
	}
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	probes := 0
	r.SetPeerRuntimeChecker(func(context.Context, string, string) (string, error) {
		probes++
		return "", errors.New("peer unreachable")
	})

	r.selfFence(ctx)

	if probes != 1 {
		t.Fatalf("an unreachable owner must be probed once per pass, got %d probes", probes)
	}
	for _, name := range []string{"vm1", "vm2", "vm3"} {
		if !fake.DomainExists(name) || wasDestroyed(fake, name) {
			t.Fatalf("%s must not be cleaned while its owner is unreachable", name)
		}
	}
}

// The owner-runs-it proof is admitted ONLY for reason "unknown". A domain holding
// resumable or investigable state stays untouchable even when the owner runs the
// VM and no managed-save image is reported — the reason itself is the evidence.
func TestReconciler_SelfFence_OwnerProofDoesNotWidenOtherReasons(t *testing.T) {
	for _, reason := range []string{"paused", "pmsuspended", "saved", "from-snapshot", "shutting-down", "crashed", "migrated"} {
		t.Run(reason, func(t *testing.T) {
			fake, r := selfFenceUnknownFixture(t, reason)
			var probed []string
			r.SetPeerRuntimeChecker(ownerRunsIt(&probed))

			r.selfFence(context.Background())

			if !fake.DomainExists("vm1") || wasDestroyed(fake, "vm1") {
				t.Fatalf("selfFence must NOT clean a domain with reason %q even when the owner runs the VM", reason)
			}
		})
	}
}
