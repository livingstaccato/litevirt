package fleet

// D2 re-review 3, I-1: a source cleanup stopped part-way (the source daemon
// died in it) resumes at the source's restart and at each minute's retry, and
// it may undefine the leftover and wipe its state only while the target is
// positively alive: active, and answering. A target lost but not yet fenced
// is offline (manual fencing leaves it so until an operator acts; best-effort
// for the detection interval), and a target whose daemon is gone may still
// read active: in both the cleanup holds, the source's copy defined and
// whole, and the operator's exits work.

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// fwliveHoldCrashTargetLost stops the source cleanup with the source daemon's
// death, takes the target down with it (recorded state, when not empty, as
// the cluster then records it), and restarts the source: its start-up
// recovery and a cleanup retry run against the lost target.
func fwliveHoldCrashTargetLost(t *testing.T, strategy, state string) (*Cluster, *Node, *Node, fwmig.Marker) {
	t.Helper()
	ctx := context.Background()
	c, src, dst, _ := fwliveCluster(t)
	if _, err := c.SelfClient(src).ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: dst.Name, FenceStrategy: strategy}); err != nil {
		t.Fatalf("fence strategy %s: %v", strategy, err)
	}
	m := fwliveRestartCleanupCrash(t, c, src, dst, nil)
	fwliveRestartDown(dst)
	if state != "" {
		if err := corrosion.UpdateHostState(ctx, src.DB, dst.Name, state); err != nil {
			t.Fatal(err)
		}
	}
	fwliveRestartUp(t, c, src)
	fwliveRestartRecovered(src)
	src.Server.RetryLiveFirmwareCleanupsOnce(ctx)
	return c, src, dst, m
}

// fwliveHeld: the source's copy is defined, shut off and whole; the marker
// is cleaning and cleanup_failed is open.
func fwliveHeld(t *testing.T, src *Node) {
	t.Helper()
	if st := fwliveState(src); st != string(libvirtfake.StateShutdown) {
		t.Fatalf("%s's leftover is %s, want defined and shut off", src.Name, st)
	}
	fwliveSourceKept(t, src)
	if m, ok := fwliveMarker(t, src); !ok || m.Phase != fwmig.PhaseCleaning {
		t.Fatalf("marker %+v (present %v), want cleaning", m, ok)
	}
	if !fwliveCondition(t, src, "firmware_migration_cleanup_failed") {
		t.Error("no firmware_migration_cleanup_failed while the cleanup holds")
	}
}

func fwliveDoctor(t *testing.T, c *Cluster, n *Node, a pb.FirmwareMoveDoctorAction) error {
	t.Helper()
	_, err := c.SelfClient(n).FirmwareMoveDoctor(context.Background(), &pb.FirmwareMoveDoctorRequest{
		VmName: fwwVM, Action: a, AcknowledgeRollback: a == pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ACCEPT_SOURCE,
	})
	return err
}

// Mutations: hold only on fenced, removed or proved off (the round-3 rule) —
// the offline cases undefine and wipe, red; take `active` alone as alive — the
// active-but-down case undefines and wipes, red.
func TestFleet_FwLiveCleanup_HoldsUntilTheTargetIsPositivelyAlive(t *testing.T) {
	ctx := context.Background()
	for _, strategy := range []string{"best-effort", "manual"} {
		t.Run(strategy+"/offline/accept_source", func(t *testing.T) {
			c, src, dst, _ := fwliveHoldCrashTargetLost(t, strategy, "offline")
			fwliveHeld(t, src)
			err := fwliveDoctor(t, c, src, pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ACCEPT_SOURCE)
			if err == nil || !strings.Contains(err.Error(), "fence-confirm") {
				t.Fatalf("--accept-source before the fence = %v, want refused naming fence-confirm", err)
			}
			fwliveHeld(t, src)
			// The operator powers the target off, then confirms it.
			dst.Virt.ShutOffDomain(fwwVM, "crashed")
			mustFenceConfirm(t, src, dst.Name)
			if err := fwliveDoctor(t, c, src, pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ACCEPT_SOURCE); err != nil {
				t.Fatalf("--accept-source after the fence: %v", err)
			}
			if m, ok := fwliveMarker(t, src); ok {
				t.Fatalf("marker left in %s after --accept-source", m.Phase)
			}
			if row := fwliveRow(t, src); row.HostName != src.Name || row.State != "stopped" {
				t.Errorf("row %s on %s, want stopped on %s", row.State, row.HostName, src.Name)
			}
			fwliveSourceKept(t, src)
			if _, err := c.SelfClient(src).StartVM(ctx, &pb.StartVMRequest{Name: fwwVM}); err != nil {
				t.Fatalf("lv start on %s after the return: %v", src.Name, err)
			}
		})
		t.Run(strategy+"/offline/accept_target", func(t *testing.T) {
			c, src, dst, _ := fwliveHoldCrashTargetLost(t, strategy, "offline")
			fwliveHeld(t, src)
			if err := fwliveDoctor(t, c, src, pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ACCEPT_TARGET); err != nil {
				t.Fatalf("--accept-target with the target down: %v", err)
			}
			if m, ok := fwliveMarker(t, src); ok {
				t.Fatalf("marker left in %s after --accept-target", m.Phase)
			}
			if row := fwliveRow(t, src); row.HostName != dst.Name {
				t.Errorf("row on %s, want %s", row.HostName, dst.Name)
			}
			if q := fwliveQuarantines(src); len(q) != 1 {
				t.Errorf("%s's quarantine %v, want the source's state", src.Name, q)
			}
		})
	}
	t.Run("active_not_answering/resumes_when_back", func(t *testing.T) {
		c, src, dst, _ := fwliveHoldCrashTargetLost(t, "best-effort", "")
		fwliveHeld(t, src)
		fwliveRestartUp(t, c, dst)
		src.Server.RetryLiveFirmwareCleanupsOnce(ctx)
		fwliveMoved(t, src, dst)
	})
}
