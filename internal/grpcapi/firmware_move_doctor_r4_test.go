package grpcapi

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Re-review D2-18 round 3 (APPROVE, m-1..m-3): the reconciler's firmware
// quarantines are listed and retained like superseded disks (m-1); every
// action on a VM whose only record is a leftover reaches the host that keeps
// it (m-2); a leftover whose row later names its host for the leftover's own
// incarnation has an lv exit that keeps it as the VM's own (m-3).
func TestDoctorFirmwareMove_R4(t *testing.T) {
	ctx := context.Background()
	// returnedReleased: a released move returned to the fenced source; the
	// target is back with the leftover shut off, and the source's owed
	// DISCARD has put it under a leftover record.
	returnedReleased := func(t *testing.T) (*fwlRig, fwmig.OwedDiscard) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseReleased)
		r.park(run, fwmig.PhaseTargetUnreachable, "Release was not answered")
		r.fenceTarget()
		if _, err := r.doctor(actAcceptSource, withAck); err != nil {
			t.Fatalf("accept-source: %v", err)
		}
		owed, _ := r.src.fwRecords().ListOwedDiscards()
		if len(owed) != 1 {
			t.Fatalf("owed discards %+v, want one", owed)
		}
		r.dstFake.SetState(fwlVM, libvirtfake.StateShutdown)
		r.dstFake.SetStateReason(fwlVM, "destroyed")
		return r, owed[0]
	}
	exec := func(t *testing.T, r *fwlRig, q string, args ...any) {
		t.Helper()
		if err := r.src.db.Execute(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	// noOwner: the leftover record stands on the target and no host owes a
	// DISCARD of it.
	noOwner := func(t *testing.T, r *fwlRig, o fwmig.OwedDiscard) {
		t.Helper()
		r.src.RetryOwedFirmwareDiscardsOnce(ctx)
		if _, ok, _ := r.dst.fwRecords().GetLeftover(fwlVM); !ok {
			t.Fatal("no leftover record")
		}
		if err := r.src.fwRecords().RemoveOwedDiscard(fwlVM, o.Attempt); err != nil {
			t.Fatal(err)
		}
	}
	// rowOnTarget: failover (keeping the incarnation) put the row on the
	// target that keeps the leftover.
	rowOnTarget := func(t *testing.T, r *fwlRig) {
		t.Helper()
		exec(t, r, `UPDATE vms SET host_name = ?, state = 'stopped' WHERE name = ?`, "dst-host", fwlVM)
	}
	type snap struct {
		nvram, permall []byte
		state          libvirtfake.State
		defined        bool
	}
	take := func(r *fwlRig) snap {
		nv, _ := os.ReadFile(r.dstStore.NvramPath(fwlVM))
		pa, _ := os.ReadFile(filepath.Join(r.dstStore.SwtpmDir(fwLiveUUID), "tpm2", "tpm2-00.permall"))
		st, ok := r.dstFake.RawState(fwlVM)
		return snap{nv, pa, st, ok}
	}
	unchanged := func(t *testing.T, r *fwlRig, before snap, recordStays bool) {
		t.Helper()
		after := take(r)
		if !after.defined || after.state != before.state || !bytes.Equal(after.nvram, before.nvram) || !bytes.Equal(after.permall, before.permall) ||
			len(after.nvram) == 0 || len(after.permall) == 0 {
			t.Errorf("the leftover changed: before %+v, after %+v", before, after)
		}
		if _, ok, _ := r.dst.fwRecords().GetLeftover(fwlVM); ok != recordStays {
			t.Errorf("leftover record present %v, want %v", ok, recordStays)
		}
	}

	// ── m-2: an action other than --discard-target on a leftover-only VM
	// reaches the host that keeps the record, which names it ──
	// Mutation: drop the leftover routing for other actions — red (the entry
	// answers "no host that answered holds a live firmware move marker").
	t.Run("leftover_only/accept_target_names_discard", func(t *testing.T) {
		r, o := returnedReleased(t)
		noOwner(t, r, o)
		before := take(r)
		_, err := r.doctor(actAcceptTarget)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "--discard-target") ||
			!strings.Contains(err.Error(), "leftover record") {
			t.Fatalf("accept-target on a leftover: %v", err)
		}
		unchanged(t, r, before, true)
	})

	// ── m-3: the row names the target for the leftover's own incarnation ──
	// The leftover is the VM's own domain: --discard-target is refused (it
	// would quarantine the VM's own state), and --adopt-target-copy drops the
	// record and keeps the shut-off domain and its state, after which the VM
	// starts there.
	// Mutation: refuse --adopt-target-copy on a leftover record (the dead end
	// of round 3) — red.
	t.Run("row_names_target/adopt_keeps_leftover", func(t *testing.T) {
		r, o := returnedReleased(t)
		noOwner(t, r, o)
		rowOnTarget(t, r)
		before := take(r)
		if err := r.dstFake.StartDomain(fwlVM); err == nil {
			t.Fatal("a start was allowed under the leftover record")
		}
		if _, err := r.doctor(actDiscard); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "the VM's own") {
			t.Fatalf("discard of the VM's own domain: %v", err)
		}
		unchanged(t, r, before, true)
		resp, err := r.doctor(actAdopt)
		if err != nil {
			t.Fatalf("adopt: %v", err)
		}
		if !strings.Contains(resp.GetOutcome(), "nothing was deleted") {
			t.Errorf("outcome %q", resp.GetOutcome())
		}
		unchanged(t, r, before, false)
		if err := r.dstFake.StartDomain(fwlVM); err != nil {
			t.Fatalf("the VM does not start on its own domain once the record went: %v", err)
		}
	})
	// Mutation: drop the shut-off check — red (a running leftover's record
	// is dropped).
	t.Run("row_names_target_running/adopt_refused", func(t *testing.T) {
		r, o := returnedReleased(t)
		noOwner(t, r, o)
		rowOnTarget(t, r)
		r.dstFake.SetState(fwlVM, libvirtfake.StateRunning)
		before := take(r)
		if _, err := r.doctor(actAdopt); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "only a shut-off leftover") {
			t.Fatalf("adopt of a running leftover: %v", err)
		}
		unchanged(t, r, before, true)
	})
	// Mutation: drop the managed-stamp check — red.
	t.Run("row_names_target_other_incarnation_stamp/adopt_refused", func(t *testing.T) {
		r, o := returnedReleased(t)
		noOwner(t, r, o)
		rowOnTarget(t, r)
		if err := r.dstFake.SetDomainManagedIncarnation(fwlVM, "2001-01-01T00:00:00Z", false); err != nil {
			t.Fatal(err)
		}
		before := take(r)
		if _, err := r.doctor(actAdopt); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "stamped incarnation") {
			t.Fatalf("adopt of a domain stamped another incarnation: %v", err)
		}
		unchanged(t, r, before, true)
	})
	// Mutation: drop the owed-DISCARD check — red.
	t.Run("row_names_target_owner_still_owes/adopt_refused", func(t *testing.T) {
		r, _ := returnedReleased(t)
		r.src.RetryOwedFirmwareDiscardsOnce(ctx)
		rowOnTarget(t, r)
		before := take(r)
		if _, err := r.doctor(actAdopt); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "owes") {
			t.Fatalf("adopt while the source owes a DISCARD: %v", err)
		}
		unchanged(t, r, before, true)
	})
	// Mutation: drop the row check — red.
	t.Run("row_on_third_host/adopt_refused", func(t *testing.T) {
		r, o := returnedReleased(t)
		noOwner(t, r, o)
		exec(t, r, `UPDATE vms SET host_name = ? WHERE name = ?`, "third-host", fwlVM)
		before := take(r)
		if _, err := r.doctor(actAdopt); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "--discard-target") {
			t.Fatalf("adopt with the row on a third host: %v", err)
		}
		unchanged(t, r, before, true)
	})
	// The leftover's source does not answer: refused until it is proved off.
	// Mutation: drop the unreachable-source check — red.
	t.Run("row_names_target_source_unreachable/adopt_after_fence", func(t *testing.T) {
		r, o := returnedReleased(t)
		noOwner(t, r, o)
		rowOnTarget(t, r)
		r.dst.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
			return nil, nil, errors.New("connection refused")
		}
		before := take(r)
		if _, err := r.doctor(actAdopt); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "not proved off") {
			t.Fatalf("adopt with the source unreachable: %v", err)
		}
		unchanged(t, r, before, true)
		if err := corrosion.RecordFenceWithState(ctx, r.src.db,
			corrosion.FenceLogRecord{ID: "fc-src", HostName: "src-host", Method: "manual", Result: "manual-confirmed"}, "fenced"); err != nil {
			t.Fatal(err)
		}
		if _, err := r.doctor(actAdopt); err != nil {
			t.Fatalf("adopt with the source proved off: %v", err)
		}
		unchanged(t, r, before, false)
	})

	// ── m-1: the reconciler's quarantine is listed with the superseded disk
	// copies, retained while the VM exists, held while its owed DISCARD is
	// open, and removed once both are over ──
	// Mutation: leave the quarantines out of the listing — red; drop the
	// owed hold — red (removed while the DISCARD is owed).
	t.Run("reconciled_quarantine/listed_retained_held_removed", func(t *testing.T) {
		r, _ := returnedReleased(t)
		rc := health.NewReconciler(r.dst.hostName, r.dst.dataDir, r.dst.db, r.dstFake)
		rc.SetFirmwareStore(r.dstStore)
		rc.ReconcileOnce(ctx)
		find := func(resp *pb.SupersededDisksResponse) *pb.SupersededDisk {
			for _, d := range resp.GetDisks() {
				if strings.HasPrefix(filepath.Base(d.GetPath()), fwlVM+"-reconciled-") {
					return d
				}
			}
			return nil
		}
		list := func(purge bool) *pb.SupersededDisksResponse {
			t.Helper()
			resp, err := r.dst.SupersededDisks(adminCtx(), &pb.SupersededDisksRequest{Purge: purge})
			if err != nil {
				t.Fatal(err)
			}
			return resp
		}
		d := find(list(false))
		if d == nil || d.GetRetained() == "" || d.GetVmName() != fwlVM {
			t.Fatalf("the reconciled quarantine is not listed as retained: %+v", d)
		}
		exec(t, r, `DELETE FROM vms WHERE name = ?`, fwlVM)
		if d := find(list(true)); d == nil || d.GetRemoved() || d.GetHeld() == "" || !exists(d.GetPath()) {
			t.Fatalf("a quarantine whose owed DISCARD is open: %+v", d)
		}
		r.src.RetryOwedFirmwareDiscardsOnce(ctx)
		d = find(list(true))
		if d == nil || !d.GetRemoved() || exists(d.GetPath()) {
			t.Fatalf("a quarantine of a deleted VM with nothing owed was not purged: %+v", d)
		}
	})
}
