package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Re-review D2-18 round 4 (CHANGES, I-1, m-1, m-2, n-1): keeping a leftover
// as the VM's own takes --acknowledge-rollback and names its age and the
// newer copies, which --restore brings back (I-1); a host list that cannot be
// read refuses it (m-1); a VM whose firmware state sits in a stage is never
// started on blank state, and an orphaned stage is finished (m-2); the doctor
// reads a stage as the VM's (n-1).
func TestDoctorFirmwareMove_R5(t *testing.T) {
	ctx := context.Background()
	returnedReleased := func(t *testing.T) *fwlRig {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseReleased)
		r.park(run, fwmig.PhaseTargetUnreachable, "Release was not answered")
		r.fenceTarget()
		if _, err := r.doctor(actAcceptSource, withAck); err != nil {
			t.Fatalf("accept-source: %v", err)
		}
		r.dstFake.SetState(fwlVM, libvirtfake.StateShutdown)
		r.dstFake.SetStateReason(fwlVM, "destroyed")
		return r
	}
	exec := func(t *testing.T, r *fwlRig, q string, args ...any) {
		t.Helper()
		if err := r.src.db.Execute(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	// leftoverOnTarget: the leftover record on dst, no host owes its
	// DISCARD, and the row is on dst for the incarnation.
	leftoverOnTarget := func(t *testing.T) *fwlRig {
		r := returnedReleased(t)
		r.src.RetryOwedFirmwareDiscardsOnce(ctx)
		owed, _ := r.src.fwRecords().ListOwedDiscards()
		for _, o := range owed {
			if err := r.src.fwRecords().RemoveOwedDiscard(o.VM, o.Attempt); err != nil {
				t.Fatal(err)
			}
		}
		if _, ok, _ := r.dst.fwRecords().GetLeftover(fwlVM); !ok {
			t.Fatal("no leftover record")
		}
		exec(t, r, `UPDATE vms SET host_name = ?, state = 'stopped' WHERE name = ?`, "dst-host", fwlVM)
		return r
	}
	qdir := func(s *Server) string { return filepath.Join(s.dataDir, fwmig.QuarantineDir) }
	write := func(t *testing.T, p, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	read := func(p string) string { b, _ := os.ReadFile(p); return string(b) }
	nvramOf := func(r *fwlRig) string { return read(r.dstStore.NvramPath(fwlVM)) }
	permallOf := func(r *fwlRig) string {
		return read(filepath.Join(r.dstStore.SwtpmDir(fwLiveUUID), "tpm2", "tpm2-00.permall"))
	}

	// ── I-1: --adopt-target-copy needs --acknowledge-rollback, and names the
	// leftover's age and the newer copies ──
	// Mutation: drop the acknowledgement check — red.
	t.Run("row_names_target/adopt_without_ack_refused", func(t *testing.T) {
		r := leftoverOnTarget(t)
		newer := filepath.Join(qdir(r.src), fwlVM+"-reconciled-1700000000")
		write(t, filepath.Join(newer, "nvram"), "NEWER")
		_, err := r.doctor(actAdopt)
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("adopt without the acknowledgement: %v", err)
		}
		for _, want := range []string{"--acknowledge-rollback", "src-host", " ago", "src-host:" + newer, "--restore"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal lacks %q: %v", want, err)
			}
		}
		if _, ok, _ := r.dst.fwRecords().GetLeftover(fwlVM); !ok {
			t.Fatal("the leftover record went without the acknowledgement")
		}
		resp, err := r.doctor(actAdopt, withAck)
		if err != nil {
			t.Fatalf("adopt with the acknowledgement: %v", err)
		}
		if !strings.Contains(resp.GetOutcome(), "rollback acknowledged") || !strings.Contains(resp.GetOutcome(), newer) {
			t.Errorf("outcome %q does not name the rollback and the newer copy", resp.GetOutcome())
		}
	})

	// ── I-1: a reconciled quarantine is restored through lv as the VM's own
	// state; what it replaces is set aside ──
	// Mutation: refuse --restore of a firmware quarantine as in round 4 — red.
	t.Run("reconciled_quarantine/restore", func(t *testing.T) {
		r := leftoverOnTarget(t)
		if _, err := r.doctor(actAdopt, withAck); err != nil {
			t.Fatal(err)
		}
		oldNvram, oldPermall := nvramOf(r), permallOf(r)
		q := filepath.Join(qdir(r.dst), fwlVM+"-reconciled-1700000000")
		write(t, filepath.Join(q, "nvram"), "NEWER")
		write(t, filepath.Join(q, "swtpm", "tpm2", "tpm2-00.permall"), "NEWERP")
		write(t, filepath.Join(q, "reason.txt"), "vm: "+fwlVM+"\nuuid: "+fwLiveUUID+"\n")
		r.dstFake.SetState(fwlVM, libvirtfake.StateRunning)
		if _, err := r.dst.SupersededDisks(adminCtx(), &pb.SupersededDisksRequest{RestorePath: q}); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("restore under an active domain: %v", err)
		}
		r.dstFake.SetState(fwlVM, libvirtfake.StateShutdown)
		resp, err := r.dst.SupersededDisks(adminCtx(), &pb.SupersededDisksRequest{RestorePath: q})
		if err != nil {
			t.Fatalf("restore: %v", err)
		}
		if nvramOf(r) != "NEWER" || permallOf(r) != "NEWERP" {
			t.Errorf("restored nvram %q permall %q", nvramOf(r), permallOf(r))
		}
		if sa := resp.GetSetAside(); sa == "" || read(filepath.Join(sa, "nvram")) != oldNvram || read(filepath.Join(sa, "swtpm", "tpm2", "tpm2-00.permall")) != oldPermall {
			t.Errorf("the replaced state is not set aside whole in %q", resp.GetSetAside())
		}
		if exists(q) {
			t.Error("the restored quarantine is still there")
		}
	})

	// ── m-1: the host list cannot be read: adopt refuses ──
	// Mutation: drop the host-list check — red.
	t.Run("host_list_unreadable/adopt_refused", func(t *testing.T) {
		r := leftoverOnTarget(t)
		hostListHook = func(host string, err error) error {
			if host == "dst-host" {
				return errors.New("database is locked")
			}
			return err
		}
		t.Cleanup(func() { hostListHook = nil })
		_, err := r.doctor(actAdopt, withAck)
		if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "host list") {
			t.Fatalf("adopt with the host list unreadable: %v", err)
		}
		if _, ok, _ := r.dst.fwRecords().GetLeftover(fwlVM); !ok {
			t.Fatal("the leftover record went with no host asked")
		}
	})

	// ── m-2: crash mid-stage, then the row comes back: the VM is never
	// started on blank firmware state, and --restore puts the state back ──
	// Mutation: leave stages out of the guard — red (the start goes ahead).
	t.Run("stage_then_row_returns/start_refused_until_restored", func(t *testing.T) {
		r := returnedReleased(t)
		nv := nvramOf(r)
		stage := filepath.Join(qdir(r.dst), fwmig.StageName(fwlVM, fwmig.StageReconciling, fwLiveUUID))
		if err := os.MkdirAll(stage, 0o700); err != nil {
			t.Fatal(err)
		}
		// The pass stopped after the NVRAM moved.
		if err := os.Rename(r.dstStore.NvramPath(fwlVM), filepath.Join(stage, "nvram")); err != nil {
			t.Fatal(err)
		}
		exec(t, r, `UPDATE vms SET host_name = ?, state = 'stopped' WHERE name = ?`, "dst-host", fwlVM)
		if err := r.dstFake.StartDomain(fwlVM); err == nil || !strings.Contains(err.Error(), "blank firmware state") {
			t.Fatalf("start with the state in a stage: %v", err)
		}
		rc := health.NewReconciler(r.dst.hostName, r.dst.dataDir, r.dst.db, r.dstFake)
		rc.SetFirmwareStore(r.dstStore)
		rc.ReconcileOnce(ctx)
		if !exists(stage) {
			t.Fatal("the stage of the VM's own domain was finished away")
		}
		if err := r.dstFake.StartDomain(fwlVM); err == nil {
			t.Fatal("the start went ahead after a reconcile pass")
		}
		if _, err := r.dst.SupersededDisks(adminCtx(), &pb.SupersededDisksRequest{RestorePath: stage}); err != nil {
			t.Fatalf("restore the stage: %v", err)
		}
		if nvramOf(r) != nv || permallOf(r) == "" {
			t.Errorf("restored nvram %q (want %q), permall %q", nvramOf(r), nv, permallOf(r))
		}
		if exists(stage) {
			t.Error("the stage is still there")
		}
		if err := r.dstFake.StartDomain(fwlVM); err != nil {
			t.Fatalf("the start is still refused after the restore: %v", err)
		}
	})

	// ── m-2: an orphaned stage (its leftover domain gone) is finished into a
	// reconciled quarantine, which --remove then takes ──
	// Mutation: never finish orphaned stages — red.
	t.Run("orphaned_stage/finished_then_removable", func(t *testing.T) {
		r := returnedReleased(t)
		nv := nvramOf(r)
		stage := filepath.Join(qdir(r.dst), fwmig.StageName(fwlVM, fwmig.StageReconciling, fwLiveUUID))
		if err := os.MkdirAll(stage, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(r.dstStore.NvramPath(fwlVM), filepath.Join(stage, "nvram")); err != nil {
			t.Fatal(err)
		}
		if err := r.dstFake.UndefineDomainPreservingState(fwlVM); err != nil {
			t.Fatal(err)
		}
		rc := health.NewReconciler(r.dst.hostName, r.dst.dataDir, r.dst.db, r.dstFake)
		rc.SetFirmwareStore(r.dstStore)
		rc.ReconcileOnce(ctx)
		if exists(stage) {
			t.Fatal("the orphaned stage was not finished")
		}
		ents, _ := os.ReadDir(qdir(r.dst))
		final := ""
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), fwlVM+"-reconciled-") {
				final = filepath.Join(qdir(r.dst), e.Name())
			}
		}
		if final == "" || read(filepath.Join(final, "nvram")) != nv || !strings.Contains(read(filepath.Join(final, "reason.txt")), "orphaned stage") {
			t.Fatalf("finished quarantine %q (entries %v)", final, ents)
		}
		r.src.RetryOwedFirmwareDiscardsOnce(ctx) // the owed DISCARD finds no domain: resolved
		resp, err := r.dst.SupersededDisks(adminCtx(), &pb.SupersededDisksRequest{Purge: true, OlderThanSec: SupersededNamedOnlySec, RemovePaths: []string{final}})
		if err != nil {
			t.Fatalf("remove the finished quarantine: %v", err)
		}
		_ = resp
		if exists(final) {
			t.Error("the finished quarantine was not removed")
		}
	})

	// ── n-1: the doctor reads <vm>-reconciling-<uuid> as the VM's ──
	// Mutation: drop the stage branch of the name parsing — red.
	t.Run("doctor_lists_the_vms_stage", func(t *testing.T) {
		r := returnedReleased(t)
		stage := filepath.Join(qdir(r.dst), fwmig.StageName(fwlVM, fwmig.StageReconciling, fwLiveUUID))
		if err := os.MkdirAll(stage, 0o700); err != nil {
			t.Fatal(err)
		}
		own := r.dst.localFirmwareMoveRecords(ctx, fwlVM)
		if !strings.Contains(strings.Join(own.GetQuarantines(), " "), stage) {
			t.Errorf("the VM's stage is not shown: %v", own.GetQuarantines())
		}
		other := r.dst.localFirmwareMoveRecords(ctx, fwlVM+"-reconciling")
		if len(other.GetQuarantines()) != 0 {
			t.Errorf("the stage is shown for VM %s-reconciling: %v", fwlVM, other.GetQuarantines())
		}
	})
}
